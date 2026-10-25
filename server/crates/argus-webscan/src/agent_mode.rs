//! Agent 模式被动扫描 (G5.9)
//!
//! Agent 部署在 Web 服务器上，采集本地 HTTP 访问日志后上报到中心扫描器。
//! 支持 Apache / Nginx / 通用 access log 格式（Common Log Format 及 Combined 格式）。
//!
//! 工作流程：
//! 1. 定时读取日志文件的新增内容
//! 2. 解析每一行日志为 HttpTransaction
//! 3. 批量缓冲，达到上报间隔后通过 HTTP POST 上报到中心扫描器
//!
//! 同时实现 `TrafficSource` trait，可被 `PassiveScanner` 直接消费。

use crate::types::{HttpRequest, HttpResponse, HttpTransaction};
use crate::passive::TrafficSource;
use async_trait::async_trait;
use regex::Regex;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Agent 配置
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// 访问日志文件路径
    pub log_path: String,
    /// 中心扫描器上报地址（HTTP POST 端点）
    pub report_url: String,
    /// 上报间隔（秒）
    pub report_interval_secs: u64,
    /// 认证 token（上报时放在 Authorization 头）
    pub auth_token: String,
    /// 单批上报最大事务数
    pub batch_size: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            log_path: "/var/log/nginx/access.log".to_string(),
            report_url: "http://localhost:8080/api/transactions".to_string(),
            report_interval_secs: 30,
            auth_token: String::new(),
            batch_size: 100,
        }
    }
}

/// 单行访问日志解析结果
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub client_ip: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub status: u16,
    pub body_bytes: u64,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

/// Agent 日志采集器
///
/// 负责解析访问日志、缓冲事务、定时上报。
pub struct AgentCollector {
    config: AgentConfig,
    /// 已解析但未上报的事务缓冲
    buffer: Arc<Mutex<VecDeque<HttpTransaction>>>,
    /// 已读取到的日志文件偏移量（字节）
    read_offset: Arc<Mutex<u64>>,
    /// 预加载事务（离线测试用）
    preloaded: Arc<Mutex<VecDeque<HttpTransaction>>>,
}

impl AgentCollector {
    /// 创建新的 Agent 采集器
    pub fn new(config: AgentConfig) -> Self {
        Self {
            config,
            buffer: Arc::new(Mutex::new(VecDeque::new())),
            read_offset: Arc::new(Mutex::new(0)),
            preloaded: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// 获取配置引用
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    /// 预加载事务（离线测试用，不读取真实日志文件）
    pub async fn load_transactions(&self, txns: Vec<HttpTransaction>) {
        self.preloaded.lock().await.extend(txns);
    }

    /// 解析单行访问日志
    ///
    /// 支持 Common Log Format (CLF) 和 Combined Log Format。
    /// - CLF: `IP - - [timestamp] "METHOD path HTTP/x.x" status size`
    /// - Combined: CLF + `"referer" "user-agent"`
    pub fn parse_log_line(line: &str) -> Option<AccessLogEntry> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        // Combined 格式正则
        // IP ident user [timestamp] "request" status size "referer" "user-agent"
        let re = Regex::new(
            r#"^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?"#,
        ).ok()?;

        let caps = re.captures(line)?;

        let client_ip = caps.get(1)?.as_str().to_string();
        let timestamp = caps.get(4)?.as_str().to_string();
        let method = caps.get(5)?.as_str().to_string();
        let path = caps.get(6)?.as_str().to_string();
        let http_version = caps.get(7)?.as_str().to_string();
        let status: u16 = caps.get(8)?.as_str().parse().ok()?;
        let body_bytes_str = caps.get(9)?.as_str();
        let body_bytes: u64 = if body_bytes_str == "-" { 0 } else { body_bytes_str.parse().ok()? };

        let referer = caps.get(10).map(|m| m.as_str().to_string());
        let user_agent = caps.get(11).map(|m| m.as_str().to_string());

        Some(AccessLogEntry {
            client_ip,
            timestamp,
            method,
            path,
            http_version,
            status,
            body_bytes,
            referer,
            user_agent,
        })
    }

    /// 将访问日志条目转换为 HttpTransaction
    ///
    /// 由于 access log 不记录请求体和响应体，仅记录请求行和状态码。
    pub fn entry_to_transaction(entry: &AccessLogEntry) -> HttpTransaction {
        let mut headers = Vec::new();
        if let Some(ua) = &entry.user_agent {
            headers.push(("User-Agent".to_string(), ua.clone()));
        }
        if let Some(referer) = &entry.referer {
            headers.push(("Referer".to_string(), referer.clone()));
        }
        headers.push(("X-Forwarded-For".to_string(), entry.client_ip.clone()));

        // 尝试将 path 转为完整 URL；若 path 已是绝对 URL 则直接使用
        let url = if entry.path.starts_with("http://") || entry.path.starts_with("https://") {
            entry.path.clone()
        } else {
            format!("http://{}{}", entry.client_ip, entry.path)
        };

        let timestamp = parse_log_timestamp(&entry.timestamp)
            .unwrap_or_else(|| entry.timestamp.clone());

        HttpTransaction {
            request: HttpRequest {
                method: entry.method.clone(),
                url,
                headers,
                body: None,
            },
            response: HttpResponse {
                status: entry.status,
                headers: vec![],
                body: String::new(),
            },
            timestamp,
        }
    }

    /// 解析多行日志文本，返回 HttpTransaction 列表
    pub fn parse_log_content(content: &str) -> Vec<HttpTransaction> {
        content
            .lines()
            .filter_map(|line| Self::parse_log_line(line))
            .map(|entry| Self::entry_to_transaction(&entry))
            .collect()
    }

    /// 读取日志文件新增内容并解析
    ///
    /// 从上次读取偏移量开始读取，解析后放入缓冲。
    pub async fn collect_new_entries(&self) -> Result<usize, String> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

        let mut file = match tokio::fs::File::open(&self.config.log_path).await {
            Ok(f) => f,
            Err(e) => return Err(format!("打开日志文件失败 ({}): {e}", self.config.log_path)),
        };

        let mut offset = self.read_offset.lock().await;
        file.seek(SeekFrom::Start(*offset))
            .await
            .map_err(|e| format!("seek 失败: {e}"))?;

        let mut content = String::new();
        let n = file
            .read_to_string(&mut content)
            .await
            .map_err(|e| format!("读取日志失败: {e}"))?;

        *offset += n as u64;
        drop(offset);

        if content.is_empty() {
            return Ok(0);
        }

        let txns = Self::parse_log_content(&content);
        let count = txns.len();
        self.buffer.lock().await.extend(txns);

        tracing::debug!("Agent 采集: 解析 {} 行日志, 生成 {} 条事务", n, count);
        Ok(count)
    }

    /// 上报缓冲中的事务到中心扫描器
    ///
    /// 以批量方式通过 HTTP POST 上报 JSON 序列化的 HttpTransaction 列表。
    pub async fn report_buffer(&self) -> Result<usize, String> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(0);
        }

        let take = self.config.batch_size.min(buffer.len());
        let batch: Vec<HttpTransaction> = buffer.drain(..take).collect();
        let count = batch.len();
        drop(buffer);

        let body = serde_json::to_string(&batch)
            .map_err(|e| format!("序列化事务失败: {e}"))?;

        let client = reqwest::Client::new();
        let mut req = client
            .post(&self.config.report_url)
            .header("Content-Type", "application/json");

        if !self.config.auth_token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.config.auth_token));
        }

        match req.body(body).send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    tracing::info!("Agent 上报成功: {} 条事务, HTTP {}", count, status);
                    Ok(count)
                } else {
                    let err_msg = format!("上报失败: HTTP {}", status);
                    tracing::error!("{}", err_msg);
                    Err(err_msg)
                }
            }
            Err(e) => {
                let err_msg = format!("上报请求失败: {e}");
                tracing::error!("{}", err_msg);
                Err(err_msg)
            }
        }
    }

    /// 运行 Agent 主循环：采集 + 定时上报
    ///
    /// 每 `report_interval_secs` 秒执行一次采集和上报。
    pub async fn run(&self) -> Result<(), String> {
        let interval = std::time::Duration::from_secs(self.config.report_interval_secs);
        loop {
            // 采集新日志
            if let Err(e) = self.collect_new_entries().await {
                tracing::warn!("Agent 采集失败: {}", e);
            }

            // 上报
            if let Err(e) = self.report_buffer().await {
                tracing::warn!("Agent 上报失败: {}", e);
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// 获取当前缓冲中的事务数量
    pub async fn buffer_len(&self) -> usize {
        self.buffer.lock().await.len()
    }
}

#[async_trait]
impl TrafficSource for AgentCollector {
    fn name(&self) -> &str {
        "agent"
    }

    async fn next_batch(&self) -> Result<Vec<HttpTransaction>, String> {
        // 优先返回预加载数据（测试用）
        {
            let mut preloaded = self.preloaded.lock().await;
            if !preloaded.is_empty() {
                let take = self.config.batch_size.min(preloaded.len());
                let batch: Vec<HttpTransaction> = preloaded.drain(..take).collect();
                return Ok(batch);
            }
        }

        // 尝试采集新日志
        let _ = self.collect_new_entries().await;

        let mut buffer = self.buffer.lock().await;
        let take = self.config.batch_size.min(buffer.len());
        let batch: Vec<HttpTransaction> = buffer.drain(..take).collect();
        Ok(batch)
    }

    async fn has_more(&self) -> bool {
        let preloaded = self.preloaded.lock().await;
        let buffer = self.buffer.lock().await;
        !preloaded.is_empty() || !buffer.is_empty()
    }
}

/// 解析 access log 时间戳为 RFC3339 格式
///
/// 输入格式: `10/Oct/2000:13:55:36 -0700`
/// 输出格式: `2000-10-10T13:55:36-07:00`
fn parse_log_timestamp(ts: &str) -> Option<String> {
    // 格式: dd/Mon/yyyy:HH:MM:SS +zzzz
    let parts: Vec<&str> = ts.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }
    let datetime = parts[0];
    let tz = parts[1];

    // 解析日期时间
    let dt_parts: Vec<&str> = datetime.split(':').collect();
    if dt_parts.len() != 4 {
        return None;
    }
    let date_part = dt_parts[0];
    let hour = dt_parts[1];
    let minute = dt_parts[2];
    let second = dt_parts[3];

    let date_parts: Vec<&str> = date_part.split('/').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let day = date_parts[0];
    let month_str = date_parts[1];
    let year = date_parts[2];

    let month = match month_str {
        "Jan" => "01", "Feb" => "02", "Mar" => "03", "Apr" => "04",
        "May" => "05", "Jun" => "06", "Jul" => "07", "Aug" => "08",
        "Sep" => "09", "Oct" => "10", "Nov" => "11", "Dec" => "12",
        _ => return None,
    };

    // 格式化时区: -0700 -> -07:00
    let tz_formatted = if tz.len() == 5 && (tz.starts_with('+') || tz.starts_with('-')) {
        format!("{}:{}", &tz[..3], &tz[3..])
    } else {
        tz.to_string()
    };

    Some(format!("{year}-{month}-{day}T{hour}:{minute}:{second}{tz_formatted}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_common_log_format() {
        let line = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "127.0.0.1");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/apache_pb.gif");
        assert_eq!(entry.http_version, "HTTP/1.0");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, 2326);
        assert!(entry.referer.is_none());
        assert!(entry.user_agent.is_none());
    }

    #[test]
    fn test_parse_combined_log_format() {
        let line = r#"192.168.1.1 - user [15/Jan/2024:10:30:45 +0800] "POST /api/login HTTP/1.1" 200 512 "https://example.com/" "Mozilla/5.0""#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "192.168.1.1");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/api/login");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, 512);
        assert_eq!(entry.referer.as_deref(), Some("https://example.com/"));
        assert_eq!(entry.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[test]
    fn test_parse_log_with_dash_size() {
        let line = r#"10.0.0.1 - - [01/Mar/2024:00:00:00 +0000] "GET / HTTP/1.1" 304 -"#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        assert_eq!(entry.status, 304);
        assert_eq!(entry.body_bytes, 0);
    }

    #[test]
    fn test_parse_invalid_log_line() {
        assert!(AgentCollector::parse_log_line("not a log line").is_none());
        assert!(AgentCollector::parse_log_line("").is_none());
    }

    #[test]
    fn test_entry_to_transaction() {
        let line = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /test HTTP/1.1" 200 100"#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        let txn = AgentCollector::entry_to_transaction(&entry);
        assert_eq!(txn.request.method, "GET");
        assert!(txn.request.url.contains("/test"));
        assert_eq!(txn.response.status, 200);
        assert!(txn.request.headers.iter().any(|(k, _)| k == "X-Forwarded-For"));
    }

    #[test]
    fn test_entry_to_transaction_combined() {
        let line = r#"192.168.1.1 - - [15/Jan/2024:10:30:45 +0800] "GET /page HTTP/1.1" 200 1024 "https://ref.com" "MyAgent/1.0""#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        let txn = AgentCollector::entry_to_transaction(&entry);
        assert!(txn.request.headers.iter().any(|(k, v)| k == "User-Agent" && v == "MyAgent/1.0"));
        assert!(txn.request.headers.iter().any(|(k, v)| k == "Referer" && v == "https://ref.com"));
    }

    #[test]
    fn test_parse_log_content_multiple() {
        let content = r#"127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.1" 200 100
127.0.0.1 - - [10/Oct/2000:13:55:37 -0700] "POST /b HTTP/1.1" 201 50
invalid line
127.0.0.1 - - [10/Oct/2000:13:55:38 -0700] "GET /c HTTP/1.1" 404 0"#;
        let txns = AgentCollector::parse_log_content(content);
        assert_eq!(txns.len(), 3);
        assert_eq!(txns[0].request.method, "GET");
        assert_eq!(txns[1].request.method, "POST");
        assert_eq!(txns[2].response.status, 404);
    }

    #[test]
    fn test_parse_log_timestamp() {
        let ts = "10/Oct/2000:13:55:36 -0700";
        let parsed = parse_log_timestamp(ts).unwrap();
        assert_eq!(parsed, "2000-10-10T13:55:36-07:00");
    }

    #[test]
    fn test_parse_log_timestamp_positive_tz() {
        let ts = "15/Jan/2024:10:30:45 +0800";
        let parsed = parse_log_timestamp(ts).unwrap();
        assert_eq!(parsed, "2024-01-15T10:30:45+08:00");
    }

    #[test]
    fn test_parse_log_timestamp_invalid() {
        assert!(parse_log_timestamp("invalid").is_none());
        assert!(parse_log_timestamp("").is_none());
    }

    #[test]
    fn test_agent_config_default() {
        let config = AgentConfig::default();
        assert!(!config.log_path.is_empty());
        assert!(!config.report_url.is_empty());
        assert!(config.report_interval_secs > 0);
        assert_eq!(config.batch_size, 100);
    }

    #[tokio::test]
    async fn test_agent_collector_preloaded() {
        let config = AgentConfig::default();
        let collector = AgentCollector::new(config);

        let txns = vec![
            HttpTransaction {
                request: HttpRequest {
                    method: "GET".to_string(),
                    url: "http://example.com/1".to_string(),
                    headers: vec![],
                    body: None,
                },
                response: HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: "ok".to_string(),
                },
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
        ];
        collector.load_transactions(txns).await;

        assert!(collector.has_more().await);
        let batch = collector.next_batch().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].request.url, "http://example.com/1");
        assert!(!collector.has_more().await);
    }

    #[tokio::test]
    async fn test_agent_collector_empty() {
        let config = AgentConfig::default();
        let collector = AgentCollector::new(config);
        assert!(!collector.has_more().await);
        let batch = collector.next_batch().await.unwrap();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_nginx_log_format() {
        // Nginx 默认 combined 格式
        let line = r#"203.0.113.10 - - [28/Feb/2024:14:28:33 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://referrer.example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""#;
        let entry = AgentCollector::parse_log_line(line).unwrap();
        assert_eq!(entry.client_ip, "203.0.113.10");
        assert_eq!(entry.path, "/index.html");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.user_agent.as_deref(), Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
    }
}
