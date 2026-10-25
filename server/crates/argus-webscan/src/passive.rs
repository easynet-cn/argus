//! 被动扫描框架（Kafka 消费 + pcap 流量镜像）
//!
//! R5.1: KafkaSource 通过 rskafka 真实连接 Kafka broker 并消费 JSON 消息
//! R5.2: PcapSource 通过 pcap + httparse 真实解析 pcap 文件提取 HTTP 事务

use crate::types::{HttpTransaction, VulnFinding};
use crate::owasp::OwaspScanner;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 流量源 trait
#[async_trait]
pub trait TrafficSource: Send + Sync {
    /// 获取流量的名称
    fn name(&self) -> &str;
    /// 拉取下一批 HTTP 事务
    async fn next_batch(&self) -> Result<Vec<HttpTransaction>, String>;
    /// 是否还有更多数据
    async fn has_more(&self) -> bool;
}

/// Kafka 消费源（R5.1: 真实 Kafka 消费）
///
/// 使用 rskafka 连接 Kafka broker，从指定 topic 的分区消费 JSON 格式的 HTTP 事务消息。
/// 消息 value 应为 HttpTransaction 的 JSON 序列化。
/// 在无 Kafka 环境时（如单元测试），可通过 `load_messages` 预填充离线数据。
pub struct KafkaSource {
    pub brokers: String,
    pub topic: String,
    pub group_id: String,
    /// 真实 Kafka 客户端（连接成功后填充）
    client: Mutex<Option<rskafka::client::partition::PartitionClient>>,
    /// 当前消费 offset（真实消费时使用）
    current_offset: Mutex<i64>,
    /// 高水位（记录最近消费的位置）
    high_watermark: Mutex<i64>,
    /// 预加载消息（离线测试用，真实消费时为空）
    messages: Arc<Mutex<Vec<HttpTransaction>>>,
    /// 预加载数据的读取索引
    index: Arc<Mutex<usize>>,
}

impl KafkaSource {
    pub fn new(brokers: String, topic: String, group_id: String) -> Self {
        Self {
            brokers,
            topic,
            group_id,
            client: Mutex::new(None),
            current_offset: Mutex::new(0),
            high_watermark: Mutex::new(-1),
            messages: Arc::new(Mutex::new(Vec::new())),
            index: Arc::new(Mutex::new(0)),
        }
    }

    /// 连接 Kafka broker 并初始化分区客户端
    ///
    /// 成功后 next_batch 将真实从 Kafka 消费消息；失败则回退到预加载数据。
    pub async fn connect(&self) -> Result<(), String> {
        use rskafka::client::{ClientBuilder, partition::UnknownTopicHandling};
        use rskafka::client::partition::OffsetAt;

        let broker_list: Vec<String> = self.brokers
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        if broker_list.is_empty() {
            return Err("Kafka broker 列表为空".to_string());
        }

        tracing::info!("连接 Kafka: brokers={}, topic={}", self.brokers, self.topic);

        let client = ClientBuilder::new(broker_list)
            .build()
            .await
            .map_err(|e| format!("Kafka 客户端构建失败: {e}"))?;

        let partition_client = client
            .partition_client(self.topic.clone(), 0, UnknownTopicHandling::Retry)
            .await
            .map_err(|e| format!("获取分区客户端失败 (topic={}): {e}", self.topic))?;

        // 获取分区最早 offset（从最早开始消费）
        let low = partition_client
            .get_offset(OffsetAt::Earliest)
            .await
            .map_err(|e| format!("获取最早 offset 失败: {e}"))?;

        *self.current_offset.lock().await = low;
        *self.client.lock().await = Some(partition_client);
        Ok(())
    }

    /// 预加载消息（离线测试用，不连接 Kafka）
    pub async fn load_messages(&self, messages: Vec<HttpTransaction>) {
        self.messages.lock().await.extend(messages);
    }

    /// 从 Kafka 消息 value（字节）解析为 HttpTransaction
    fn parse_kafka_bytes(value: &[u8]) -> Result<HttpTransaction, String> {
        let json_str = String::from_utf8_lossy(value);
        Self::parse_kafka_message(&json_str)
    }

    /// 从 JSON 消息解析为 HttpTransaction
    pub fn parse_kafka_message(json: &str) -> Result<HttpTransaction, String> {
        serde_json::from_str(json).map_err(|e| format!("解析 Kafka 消息失败: {e}"))
    }
}

#[async_trait]
impl TrafficSource for KafkaSource {
    fn name(&self) -> &str {
        "Kafka"
    }

    async fn next_batch(&self) -> Result<Vec<HttpTransaction>, String> {
        // 真实 Kafka 消费路径
        let mut client_guard = self.client.lock().await;
        if let Some(partition_client) = client_guard.as_ref() {
            let offset = *self.current_offset.lock().await;

            // 批量拉取：min..max bytes 限制，max wait 1000ms
            let (records, high_watermark) = partition_client
                .fetch_records(offset, 1..1_000_000, 1_000).await
                .map_err(|e| format!("Kafka 拉取失败 (offset={}): {e}", offset))?;

            if records.is_empty() {
                return Ok(vec![]);
            }

            // 更新 offset 和高水位
            let last_offset = records.last().map(|r| r.offset + 1).unwrap_or(offset);
            *self.current_offset.lock().await = last_offset as i64;
            *self.high_watermark.lock().await = high_watermark;
            drop(client_guard);

            // 解析每条记录的 value 为 HttpTransaction
            let mut transactions = Vec::with_capacity(records.len());
            let mut parse_errors = 0u32;
            for record in records {
                if let Some(value) = record.record.value {
                    match Self::parse_kafka_bytes(&value) {
                        Ok(txn) => transactions.push(txn),
                        Err(e) => {
                            tracing::debug!("Kafka 消息解析失败 (offset={}): {}", record.offset, e);
                            parse_errors += 1;
                        }
                    }
                }
            }
            if parse_errors > 0 {
                tracing::warn!("Kafka 批次: {} 条消息解析失败", parse_errors);
            }
            tracing::info!(
                "Kafka 消费: offset {} → {}, 解析出 {} 条事务",
                offset, last_offset, transactions.len()
            );
            return Ok(transactions);
        }
        drop(client_guard);

        // 回退到预加载消息（离线测试模式）
        let messages = self.messages.lock().await;
        let mut index = self.index.lock().await;
        let batch_size = 100;
        let start = *index;
        let end = (start + batch_size).min(messages.len());
        if start >= messages.len() {
            return Ok(vec![]);
        }
        let batch = messages[start..end].to_vec();
        *index = end;
        Ok(batch)
    }

    async fn has_more(&self) -> bool {
        let client_guard = self.client.lock().await;
        if client_guard.is_some() {
            // 真实 Kafka：如果 offset 未达高水位，还有更多
            let offset = *self.current_offset.lock().await;
            let hw = *self.high_watermark.lock().await;
            // 初次连接时 high_watermark 为 -1，尝试拉取
            offset < hw || hw < 0
        } else {
            drop(client_guard);
            // 预加载模式
            let messages = self.messages.lock().await;
            let index = self.index.lock().await;
            *index < messages.len()
        }
    }
}

/// pcap 文件源（R5.2: 真实 pcap 文件解析）
///
/// 使用 pcap crate 打开 pcap 文件，通过 etherparse 解析以太网/IP/TCP 层，
/// 用 httparse 解析 HTTP 请求/响应，配对为 HttpTransaction。
/// 在无 pcap 文件时（如单元测试），可通过 `load_transactions` 预填充离线数据。
pub struct PcapSource {
    file_path: String,
    /// 预加载事务（离线测试用）
    transactions: Arc<Mutex<Vec<HttpTransaction>>>,
    index: Arc<Mutex<usize>>,
    /// 真实解析是否已完成
    parsed: Mutex<bool>,
}

impl PcapSource {
    pub fn new(file_path: String) -> Self {
        Self {
            file_path,
            transactions: Arc::new(Mutex::new(Vec::new())),
            index: Arc::new(Mutex::new(0)),
            parsed: Mutex::new(false),
        }
    }

    /// 预加载事务（离线测试用，不解析 pcap 文件）
    pub async fn load_transactions(&self, txns: Vec<HttpTransaction>) {
        self.transactions.lock().await.extend(txns);
    }

    /// 从 pcap 文件路径获取
    pub fn path(&self) -> &str {
        &self.file_path
    }

    /// 真实解析 pcap 文件，提取 HTTP 事务（R5.2 同步入口）
    ///
    /// 流程：pcap → 以太网帧 → IP 包 → TCP 段 → HTTP 请求/响应配对
    pub fn parse_file(&self) -> Result<usize, String> {
        let txns = parse_pcap_file(&self.file_path)?;
        let count = txns.len();
        self.transactions.blocking_lock().extend(txns);
        *self.parsed.blocking_lock() = true;
        Ok(count)
    }

    /// 用 httparse 解析 HTTP 请求
    fn parse_http_request(data: &[u8]) -> Option<crate::types::HttpRequest> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        let status = req.parse(data).ok()?;
        if !status.is_complete() {
            return None;
        }

        let method = req.method?.to_string();
        let path = req.path?.to_string();

        // 从 Host 头构建完整 URL
        let host = headers.iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .map(|h| String::from_utf8_lossy(h.value).to_string())
            .unwrap_or_default();
        let url = if host.is_empty() {
            path
        } else if path.starts_with("http://") || path.starts_with("https://") {
            path
        } else {
            format!("http://{}{}", host, path)
        };

        // 收集所有头
        let headers_vec: Vec<(String, String)> = headers.iter()
            .filter(|h| !h.name.is_empty())
            .map(|h| (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string()
            ))
            .collect();

        // 提取 body（headers 之后的 \r\n\r\n）
        let body = Self::extract_body(data);

        Some(crate::types::HttpRequest {
            method,
            url,
            headers: headers_vec,
            body,
        })
    }

    /// 用 httparse 解析 HTTP 响应
    fn parse_http_response(data: &[u8]) -> Option<crate::types::HttpResponse> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers);
        let status = resp.parse(data).ok()?;
        if !status.is_complete() {
            return None;
        }

        let status_code = resp.code.unwrap_or(0);

        let headers_vec: Vec<(String, String)> = headers.iter()
            .filter(|h| !h.name.is_empty())
            .map(|h| (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string()
            ))
            .collect();

        let body = Self::extract_body(data).unwrap_or_default();

        Some(crate::types::HttpResponse {
            status: status_code,
            headers: headers_vec,
            body,
        })
    }

    /// 从 HTTP 报文中提取 body（\r\n\r\n 之后的部分）
    fn extract_body(data: &[u8]) -> Option<String> {
        // 查找 \r\n\r\n 分隔符
        let sep = b"\r\n\r\n";
        let pos = data.windows(4).position(|w| w == sep)?;
        let body_bytes = &data[pos + 4..];
        if body_bytes.is_empty() {
            return None;
        }
        // 尝试 UTF-8 解码，忽略非 UTF-8 字符
        Some(String::from_utf8_lossy(body_bytes).to_string())
    }
}

/// 真实解析 pcap 文件，提取 HTTP 事务（R5.2 核心）
///
/// 独立函数，便于在 spawn_blocking 中调用。
/// 流程：pcap → 以太网帧 → IP 包 → TCP 段 → HTTP 请求/响应配对
fn parse_pcap_file(file_path: &str) -> Result<Vec<HttpTransaction>, String> {
    use pcap::Capture;
    use etherparse::SlicedPacket;
    use std::collections::HashMap as StdHashMap;

    let mut cap = Capture::from_file(file_path)
        .map_err(|e| format!("打开 pcap 文件失败 ({}): {e}", file_path))?;

    // 按 TCP 四元组分组累积 payload
    let mut streams: StdHashMap<(String, u16, String, u16), Vec<u8>> = StdHashMap::new();
    let mut http_requests: Vec<(String, u16, String, u16, Vec<u8>)> = Vec::new();
    let mut http_responses: Vec<(String, u16, String, u16, Vec<u8>)> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(&packet) {
            Ok(sliced) => {
                if let (Some(ip), Some(tcp)) = (&sliced.net, &sliced.transport) {
                    let (src_ip, dst_ip) = match ip {
                        etherparse::NetSlice::Ipv4(v4) => (
                            format!("{}", v4.header().source_addr()),
                            format!("{}", v4.header().destination_addr()),
                        ),
                        etherparse::NetSlice::Ipv6(v6) => (
                            format!("{}", v6.header().source_addr()),
                            format!("{}", v6.header().destination_addr()),
                        ),
                    };
                    let (src_port, dst_port, payload) = match tcp {
                        etherparse::TransportSlice::Tcp(t) => {
                            (t.source_port(), t.destination_port(), t.payload())
                        }
                        _ => continue,
                    };

                    if payload.is_empty() {
                        continue;
                    }

                    let is_http_request = payload.starts_with(b"GET ")
                        || payload.starts_with(b"POST ")
                        || payload.starts_with(b"PUT ")
                        || payload.starts_with(b"DELETE ")
                        || payload.starts_with(b"HEAD ")
                        || payload.starts_with(b"OPTIONS ")
                        || payload.starts_with(b"PATCH ")
                        || payload.starts_with(b"CONNECT ")
                        || payload.starts_with(b"TRACE ");
                    let is_http_response = payload.starts_with(b"HTTP/1.")
                        || payload.starts_with(b"HTTP/2.");

                    if is_http_request {
                        let key = (src_ip.clone(), src_port, dst_ip.clone(), dst_port);
                        streams.entry(key.clone()).or_default().extend_from_slice(payload);
                        if let Some(stream_data) = streams.get(&key) {
                            if PcapSource::parse_http_request(stream_data).is_some() {
                                http_requests.push((src_ip, src_port, dst_ip, dst_port, stream_data.clone()));
                                streams.remove(&key);
                            }
                        }
                    } else if is_http_response {
                        // 响应方向：源/目的互换，以匹配请求
                        let key = (dst_ip.clone(), dst_port, src_ip.clone(), src_port);
                        streams.entry(key.clone()).or_default().extend_from_slice(payload);
                        if let Some(stream_data) = streams.get(&key) {
                            if PcapSource::parse_http_response(stream_data).is_some() {
                                http_responses.push((dst_ip, dst_port, src_ip, src_port, stream_data.clone()));
                                streams.remove(&key);
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // 配对请求和响应：同一 TCP 流（源/目的 IP 和端口互换）
    let mut transactions = Vec::new();
    for (src_ip, src_port, dst_ip, dst_port, req_data) in &http_requests {
        let matching_response = http_responses.iter().find_map(|(r_src_ip, r_src_port, r_dst_ip, r_dst_port, resp_data)| {
            if r_dst_ip == src_ip && *r_dst_port == *src_port && r_src_ip == dst_ip && *r_src_port == *dst_port {
                Some(resp_data.clone())
            } else {
                None
            }
        });

        if let Some(req) = PcapSource::parse_http_request(req_data) {
            let resp = matching_response
                .and_then(|d| PcapSource::parse_http_response(&d))
                .unwrap_or(crate::types::HttpResponse { status: 0, headers: vec![], body: String::new() });
            transactions.push(HttpTransaction {
                request: req,
                response: resp,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    tracing::info!(
        "pcap 解析: {} 个请求, {} 个响应, {} 个事务",
        http_requests.len(), http_responses.len(), transactions.len()
    );
    Ok(transactions)
}

#[async_trait]
impl TrafficSource for PcapSource {
    fn name(&self) -> &str {
        "pcap"
    }

    async fn next_batch(&self) -> Result<Vec<HttpTransaction>, String> {
        // 尚未解析且文件路径非空 → 通过 spawn_blocking 真实解析
        let already_parsed = *self.parsed.lock().await;
        if !already_parsed && !self.file_path.is_empty() {
            let file_path = self.file_path.clone();
            match tokio::task::spawn_blocking(move || parse_pcap_file(&file_path)).await {
                Ok(Ok(txns)) => {
                    self.transactions.lock().await.extend(txns);
                    *self.parsed.lock().await = true;
                }
                Ok(Err(e)) => {
                    // 文件不存在或解析失败：标记已解析，回退到预加载数据
                    tracing::warn!("pcap 文件解析失败，回退到预加载数据: {}", e);
                    *self.parsed.lock().await = true;
                }
                Err(e) => {
                    tracing::warn!("pcap 解析任务失败，回退到预加载数据: {}", e);
                    *self.parsed.lock().await = true;
                }
            }
        }

        // 返回批次
        let txns = self.transactions.lock().await;
        let mut index = self.index.lock().await;
        let batch_size = 100;
        let start = *index;
        let end = (start + batch_size).min(txns.len());
        if start >= txns.len() {
            return Ok(vec![]);
        }
        let batch = txns[start..end].to_vec();
        *index = end;
        Ok(batch)
    }

    async fn has_more(&self) -> bool {
        let txns = self.transactions.lock().await;
        let index = self.index.lock().await;
        *index < txns.len()
    }
}

/// 被动扫描引擎
pub struct PassiveScanner {
    scanner: OwaspScanner,
    all_findings: Vec<VulnFinding>,
}

impl PassiveScanner {
    pub fn new() -> Self {
        Self {
            scanner: OwaspScanner::new(),
            all_findings: Vec::new(),
        }
    }

    /// 从流量源消费并扫描
    pub async fn scan_source(&mut self, source: &dyn TrafficSource) -> Vec<VulnFinding> {
        let mut batch_count = 0;
        while source.has_more().await {
            match source.next_batch().await {
                Ok(batch) => {
                    if batch.is_empty() {
                        break;
                    }
                    batch_count += 1;
                    let findings = self.scanner.scan_passive(&batch);
                    tracing::info!(
                        "批次 {}: {} 条事务, {} 个发现",
                        batch_count,
                        batch.len(),
                        findings.len()
                    );
                    self.all_findings.extend(findings.clone());
                }
                Err(e) => {
                    tracing::error!("从 {} 拉取数据失败: {}", source.name(), e);
                    break;
                }
            }
        }
        self.all_findings.clone()
    }

    /// 获取所有发现
    pub fn findings(&self) -> &[VulnFinding] {
        &self.all_findings
    }
}

impl Default for PassiveScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HttpRequest, HttpResponse};

    fn make_txn(url: &str, body: &str) -> HttpTransaction {
        HttpTransaction {
            request: HttpRequest {
                method: "GET".to_string(),
                url: url.to_string(),
                headers: vec![],
                body: None,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![],
                body: body.to_string(),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn test_kafka_source() {
        let source = KafkaSource::new(
            "localhost:9092".to_string(),
            "http-traffic".to_string(),
            "argus-scanner".to_string(),
        );
        source.load_messages(vec![make_txn("http://example.com/1", "ok"), make_txn("http://example.com/2", "ok")]).await;

        assert!(source.has_more().await);
        let batch = source.next_batch().await.unwrap();
        assert_eq!(batch.len(), 2);
        assert!(!source.has_more().await);
    }

    #[tokio::test]
    async fn test_kafka_source_batching() {
        let source = KafkaSource::new(
            "localhost:9092".to_string(),
            "test".to_string(),
            "test".to_string(),
        );
        let mut txns = Vec::new();
        for i in 0..250 {
            txns.push(make_txn(&format!("http://example.com/{}", i), "ok"));
        }
        source.load_messages(txns).await;

        let batch1 = source.next_batch().await.unwrap();
        assert_eq!(batch1.len(), 100);
        let batch2 = source.next_batch().await.unwrap();
        assert_eq!(batch2.len(), 100);
        let batch3 = source.next_batch().await.unwrap();
        assert_eq!(batch3.len(), 50);
        let batch4 = source.next_batch().await.unwrap();
        assert_eq!(batch4.len(), 0);
    }

    #[tokio::test]
    async fn test_pcap_source() {
        let source = PcapSource::new("capture.pcap".to_string());
        source.load_transactions(vec![make_txn("http://example.com/", "body")]).await;

        assert!(source.has_more().await);
        let batch = source.next_batch().await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].request.url, "http://example.com/");
    }

    #[tokio::test]
    async fn test_passive_scanner_with_kafka() {
        let mut scanner = PassiveScanner::new();
        let source = KafkaSource::new(
            "localhost:9092".to_string(),
            "test".to_string(),
            "test".to_string(),
        );
        // 包含泄露 AWS key 的响应
        source.load_messages(vec![
            make_txn("http://example.com/config", r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#),
            make_txn("http://example.com/normal", "normal content"),
        ]).await;

        let findings = scanner.scan_source(&source).await;
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.evidence.contains("AWS")));
    }

    #[tokio::test]
    async fn test_kafka_message_parse() {
        let json = r#"{
            "request": {"method": "GET", "url": "http://example.com/", "headers": [], "body": null},
            "response": {"status": 200, "headers": [], "body": "ok"},
            "timestamp": "2024-01-01T00:00:00Z"
        }"#;
        let txn = KafkaSource::parse_kafka_message(json).unwrap();
        assert_eq!(txn.request.method, "GET");
        assert_eq!(txn.response.status, 200);
    }

    #[test]
    fn test_kafka_message_parse_invalid() {
        assert!(KafkaSource::parse_kafka_message("invalid").is_err());
    }

    #[tokio::test]
    async fn test_empty_source() {
        let source = KafkaSource::new(
            "localhost:9092".to_string(),
            "empty".to_string(),
            "empty".to_string(),
        );
        assert!(!source.has_more().await);
        let batch = source.next_batch().await.unwrap();
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_parse_http_request() {
        let raw = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let req = PcapSource::parse_http_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://example.com/test");
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn test_parse_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>";
        let resp = PcapSource::parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "<html>hello</html>");
        assert_eq!(resp.headers.len(), 1);
    }

    #[test]
    fn test_parse_http_request_with_body() {
        let raw = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 16\r\n\r\nuser=admin&pw=123";
        let req = PcapSource::parse_http_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "http://example.com/api/login");
        assert!(req.body.is_some());
        assert_eq!(req.body.unwrap(), "user=admin&pw=123");
    }

    #[test]
    fn test_parse_http_response_partial() {
        let raw = b"HTTP/1.1 200";
        assert!(PcapSource::parse_http_response(raw).is_none());
    }

    #[test]
    fn test_extract_body_empty() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert!(PcapSource::extract_body(raw).is_none());
    }

    #[test]
    fn test_extract_body_present() {
        let raw = b"HTTP/1.1 200\r\n\r\nbody content";
        assert_eq!(PcapSource::extract_body(raw).unwrap(), "body content");
    }
}
