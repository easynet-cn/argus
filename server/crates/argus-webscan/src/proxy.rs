//! HTTP 代理被动扫描
//!
//! TCP 监听器充当 HTTP 代理，拦截请求/响应并运行被动扫描器。
//! 支持 HTTP CONNECT 隧道（HTTPS 流量仅可见 CONNECT，不解密 TLS）。

use crate::types::{HttpTransaction, VulnFinding};
use crate::owasp::OwaspScanner;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// 代理配置
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 8888,
        }
    }
}

/// HTTP 代理服务器
pub struct HttpProxy {
    config: ProxyConfig,
    scanner: OwaspScanner,
    findings: Arc<Mutex<Vec<VulnFinding>>>,
    transactions: Arc<Mutex<VecDeque<HttpTransaction>>>,
}

impl HttpProxy {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            scanner: OwaspScanner::new(),
            findings: Arc::new(Mutex::new(Vec::new())),
            transactions: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
        }
    }

    /// 启动代理
    pub async fn run(&self) -> std::io::Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.listen_addr, self.config.listen_port)
            .parse()
            .expect("无效监听地址");
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("HTTP 代理监听: {}", addr);

        loop {
            let (mut client, client_addr) = listener.accept().await?;
            let findings = self.findings.clone();
            let transactions = self.transactions.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_proxy_connection(&mut client, client_addr, &findings, &transactions).await {
                    tracing::warn!("代理连接 {} 处理失败: {}", client_addr, e);
                }
            });
        }
    }

    /// 获取扫描结果
    pub async fn get_findings(&self) -> Vec<VulnFinding> {
        self.findings.lock().await.clone()
    }

    /// 获取已记录的事务
    pub async fn get_transactions(&self) -> Vec<HttpTransaction> {
        self.transactions.lock().await.iter().cloned().collect()
    }

    /// 执行被动扫描
    pub async fn run_passive_scan(&self) -> Vec<VulnFinding> {
        let txns = self.transactions.lock().await.iter().cloned().collect::<Vec<_>>();
        let findings = self.scanner.scan_passive(&txns);
        if !findings.is_empty() {
            let mut all = self.findings.lock().await;
            all.extend(findings.clone());
        }
        findings
    }
}

/// 处理单个代理连接
async fn handle_proxy_connection(
    client: &mut tokio::net::TcpStream,
    _client_addr: SocketAddr,
    _findings: &Arc<Mutex<Vec<VulnFinding>>>,
    transactions: &Arc<Mutex<VecDeque<HttpTransaction>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 读取请求数据
    let mut buf = vec![0u8; 65536];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]).to_string();
    let request = parse_http_request(&request_str);

    // 处理 CONNECT 方法（HTTPS 隧道）
    if request.method == "CONNECT" {
        // 回复 200 Connection Established
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        // 后续流量是加密的，仅记录 CONNECT 目标
        let txn = HttpTransaction {
            request: crate::types::HttpRequest {
                method: "CONNECT".to_string(),
                url: request.url,
                headers: request.headers,
                body: None,
            },
            response: crate::types::HttpResponse {
                status: 200,
                headers: vec![],
                body: "[TLS tunnel established]".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        transactions.lock().await.push_back(txn);
        return Ok(());
    }

    // 处理普通 HTTP 请求：转发到目标服务器
    let target_url = &request.url;
    let target_host = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .or_else(|| {
            let parsed = url::Url::parse(target_url).ok()?;
            parsed.host_str().map(|s| s.to_string())
        })
        .unwrap_or_default();

    if target_host.is_empty() {
        client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    }

    // 转发请求到目标
    let upstream = match tokio::net::TcpStream::connect(format!("{}:80", target_host)).await {
        Ok(s) => s,
        Err(_) => {
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Ok(());
        }
    };

    let (mut ri, mut wi) = client.split();
    let (mut ro, mut wo) = upstream.into_split();

    // 转发请求
    let _ = wo.write_all(&buf[..n]).await;
    let _ = wo.flush().await;

    // 双向转发 + 捕获响应
    let transactions_clone = transactions.clone();
    let _response_buf = Arc::new(Mutex::new(Vec::new()));
    let resp_buf = _response_buf.clone();

    // 客户端 → 目标
    let c2s = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match ri.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => { let _ = wo.write_all(&buf[..n]).await; }
            }
        }
    };

    // 目标 → 客户端（捕获响应）
    let s2c = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match ro.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = wi.write_all(&buf[..n]).await;
                    resp_buf.lock().await.extend_from_slice(&buf[..n]);
                }
            }
        }
    };

    tokio::join!(c2s, s2c);

    // 解析响应并记录事务
    let resp_data = _response_buf.lock().await.clone();
    let response = parse_http_response(&String::from_utf8_lossy(&resp_data));
    let txn = HttpTransaction {
        request: crate::types::HttpRequest {
            method: request.method,
            url: target_url.to_string(),
            headers: request.headers,
            body: request.body,
        },
        response,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    transactions.lock().await.push_back(txn);

    Ok(())
}

/// 解析 HTTP 请求
pub fn parse_http_request(raw: &str) -> ParsedRequest {
    let mut lines = raw.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET").to_string();
    let url = parts.get(1).copied().unwrap_or("/").to_string();

    let mut headers = Vec::new();
    let mut body = None;
    let mut in_body = false;
    for line in lines {
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body = Some(line.to_string());
        } else if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_string();
            let val = line[pos + 1..].trim().to_string();
            headers.push((key, val));
        }
    }

    ParsedRequest { method, url, headers, body }
}

/// 解析 HTTP 响应
pub fn parse_http_response(raw: &str) -> crate::types::HttpResponse {
    let mut lines = raw.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_body = false;
    for line in lines {
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body.push_str(line);
            body.push('\n');
        } else if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_string();
            let val = line[pos + 1..].trim().to_string();
            headers.push((key, val));
        }
    }

    crate::types::HttpResponse { status, headers, body }
}

/// 解析后的 HTTP 请求
pub struct ParsedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

// ===========================================================================
// G5.10: SOCKS5 代理支持
// ===========================================================================

use std::net::ToSocketAddrs;

/// SOCKS5 认证方式
#[derive(Debug, Clone)]
pub enum Socks5Auth {
    /// 无认证
    None,
    /// 用户名/密码认证
    UsernamePassword { username: String, password: String },
}

/// SOCKS5 代理配置
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// SOCKS5 代理服务器地址（host:port）
    pub proxy_addr: String,
    /// 认证方式
    pub auth: Socks5Auth,
}

impl Socks5Config {
    /// 创建无认证的 SOCKS5 配置
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: Socks5Auth::None,
        }
    }

    /// 创建带用户名/密码认证的 SOCKS5 配置
    pub fn with_auth(proxy_addr: impl Into<String>, username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            auth: Socks5Auth::UsernamePassword {
                username: username.into(),
                password: password.into(),
            },
        }
    }

    /// 从 socks5:// URL 解析配置
    ///
    /// 支持格式：
    /// - `socks5://host:port`
    /// - `socks5://username:password@host:port`
    pub fn from_url(url: &str) -> Result<Self, String> {
        let url = url.strip_prefix("socks5://")
            .ok_or_else(|| "URL 必须以 socks5:// 开头".to_string())?;

        let (auth_part, host_part) = if let Some(at_pos) = url.rfind('@') {
            let auth = &url[..at_pos];
            let host = &url[at_pos + 1..];
            (Some(auth), host)
        } else {
            (None, url)
        };

        if host_part.is_empty() {
            return Err("SOCKS5 代理地址为空".to_string());
        }

        let auth = match auth_part {
            Some(auth) => {
                let parts: Vec<&str> = auth.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Socks5Auth::UsernamePassword {
                        username: parts[0].to_string(),
                        password: parts[1].to_string(),
                    }
                } else {
                    Socks5Auth::None
                }
            }
            None => Socks5Auth::None,
        };

        Ok(Self {
            proxy_addr: host_part.to_string(),
            auth,
        })
    }
}

/// SOCKS5 连接器
///
/// 通过 SOCKS5 代理建立 TCP 连接（CONNECT 命令）。
/// 支持无认证和用户名/密码认证。
pub struct Socks5Connector {
    config: Socks5Config,
}

impl Socks5Connector {
    /// 创建新的 SOCKS5 连接器
    pub fn new(config: Socks5Config) -> Self {
        Self { config }
    }

    /// 获取配置引用
    pub fn config(&self) -> &Socks5Config {
        &self.config
    }

    /// 通过 SOCKS5 代理连接到目标主机
    ///
    /// 执行 SOCKS5 握手（认证协商 + CONNECT 命令），
    /// 返回已建立的 TCP 流，可直接用于 HTTP 请求。
    pub async fn connect(&self, target_host: &str, target_port: u16) -> Result<tokio::net::TcpStream, String> {
        use fast_socks5::client::{Config as S5Config, Socks5Stream};

        let s5_config = S5Config::default();

        // 解析代理地址
        let proxy_addr = self.config.proxy_addr.clone();
        let proxy_socket = proxy_addr
            .to_socket_addrs()
            .map_err(|e| format!("解析 SOCKS5 代理地址失败: {e}"))?
            .next()
            .ok_or_else(|| "无法解析 SOCKS5 代理地址".to_string())?;

        let stream = match &self.config.auth {
            Socks5Auth::None => {
                Socks5Stream::connect(
                    proxy_socket,
                    target_host.to_string(),
                    target_port,
                    s5_config,
                )
                .await
                .map_err(|e| format!("SOCKS5 连接失败: {e}"))?
            }
            Socks5Auth::UsernamePassword { username, password } => {
                Socks5Stream::connect_with_password(
                    proxy_socket,
                    target_host.to_string(),
                    target_port,
                    username.clone(),
                    password.clone(),
                    s5_config,
                )
                .await
                .map_err(|e| format!("SOCKS5 连接失败: {e}"))?
            }
        };

        Ok(stream.get_socket())
    }
}

/// 构建支持 SOCKS5 代理的 reqwest 客户端
///
/// 利用 reqwest 内置的 socks 特性，通过 `socks5://` URL 配置代理。
pub fn build_socks5_client(config: &Socks5Config) -> Result<reqwest::Client, String> {
    let proxy_url = match &config.auth {
        Socks5Auth::None => format!("socks5://{}", config.proxy_addr),
        Socks5Auth::UsernamePassword { username, password } => {
            format!("socks5://{}:{}@{}", username, password, config.proxy_addr)
        }
    };

    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("创建 reqwest SOCKS5 代理失败: {e}"))?;

    reqwest::Client::builder()
        .proxy(proxy)
        .build()
        .map_err(|e| format!("构建 reqwest 客户端失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_request_get() {
        let raw = "GET /test?foo=bar HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let req = parse_http_request(raw);
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "/test?foo=bar");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0, "Host");
        assert!(req.body.is_none());
    }

    #[test]
    fn test_parse_http_request_post() {
        let raw = "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}";
        let req = parse_http_request(raw);
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "/api/login");
        assert!(req.body.is_some());
        assert!(req.body.as_ref().unwrap().contains("admin"));
    }

    #[test]
    fn test_parse_http_response() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nHello";
        let resp = parse_http_response(raw);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 2);
        assert!(resp.body.contains("Hello"));
    }

    #[test]
    fn test_parse_http_response_error() {
        let raw = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nError";
        let resp = parse_http_response(raw);
        assert_eq!(resp.status, 500);
        assert!(resp.body.contains("Error"));
    }

    #[test]
    fn test_parse_http_request_empty() {
        let req = parse_http_request("");
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "/");
        assert!(req.headers.is_empty());
    }

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr, "127.0.0.1");
        assert_eq!(config.listen_port, 8888);
    }

    // --- SOCKS5 测试 (G5.10) ---

    #[test]
    fn test_socks5_config_no_auth() {
        let config = Socks5Config::new("127.0.0.1:1080");
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert!(matches!(config.auth, Socks5Auth::None));
    }

    #[test]
    fn test_socks5_config_with_auth() {
        let config = Socks5Config::with_auth("127.0.0.1:1080", "user", "pass");
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        match &config.auth {
            Socks5Auth::UsernamePassword { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("期望用户名/密码认证"),
        }
    }

    #[test]
    fn test_socks5_config_from_url_no_auth() {
        let config = Socks5Config::from_url("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(config.proxy_addr, "127.0.0.1:1080");
        assert!(matches!(config.auth, Socks5Auth::None));
    }

    #[test]
    fn test_socks5_config_from_url_with_auth() {
        let config = Socks5Config::from_url("socks5://admin:secret@proxy.example.com:1080").unwrap();
        assert_eq!(config.proxy_addr, "proxy.example.com:1080");
        match &config.auth {
            Socks5Auth::UsernamePassword { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "secret");
            }
            _ => panic!("期望用户名/密码认证"),
        }
    }

    #[test]
    fn test_socks5_config_from_url_invalid_scheme() {
        assert!(Socks5Config::from_url("http://127.0.0.1:1080").is_err());
    }

    #[test]
    fn test_socks5_config_from_url_empty_host() {
        assert!(Socks5Config::from_url("socks5://").is_err());
    }

    #[test]
    fn test_socks5_connector_new() {
        let config = Socks5Config::new("127.0.0.1:1080");
        let connector = Socks5Connector::new(config);
        assert_eq!(connector.config().proxy_addr, "127.0.0.1:1080");
    }

    #[tokio::test]
    async fn test_socks5_connect_no_proxy_fails() {
        // 连接到不存在的 SOCKS5 代理应失败
        let config = Socks5Config::new("127.0.0.1:1"); // 端口 1 不太可能有服务
        let connector = Socks5Connector::new(config);
        let result = connector.connect("example.com", 80).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_build_socks5_client_no_auth() {
        let config = Socks5Config::new("127.0.0.1:1080");
        let client = build_socks5_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_socks5_client_with_auth() {
        let config = Socks5Config::with_auth("127.0.0.1:1080", "user", "pass");
        let client = build_socks5_client(&config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_socks5_config_from_url_password_with_colon() {
        // 密码中包含冒号时，splitn(2, ':') 只分割第一个冒号
        let config = Socks5Config::from_url("socks5://user:pa:ss@host:1080").unwrap();
        match &config.auth {
            Socks5Auth::UsernamePassword { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pa:ss");
            }
            _ => panic!("期望用户名/密码认证"),
        }
    }
}
