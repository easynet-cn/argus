//! DefaultHostApi 实现
//!
//! 通过 reqwest HTTP + tokio TCP + DNS lookup 实现 HostApi trait

use std::time::Duration;
use async_trait::async_trait;
use argus_engine::host_api::{HostApi, HttpResponse};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 默认 HostApi 实现
pub struct DefaultHostApi {
    http_client: reqwest::Client,
    tcp_timeout: Duration,
}

impl DefaultHostApi {
    pub fn new(timeout_secs: u64) -> Self {
        let timeout = Duration::from_secs(timeout_secs);
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            http_client,
            tcp_timeout: timeout,
        }
    }
}

impl Default for DefaultHostApi {
    fn default() -> Self {
        Self::new(10)
    }
}

#[async_trait]
impl HostApi for DefaultHostApi {
    async fn http_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String> {
        let req_method = match method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            "PATCH" => reqwest::Method::PATCH,
            _ => reqwest::Method::GET,
        };

        let mut req = self.http_client.request(req_method, url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }

        let resp = req.send().await.map_err(|e| format!("HTTP 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in resp.headers().iter() {
            headers.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            ));
        }
        let body = resp.text().await.map_err(|e| format!("读取响应体失败: {e}"))?;
        Ok(HttpResponse { status, headers, body })
    }

    async fn tcp_send(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let addr = format!("{host}:{port}");
        let mut stream = tokio::time::timeout(
            self.tcp_timeout,
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| format!("TCP 连接超时: {addr}"))?
        .map_err(|e| format!("TCP 连接失败: {e}"))?;

        stream.write_all(data).await.map_err(|e| format!("写入失败: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush 失败: {e}"))?;

        let mut buf = Vec::with_capacity(4096);
        match tokio::time::timeout(self.tcp_timeout, stream.read_to_end(&mut buf)).await {
            Ok(Ok(0)) => Err("对端关闭连接".to_string()),
            Ok(Ok(_n)) => Ok(buf),
            Ok(Err(e)) => Err(format!("读取响应失败: {e}")),
            Err(_) => Err("读取响应超时".to_string()),
        }
    }

    async fn dns_lookup(&self, domain: &str) -> Result<Vec<String>, String> {
        let addrs = tokio::net::lookup_host((domain, 80))
            .await
            .map_err(|e| format!("DNS 查询失败: {e}"))?;
        let mut results: Vec<String> = Vec::new();
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !results.contains(&ip) {
                results.push(ip);
            }
        }
        if results.is_empty() {
            Err(format!("无 DNS 记录: {domain}"))
        } else {
            Ok(results)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_constructor() {
        let api = DefaultHostApi::default();
        assert_eq!(api.tcp_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_new_with_custom_timeout() {
        let api = DefaultHostApi::new(30);
        assert_eq!(api.tcp_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_dns_lookup_invalid_returns_err() {
        // 使用一个无效域名，应该返回错误（不抛 panic）
        let api = DefaultHostApi::new(2);
        let result = api.dns_lookup("this-domain-does-not-exist-xyz-123.invalid").await;
        assert!(result.is_err(), "无效域名应该返回错误");
    }

    #[tokio::test]
    async fn test_http_request_invalid_url_returns_err() {
        let api = DefaultHostApi::new(2);
        // 使用一个无法访问的 URL，应当返回 Err
        let result = api.http_request("GET", "http://127.0.0.1:1/test", &[], None).await;
        assert!(result.is_err(), "无效 URL 应该返回错误");
    }
}
