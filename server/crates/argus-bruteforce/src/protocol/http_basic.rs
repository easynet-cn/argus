//! HTTP Basic 认证连接器
//!
//! 真实实现 HTTP Basic 认证爆破：
//! 1. 构造 HTTP GET 请求，带 Authorization: Basic base64(user:pass) 头
//! 2. 发送请求到目标 URL
//! 3. 200 = 认证成功，401 = 认证失败

use async_trait::async_trait;
use base64::Engine;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct HttpBasicConnector;

#[async_trait]
impl ProtocolConnector for HttpBasicConnector {
    fn protocol(&self) -> Protocol {
        Protocol::HttpBasic
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let dur = Duration::from_millis(timeout_ms);

        // 构造目标 URL（默认 http）
        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/");

        // 构造 Basic Auth 头
        let credentials = format!("{}:{}", credential.username, credential.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&credentials);
        let auth_header = format!("Basic {encoded}");

        // 发送请求
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none()) // 不跟随重定向
            .timeout(dur)
            .build()
            .map_err(|e| format!("HTTP 客户端构建失败: {e}"))?;

        let req = client
            .get(&url)
            .header("Authorization", &auth_header)
            .header("User-Agent", "Argus-Scanner/1.0");

        let resp = timeout(dur, req.send())
            .await
            .map_err(|e| format!("HTTP 请求超时: {e}"))?
            .map_err(|e| format!("HTTP 请求失败: {e}"))?;

        let status = resp.status().as_u16();

        // 200 = 认证成功，401 = 认证失败
        // 301/302 到已认证页面也可能表示成功
        match status {
            200 => Ok(true),
            401 => Ok(false),
            403 => Ok(false),
            301 | 302 | 303 | 307 | 308 => {
                // 重定向到非 401 页面可能表示成功
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_basic_protocol() {
        assert_eq!(HttpBasicConnector.protocol(), Protocol::HttpBasic);
    }

    #[test]
    fn test_http_basic_auth_header() {
        let credentials = "admin:password";
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(credentials);
        let auth_header = format!("Basic {encoded}");
        assert!(auth_header.starts_with("Basic "));
        // base64("admin:password") = YWRtaW46cGFzc3dvcmQ=
        assert_eq!(encoded, "YWRtaW46cGFzc3dvcmQ=");
    }
}
