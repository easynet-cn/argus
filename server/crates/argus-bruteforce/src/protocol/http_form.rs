//! HTTP 表单登录连接器
//!
//! 真实实现 HTTP 表单登录爆破：
//! 1. 构造 POST 请求，将用户名密码放入表单字段
//! 2. 发送到目标登录 URL
//! 3. 检查响应判断是否登录成功：
//!    - 302 重定向到非登录页 = 成功
//!    - 200 且响应体无 "login failed" / "error" 关键词 = 成功
//!    - 200 且响应体包含 "logout" / "welcome" / "dashboard" = 成功

use async_trait::async_trait;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct HttpFormConnector;

#[async_trait]
impl ProtocolConnector for HttpFormConnector {
    fn protocol(&self) -> Protocol {
        Protocol::HttpForm
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let dur = Duration::from_millis(timeout_ms);

        // 构造目标 URL（默认 http, 路径 /login）
        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/login");

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(dur)
            .build()
            .map_err(|e| format!("HTTP 客户端构建失败: {e}"))?;

        // 构造表单数据（常见字段名: username/user/login + password/pass）
        let form = vec![
            ("username".to_string(), credential.username.clone()),
            ("password".to_string(), credential.password.clone()),
        ];

        let req = client
            .post(&url)
            .form(&form)
            .header("User-Agent", "Argus-Scanner/1.0");

        let resp = timeout(dur, req.send())
            .await
            .map_err(|e| format!("HTTP 请求超时: {e}"))?
            .map_err(|e| format!("HTTP 请求失败: {e}"))?;

        let status = resp.status().as_u16();

        // 302 重定向 = 登录成功（重定向到 dashboard/home）
        if status == 302 || status == 303 || status == 307 {
            // 检查 Location 头是否指向非登录页
            if let Some(location) = resp.headers().get("location") {
                let loc = location.to_str().unwrap_or("");
                // 重定向到 login/error 页 = 失败
                if loc.contains("login") || loc.contains("error") {
                    return Ok(false);
                }
            }
            return Ok(true);
        }

        // 200: 检查响应体关键词
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();

            // 失败关键词
            let fail_keywords = [
                "login failed",
                "log in failed",
                "incorrect",
                "invalid",
                "error",
                "unauthorized",
                "access denied",
                "wrong",
            ];
            for kw in &fail_keywords {
                if body_lower.contains(kw) {
                    return Ok(false);
                }
            }

            // 成功关键词
            let success_keywords = [
                "logout",
                "welcome",
                "dashboard",
                "home",
                "success",
                "logged in",
            ];
            for kw in &success_keywords {
                if body_lower.contains(kw) {
                    return Ok(true);
                }
            }

            // 无法判断时返回 false
            return Ok(false);
        }

        // 其他状态码
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_form_protocol() {
        assert_eq!(HttpFormConnector.protocol(), Protocol::HttpForm);
    }
}
