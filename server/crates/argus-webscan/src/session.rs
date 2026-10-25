//! Cookie/会话录制
//!
//! 记录和管理 HTTP 会话状态，支持 Cookie jar、Token 提取、
//! 会话回放（用于携带认证信息重放扫描请求）。

use crate::types::{Cookie, SessionState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Cookie Jar 管理
pub struct CookieJar {
    cookies: Arc<Mutex<HashMap<String, Cookie>>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 从 Set-Cookie 响应头解析并存储 Cookie
    pub async fn store_from_header(&self, set_cookie: &str, domain: &str) {
        for cookie in parse_set_cookie(set_cookie, domain) {
            let key = format!("{}|{}|{}", cookie.domain, cookie.path, cookie.name);
            self.cookies.lock().await.insert(key, cookie);
        }
    }

    /// 添加 Cookie
    pub async fn add(&self, cookie: Cookie) {
        let key = format!("{}|{}|{}", cookie.domain, cookie.path, cookie.name);
        self.cookies.lock().await.insert(key, cookie);
    }

    /// 获取所有 Cookie
    pub async fn all(&self) -> Vec<Cookie> {
        self.cookies.lock().await.values().cloned().collect()
    }

    /// 获取匹配的 Cookie（按 domain + path 匹配）
    pub async fn get_for_url(&self, url: &str) -> Vec<Cookie> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return vec![],
        };
        let domain = parsed.host_str().unwrap_or("");
        let path = parsed.path();

        self.cookies
            .lock()
            .await
            .values()
            .filter(|c| {
                // domain 匹配
                let domain_match = domain == c.domain
                    || (c.domain.starts_with('.') && domain.ends_with(&c.domain[1..]));
                // path 匹配
                let path_match = path.starts_with(&c.path) || c.path == "/";
                domain_match && path_match
            })
            .cloned()
            .collect()
    }

    /// 构建 Cookie 请求头
    pub async fn to_header(&self, url: &str) -> Option<String> {
        let cookies = self.get_for_url(url).await;
        if cookies.is_empty() {
            return None;
        }
        let value: Vec<String> = cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Some(value.join("; "))
    }

    /// 清空 Cookie
    pub async fn clear(&self) {
        self.cookies.lock().await.clear();
    }

    /// Cookie 数量
    pub async fn count(&self) -> usize {
        self.cookies.lock().await.len()
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// 会话录制器
pub struct SessionRecorder {
    jar: CookieJar,
    tokens: Arc<Mutex<Vec<String>>>,
    history: Arc<Mutex<Vec<RecordedRequest>>>,
}

/// 录制的请求
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timestamp: String,
    pub response_status: u16,
}

impl SessionRecorder {
    pub fn new() -> Self {
        Self {
            jar: CookieJar::new(),
            tokens: Arc::new(Mutex::new(Vec::new())),
            history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 录制一次请求/响应
    pub async fn record(
        &self,
        method: &str,
        url: &str,
        request_headers: &[(String, String)],
        request_body: Option<&str>,
        response_status: u16,
        response_headers: &[(String, String)],
    ) {
        // 从响应中提取 Cookie
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
            .unwrap_or_default();

        for (k, v) in response_headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                self.jar.store_from_header(v, &domain).await;
            }
        }

        // 提取 Token（JWT、Bearer）
        for (k, v) in response_headers {
            if k.eq_ignore_ascii_case("authorization") {
                if v.starts_with("Bearer ") {
                    self.tokens.lock().await.push(v[7..].to_string());
                }
            }
            // 从响应体中提取 token（如果 body 包含 JSON token）
        }
        for (k, v) in request_headers {
            if k.eq_ignore_ascii_case("authorization") {
                if v.starts_with("Bearer ") {
                    self.tokens.lock().await.push(v[7..].to_string());
                }
            }
        }

        // 记录请求历史
        self.history.lock().await.push(RecordedRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: request_headers.to_vec(),
            body: request_body.map(|s| s.to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            response_status,
        });
    }

    /// 导出会话状态
    pub async fn export_state(&self) -> SessionState {
        SessionState {
            cookies: self.jar.all().await,
            tokens: self.tokens.lock().await.clone(),
            referer: self.history.lock().await.last().map(|r| r.url.clone()),
        }
    }

    /// 获取 Cookie Jar
    pub fn cookie_jar(&self) -> &CookieJar {
        &self.jar
    }

    /// 获取请求历史
    pub async fn history(&self) -> Vec<RecordedRequest> {
        self.history.lock().await.clone()
    }

    /// 获取 Token 列表
    pub async fn tokens(&self) -> Vec<String> {
        self.tokens.lock().await.clone()
    }

    /// 构建请求头（含 Cookie + Authorization）
    pub async fn build_auth_headers(&self, url: &str) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if let Some(cookie) = self.jar.to_header(url).await {
            headers.push(("Cookie".to_string(), cookie));
        }
        let tokens = self.tokens.lock().await;
        if let Some(token) = tokens.last() {
            headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
        }
        headers
    }
}

impl Default for SessionRecorder {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析 Set-Cookie 头
pub fn parse_set_cookie(header: &str, domain: &str) -> Vec<Cookie> {
    header
        .split(',')
        .filter_map(|cookie_str| {
            let parts: Vec<&str> = cookie_str.split(';').map(|s| s.trim()).collect();
            if parts.is_empty() {
                return None;
            }
            let nv: Vec<&str> = parts[0].splitn(2, '=').collect();
            if nv.len() != 2 {
                return None;
            }
            let name = nv[0].trim().to_string();
            let value = nv[1].trim().to_string();

            let mut cookie = Cookie {
                name,
                value,
                domain: domain.to_string(),
                path: "/".to_string(),
                secure: false,
                httponly: false,
            };

            for attr in &parts[1..] {
                let lower = attr.to_lowercase();
                if lower == "secure" {
                    cookie.secure = true;
                } else if lower == "httponly" {
                    cookie.httponly = true;
                } else if let Some(path) = lower.strip_prefix("path=") {
                    cookie.path = path.to_string();
                } else if let Some(d) = lower.strip_prefix("domain=") {
                    cookie.domain = d.trim_start_matches('.').to_string();
                }
            }
            Some(cookie)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_cookie() {
        let cookies = parse_set_cookie("session=abc123; Path=/; HttpOnly", "example.com");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc123");
        assert_eq!(cookies[0].path, "/");
        assert!(cookies[0].httponly);
    }

    #[test]
    fn test_parse_cookie_with_domain() {
        let cookies = parse_set_cookie("token=xyz; Domain=.example.com; Secure; Path=/api", "other.com");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].domain, "example.com"); // 去掉前导 .
        assert_eq!(cookies[0].path, "/api");
        assert!(cookies[0].secure);
    }

    #[test]
    fn test_parse_multiple_cookies() {
        let cookies = parse_set_cookie("a=1; Path=/, b=2; Path=/secure; Secure", "example.com");
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name, "a");
        assert_eq!(cookies[1].name, "b");
    }

    #[test]
    fn test_parse_cookie_no_value() {
        let cookies = parse_set_cookie("justname; Path=/", "example.com");
        assert_eq!(cookies.len(), 0);
    }

    #[tokio::test]
    async fn test_cookie_jar() {
        let jar = CookieJar::new();
        jar.add(Cookie {
            name: "session".to_string(),
            value: "abc".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: true,
            httponly: true,
        }).await;

        assert_eq!(jar.count().await, 1);

        let cookies = jar.get_for_url("https://example.com/page").await;
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");

        let header = jar.to_header("https://example.com/page").await;
        assert!(header.is_some());
        assert!(header.unwrap().contains("session=abc"));
    }

    #[tokio::test]
    async fn test_cookie_jar_path_match() {
        let jar = CookieJar::new();
        jar.add(Cookie {
            name: "api_token".to_string(),
            value: "xyz".to_string(),
            domain: "example.com".to_string(),
            path: "/api".to_string(),
            secure: false,
            httponly: false,
        }).await;

        // 匹配 /api 路径
        let cookies = jar.get_for_url("https://example.com/api/data").await;
        assert_eq!(cookies.len(), 1);

        // 不匹配 /other 路径
        let cookies = jar.get_for_url("https://example.com/other").await;
        assert_eq!(cookies.len(), 0);
    }

    #[tokio::test]
    async fn test_session_recorder() {
        let recorder = SessionRecorder::new();
        recorder.record(
            "POST",
            "https://example.com/login",
            &[("Content-Type".to_string(), "application/json".to_string())],
            Some(r#"{"user":"admin","pass":"123"}"#),
            200,
            &[
                ("Set-Cookie".to_string(), "session=abc123; Path=/; HttpOnly".to_string()),
                ("Authorization".to_string(), "Bearer jwt_token_123".to_string()),
            ],
        ).await;

        let state = recorder.export_state().await;
        assert_eq!(state.cookies.len(), 1);
        assert_eq!(state.cookies[0].name, "session");
        assert!(state.tokens.contains(&"jwt_token_123".to_string()));

        let history = recorder.history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].method, "POST");
        assert_eq!(history[0].response_status, 200);

        let headers = recorder.build_auth_headers("https://example.com/dashboard").await;
        assert!(headers.iter().any(|(k, _)| k == "Cookie"));
        assert!(headers.iter().any(|(k, v)| k == "Authorization" && v.contains("jwt_token_123")));
    }

    #[tokio::test]
    async fn test_cookie_jar_clear() {
        let jar = CookieJar::new();
        jar.add(Cookie {
            name: "test".to_string(), value: "1".to_string(),
            domain: "example.com".to_string(), path: "/".to_string(),
            secure: false, httponly: false,
        }).await;
        assert_eq!(jar.count().await, 1);
        jar.clear().await;
        assert_eq!(jar.count().await, 0);
    }
}
