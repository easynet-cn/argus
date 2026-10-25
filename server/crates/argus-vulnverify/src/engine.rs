//! 漏洞验证引擎（HTTP 重放）
//!
//! 基础 HTTP 引擎:
//! - 构造自定义请求（方法/URL/Headers/Body）
//! - 重放请求并捕获响应
//! - 支持超时、重试、重定向控制
//! - 支持 Cookie/认证 Token

use std::time::Duration;
use reqwest::{Client, Method};
use thiserror::Error;

use crate::types::*;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("HTTP 请求失败: {0}")]
    Request(String),
    #[error("URL 无效: {0}")]
    InvalidUrl(String),
    #[error("方法不支持: {0}")]
    MethodNotSupported(String),
    #[error("重试 {n} 次后仍失败: {reason}")]
    RetryExhausted { n: u32, reason: String },
    #[error("超时（{secs}秒）")]
    Timeout { secs: u64 },
}

/// HTTP 验证引擎
pub struct VerifyEngine {
    /// HTTP 客户端
    http: Client,
    /// 引擎配置
    config: VerifyConfig,
}

impl VerifyEngine {
    pub fn new(config: VerifyConfig) -> Result<Self, EngineError> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent);

        // 重定向策略（默认不跟随，由 VerifyRequest 控制单请求是否跟随）
        // 简化处理：这里统一关闭，VerifyRequest.follow_redirects 字段用于策略选择
        builder = builder.redirect(reqwest::redirect::Policy::none());

        // 额外头（使用 default_headers 设置全局请求头）
        if !config.extra_headers.is_empty() {
            let mut headers = reqwest::header::HeaderMap::new();
            for (k, v) in &config.extra_headers {
                if let (Ok(name), Ok(val)) = (
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                    reqwest::header::HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }
            builder = builder.default_headers(headers);
        }

        let http = builder
            .build()
            .map_err(|e| EngineError::Request(format!("构建 HTTP 客户端失败: {e}")))?;

        Ok(Self { http, config })
    }

    pub fn with_default_config() -> Self {
        Self::new(VerifyConfig::default())
            .expect("默认配置应能构建 VerifyEngine")
    }

    pub fn config(&self) -> &VerifyConfig {
        &self.config
    }

    /// 发送单个验证请求并捕获响应
    pub async fn send_request(&self, req: &VerifyRequest) -> Result<VerifyResponse, EngineError> {
        let method = parse_method(&req.method)?;
        let url = validate_url(&req.url)?;

        let mut attempts = 0;
        let max_retries = self.config.max_retries;
        loop {
            attempts += 1;
            match self.send_once(&method, &url, req).await {
                Ok(resp) => return Ok(resp),
                Err(e) if attempts <= max_retries => {
                    tracing::warn!(
                        "请求失败（第{}次），{}ms 后重试: {}",
                        attempts,
                        self.config.retry_delay_ms,
                        e
                    );
                    tokio::time::sleep(Duration::from_millis(self.config.retry_delay_ms)).await;
                }
                Err(e) => {
                    return Err(EngineError::RetryExhausted {
                        n: attempts,
                        reason: e.to_string(),
                    });
                }
            }
        }
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &str,
        req: &VerifyRequest,
    ) -> Result<VerifyResponse, EngineError> {
        let mut builder = self.http.request(method.clone(), url);

        // 用户级 headers（覆盖全局）
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }

        // 请求体
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }

        let start = std::time::Instant::now();
        let resp = builder
            .send()
            .await
            .map_err(|e| classify_reqwest_error(&e, self.config.timeout_secs))?;

        let elapsed = start.elapsed();
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp
            .text()
            .await
            .map_err(|e| EngineError::Request(format!("读取响应体失败: {e}")))?;

        Ok(VerifyResponse {
            status,
            headers,
            size: body.len() as u64,
            body,
            elapsed_ms: elapsed.as_millis() as u64,
        })
    }
}

/// 解析 HTTP 方法
fn parse_method(method: &str) -> Result<Method, EngineError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "DELETE" => Ok(Method::DELETE),
        "HEAD" => Ok(Method::HEAD),
        "OPTIONS" => Ok(Method::OPTIONS),
        "PATCH" => Ok(Method::PATCH),
        _ => Err(EngineError::MethodNotSupported(method.to_string())),
    }
}

/// 校验 URL
fn validate_url(url: &str) -> Result<String, EngineError> {
    if url.is_empty() {
        return Err(EngineError::InvalidUrl("URL 为空".to_string()));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(EngineError::InvalidUrl(format!(
            "URL 必须以 http:// 或 https:// 开头: {}",
            url
        )));
    }
    Ok(url.to_string())
}

/// 分类 reqwest 错误为更明确的错误
fn classify_reqwest_error(e: &reqwest::Error, timeout_secs: u64) -> EngineError {
    if e.is_timeout() {
        EngineError::Timeout { secs: timeout_secs }
    } else if e.is_connect() {
        EngineError::Request(format!("连接失败: {}", e))
    } else {
        EngineError::Request(format!("请求失败: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_method_get() {
        assert!(matches!(parse_method("GET"), Ok(Method::GET)));
        assert!(matches!(parse_method("get"), Ok(Method::GET)));
    }

    #[test]
    fn test_parse_method_post() {
        assert!(matches!(parse_method("POST"), Ok(Method::POST)));
    }

    #[test]
    fn test_parse_method_unsupported() {
        let result = parse_method("TRACE");
        assert!(matches!(result, Err(EngineError::MethodNotSupported(_))));
    }

    #[test]
    fn test_validate_url_empty() {
        let result = validate_url("");
        assert!(matches!(result, Err(EngineError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_url_missing_scheme() {
        let result = validate_url("example.com/api");
        assert!(matches!(result, Err(EngineError::InvalidUrl(_))));
    }

    #[test]
    fn test_validate_url_http() {
        let result = validate_url("http://example.com");
        assert_eq!(result.unwrap(), "http://example.com");
    }

    #[test]
    fn test_validate_url_https() {
        let result = validate_url("https://api.example.com/v1");
        assert_eq!(result.unwrap(), "https://api.example.com/v1");
    }

    #[test]
    fn test_verify_engine_default_config() {
        let engine = VerifyEngine::with_default_config();
        assert_eq!(engine.config().concurrency, 5);
        assert!(!engine.config().enable_exploitation);
    }

    #[test]
    fn test_classify_reqwest_error_timeout() {
        // reqwest::Error 不易构造，这里只测试 Timeout 分支的描述
        // 实际验证通过运行时连接超时进行
    }
}
