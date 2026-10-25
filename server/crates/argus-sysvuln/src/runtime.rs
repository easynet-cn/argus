//! 漏洞插件运行时
//!
//! 扩展 PluginRuntime，按 MatchType 判定 HTTP 响应

use std::sync::Arc;
use std::time::Duration;
use argus_engine::EngineError;
use argus_engine::host_api::HostApi;
use argus_engine::result::PluginResult;
use argus_engine::template::{PluginTemplate, MatchType};
use crate::host_api_impl::DefaultHostApi;

/// 漏洞插件运行时（active 探测核心）
#[derive(Clone)]
pub struct VulnPluginRuntime {
    host_api: Arc<dyn HostApi>,
    timeout: Duration,
}

impl VulnPluginRuntime {
    pub fn new(host_api: Arc<dyn HostApi>, timeout: Duration) -> Self {
        Self { host_api, timeout }
    }

    /// 用 DefaultHostApi 构造
    pub fn with_default(timeout_secs: u64) -> Self {
        let api = Arc::new(DefaultHostApi::new(timeout_secs));
        Self::new(api, Duration::from_secs(timeout_secs))
    }

    /// 执行单个模板检测
    ///
    /// target 可为完整 URL 或 "host:port"，自动补全 http:// 默认
    pub async fn execute_template(
        &self,
        template: &PluginTemplate,
        target: &str,
    ) -> Result<Option<PluginResult>, EngineError> {
        let detection = &template.detection;

        // 构造请求 URL
        let url = if target.starts_with("http://") || target.starts_with("https://") {
            format!(
                "{}/{}",
                target.trim_end_matches('/'),
                detection.path.trim_start_matches('/')
            )
        } else if target.contains(':') {
            format!(
                "http://{}/{}",
                target.trim_end_matches('/'),
                detection.path.trim_start_matches('/')
            )
        } else {
            format!(
                "http://{}/{}",
                target.trim_end_matches('/'),
                detection.path.trim_start_matches('/')
            )
        };

        // 准备 headers
        let headers: Vec<(&str, &str)> = detection.headers
            .as_ref()
            .map(|h| h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();

        // 带超时执行 HTTP 请求
        let response = match tokio::time::timeout(
            self.timeout,
            self.host_api.http_request(&detection.method, &url, &headers, detection.body.as_deref()),
        ).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(EngineError::ScriptExec(format!("HTTP 请求失败: {e}"))),
            Err(_) => return Err(EngineError::Timeout),
        };

        // 匹配判定
        let matched = self.match_response(&response, &detection.match_rule.match_type, &detection.match_rule.pattern);

        if matched {
            let host = extract_host(target);
            let port = extract_port(target);
            let mut result = PluginResult::new(
                host.clone(),
                template.name.clone(),
                template.severity.clone(),
            );
            result.evidence = format!(
                "HTTP {} {} → Status: {}, Body (前200字): {}",
                detection.method,
                detection.path,
                response.status,
                response.body.chars().take(200).collect::<String>()
            );
            result.cve = template.cve.clone();
            result.cvss = template.cvss;
            result.fix_advice = template.fix_advice.clone();
            result.port = port;
            result.service = template.metadata.service.clone();
            result.timestamp = chrono::Utc::now();
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// 响应匹配判定（按 MatchType）
    fn match_response(
        &self,
        response: &argus_engine::host_api::HttpResponse,
        match_type: &MatchType,
        pattern: &str,
    ) -> bool {
        match match_type {
            MatchType::Status => {
                let expected: u16 = pattern.parse().unwrap_or(0);
                response.status == expected
            }
            MatchType::Body => response.body.contains(pattern),
            MatchType::Header => response.headers.iter().any(|(k, v)| {
                k.contains(pattern) || v.contains(pattern)
            }),
            MatchType::BodyRegex => {
                match regex::Regex::new(pattern) {
                    Ok(re) => re.is_match(&response.body),
                    Err(_) => false,
                }
            }
        }
    }

    /// 批量执行模板（并发）
    pub async fn execute_batch(
        &self,
        templates: &[PluginTemplate],
        target: &str,
        concurrency: usize,
    ) -> Vec<PluginResult> {
        use futures_util::stream::{self, StreamExt};

        let results: Vec<Option<PluginResult>> = stream::iter(templates.iter().cloned())
            .map(|t| async move { self.execute_template(&t, target).await.ok().flatten() })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        results.into_iter().flatten().collect()
    }
}

/// 从 target 字符串提取端口号
fn extract_port(target: &str) -> Option<u16> {
    let is_https = target.starts_with("https://");
    let target = target.trim_start_matches("http://").trim_start_matches("https://");
    if let Some(colon_pos) = target.find(':') {
        let port_str = &target[colon_pos + 1..];
        let port_str = port_str.split('/').next().unwrap_or(port_str);
        port_str.parse().ok()
    } else if is_https {
        Some(443)
    } else {
        Some(80)
    }
}

/// 从 target 字符串提取主机名
fn extract_host(target: &str) -> String {
    let target = target.trim_start_matches("http://").trim_start_matches("https://");
    let target = target.split('/').next().unwrap_or(target);
    if let Some(colon_pos) = target.find(':') {
        target[..colon_pos].to_string()
    } else {
        target.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_engine::template::{PluginTemplate, DetectionConfig, MatchRule, MatchType, TemplateMetadata};

    #[test]
    fn test_extract_port() {
        assert_eq!(extract_port("http://192.168.1.1:8080"), Some(8080));
        assert_eq!(extract_port("http://192.168.1.1"), Some(80));
        assert_eq!(extract_port("https://192.168.1.1:8443/path"), Some(8443));
        assert_eq!(extract_port("https://192.168.1.1"), Some(443));
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("http://192.168.1.1:8080"), "192.168.1.1");
        assert_eq!(extract_host("http://example.com:8080/path"), "example.com");
        assert_eq!(extract_host("https://192.168.1.1"), "192.168.1.1");
    }

    fn make_template(
        name: &str,
        severity: &str,
        match_type: MatchType,
        pattern: &str,
        path: &str,
    ) -> PluginTemplate {
        PluginTemplate {
            id: format!("test-{name}"),
            name: name.to_string(),
            severity: severity.to_string(),
            author: None,
            description: None,
            cve: None,
            cvss: None,
            fix_advice: None,
            detection: DetectionConfig {
                method: "GET".to_string(),
                path: path.to_string(),
                headers: None,
                body: None,
                match_rule: MatchRule {
                    match_type,
                    pattern: pattern.to_string(),
                },
            },
            metadata: TemplateMetadata::default(),
        }
    }

    #[test]
    fn test_make_template_helper() {
        let t = make_template("X", "high", MatchType::Status, "200", "/healthz");
        assert_eq!(t.id, "test-X");
        assert_eq!(t.detection.path, "/healthz");
        assert!(matches!(t.detection.match_rule.match_type, MatchType::Status));
    }

    #[tokio::test]
    async fn test_execute_template_invalid_target_returns_err() {
        let runtime = VulnPluginRuntime::with_default(1);
        let tpl = make_template("X", "high", MatchType::Status, "200", "/healthz");
        let result = runtime.execute_template(&tpl, "http://127.0.0.1:1").await;
        assert!(result.is_err(), "无效目标应该返回错误");
    }
}
