//! 插件运行时 —— 执行 YAML 模板对目标进行检测

use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::error::EngineError;
use crate::template::{PluginTemplate, MatchType};
use crate::host_api::HostApi;
use crate::result::PluginResult;

/// 插件运行时
pub struct PluginRuntime {
    host_api: Arc<dyn HostApi>,
    timeout: Duration,
}

impl PluginRuntime {
    pub fn new(host_api: Arc<dyn HostApi>, timeout: Duration) -> Self {
        Self { host_api, timeout }
    }

    /// 执行单个模板检测
    ///
    /// target 应为完整 URL（如 "http://192.168.1.1:8080"）或 "host:port"
    pub async fn execute_template(
        &self,
        template: &PluginTemplate,
        target: &str,
    ) -> Result<Option<PluginResult>, EngineError> {
        let detection = &template.detection;
        
        // 构造请求 URL
        let url = if target.starts_with("http://") || target.starts_with("https://") {
            format!("{}/{}", target.trim_end_matches('/'), detection.path.trim_start_matches('/'))
        } else {
            format!("http://{}/{}", target.trim_end_matches('/'), detection.path.trim_start_matches('/'))
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
        let matched = match detection.match_rule.match_type {
            MatchType::Status => {
                let expected: u16 = detection.match_rule.pattern
                    .parse()
                    .unwrap_or(0);
                response.status == expected
            }
            MatchType::Body => {
                response.body.contains(&detection.match_rule.pattern)
            }
            MatchType::Header => {
                response.headers.iter().any(|(k, v)| {
                    k.contains(&detection.match_rule.pattern) 
                    || v.contains(&detection.match_rule.pattern)
                })
            }
            MatchType::BodyRegex => {
                match regex::Regex::new(&detection.match_rule.pattern) {
                    Ok(re) => re.is_match(&response.body),
                    Err(_) => false,
                }
            }
        };

        if matched {
            let port = extract_port(target);
            let host = extract_host(target);
            let mut result = PluginResult::new(
                format!("{}", host),
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

    /// 批量执行模板
    pub async fn execute_batch(
        &self,
        templates: &[PluginTemplate],
        target: &str,
        concurrency: usize,
    ) -> Vec<PluginResult> {
        use futures_util::stream::{self, StreamExt};
        
        let results: Vec<Option<PluginResult>> = stream::iter(templates)
            .map(|t| async move { self.execute_template(t, target).await.ok().flatten() })
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
}
