//! G5.2 LDAP 注入检测
//!
//! 通过向用户输入参数注入 LDAP 元字符（`*`、`)(`、`|` 等）检测 LDAP 注入漏洞。
//! 检测依据：
//! - 响应体出现 LDAP 错误关键字（operations error、invalid dn syntax 等）
//! - 注入通配符 `*` 后响应长度异常放大（命中所有条目）

use crate::types::{FormData, HttpResponse, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// G5.2 LDAP 注入扫描器
pub struct LdapScanner {
    http: reqwest::Client,
}

impl LdapScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { http }
    }

    /// 扫描 URL 查询参数中的 LDAP 注入
    pub async fn scan_url(&self, url: &str, param: &str, value: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        // 先取一次基线响应
        let baseline = self.fetch_get(url).await;
        for payload in LDAP_PAYLOADS {
            let test_url = inject_param(url, param, payload);
            if let Some(resp) = self.fetch_get(&test_url).await {
                if let Some(finding) = self.analyze_response(
                    &resp,
                    payload,
                    &test_url,
                    param,
                    baseline.as_ref(),
                ) {
                    findings.push(finding);
                }
            }
        }
        // 去重：同一参数+同一 payload 只保留一条
        dedup_findings(findings)
    }

    /// 扫描表单字段的 LDAP 注入
    pub async fn scan_form(&self, form: &FormData, field_name: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in LDAP_PAYLOADS {
            if let Ok(resp) = self.send_form_payload(form, field_name, payload).await {
                if let Some(finding) = self.analyze_response(
                    &resp,
                    payload,
                    &form.action,
                    field_name,
                    None,
                ) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// 分析响应体，判断是否命中 LDAP 注入特征
    fn analyze_response(
        &self,
        resp: &HttpResponse,
        payload: &str,
        url: &str,
        param: &str,
        baseline: Option<&HttpResponse>,
    ) -> Option<VulnFinding> {
        let body_lower = resp.body.to_lowercase();
        // 1) 基于 LDAP 错误关键字
        for pattern in LDAP_ERROR_PATTERNS {
            if body_lower.contains(pattern) {
                return Some(VulnFinding {
                    category: VulnCategory::Injection,
                    url: url.to_string(),
                    parameter: Some(param.to_string()),
                    payload: Some(payload.to_string()),
                    evidence: format!("LDAP 错误关键字: {}", pattern),
                    severity: Severity::High,
                });
            }
        }
        // 2) 基线对比：注入 `*` 后响应体显著放大
        if let Some(base) = baseline {
            if payload == "*" || payload.contains('*') {
                let base_len = base.body.len();
                let cur_len = resp.body.len();
                if cur_len > base_len * 3 && cur_len - base_len > 200 {
                    return Some(VulnFinding {
                        category: VulnCategory::Injection,
                        url: url.to_string(),
                        parameter: Some(param.to_string()),
                        payload: Some(payload.to_string()),
                        evidence: format!(
                            "通配符注入后响应体放大: baseline={}, payload={}",
                            base_len, cur_len
                        ),
                        severity: Severity::Medium,
                    });
                }
            }
        }
        None
    }

    /// 发送 GET 请求并返回简化响应
    async fn fetch_get(&self, url: &str) -> Option<HttpResponse> {
        let resp = self.http.get(url).send().await.ok()?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();
        Some(HttpResponse { status, headers, body })
    }

    /// 复用 owasp 模块的表单 payload 发送逻辑
    async fn send_form_payload(
        &self,
        form: &FormData,
        field_name: &str,
        payload: &str,
    ) -> Result<HttpResponse, String> {
        let mut params = Vec::new();
        for f in &form.fields {
            let val = if f.name == field_name {
                payload.to_string()
            } else {
                f.value.clone()
            };
            params.push((f.name.clone(), val));
        }
        let resp = if form.method.eq_ignore_ascii_case("POST") {
            self.http.post(&form.action).form(&params).send().await
        } else {
            let query: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            let url = if form.action.contains('?') {
                format!("{}&{}", form.action, query)
            } else {
                format!("{}?{}", form.action, query)
            };
            self.http.get(&url).send().await
        };
        let resp = resp.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        Ok(HttpResponse { status, headers, body })
    }
}

impl Default for LdapScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// LDAP 注入 payload（包含通配符 `*` 与逻辑运算符 `)(` `|`）
const LDAP_PAYLOADS: &[&str] = &[
    "*",
    "*()",
    "*)",
    "*()&",
    "*(|",
    "*()(|",
    "*)(uid=*))(|",
    "*()(|uid=*))",
    "admin*)",
    "*)(&",
    "*|(uid",
    "*(objectClass=*))",
];

/// LDAP 错误关键字（响应体命中即视为注入成功）
const LDAP_ERROR_PATTERNS: &[&str] = &[
    "ldap error",
    "ldap_search",
    "ldap_bind",
    "ldap_add",
    "ldap_modify",
    "ldap_opt",
    "operations error",
    "no such object",
    "invalid dn syntax",
    "invalid credentials",
    "protocol error",
    "naming violation",
    "constraint violation",
    "ldap_result",
    "ldap_searchext",
    "rid of the search",
];

/// 向 URL 的查询参数注入 payload
fn inject_param(url: &str, param: &str, payload: &str) -> String {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };
    let mut new_url = parsed.clone();
    new_url.query_pairs_mut().clear().append_pair(param, payload);
    new_url.to_string()
}

/// 简单去重：相同 (url, payload) 只保留一条
fn dedup_findings(mut findings: Vec<VulnFinding>) -> Vec<VulnFinding> {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (f.url.clone(), f.payload.clone());
        seen.insert(key)
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FormField, HttpResponse};

    #[test]
    fn test_payloads_nonempty() {
        assert!(!LDAP_PAYLOADS.is_empty());
        assert!(LDAP_PAYLOADS.iter().any(|p| p.contains('*')));
    }

    #[test]
    fn test_error_patterns_nonempty() {
        assert!(!LDAP_ERROR_PATTERNS.is_empty());
        assert!(LDAP_ERROR_PATTERNS.iter().any(|p| p.contains("ldap")));
    }

    #[test]
    fn test_inject_param_ldap() {
        let url = "https://example.com/search?q=user";
        let result = inject_param(url, "q", "*");
        // `*` 是 URL 中的 unreserved 字符，url crate 不会编码为 %2A
        assert!(result.contains("q=*"));
    }

    #[test]
    fn test_analyze_response_error_hit() {
        let scanner = LdapScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "LDAP Operations Error occurred".to_string(),
        };
        let finding = scanner.analyze_response(&resp, "*", "https://example.com", "q", None);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.category, VulnCategory::Injection);
        assert!(f.evidence.contains("LDAP"));
    }

    #[test]
    fn test_analyze_response_baseline_growth() {
        let scanner = LdapScanner::new();
        // 基线只有 100 字节
        let baseline = HttpResponse {
            status: 200,
            headers: vec![],
            body: "a".repeat(100),
        };
        // 注入后 400 字节，超过基线 3 倍且差值大于 200
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "b".repeat(400),
        };
        let finding =
            scanner.analyze_response(&resp, "*", "https://example.com", "q", Some(&baseline));
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("通配符"));
    }

    #[test]
    fn test_analyze_response_negative() {
        let scanner = LdapScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Normal search result".to_string(),
        };
        let finding = scanner.analyze_response(&resp, "*", "https://example.com", "q", None);
        assert!(finding.is_none());
    }

    #[test]
    fn test_dedup() {
        let f = VulnFinding {
            category: VulnCategory::Injection,
            url: "https://example.com".to_string(),
            parameter: Some("q".to_string()),
            payload: Some("*".to_string()),
            evidence: "test".to_string(),
            severity: Severity::High,
        };
        let findings = vec![f.clone(), f.clone(), f];
        assert_eq!(dedup_findings(findings).len(), 1);
    }

    #[test]
    fn test_form_payload_construction() {
        // 验证表单字段构造逻辑
        let form = FormData {
            action: "https://example.com/login".to_string(),
            method: "POST".to_string(),
            fields: vec![
                FormField {
                    name: "user".to_string(),
                    field_type: "text".to_string(),
                    value: String::new(),
                },
                FormField {
                    name: "pass".to_string(),
                    field_type: "password".to_string(),
                    value: String::new(),
                },
            ],
        };
        // 模拟构造 params
        let mut params = Vec::new();
        for f in &form.fields {
            let val = if f.name == "user" {
                "*".to_string()
            } else {
                f.value.clone()
            };
            params.push((f.name.clone(), val));
        }
        assert_eq!(params[0].1, "*");
        assert_eq!(params[1].1, "");
    }
}
