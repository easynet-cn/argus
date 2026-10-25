//! G5.5 CRLF 注入检测
//!
//! 通过注入 `%0d%0a`（CRLF）序列检测响应头/响应体可被劫持的注入点。
//! 命中依据：
//! - 响应头出现注入标记 `argus-crlf-test`
//! - 响应头多出 `X-Injected` 字段
//! - 响应头多出 `Set-Cookie: argus=` 字段
//! - 响应体出现注入标记

use crate::types::{FormData, HttpResponse, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// 唯一标记，用于在响应中识别注入
const MARKER: &str = "arguscrlftest";

/// G5.5 CRLF 注入扫描器
pub struct CrlfScanner {
    http: reqwest::Client,
}

impl CrlfScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { http }
    }

    /// 扫描 URL 查询参数的 CRLF 注入
    pub async fn scan_url(&self, url: &str, param: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in CRLF_PAYLOADS {
            let test_url = inject_param(url, param, payload);
            if let Some(resp) = self.fetch_get(&test_url).await {
                if let Some(finding) = self.analyze_response(&resp, payload, &test_url, param) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// 扫描表单字段的 CRLF 注入
    pub async fn scan_form(&self, form: &FormData, field_name: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in CRLF_PAYLOADS {
            if let Ok(resp) = self.send_form_payload(form, field_name, payload).await {
                if let Some(finding) = self.analyze_response(&resp, payload, &form.action, field_name) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// 分析响应，命中返回 VulnFinding
    fn analyze_response(
        &self,
        resp: &HttpResponse,
        payload: &str,
        url: &str,
        param: &str,
    ) -> Option<VulnFinding> {
        // 1) 检查响应头是否出现注入字段
        for (name, value) in &resp.headers {
            let name_lower = name.to_lowercase();
            let value_lower = value.to_lowercase();
            if name_lower == "x-injected" || value_lower.contains(MARKER) {
                return Some(self.build_finding(payload, url, param, format!("响应头注入: {}={}", name, value)));
            }
            if name_lower == "set-cookie" && value_lower.contains("argus=") {
                return Some(self.build_finding(payload, url, param, format!("Set-Cookie 注入: {}", value)));
            }
        }
        // 2) 检查响应体是否出现注入标记
        if resp.body.to_lowercase().contains(MARKER) {
            return Some(self.build_finding(payload, url, param, "响应体出现 CRLF 注入标记".to_string()));
        }
        // 3) 响应头数量异常增加（与 payload 中的 CRLF 数量相关）
        let crlf_count = payload.to_lowercase().matches("%0d%0a").count()
            + payload.matches("\r\n").count()
            + payload.to_lowercase().matches("%0a").count();
        if crlf_count > 0 && resp.headers.len() >= 3 + crlf_count {
            // 进一步确认响应头里有非常规字段（非标准响应头）
            for (name, _) in &resp.headers {
                let name_lower = name.to_lowercase();
                if !STANDARD_HEADERS.contains(&name_lower.as_str()) {
                    return Some(self.build_finding(payload, url, param, format!("响应头多出非常规字段: {}", name)));
                }
            }
        }
        None
    }

    fn build_finding(&self, payload: &str, url: &str, param: &str, evidence: String) -> VulnFinding {
        VulnFinding {
            category: VulnCategory::Injection,
            url: url.to_string(),
            parameter: Some(param.to_string()),
            payload: Some(payload.to_string()),
            evidence,
            severity: Severity::High,
        }
    }

    async fn fetch_get(&self, url: &str) -> Option<HttpResponse> {
        let resp = self.http.get(url).send().await.ok()?;
        Some(http_response_from(resp).await)
    }

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
        Ok(http_response_from(resp).await)
    }
}

impl Default for CrlfScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// CRLF 注入 payload：URL 编码 + 头注入 + 体注入
const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0a",
    "%0d%0aX-Injected:%20yes",
    "%0d%0aX-Injected:%20arguscrlftest",
    "%0d%0aSet-Cookie:%20argus=arguscrlftest",
    "%0aSet-Cookie:%20argus=crlf",
    "argus%0d%0aSet-Cookie:%20argus=arguscrlftest",
    "%0d%0a%0d%0a<html>arguscrlftest</html>",
    "%0d%0aContent-Length:%200",
    "%0d%0aLocation:%20https://evil.example.com/",
    "arguscrlftest%0d%0aX-Injected:%20true",
    "%0d%0aSet-Cookie:%20argus=1;%20HttpOnly",
    "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>",
];

/// 标准响应头白名单（用于异常响应头检测）
const STANDARD_HEADERS: &[&str] = &[
    "date",
    "server",
    "content-type",
    "content-length",
    "connection",
    "cache-control",
    "pragma",
    "expires",
    "last-modified",
    "etag",
    "accept-ranges",
    "content-encoding",
    "vary",
    "location",
    "set-cookie",
    "x-powered-by",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "access-control-allow-origin",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "www-authenticate",
    "transfer-encoding",
    "host",
    "user-agent",
    "allow",
    "x-request-id",
    "x-correlation-id",
];

/// 通用：从 reqwest::Response 提取 HttpResponse
async fn http_response_from(resp: reqwest::Response) -> HttpResponse {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    HttpResponse { status, headers, body }
}

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

/// 简单去重
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

    #[test]
    fn test_payloads_nonempty() {
        assert!(!CRLF_PAYLOADS.is_empty());
        // 每个 payload 至少包含 CRLF 或 LF 编码或注入标记
        assert!(
            CRLF_PAYLOADS
                .iter()
                .all(|p| p.to_lowercase().contains("%0d%0a")
                    || p.to_lowercase().contains("%0a")
                    || p.contains(MARKER))
        );
    }

    #[test]
    fn test_standard_headers_list() {
        assert!(STANDARD_HEADERS.contains(&"set-cookie"));
        assert!(STANDARD_HEADERS.contains(&"content-type"));
        assert!(!STANDARD_HEADERS.contains(&"x-injected"));
    }

    #[test]
    fn test_inject_param_crlf() {
        let url = "https://example.com/page?q=1";
        let result = inject_param(url, "q", "%0d%0aX-Injected: yes");
        assert!(result.contains("q="));
    }

    #[test]
    fn test_analyze_header_injected() {
        let scanner = CrlfScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("X-Injected".to_string(), "yes".to_string()),
            ],
            body: String::new(),
        };
        let finding = scanner.analyze_response(&resp, "%0d%0aX-Injected:%20yes", "https://example.com", "q");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_analyze_set_cookie_injected() {
        let scanner = CrlfScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![
                ("Set-Cookie".to_string(), "argus=arguscrlftest; Path=/".to_string()),
            ],
            body: String::new(),
        };
        let finding = scanner.analyze_response(&resp, "%0d%0aSet-Cookie:%20argus=arguscrlftest", "https://example.com", "q");
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("Set-Cookie"));
    }

    #[test]
    fn test_analyze_body_marker() {
        let scanner = CrlfScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "<html><body>arguscrlftest</body></html>".to_string(),
        };
        let finding = scanner.analyze_response(&resp, "%0d%0a%0d%0a<html>arguscrlftest</html>", "https://example.com", "q");
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("响应体"));
    }

    #[test]
    fn test_analyze_negative() {
        let scanner = CrlfScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Server".to_string(), "nginx".to_string()),
            ],
            body: "<html>normal</html>".to_string(),
        };
        let finding = scanner.analyze_response(&resp, "%0d%0a", "https://example.com", "q");
        assert!(finding.is_none());
    }

    #[test]
    fn test_dedup() {
        let f = VulnFinding {
            category: VulnCategory::Injection,
            url: "https://example.com".to_string(),
            parameter: Some("q".to_string()),
            payload: Some("%0d%0a".to_string()),
            evidence: "test".to_string(),
            severity: Severity::High,
        };
        let findings = vec![f.clone(), f];
        assert_eq!(dedup_findings(findings).len(), 1);
    }
}
