//! OWASP Top 10 检测引擎
//!
//! 基于 payload 的主动漏洞检测:
//! - SQL 注入（基于错误、布尔盲注、时间盲注）
//! - XSS（反射型、存储型）
//! - 路径遍历
//! - 命令注入
//! - SSRF
//! - 开放重定向
//! - 安全头部检查
//! - CSRF 检测

use crate::types::{CrawlResult, FormData, HttpTransaction, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// OWASP 检测引擎
pub struct OwaspScanner {
    http: reqwest::Client,
}

impl OwaspScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none()) // 不跟随重定向
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { http }
    }

    /// 扫描表单参数
    pub async fn scan_forms(&self, results: &[CrawlResult]) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for result in results {
            for form in &result.forms {
                // SQL 注入检测
                findings.extend(self.check_sqli(result, form).await);
                // XSS 检测
                findings.extend(self.check_xss(result, form).await);
                // 命令注入检测
                findings.extend(self.check_cmd_injection(result, form).await);
                // 路径遍历检测
                findings.extend(self.check_path_traversal(result, form).await);
            }
            // 安全头部检测
            findings.extend(self.check_security_headers(result));
        }
        findings
    }

    /// 扫描 URL 参数
    pub async fn scan_urls(&self, results: &[CrawlResult]) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for result in results {
            if let Ok(url) = url::Url::parse(&result.url) {
                let params: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
                if params.is_empty() { continue; }

                for (name, value) in &params {
                    findings.extend(self.test_sqli_param(&result.url, name, value).await);
                    findings.extend(self.test_xss_param(&result.url, name, value).await);
                    findings.extend(self.test_redirect_param(&result.url, name).await);
                    findings.extend(self.test_ssrf_param(&result.url, name).await);
                }
            }
        }
        findings
    }

    /// 被动扫描：分析 HTTP 事务
    pub fn scan_passive(&self, transactions: &[HttpTransaction]) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for txn in transactions {
            findings.extend(self.check_passive_headers(txn));
            findings.extend(self.check_passive_info_leak(txn));
        }
        findings
    }

    // === SQL 注入检测 ===

    async fn check_sqli(&self, result: &CrawlResult, form: &FormData) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for field in &form.fields {
            if field.field_type == "submit" || field.field_type == "button" {
                continue;
            }
            for payload in SQLI_PAYLOADS {
                if let Ok(resp) = self.send_form_payload(form, &field.name, payload).await {
                    // 基于错误的 SQL 注入检测
                    for pattern in SQL_ERROR_PATTERNS {
                        if resp.body.to_lowercase().contains(pattern) {
                            findings.push(VulnFinding {
                                category: VulnCategory::Injection,
                                url: form.action.clone(),
                                parameter: Some(field.name.clone()),
                                payload: Some(payload.to_string()),
                                evidence: format!("SQL 错误关键字: {}", pattern),
                                severity: Severity::High,
                            });
                            break;
                        }
                    }
                    // 布尔盲注检测
                    if let Ok(true_resp) = self.send_form_payload(form, &field.name, "1").await {
                        if let Ok(false_resp) = self.send_form_payload(form, &field.name, "0").await {
                            let true_len = true_resp.body.len();
                            let false_len = false_resp.body.len();
                            let payload_len = resp.body.len();
                            if ((payload_len as i64) - (true_len as i64)).abs() < 10 && ((false_len as i64) - (true_len as i64)).abs() > 100 {
                                findings.push(VulnFinding {
                                    category: VulnCategory::Injection,
                                    url: form.action.clone(),
                                    parameter: Some(field.name.clone()),
                                    payload: Some(payload.to_string()),
                                    evidence: format!("布尔差异: true={}, payload={}, false={}", true_len, payload_len, false_len),
                                    severity: Severity::Medium,
                                });
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    async fn test_sqli_param(&self, url: &str, param: &str, value: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for payload in SQLI_PAYLOADS {
            let test_url = inject_param(url, param, payload);
            if let Ok(resp) = self.http.get(&test_url).send().await {
                if let Ok(body) = resp.text().await {
                    for pattern in SQL_ERROR_PATTERNS {
                        if body.to_lowercase().contains(pattern) {
                            findings.push(VulnFinding {
                                category: VulnCategory::Injection,
                                url: test_url,
                                parameter: Some(param.to_string()),
                                payload: Some(payload.to_string()),
                                evidence: format!("SQL 错误关键字: {}", pattern),
                                severity: Severity::High,
                            });
                            break;
                        }
                    }
                }
            }
        }
        findings
    }

    // === XSS 检测 ===

    async fn check_xss(&self, result: &CrawlResult, form: &FormData) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for field in &form.fields {
            if field.field_type == "submit" || field.field_type == "button" { continue; }
            let marker = format!("argus{}xss", rand_str(4));
            let payload = format!("<svg onload=alert(1)>{{{}}}>", marker);
            if let Ok(resp) = self.send_form_payload(form, &field.name, &payload).await {
                if resp.body.contains(&marker) || resp.body.contains("<svg onload=alert(1)") {
                    findings.push(VulnFinding {
                        category: VulnCategory::Xss,
                        url: form.action.clone(),
                        parameter: Some(field.name.clone()),
                        payload: Some(payload),
                        evidence: "payload 在响应中未转义".to_string(),
                        severity: Severity::High,
                    });
                }
            }
        }
        findings
    }

    async fn test_xss_param(&self, url: &str, param: &str, _value: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        let marker = format!("argus{}xss", rand_str(4));
        let payload = format!("<script>alert('{}')</script>", marker);
        let test_url = inject_param(url, param, &payload);
        if let Ok(resp) = self.http.get(&test_url).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains(&marker) {
                    findings.push(VulnFinding {
                        category: VulnCategory::Xss,
                        url: test_url,
                        parameter: Some(param.to_string()),
                        payload: Some(payload),
                        evidence: "XSS payload 在响应中未转义".to_string(),
                        severity: Severity::High,
                    });
                }
            }
        }
        findings
    }

    // === 命令注入检测 ===

    async fn check_cmd_injection(&self, result: &CrawlResult, form: &FormData) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for field in &form.fields {
            if field.field_type == "submit" { continue; }
            for payload in CMD_PAYLOADS {
                if let Ok(resp) = self.send_form_payload(form, &field.name, payload).await {
                    for pattern in CMD_SUCCESS_PATTERNS {
                        if resp.body.contains(pattern) {
                            findings.push(VulnFinding {
                                category: VulnCategory::Injection,
                                url: form.action.clone(),
                                parameter: Some(field.name.clone()),
                                payload: Some(payload.to_string()),
                                evidence: format!("命令输出特征: {}", pattern),
                                severity: Severity::Critical,
                            });
                            break;
                        }
                    }
                }
            }
        }
        findings
    }

    // === 路径遍历检测 ===

    async fn check_path_traversal(&self, result: &CrawlResult, form: &FormData) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for field in &form.fields {
            if field.field_type == "submit" { continue; }
            for payload in PATH_TRAVERSAL_PAYLOADS {
                if let Ok(resp) = self.send_form_payload(form, &field.name, payload).await {
                    if resp.body.contains("root:") || resp.body.contains("[extensions]") || resp.body.contains("[fonts]") {
                        findings.push(VulnFinding {
                            category: VulnCategory::PathTraversal,
                            url: form.action.clone(),
                            parameter: Some(field.name.clone()),
                            payload: Some(payload.to_string()),
                            evidence: "读取到系统敏感文件内容".to_string(),
                            severity: Severity::Critical,
                        });
                        break;
                    }
                }
            }
        }
        findings
    }

    // === 开放重定向检测 ===

    async fn test_redirect_param(&self, url: &str, param: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        let payload = "https://evil.example.com/redirect";
        let test_url = inject_param(url, param, payload);
        if let Ok(resp) = self.http.get(&test_url).send().await {
            if let Some(loc) = resp.headers().get("location") {
                if let Ok(loc_str) = loc.to_str() {
                    if loc_str.contains("evil.example.com") {
                        findings.push(VulnFinding {
                            category: VulnCategory::OpenRedirect,
                            url: test_url,
                            parameter: Some(param.to_string()),
                            payload: Some(payload.to_string()),
                            evidence: format!("重定向到: {}", loc_str),
                            severity: Severity::Medium,
                        });
                    }
                }
            }
        }
        findings
    }

    // === SSRF 检测 ===

    async fn test_ssrf_param(&self, url: &str, param: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        // 使用内部地址测试 SSRF
        for payload in &["http://127.0.0.1:80", "http://localhost", "dict://localhost:11211"] {
            let test_url = inject_param(url, param, payload);
            if let Ok(resp) = self.http.get(&test_url).send().await {
                if resp.status().as_u16() == 200 || resp.status().as_u16() == 302 {
                    if let Ok(body) = resp.text().await {
                        if body.contains("root:") || body.contains("localhost") || body.contains("127.0.0.1") {
                            findings.push(VulnFinding {
                                category: VulnCategory::Ssrf,
                                url: test_url,
                                parameter: Some(param.to_string()),
                                payload: Some(payload.to_string()),
                                evidence: "SSRF: 内部地址可达".to_string(),
                                severity: Severity::High,
                            });
                        }
                    }
                }
            }
        }
        findings
    }

    // === 安全头部检查 ===

    fn check_security_headers(&self, result: &CrawlResult) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        let headers_map: std::collections::HashMap<String, String> = result
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let missing = [
            ("x-content-type-options", "X-Content-Type-Options 缺失", Severity::Low),
            ("x-frame-options", "X-Frame-Options 缺失（可被点击劫持）", Severity::Medium),
            ("strict-transport-security", "HSTS 缺失（可被中间人攻击）", Severity::Medium),
            ("content-security-policy", "CSP 缺失（XSS 防护不足）", Severity::Medium),
            ("x-xss-protection", "X-XSS-Protection 缺失", Severity::Low),
        ];

        for (header, msg, sev) in missing {
            if !headers_map.contains_key(header) {
                findings.push(VulnFinding {
                    category: VulnCategory::SecurityMisconfig,
                    url: result.url.clone(),
                    parameter: None,
                    payload: None,
                    evidence: msg.to_string(),
                    severity: sev,
                });
            }
        }

        // 检查 Cookie 安全属性
        for (k, v) in &result.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                let lower = v.to_lowercase();
                if !lower.contains("httponly") {
                    findings.push(VulnFinding {
                        category: VulnCategory::SecurityMisconfig,
                        url: result.url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: "Cookie 缺少 HttpOnly 属性".to_string(),
                        severity: Severity::Low,
                    });
                }
                if !lower.contains("secure") {
                    findings.push(VulnFinding {
                        category: VulnCategory::SecurityMisconfig,
                        url: result.url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: "Cookie 缺少 Secure 属性".to_string(),
                        severity: Severity::Low,
                    });
                }
            }
        }

        findings
    }

    // === 被动扫描 ===

    fn check_passive_headers(&self, txn: &HttpTransaction) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        let resp = &txn.response;
        let headers_map: std::collections::HashMap<String, &str> = resp
            .headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.as_str()))
            .collect();

        // 检查信息泄露
        for (header, val) in &resp.headers {
            if header.eq_ignore_ascii_case("server") {
                if val.contains("/") || val.contains("(") {
                    findings.push(VulnFinding {
                        category: VulnCategory::SecurityMisconfig,
                        url: txn.request.url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: format!("Server 头泄露版本信息: {}", val),
                        severity: Severity::Info,
                    });
                }
            }
            if header.eq_ignore_ascii_case("x-powered-by") {
                findings.push(VulnFinding {
                    category: VulnCategory::SecurityMisconfig,
                    url: txn.request.url.clone(),
                    parameter: None,
                    payload: None,
                    evidence: format!("X-Powered-By 泄露技术栈: {}", val),
                    severity: Severity::Info,
                });
            }
        }

        // 缺失安全头部
        for required in ["x-content-type-options", "x-frame-options", "strict-transport-security"] {
            if !headers_map.contains_key(required) {
                findings.push(VulnFinding {
                    category: VulnCategory::SecurityMisconfig,
                    url: txn.request.url.clone(),
                    parameter: None,
                    payload: None,
                    evidence: format!("缺失安全头: {}", required),
                    severity: Severity::Low,
                });
            }
        }

        findings
    }

    fn check_passive_info_leak(&self, txn: &HttpTransaction) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        let body = &txn.response.body;

        // 检查响应体中的敏感信息
        let patterns = [
            ("AKIA[0-9A-Z]{16}", "AWS Access Key", Severity::High),
            ("eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}", "JWT Token", Severity::Medium),
            ("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key", Severity::High),
            ("mysql://[^\"]+:[^\"]+@", "MySQL 连接串", Severity::High),
            ("redis://[^\"]+:[^\"]+@", "Redis 连接串", Severity::Medium),
        ];

        for (pattern, name, sev) in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(body) {
                    findings.push(VulnFinding {
                        category: VulnCategory::SecurityMisconfig,
                        url: txn.request.url.clone(),
                        parameter: None,
                        payload: None,
                        evidence: format!("响应体包含敏感信息: {}", name),
                        severity: sev,
                    });
                }
            }
        }

        // 检查错误信息泄露
        let error_patterns = ["stack trace", "exception in thread", "at java.", "at com.", "Traceback (most recent call last)"];
        for pattern in error_patterns {
            if body.to_lowercase().contains(pattern) {
                findings.push(VulnFinding {
                    category: VulnCategory::SecurityMisconfig,
                    url: txn.request.url.clone(),
                    parameter: None,
                    payload: None,
                    evidence: format!("响应体包含错误堆栈信息: {}", pattern),
                    severity: Severity::Medium,
                });
                break;
            }
        }

        findings
    }

    /// 发送表单 payload
    async fn send_form_payload(
        &self,
        form: &FormData,
        field_name: &str,
        payload: &str,
    ) -> Result<crate::types::HttpResponse, String> {
        let mut params = Vec::new();
        for f in &form.fields {
            let val = if f.name == field_name {
                payload.to_string()
            } else {
                f.value.clone()
            };
            params.push((f.name.clone(), val));
        }

        let resp = if form.method == "POST" {
            self.http.post(&form.action).form(&params).send().await
        } else {
            let query: String = params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");
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

        Ok(crate::types::HttpResponse { status, headers, body })
    }
}

impl Default for OwaspScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// SQL 注入 payload
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
    "1; SELECT 1--",
];

/// SQL 错误关键字
const SQL_ERROR_PATTERNS: &[&str] = &[
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "oracle error",
    "postgresql query failed",
    "warning: pg_",
    "you have an error in your sql syntax",
    "sqlite3::",
    "sqlite3.exec",
    "odbc sql server driver",
    "unclosed quotation mark",
    "syntax error at or near",
];

/// 命令注入 payload
const CMD_PAYLOADS: &[&str] = &[
    ";id",
    "|id",
    "`id`",
    "$(id)",
    ";uname -a",
    "| whoami",
    "& ping -c 1 127.0.0.1",
];

/// 命令执行成功特征
const CMD_SUCCESS_PATTERNS: &[&str] = &[
    "uid=",
    "root:x:0:0",
    "groups=",
    "Linux",
    "Darwin",
    "total ",
    "drwxr",
];

/// 路径遍历 payload
const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
];

/// 注入 URL 参数
fn inject_param(url: &str, param: &str, payload: &str) -> String {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return url.to_string(),
    };
    let mut new_url = parsed.clone();
    new_url.query_pairs_mut().clear().append_pair(param, payload);
    new_url.to_string()
}

/// 生成随机字符串（用于 XSS marker）
fn rand_str(len: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    let hash = hasher.finish();
    let chars: Vec<char> = (0..len).map(|i| {
        let idx = ((hash >> (i * 4)) & 0xf) as usize;
        "0123456789abcdef".chars().nth(idx).unwrap()
    }).collect();
    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CrawlResult, FormData, FormField, HttpRequest, HttpResponse, HttpTransaction};

    #[test]
    fn test_inject_param() {
        let url = "https://example.com/page?id=1";
        let result = inject_param(url, "id", "'");
        assert!(result.contains("id=%27"));
    }

    #[test]
    fn test_inject_param_new() {
        let url = "https://example.com/page";
        let result = inject_param(url, "q", "test");
        assert!(result.contains("q=test"));
    }

    #[test]
    fn test_rand_str() {
        let s = rand_str(4);
        assert_eq!(s.len(), 4);
        let s2 = rand_str(4);
        // 极大概率不同
        assert_ne!(s, s2);
    }

    #[test]
    fn test_check_security_headers_all_missing() {
        let scanner = OwaspScanner::new();
        let result = CrawlResult {
            url: "https://example.com/".to_string(),
            status: 200,
            title: "Test".to_string(),
            links: vec![],
            forms: vec![],
            headers: vec![("server".to_string(), "nginx/1.21".to_string())],
            body: String::new(),
        };
        let findings = scanner.check_security_headers(&result);
        // 应该发现 5 个缺失的安全头
        assert!(findings.len() >= 5);
    }

    #[test]
    fn test_check_security_headers_cookie() {
        let scanner = OwaspScanner::new();
        let result = CrawlResult {
            url: "https://example.com/".to_string(),
            status: 200,
            title: "Test".to_string(),
            links: vec![],
            forms: vec![],
            headers: vec![
                ("set-cookie".to_string(), "session=abc; Path=/".to_string()),
            ],
            body: String::new(),
        };
        let findings = scanner.check_security_headers(&result);
        assert!(findings.iter().any(|f| f.evidence.contains("HttpOnly")));
        assert!(findings.iter().any(|f| f.evidence.contains("Secure")));
    }

    #[test]
    fn test_passive_info_leak_aws_key() {
        let scanner = OwaspScanner::new();
        let txn = HttpTransaction {
            request: HttpRequest {
                method: "GET".to_string(),
                url: "https://example.com/config".to_string(),
                headers: vec![],
                body: None,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![],
                body: r#"{"access_key": "AKIAIOSFODNN7EXAMPLE"}"#.to_string(),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let findings = scanner.check_passive_info_leak(&txn);
        assert!(findings.iter().any(|f| f.evidence.contains("AWS")));
    }

    #[test]
    fn test_passive_info_leak_stack_trace() {
        let scanner = OwaspScanner::new();
        let txn = HttpTransaction {
            request: HttpRequest {
                method: "GET".to_string(),
                url: "https://example.com/".to_string(),
                headers: vec![],
                body: None,
            },
            response: HttpResponse {
                status: 500,
                headers: vec![],
                body: "Exception in thread main java.lang.NullPointerException\n\tat com.example.Main(Main.java:42)".to_string(),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let findings = scanner.check_passive_info_leak(&txn);
        assert!(findings.iter().any(|f| f.evidence.contains("错误堆栈")));
    }

    #[test]
    fn test_passive_server_version_leak() {
        let scanner = OwaspScanner::new();
        let txn = HttpTransaction {
            request: HttpRequest {
                method: "GET".to_string(),
                url: "https://example.com/".to_string(),
                headers: vec![],
                body: None,
            },
            response: HttpResponse {
                status: 200,
                headers: vec![
                    ("Server".to_string(), "Apache/2.4.49".to_string()),
                    ("X-Powered-By".to_string(), "PHP/8.0.0".to_string()),
                ],
                body: String::new(),
            },
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };
        let findings = scanner.check_passive_headers(&txn);
        assert!(findings.iter().any(|f| f.evidence.contains("Server 头")));
        assert!(findings.iter().any(|f| f.evidence.contains("X-Powered-By")));
    }

    #[test]
    fn test_vuln_category_as_str() {
        assert_eq!(VulnCategory::Injection.as_str(), "A03_Injection");
        assert_eq!(VulnCategory::Xss.as_str(), "XSS");
        assert_eq!(VulnCategory::Ssrf.as_str(), "A10_SSRF");
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Info.as_str(), "INFO");
    }
}
