//! Web 扫描共享类型

use serde::{Deserialize, Serialize};

/// 爬虫配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlConfig {
    pub max_depth: u32,
    pub max_pages: usize,
    pub same_domain_only: bool,
    pub respect_robots: bool,
    pub timeout_secs: u64,
    pub user_agent: String,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 200,
            same_domain_only: true,
            respect_robots: true,
            timeout_secs: 15,
            user_agent: "Argus-WebScanner/0.1".to_string(),
        }
    }
}

/// 爬虫结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub links: Vec<String>,
    pub forms: Vec<FormData>,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// 表单数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormData {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
}

/// 表单字段
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub value: String,
}

/// 漏洞分类（OWASP Top 10）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnCategory {
    BrokenAccessControl,   // A01
    CryptographicFailures,  // A02
    Injection,             // A03 (SQLi, Command Injection)
    InsecureDesign,        // A04
    SecurityMisconfig,     // A05
    VulnerableComponents,  // A06
    AuthFailures,         // A07
    SoftwareDataFailures, // A08 (XXE, Deserialization)
    LoggingFailures,      // A09
    Ssrf,                // A10
    Xss,                 // 旧 A03，仍常见
    PathTraversal,
    OpenRedirect,
    Csrf,
}

impl VulnCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrokenAccessControl => "A01_BrokenAccessControl",
            Self::CryptographicFailures => "A02_CryptographicFailures",
            Self::Injection => "A03_Injection",
            Self::InsecureDesign => "A04_InsecureDesign",
            Self::SecurityMisconfig => "A05_SecurityMisconfiguration",
            Self::VulnerableComponents => "A06_VulnerableComponents",
            Self::AuthFailures => "A07_AuthFailures",
            Self::SoftwareDataFailures => "A08_SoftwareDataIntegrityFailures",
            Self::LoggingFailures => "A09_LoggingFailures",
            Self::Ssrf => "A10_SSRF",
            Self::Xss => "XSS",
            Self::PathTraversal => "PathTraversal",
            Self::OpenRedirect => "OpenRedirect",
            Self::Csrf => "CSRF",
        }
    }
}

/// 漏洞严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

/// 漏洞发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub category: VulnCategory,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub evidence: String,
    pub severity: Severity,
}

/// HTTP 请求（被动扫描用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// HTTP 响应（被动扫描用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// HTTP 事务（请求 + 响应）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub timestamp: String,
}

/// Cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub httponly: bool,
}

/// 会话状态
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionState {
    pub cookies: Vec<Cookie>,
    pub tokens: Vec<String>,
    pub referer: Option<String>,
}

/// POC 模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub vuln_category: String,
    pub template: String,
}

/// 扫描统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanStats {
    pub urls_crawled: usize,
    pub forms_found: usize,
    pub vulnerabilities: usize,
    pub elapsed_secs: f64,
}
