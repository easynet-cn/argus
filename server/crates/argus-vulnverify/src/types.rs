//! 漏洞验证共享类型定义

use serde::{Deserialize, Serialize};

/// 验证状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerifyStatus {
    /// 验证成功（漏洞可利用）
    Verified,
    /// 验证失败（漏洞不可利用）
    NotVerified,
    /// 验证错误（请求异常）
    Error,
    /// 跳过（安全考虑，未执行利用）
    Skipped,
}

impl VerifyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::NotVerified => "not_verified",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }
}

/// 漏洞类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnType {
    /// SQL 注入
    Sqli,
    /// 命令执行
    CommandExecution,
    /// 文件读取（路径遍历/任意文件读取）
    FileRead,
    /// 自定义
    Custom(String),
}

impl VulnType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sqli => "sqli",
            Self::CommandExecution => "command_exec",
            Self::FileRead => "file_read",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// HTTP 请求构造参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// 请求方法 (GET/POST/PUT/DELETE)
    pub method: String,
    /// URL
    pub url: String,
    /// 请求头
    pub headers: Vec<(String, String)>,
    /// 请求体 (POST/PUT)
    pub body: Option<String>,
    /// 超时（秒）
    pub timeout_secs: u64,
    /// 是否跟随重定向
    pub follow_redirects: bool,
}

impl Default for VerifyRequest {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            url: String::new(),
            headers: vec![],
            body: None,
            timeout_secs: 15,
            follow_redirects: false,
        }
    }
}

/// HTTP 响应（验证结果用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// HTTP 状态码
    pub status: u16,
    /// 响应头
    pub headers: Vec<(String, String)>,
    /// 响应体
    pub body: String,
    /// 响应大小 (bytes)
    pub size: u64,
    /// 响应耗时（毫秒）
    pub elapsed_ms: u64,
}

/// 验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// 目标 URL
    pub target: String,
    /// 漏洞类型
    pub vuln_type: VulnType,
    /// 验证状态
    pub status: VerifyStatus,
    /// 严重级别 (critical/high/medium/low)
    pub severity: String,
    /// 使用的 payload
    pub payload: Option<String>,
    /// 证据（关键响应内容）
    pub evidence: String,
    /// 发送的请求
    pub request: VerifyRequest,
    /// 接收的响应
    pub response: Option<VerifyResponse>,
    /// 修复建议
    pub fix_advice: Option<String>,
}

impl VerifyResult {
    pub fn new(target: impl Into<String>, vuln_type: VulnType) -> Self {
        Self {
            target: target.into(),
            vuln_type,
            status: VerifyStatus::NotVerified,
            severity: "medium".to_string(),
            payload: None,
            evidence: String::new(),
            request: VerifyRequest::default(),
            response: None,
            fix_advice: None,
        }
    }
}

/// 验证引擎配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    /// 最大并发数
    pub concurrency: usize,
    /// 请求超时（秒）
    pub timeout_secs: u64,
    /// 失败重试次数
    pub max_retries: u32,
    /// 失败重试间隔（毫秒）
    pub retry_delay_ms: u64,
    /// 是否启用利用类 payload（危险，默认关闭）
    pub enable_exploitation: bool,
    /// 是否在验证成功后停止（避免重复利用）
    pub stop_on_success: bool,
    /// 自定义请求头（如 Cookie/Token）
    pub extra_headers: Vec<(String, String)>,
    /// User-Agent
    pub user_agent: String,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            concurrency: 5,
            timeout_secs: 15,
            max_retries: 2,
            retry_delay_ms: 500,
            enable_exploitation: false,
            stop_on_success: true,
            extra_headers: vec![],
            user_agent: "Argus-VulnVerify/0.1".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_status_as_str() {
        assert_eq!(VerifyStatus::Verified.as_str(), "verified");
        assert_eq!(VerifyStatus::NotVerified.as_str(), "not_verified");
        assert_eq!(VerifyStatus::Error.as_str(), "error");
        assert_eq!(VerifyStatus::Skipped.as_str(), "skipped");
    }

    #[test]
    fn test_vuln_type_as_str() {
        assert_eq!(VulnType::Sqli.as_str(), "sqli");
        assert_eq!(VulnType::CommandExecution.as_str(), "command_exec");
        assert_eq!(VulnType::FileRead.as_str(), "file_read");
        assert_eq!(VulnType::Custom("xxe".to_string()).as_str(), "xxe");
    }

    #[test]
    fn test_verify_request_default() {
        let req = VerifyRequest::default();
        assert_eq!(req.method, "GET");
        assert_eq!(req.timeout_secs, 15);
        assert!(!req.follow_redirects);
    }

    #[test]
    fn test_verify_config_default() {
        let cfg = VerifyConfig::default();
        assert_eq!(cfg.concurrency, 5);
        assert!(!cfg.enable_exploitation);
        assert!(cfg.stop_on_success);
    }

    #[test]
    fn test_verify_result_new() {
        let r = VerifyResult::new("http://example.com", VulnType::Sqli);
        assert_eq!(r.target, "http://example.com");
        assert_eq!(r.status, VerifyStatus::NotVerified);
    }
}
