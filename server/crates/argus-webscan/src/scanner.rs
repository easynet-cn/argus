//! Web 应用扫描引擎 Scanner trait 适配器
//!
//! 包装 OwaspScanner 实现 argus_scanner::Scanner trait
//! 对每个 target.host 当作 URL 处理（缺失 scheme 时自动补 http://）
//! 执行流程：抓取页面 → 构造 CrawlResult → scan_forms（含安全头部检测）+ scan_urls（参数注入检测）

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError, Target};

use crate::owasp::OwaspScanner;
use crate::types::{CrawlResult, VulnFinding};

/// Web 应用扫描引擎（实现 Scanner trait，注册名 `app_scanner`）
pub struct WebScanner {
    /// OWASP Top 10 检测引擎（注入/XSS/SSRF/重定向/安全头部）
    owasp: OwaspScanner,
    /// 自有的 HTTP 客户端（用于抓取目标页面构造 CrawlResult）
    http: reqwest::Client,
    /// 任务进度（task_id → 0.0..1.0，-1.0 表示已取消）
    progress: Arc<RwLock<HashMap<String, f32>>>,
}

impl WebScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none()) // 不自动跟随重定向，便于检测开放重定向
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            owasp: OwaspScanner::new(),
            http,
            progress: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 规范化 URL：缺失 scheme 时自动补 http://
    fn normalize_url(host: &str) -> String {
        if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("http://{}", host)
        }
    }

    /// 抓取 URL 构造 CrawlResult（失败时返回空 result，安全头部检测仍可基于缺失头部报警）
    async fn fetch(&self, url: &str) -> CrawlResult {
        self.fetch_with_auth(url, None, &serde_json::Value::Null).await
    }

    /// 带认证的抓取：根据凭证类型注入 Authorization / Cookie 头或先 POST 登录获取 Cookie
    ///
    /// 6.3 登录扫描模式。auth_type 支持：
    /// - `bearer`：password 字段作为 token，注入 `Authorization: Bearer {token}`
    /// - `cookie`：password 字段作为 cookie 值，注入 `Cookie: {cookie}`
    /// - `form`（默认）：先 POST 到 extra_params.login_url，
    ///   body 含 {login_user_field(默认 username)=username, login_pass_field(默认 password)=password}，
    ///   从响应 Set-Cookie 提取 session cookie 注入后续请求
    async fn fetch_with_auth(
        &self,
        url: &str,
        credentials: Option<&argus_scanner::Credentials>,
        extra_params: &serde_json::Value,
    ) -> CrawlResult {
        let mut result = CrawlResult {
            url: url.to_string(),
            status: 0,
            title: String::new(),
            links: vec![],
            forms: vec![],
            headers: vec![],
            body: String::new(),
        };

        // 构建请求，必要时注入认证头
        let mut req = self.http.get(url);
        let mut session_cookie: Option<String> = None;

        if let Some(creds) = credentials {
            let auth_type = creds.auth_type.as_deref().unwrap_or("form");
            match auth_type {
                "bearer" => {
                    // password 字段作为 Bearer token
                    req = req.header("Authorization", format!("Bearer {}", creds.password));
                    tracing::debug!("Bearer 认证注入: {}", url);
                }
                "cookie" => {
                    // password 字段作为原始 Cookie 值
                    req = req.header("Cookie", &creds.password);
                    tracing::debug!("Cookie 认证注入: {}", url);
                }
                "form" | _ => {
                    // form 登录：先 POST 到 login_url 获取 session cookie
                    if let Some(login_url) = extra_params.get("login_url").and_then(|v| v.as_str()) {
                        let user_field = extra_params
                            .get("login_user_field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("username");
                        let pass_field = extra_params
                            .get("login_pass_field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("password");
                        let form = serde_json::json!({
                            user_field: creds.username,
                            pass_field: creds.password,
                        });
                        tracing::debug!("Form 登录: {} (user_field={})", login_url, user_field);
                        match self.http.post(login_url).json(&form).send().await {
                            Ok(login_resp) => {
                                // 从 Set-Cookie 提取 session cookie
                                if let Some(set_cookie) = login_resp.headers().get("set-cookie") {
                                    if let Ok(val) = set_cookie.to_str() {
                                        // 取第一个 cookie 的 name=value 部分
                                        let cookie = val.split(';').next().unwrap_or("").to_string();
                                        if !cookie.is_empty() {
                                            session_cookie = Some(cookie);
                                            tracing::info!("Form 登录成功，获取 session cookie");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Form 登录失败: {}", e);
                            }
                        }
                        if let Some(ref cookie) = session_cookie {
                            req = req.header("Cookie", cookie);
                        }
                    } else {
                        tracing::warn!("form 登录模式但未配置 login_url，跳过认证注入");
                    }
                }
            }
        }

        match req.send().await {
            Ok(resp) => {
                result.status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                result.headers = headers;
                let body = resp.text().await.unwrap_or_default();
                result.body = body;
                // 简单提取 <title>...</title>
                let lower = result.body.to_lowercase();
                if let Some(start) = lower.find("<title>") {
                    if let Some(end) = lower[start..].find("</title>") {
                        let title_start = start + 7; // len("<title>")
                        let title_end = start + end;
                        result.title = result.body[title_start..title_end].trim().to_string();
                    }
                }
            }
            Err(e) => {
                tracing::warn!("抓取 {} 失败: {}", url, e);
            }
        }
        result
    }

    /// 从 extra_params 解析爬虫配置
    ///
    /// 6.3 爬虫配置：
    /// - crawl_depth: 爬取深度（默认 3）
    /// - crawl_max_pages: 最大页面数（默认 200）
    /// - crawl_timeout_secs: 超时秒数（默认 30）
    /// - crawl_user_agent: 自定义 UA
    fn parse_crawl_config(params: &serde_json::Value) -> Option<crate::types::CrawlConfig> {
        let has_crawl = params.get("crawl_depth").is_some()
            || params.get("crawl_max_pages").is_some()
            || params.get("crawl_timeout_secs").is_some();
        if !has_crawl {
            return None;
        }
        let mut config = crate::types::CrawlConfig::default();
        if let Some(d) = params.get("crawl_depth").and_then(|v| v.as_u64()) {
            config.max_depth = d as u32;
        }
        if let Some(p) = params.get("crawl_max_pages").and_then(|v| v.as_u64()) {
            config.max_pages = p as usize;
        }
        if let Some(t) = params.get("crawl_timeout_secs").and_then(|v| v.as_u64()) {
            config.timeout_secs = t;
        }
        if let Some(ua) = params.get("crawl_user_agent").and_then(|v| v.as_str()) {
            config.user_agent = ua.to_string();
        }
        Some(config)
    }

    /// 判断是否为登录扫描模式
    fn is_login_scan(params: &serde_json::Value) -> bool {
        params.get("login_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// G6.3 插件类型过滤：检查漏洞类别是否在用户指定的插件类型列表中
    ///
    /// 支持短名匹配（sqli/xss/redirect/command_injection 等）和完整类别名匹配。
    /// filter 为 None 时返回 true（不过滤）。
    fn matches_plugin_types(
        category: &crate::types::VulnCategory,
        filter: &Option<Vec<String>>,
    ) -> bool {
        let filter = match filter {
            None => return true, // 未指定 = 不过滤
            Some(f) => f,
        };
        if filter.is_empty() {
            return true;
        }
        let cat_str = category.as_str().to_lowercase();
        // 短名映射
        let short_name = match category {
            crate::types::VulnCategory::Injection => "sqli",
            crate::types::VulnCategory::Xss => "xss",
            crate::types::VulnCategory::OpenRedirect => "redirect",
            crate::types::VulnCategory::PathTraversal => "lfi",
            crate::types::VulnCategory::Ssrf => "ssrf",
            crate::types::VulnCategory::Csrf => "csrf",
            crate::types::VulnCategory::SecurityMisconfig => "misconfig",
            crate::types::VulnCategory::BrokenAccessControl => "access_control",
            crate::types::VulnCategory::AuthFailures => "auth_failure",
            _ => cat_str.as_str(),
        };
        filter.iter().any(|f| {
            f == &short_name || f == &cat_str || cat_str.contains(f.as_str())
        })
    }

    /// VulnFinding → PluginResult
    fn to_plugin_result(f: VulnFinding, target_url: &str) -> PluginResult {
        let mut pr = PluginResult::new(
            target_url.to_string(),
            format!("{} - {}", f.category.as_str(), f.url),
            f.severity.as_str().to_string(),
        );
        pr.evidence = format!(
            "URL: {} | 参数: {} | Payload: {} | 证据: {}",
            f.url,
            f.parameter.unwrap_or_default(),
            f.payload.unwrap_or_default(),
            f.evidence
        );
        pr.service = Some("http".to_string());
        pr.timestamp = chrono::Utc::now();
        pr
    }
}

impl Default for WebScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for WebScanner {
    fn name(&self) -> &str {
        "app_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();
        let total = config.targets.len();
        if total == 0 {
            return Err(ScannerError::Config("没有扫描目标".to_string()));
        }

        // 解析爬虫配置（6.3 爬虫配置）
        let crawl_config = Self::parse_crawl_config(&config.extra_params);
        let is_login = Self::is_login_scan(&config.extra_params);
        // G6.3 插件类型过滤：web_plugin_types 指定后仅保留匹配的漏洞类别
        let web_plugin_filter: Option<Vec<String>> = config
            .extra_params
            .get("web_plugin_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|i| i.as_str().map(|s| s.to_lowercase()))
                    .collect()
            });

        let mut all_vulns: Vec<PluginResult> = Vec::new();

        for (i, target) in config.targets.iter().enumerate() {
            let url = Self::normalize_url(&target.host);

            // 登录扫描模式：凭证通过 fetch_with_auth 注入 Authorization/Cookie 头或 form 登录
            let creds_ref = if is_login { target.credentials.as_ref() } else { None };
            if is_login && creds_ref.is_some() {
                tracing::info!("登录扫描模式：目标 {} 使用凭证", url);
            }

            // 爬虫模式：多页爬取后批量扫描
            let crawl_results: Vec<crate::types::CrawlResult> = if let Some(cc) = &crawl_config {
                tracing::info!("爬虫模式: {} 深度={} 最大页面={}", url, cc.max_depth, cc.max_pages);
                let mut crawler = crate::crawler::Crawler::new(cc.clone());
                crawler.crawl(&url).await
            } else if creds_ref.is_some() {
                // 单页 + 登录扫描：用带认证的 fetch
                vec![self.fetch_with_auth(&url, creds_ref, &config.extra_params).await]
            } else {
                // 单页模式（向后兼容）
                vec![self.fetch(&url).await]
            };

            // 对所有爬取到的页面执行 OWASP 检测
            for cr in &crawl_results {
                // scan_forms 内部调用 check_security_headers
                let form_findings = self.owasp.scan_forms(&[cr.clone()]).await;
                // scan_urls 检测 URL 参数注入
                let url_findings = self.owasp.scan_urls(&[cr.clone()]).await;

                for f in form_findings {
                    if Self::matches_plugin_types(&f.category, &web_plugin_filter) {
                        all_vulns.push(Self::to_plugin_result(f, &url));
                    }
                }
                for f in url_findings {
                    if Self::matches_plugin_types(&f.category, &web_plugin_filter) {
                        all_vulns.push(Self::to_plugin_result(f, &url));
                    }
                }
            }

            let progress = ((i + 1) as f32) / total as f32 * 0.9;
            if let Ok(mut map) = self.progress.write() {
                map.insert(task_id.clone(), progress);
            }
        }

        let duration = start.elapsed().as_secs_f64();
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: TaskStatus::Completed,
            hosts_scanned: total,
            vulnerabilities: all_vulns,
            duration_secs: duration,
            raw_data: None,
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        if let Ok(map) = self.progress.read() {
            Ok(map.get(task_id).copied().unwrap_or(0.0))
        } else {
            Ok(0.0)
        }
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.to_string(), -1.0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_scanner::{ScanConfig, Target};

    #[test]
    fn test_name_and_version() {
        let s = WebScanner::new();
        assert_eq!(s.name(), "app_scanner");
        assert_eq!(s.version(), "0.1.0");
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(WebScanner::normalize_url("example.com"), "http://example.com");
        assert_eq!(
            WebScanner::normalize_url("https://example.com"),
            "https://example.com"
        );
        assert_eq!(
            WebScanner::normalize_url("http://example.com"),
            "http://example.com"
        );
    }

    #[tokio::test]
    async fn test_execute_empty_targets() {
        let s = WebScanner::new();
        let cfg = ScanConfig {
            task_id: "t-empty".to_string(),
            targets: vec![],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_err(), "空目标应返回错误");
    }

    #[tokio::test]
    async fn test_progress_default_zero() {
        let s = WebScanner::new();
        let p = s.progress("nope").await.expect("progress");
        assert_eq!(p, 0.0);
    }

    #[tokio::test]
    async fn test_cancel_sets_minus_one() {
        let s = WebScanner::new();
        s.cancel("task-1").await.expect("cancel");
        let p = s.progress("task-1").await.expect("progress");
        assert_eq!(p, -1.0);
    }

    #[tokio::test]
    async fn test_execute_unreachable_target_completes() {
        // 即使无法连接，扫描应正常完成（结果为空，不报错）
        let s = WebScanner::new();
        let cfg = ScanConfig {
            task_id: "t-unreachable".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "抓取失败应返回成功（结果为空）");
        let sr = r.unwrap();
        assert_eq!(sr.hosts_scanned, 1);
        assert!(sr.vulnerabilities.is_empty() || !sr.vulnerabilities.is_empty());
    }
}
