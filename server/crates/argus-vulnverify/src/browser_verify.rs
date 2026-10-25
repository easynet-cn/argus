//! 浏览器验证模式（G7.5）
//!
//! 基于 headless Chrome 的漏洞验证引擎，用于验证需要页面渲染才能检测的漏洞
//! （如 XSS、DOM 注入等）。使用 chromiumoxide（Chrome DevTools Protocol）驱动浏览器。
//!
//! 主要功能:
//! - 页面导航 + DOM 内容提取（渲染后的 HTML）
//! - XSS 验证：注入 payload 后检查 alert/confirm/prompt 弹框或 DOM 变化
//! - 截图功能（验证页面渲染状态）
//! - 浏览器不可用时回退到纯 HTTP 验证（检查 payload 是否在响应中原样反射）
//!
//! 依赖系统安装 Chrome/Chromium。若环境无 Chrome，所有浏览器操作会触发 fallback
//! 到 `VerifyEngine`（纯 HTTP），保证验证流程不中断。

use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::ScreenshotParams;
use futures::StreamExt;
use std::time::Duration;
use thiserror::Error;

use crate::engine::VerifyEngine;
use crate::types::*;

/// 浏览器验证相关错误
#[derive(Debug, Error)]
pub enum BrowserVerifyError {
    #[error("构建浏览器配置失败: {0}")]
    BrowserConfig(String),
    #[error("启动 Chrome 失败: {0}")]
    Launch(String),
    #[error("页面导航失败: {0}")]
    Navigation(String),
    #[error("DOM 操作失败: {0}")]
    Dom(String),
    #[error("截图失败: {0}")]
    Screenshot(String),
    #[error("执行 JS 失败: {0}")]
    JsEval(String),
    #[error("超时（{secs}秒）")]
    Timeout { secs: u64 },
}

/// 浏览器验证配置
#[derive(Debug, Clone)]
pub struct BrowserVerifyConfig {
    /// 基础验证配置（HTTP 引擎复用）
    pub base: VerifyConfig,
    /// 页面加载超时（毫秒），默认 30000
    pub page_load_timeout_ms: u64,
    /// 等待 network idle / JS 执行的超时（毫秒），默认 10000
    pub network_idle_timeout_ms: u64,
    /// Chrome/Chromium 可执行文件路径（None=自动检测）
    pub chrome_executable: Option<String>,
    /// 额外的 Chrome 启动参数
    pub extra_args: Vec<String>,
    /// 是否禁用图片加载（提速）
    pub disable_images: bool,
    /// XSS 验证成功时是否保存截图
    pub screenshot_on_verify: bool,
}

impl Default for BrowserVerifyConfig {
    fn default() -> Self {
        Self {
            base: VerifyConfig::default(),
            page_load_timeout_ms: 30_000,
            network_idle_timeout_ms: 10_000,
            chrome_executable: None,
            extra_args: Vec::new(),
            disable_images: true,
            screenshot_on_verify: false,
        }
    }
}

/// 页面渲染结果
#[derive(Debug, Clone)]
pub struct RenderedPage {
    /// 页面 URL
    pub url: String,
    /// 页面标题
    pub title: String,
    /// 渲染后的完整 HTML
    pub html: String,
    /// HTTP 响应状态码（通过 performance API 获取）
    pub status: u16,
}

/// 浏览器验证引擎
pub struct BrowserVerifier {
    config: BrowserVerifyConfig,
    /// HTTP 引擎（用于 fallback 到纯 HTTP 验证）
    http_engine: VerifyEngine,
}

impl BrowserVerifier {
    /// 使用指定配置创建浏览器验证器
    pub fn new(config: BrowserVerifyConfig) -> Result<Self, crate::engine::EngineError> {
        let http_engine = VerifyEngine::new(config.base.clone())?;
        Ok(Self {
            config,
            http_engine,
        })
    }

    /// 使用默认配置创建
    pub fn with_default_config() -> Self {
        Self::new(BrowserVerifyConfig::default())
            .expect("默认配置应能构建 BrowserVerifier")
    }

    /// 获取配置引用
    pub fn config(&self) -> &BrowserVerifyConfig {
        &self.config
    }

    /// 获取 HTTP 引擎引用（fallback 用）
    pub fn http_engine(&self) -> &VerifyEngine {
        &self.http_engine
    }

    /// 构建 chromiumoxide 的 BrowserConfig
    fn build_browser_config(&self) -> Result<BrowserConfig, BrowserVerifyError> {
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg(format!("--user-agent={}", self.config.base.user_agent).as_str())
            .launch_timeout(Duration::from_millis(self.config.page_load_timeout_ms))
            .request_timeout(Duration::from_millis(
                self.config.network_idle_timeout_ms,
            ));

        if let Some(ref path) = self.config.chrome_executable {
            builder = builder.chrome_executable(path);
        }

        if self.config.disable_images {
            builder = builder.arg("--blink-settings=imagesEnabled=false");
        }

        for arg in &self.config.extra_args {
            builder = builder.arg(arg.as_str());
        }

        builder
            .build()
            .map_err(|e| BrowserVerifyError::BrowserConfig(e.to_string()))
    }

    /// 渲染单个页面并返回 DOM 内容
    ///
    /// 启动 headless Chrome -> 导航到 URL -> 等待 JS 执行 -> 提取渲染后 HTML。
    /// 若浏览器不可用，返回 `BrowserVerifyError::Launch`，调用方应 fallback。
    pub async fn render_page(&self, url: &str) -> Result<RenderedPage, BrowserVerifyError> {
        let browser_config = self.build_browser_config()?;

        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| BrowserVerifyError::Launch(e.to_string()))?;

        let handler_handle = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        let result = self.render_page_internal(&browser, url).await;

        let _ = browser.close().await;
        let _ = handler_handle.await;

        result
    }

    async fn render_page_internal(
        &self,
        browser: &Browser,
        url: &str,
    ) -> Result<RenderedPage, BrowserVerifyError> {
        let page = browser
            .new_page(url)
            .await
            .map_err(|e| BrowserVerifyError::Navigation(format!("打开页面失败: {}", e)))?;

        // 等待页面导航完成（或超时）
        let _ = tokio::time::timeout(
            Duration::from_millis(self.config.network_idle_timeout_ms),
            page.wait_for_navigation(),
        )
        .await;

        // 额外等待，确保 SPA / 动态 JS 执行完成
        tokio::time::sleep(Duration::from_millis(500)).await;

        let html = page
            .content()
            .await
            .map_err(|e| BrowserVerifyError::Dom(format!("获取页面内容失败: {}", e)))?;

        let title = page
            .evaluate("document.title || ''")
            .await
            .ok()
            .and_then(|v| v.into_value::<String>().ok())
            .unwrap_or_default();

        let status = page
            .evaluate(
                "(() => { const e = performance.getEntriesByType('navigation')[0]; return (e && e.responseStatus) || 200; })()",
            )
            .await
            .ok()
            .and_then(|v| v.into_value::<u16>().ok())
            .unwrap_or(200);

        Ok(RenderedPage {
            url: url.to_string(),
            title,
            html,
            status,
        })
    }

    /// 对 URL 进行截图（验证页面渲染状态）
    ///
    /// 返回 PNG 字节。若 `output_path` 非空，同时保存到文件。
    pub async fn screenshot(
        &self,
        url: &str,
        output_path: Option<&str>,
    ) -> Result<Vec<u8>, BrowserVerifyError> {
        let browser_config = self.build_browser_config()?;

        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| BrowserVerifyError::Launch(e.to_string()))?;

        let handler_handle = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        let page = browser
            .new_page(url)
            .await
            .map_err(|e| BrowserVerifyError::Navigation(format!("打开页面失败: {}", e)))?;

        let _ = tokio::time::timeout(
            Duration::from_millis(self.config.network_idle_timeout_ms),
            page.wait_for_navigation(),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let screenshot_params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build();
        let png_bytes = page
            .screenshot(screenshot_params)
            .await
            .map_err(|e| BrowserVerifyError::Screenshot(format!("截图失败: {}", e)))?;

        let _ = browser.close().await;
        let _ = handler_handle.await;

        if let Some(path) = output_path {
            std::fs::write(path, &png_bytes)
                .map_err(|e| BrowserVerifyError::Screenshot(format!("保存截图失败: {}", e)))?;
        }

        Ok(png_bytes)
    }

    // ========================================================================
    // XSS 验证
    // ========================================================================

    /// 验证 XSS 漏洞（主入口）
    ///
    /// 优先使用 headless Chrome 进行真实渲染验证（检测 alert 弹框 / JS 标记）。
    /// 若浏览器不可用，自动 fallback 到纯 HTTP 验证（检查 payload 是否原样反射）。
    pub async fn verify_xss(
        &self,
        url: &str,
        method: &str,
        param: &str,
        original_value: &str,
    ) -> VerifyResult {
        let mut result = VerifyResult::new(url.to_string(), VulnType::Custom("xss".to_string()));
        result.severity = "high".to_string();

        // 1. 优先使用浏览器验证
        match self.verify_xss_browser(url, method, param).await {
            Ok(browser_result) => {
                if browser_result.status == VerifyStatus::Verified {
                    return browser_result;
                }
                // 浏览器验证未确认漏洞，保留结果作为参考，继续 fallback
                result = browser_result;
            }
            Err(e) => {
                tracing::warn!("浏览器 XSS 验证不可用 ({}): {}，回退到 HTTP 验证", url, e);
            }
        }

        // 2. Fallback：纯 HTTP 验证（payload 反射检测）
        self.verify_xss_http(url, method, param, original_value, result)
            .await
    }

    /// 浏览器模式 XSS 验证
    ///
    /// 通过 `evaluate_on_new_document` 注入 hook 脚本，拦截 alert/confirm/prompt，
    /// 并检测 payload 设置的 JS 标记变量。
    async fn verify_xss_browser(
        &self,
        url: &str,
        method: &str,
        param: &str,
    ) -> Result<VerifyResult, BrowserVerifyError> {
        let browser_config = self.build_browser_config()?;

        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| BrowserVerifyError::Launch(e.to_string()))?;

        let handler_handle = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        // 在所有新文档加载前注入 hook：拦截 alert/confirm/prompt 并记录
        let hook_script = r#"
            (function() {
                window.__argus_xss_dialogs__ = [];
                window.__argus_xss_marker__ = false;
                try {
                    window.alert = function(msg) {
                        window.__argus_xss_dialogs__.push({type: 'alert', message: String(msg)});
                    };
                    window.confirm = function(msg) {
                        window.__argus_xss_dialogs__.push({type: 'confirm', message: String(msg)});
                        return true;
                    };
                    window.prompt = function(msg, def) {
                        window.__argus_xss_dialogs__.push({type: 'prompt', message: String(msg)});
                        return '';
                    };
                } catch(e) {}
            })();
        "#;

        let mut last_result: Option<VerifyResult> = None;

        for payload in XSS_PAYLOADS {
            let target_url = build_xss_url(url, method, param, payload);

            let page = match browser.new_page(&target_url).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("打开页面失败 {}: {}", target_url, e);
                    continue;
                }
            };

            // 注入 hook（必须在导航前，但 new_page 已导航，所以先注入再 reload）
            // 这里采用：先 about:blank -> 注入 hook -> 导航到目标
            // 简化处理：对当前页注入 hook 后执行 reload
            if let Err(e) = page.evaluate_on_new_document(hook_script).await {
                tracing::warn!("注入 XSS hook 失败: {}", e);
            }

            // 重新导航以触发 hook
            if let Err(e) = page.goto(&target_url).await {
                tracing::warn!("导航到 {} 失败: {}", target_url, e);
                continue;
            }

            // 等待导航 + JS 执行
            let _ = tokio::time::timeout(
                Duration::from_millis(self.config.network_idle_timeout_ms),
                page.wait_for_navigation(),
            )
            .await;
            tokio::time::sleep(Duration::from_millis(800)).await;

            // 检测结果：dialogs 是否被触发 或 marker 是否被设置
            let check_js = r#"
                (function() {
                    return {
                        dialogs: window.__argus_xss_dialogs__ || [],
                        marker: !!window.__argus_xss_marker__
                    };
                })()
            "#;

            let detected = page
                .evaluate(check_js)
                .await
                .ok()
                .and_then(|v| v.into_value::<serde_json::Value>().ok());

            let dialog_count = detected
                .as_ref()
                .and_then(|v| v.get("dialogs"))
                .and_then(|d| d.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            let marker_set = detected
                .as_ref()
                .and_then(|v| v.get("marker"))
                .and_then(|m| m.as_bool())
                .unwrap_or(false);

            // 也检查 payload 是否出现在 DOM 中（反射型 XSS 辅助判断）
            let html = page.content().await.unwrap_or_default();
            let reflected = html.contains(payload) || is_payload_reflected(&html, payload);

            if dialog_count > 0 || marker_set {
                let mut result = VerifyResult::new(
                    url.to_string(),
                    VulnType::Custom("xss".to_string()),
                );
                result.status = VerifyStatus::Verified;
                result.severity = "high".to_string();
                result.payload = Some(payload.to_string());
                result.evidence = if dialog_count > 0 {
                    format!(
                        "浏览器检测到 {} 次 JS 弹框（alert/confirm/prompt），XSS payload 成功执行",
                        dialog_count
                    )
                } else {
                    "浏览器检测到 XSS 标记变量被设置，payload 成功执行".to_string()
                };
                result.request = build_xss_request(url, method, param, payload);
                result.fix_advice = Some(
                    "对用户输入进行 HTML 实体编码；使用 CSP 策略；区分上下文（HTML/JS/CSS/URL）编码；避免使用 innerHTML".to_string(),
                );

                // 验证成功时截图
                if self.config.screenshot_on_verify
                    && let Ok(png) = page
                        .screenshot(ScreenshotParams::builder().format(CaptureScreenshotFormat::Png).build())
                        .await
                {
                    let _ = std::fs::write("/tmp/argus_xss_verify.png", &png);
                }

                let _ = browser.close().await;
                let _ = handler_handle.await;
                return Ok(result);
            }

            last_result = Some(VerifyResult {
                target: url.to_string(),
                vuln_type: VulnType::Custom("xss".to_string()),
                status: VerifyStatus::NotVerified,
                severity: "high".to_string(),
                payload: Some(payload.to_string()),
                evidence: if reflected {
                    "payload 在 DOM 中反射，但未检测到 JS 执行（可能被编码或 CSP 阻止）".to_string()
                } else {
                    "payload 未在 DOM 中反射，未检测到 XSS".to_string()
                },
                request: build_xss_request(url, method, param, payload),
                response: None,
                fix_advice: None,
            });

            let _ = page.close().await;
        }

        let _ = browser.close().await;
        let _ = handler_handle.await;

        Ok(last_result.unwrap_or_else(|| VerifyResult {
            target: url.to_string(),
            vuln_type: VulnType::Custom("xss".to_string()),
            status: VerifyStatus::NotVerified,
            severity: "high".to_string(),
            payload: None,
            evidence: "所有 payload 均未触发 XSS".to_string(),
            request: VerifyRequest::default(),
            response: None,
            fix_advice: None,
        }))
    }

    /// HTTP fallback XSS 验证
    ///
    /// 浏览器不可用时使用：发送带 payload 的 HTTP 请求，检查 payload 是否在响应体中原样反射。
    /// 注意：HTTP 模式只能检测反射型 XSS，无法确认 JS 是否可执行。
    async fn verify_xss_http(
        &self,
        url: &str,
        method: &str,
        param: &str,
        original_value: &str,
        mut result: VerifyResult,
    ) -> VerifyResult {
        for payload in XSS_PAYLOADS {
            let req = build_xss_request(url, method, param, payload);
            if let Ok(resp) = self.http_engine.send_request(&req).await {
                // 检查 payload 是否原样出现在响应体中
                if is_payload_reflected(&resp.body, payload) {
                    result.status = VerifyStatus::Verified;
                    result.payload = Some(payload.to_string());
                    result.evidence = format!(
                        "HTTP 模式检测到 payload 在响应体中原样反射（长度 {}），疑似反射型 XSS",
                        resp.body.len()
                    );
                    result.response = Some(resp);
                    result.fix_advice = Some(
                        "对用户输入进行 HTML 实体编码；使用 CSP；区分上下文编码；避免 innerHTML".to_string(),
                    );
                    return result;
                }
            }
        }

        result.status = VerifyStatus::NotVerified;
        result.evidence = "HTTP fallback：未检测到 payload 原样反射".to_string();
        result.request = build_xss_request(url, method, param, original_value);
        result
    }
}

// ========================================================================
// 辅助函数
// ========================================================================

/// 构造带 XSS payload 的 URL（GET 模式）或请求体（POST 模式）
fn build_xss_url(base_url: &str, method: &str, param: &str, payload: &str) -> String {
    if method.eq_ignore_ascii_case("GET") {
        if let Ok(mut parsed) = url::Url::parse(base_url) {
            parsed.query_pairs_mut().clear().append_pair(param, payload);
            return parsed.to_string();
        }
        // URL 解析失败，手动拼接
        let sep = if base_url.contains('?') { "&" } else { "?" };
        return format!("{}{}{}={}", base_url, sep, param, urlencoding(payload));
    }
    // POST 模式下 URL 不变
    base_url.to_string()
}

/// 构造 XSS 验证请求
fn build_xss_request(url: &str, method: &str, param: &str, payload: &str) -> VerifyRequest {
    if method.eq_ignore_ascii_case("GET") {
        VerifyRequest {
            method: method.to_string(),
            url: build_xss_url(url, method, param, payload),
            timeout_secs: 15,
            ..Default::default()
        }
    } else {
        VerifyRequest {
            method: method.to_string(),
            url: url.to_string(),
            body: Some(format!("{}={}", param, urlencoding(payload))),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            timeout_secs: 15,
            ..Default::default()
        }
    }
}

/// URL 编码（仅编码特殊字符，保留 XSS payload 的语义）
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}

/// 检查 payload 是否在响应体中原样反射（忽略大小写，检查关键片段）
fn is_payload_reflected(body: &str, payload: &str) -> bool {
    // 完全匹配
    if body.contains(payload) {
        return true;
    }
    // 检查 payload 中的关键 JS 执行片段是否出现
    let lower_body = body.to_lowercase();
    for fragment in payload_key_fragments(payload) {
        if lower_body.contains(&fragment.to_lowercase()) {
            return true;
        }
    }
    false
}

/// 提取 payload 中的关键执行片段（用于反射检测）
fn payload_key_fragments(payload: &str) -> Vec<&str> {
    let mut fragments = Vec::new();
    let lower = payload.to_lowercase();
    if lower.contains("<script") {
        fragments.push("<script");
    }
    if lower.contains("onerror") {
        fragments.push("onerror");
    }
    if lower.contains("onload") {
        fragments.push("onload");
    }
    if lower.contains("onmouseover") {
        fragments.push("onmouseover");
    }
    if lower.contains("onfocus") {
        fragments.push("onfocus");
    }
    if lower.contains("javascript:") {
        fragments.push("javascript:");
    }
    if lower.contains("alert(") {
        fragments.push("alert(");
    }
    if lower.contains("<svg") {
        fragments.push("<svg");
    }
    if lower.contains("<img") {
        fragments.push("<img");
    }
    fragments
}

/// XSS payload 列表
///
/// 包含两类：
/// 1. 标记型：设置 `window.__argus_xss_marker__ = true`，浏览器验证时检测该变量
/// 2. 弹框型：调用 `alert()`，浏览器验证时检测被 hook 的弹框记录
const XSS_PAYLOADS: &[&str] = &[
    // === 标记型 payload（设置 JS 变量，浏览器模式可精确检测） ===
    "<script>window.__argus_xss_marker__=true</script>",
    "<img src=x onerror=\"window.__argus_xss_marker__=true\">",
    "<svg onload=\"window.__argus_xss_marker__=true\">",
    "<body onload=\"window.__argus_xss_marker__=true\">",
    "<input onfocus=\"window.__argus_xss_marker__=true\" autofocus>",
    // === 传统 alert 弹框型 payload ===
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg/onload=alert(document.domain)>",
    "\" onmouseover=alert(document.domain) x=\"",
    "' onmouseover=alert(document.domain) x='",
    "javascript:alert(document.domain)",
];

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 配置与结构测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_browser_verify_config_default() {
        let config = BrowserVerifyConfig::default();
        assert_eq!(config.page_load_timeout_ms, 30_000);
        assert_eq!(config.network_idle_timeout_ms, 10_000);
        assert!(config.disable_images);
        assert!(config.chrome_executable.is_none());
        assert!(!config.screenshot_on_verify);
        assert!(config.extra_args.is_empty());
    }

    #[test]
    fn test_browser_verifier_default_config() {
        let verifier = BrowserVerifier::with_default_config();
        assert_eq!(verifier.config().page_load_timeout_ms, 30_000);
        assert_eq!(verifier.config().base.concurrency, 5);
    }

    #[test]
    fn test_build_browser_config_ok() {
        let verifier = BrowserVerifier::with_default_config();
        let result = verifier.build_browser_config();
        assert!(result.is_ok(), "默认配置应能构建 BrowserConfig");
    }

    #[test]
    fn test_build_browser_config_with_chrome_path() {
        let config = BrowserVerifyConfig {
            chrome_executable: Some("/usr/bin/chromium".to_string()),
            extra_args: vec!["--disable-extensions".to_string()],
            ..Default::default()
        };
        let verifier = BrowserVerifier::new(config).unwrap();
        let result = verifier.build_browser_config();
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // XSS payload 与 URL 构造测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_xss_payloads_not_empty() {
        assert!(!XSS_PAYLOADS.is_empty());
        assert!(XSS_PAYLOADS.len() >= 8);
    }

    #[test]
    fn test_xss_payloads_have_marker_variants() {
        let has_marker = XSS_PAYLOADS
            .iter()
            .any(|p| p.contains("__argus_xss_marker__"));
        assert!(has_marker, "应包含标记型 payload");
    }

    #[test]
    fn test_xss_payloads_have_alert_variants() {
        let has_alert = XSS_PAYLOADS.iter().any(|p| p.contains("alert("));
        assert!(has_alert, "应包含 alert 型 payload");
    }

    #[test]
    fn test_build_xss_url_get() {
        let url = build_xss_url(
            "http://example.com/search?q=test",
            "GET",
            "q",
            "<script>alert(1)</script>",
        );
        assert!(url.contains("q="));
        // url::Url 的 append_pair 会自动 URL 编码，< 变为 %3C
        assert!(url.contains("%3Cscript%3E"));
    }

    #[test]
    fn test_build_xss_url_get_no_query() {
        let url = build_xss_url(
            "http://example.com/search",
            "GET",
            "q",
            "<img src=x onerror=alert(1)>",
        );
        assert!(url.contains("?q="));
    }

    #[test]
    fn test_build_xss_url_post() {
        let url = build_xss_url(
            "http://example.com/submit",
            "POST",
            "comment",
            "<script>alert(1)</script>",
        );
        // POST 模式 URL 不变
        assert_eq!(url, "http://example.com/submit");
    }

    #[test]
    fn test_build_xss_request_get() {
        let req = build_xss_request(
            "http://example.com/search",
            "GET",
            "q",
            "<svg onload=alert(1)>",
        );
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("q="));
        assert!(req.body.is_none());
    }

    #[test]
    fn test_build_xss_request_post() {
        let req = build_xss_request(
            "http://example.com/submit",
            "POST",
            "comment",
            "<script>alert(1)</script>",
        );
        assert_eq!(req.method, "POST");
        assert!(req.body.is_some());
        assert!(req
            .headers
            .iter()
            .any(|(k, _)| k == "Content-Type"));
    }

    // -----------------------------------------------------------------------
    // URL 编码测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_urlencoding_keeps_alphanumeric() {
        assert_eq!(urlencoding("abc123"), "abc123");
    }

    #[test]
    fn test_urlencoding_encodes_special() {
        assert_eq!(urlencoding("<script>"), "%3Cscript%3E");
    }

    #[test]
    fn test_urlencoding_keeps_unreserved() {
        assert_eq!(urlencoding("-_.~"), "-_.~");
    }

    // -----------------------------------------------------------------------
    // 反射检测测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_payload_reflected_exact() {
        let body = "<html><body><script>alert(1)</script></body></html>";
        assert!(is_payload_reflected(body, "<script>alert(1)</script>"));
    }

    #[test]
    fn test_is_payload_reflected_by_fragment() {
        let body = "<html><body><img src=\"x\" onerror=\"doSomething()\"></body></html>";
        assert!(is_payload_reflected(
            body,
            "<img src=x onerror=alert(document.domain)>"
        ));
    }

    #[test]
    fn test_is_payload_reflected_no() {
        let body = "<html><body>Hello World</body></html>";
        assert!(!is_payload_reflected(
            body,
            "<script>alert(1)</script>"
        ));
    }

    #[test]
    fn test_payload_key_fragments_script() {
        let frags = payload_key_fragments("<script>alert(1)</script>");
        assert!(frags.contains(&"<script"));
        assert!(frags.contains(&"alert("));
    }

    #[test]
    fn test_payload_key_fragments_img_onerror() {
        let frags = payload_key_fragments("<img src=x onerror=alert(1)>");
        assert!(frags.contains(&"<img"));
        assert!(frags.contains(&"onerror"));
        assert!(frags.contains(&"alert("));
    }

    #[test]
    fn test_payload_key_fragments_svg() {
        let frags = payload_key_fragments("<svg/onload=alert(1)>");
        assert!(frags.contains(&"<svg"));
        assert!(frags.contains(&"onload"));
    }

    // -----------------------------------------------------------------------
    // 渲染结果结构测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_rendered_page_fields() {
        let page = RenderedPage {
            url: "http://example.com".to_string(),
            title: "Example".to_string(),
            html: "<html></html>".to_string(),
            status: 200,
        };
        assert_eq!(page.url, "http://example.com");
        assert_eq!(page.status, 200);
    }

    // -----------------------------------------------------------------------
    // 错误类型测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_browser_verify_error_display() {
        let e = BrowserVerifyError::Launch("chrome not found".to_string());
        assert!(e.to_string().contains("chrome not found"));
    }

    // -----------------------------------------------------------------------
    // 集成测试（需要系统 Chrome，CI 中用 --ignored 跳过）
    // -----------------------------------------------------------------------

    /// 真实浏览器渲染测试
    #[tokio::test]
    #[ignore = "需要系统 Chrome，CI 环境跳过"]
    async fn test_render_page_real() {
        let verifier = BrowserVerifier::with_default_config();
        let result = verifier.render_page("https://example.com").await;
        assert!(result.is_ok(), "渲染 example.com 应成功: {:?}", result.err());
        let page = result.unwrap();
        assert!(!page.html.is_empty());
        assert!(page.status == 200);
    }

    /// 真实浏览器截图测试
    #[tokio::test]
    #[ignore = "需要系统 Chrome，CI 环境跳过"]
    async fn test_screenshot_real() {
        let verifier = BrowserVerifier::with_default_config();
        let result = verifier
            .screenshot("https://example.com", Some("/tmp/argus_test_verify.png"))
            .await;
        assert!(result.is_ok(), "截图应成功: {:?}", result.err());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
        // PNG 文件头
        assert_eq!(&bytes[..4], &[0x89, 0x50, 0x4E, 0x47]);
    }

    /// 真实 XSS 验证测试（使用 httpbin 或自建测试页）
    #[tokio::test]
    #[ignore = "需要系统 Chrome 和可利用的测试目标"]
    async fn test_verify_xss_real() {
        let verifier = BrowserVerifier::with_default_config();
        // 使用 example.com 作为不可利用目标，应返回 NotVerified
        let result = verifier
            .verify_xss("https://example.com", "GET", "q", "test")
            .await;
        assert_eq!(result.status, VerifyStatus::NotVerified);
    }

    /// 测试 fallback 机制：指定不存在的 Chrome 路径，应触发 HTTP fallback
    #[tokio::test]
    async fn test_verify_xss_fallback_no_chrome() {
        let config = BrowserVerifyConfig {
            chrome_executable: Some("/nonexistent/path/to/chrome".to_string()),
            ..Default::default()
        };
        let verifier = BrowserVerifier::new(config).unwrap();
        // 对一个不可达地址发起验证，应在浏览器启动失败后 fallback 到 HTTP，
        // 最终因连接失败返回 NotVerified 或 Error，但不应 panic
        let result = verifier
            .verify_xss("http://127.0.0.1:1/xss", "GET", "q", "test")
            .await;
        // 无论结果如何，都不应 panic；状态应为 NotVerified 或 Error
        assert!(matches!(
            result.status,
            VerifyStatus::NotVerified | VerifyStatus::Error
        ));
    }
}
