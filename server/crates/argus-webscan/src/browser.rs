//! 浏览器爬虫（headless Chrome，执行 JavaScript 渲染 SPA 页面）
//!
//! G5.1: 使用 chromiumoxide（Chrome DevTools Protocol）驱动 headless Chrome，
//! 渲染 SPA 页面后提取 DOM 链接/表单，支持自定义 JS 执行和截图。
//!
//! 需要系统安装 Chrome/Chromium。若环境无 Chrome，构造时返回错误，
//! 调用方可 fallback 到纯 HTML 爬虫（`crawler::Crawler`）。

use crate::crawler::Crawler;
use crate::types::{CrawlConfig, CrawlResult, FormData};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::Page;
use futures::StreamExt;
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use url::Url;

/// 浏览器爬虫配置（在 CrawlConfig 基础上扩展浏览器特定选项）
#[derive(Debug, Clone)]
pub struct BrowserCrawlConfig {
    /// 基础爬虫配置
    pub base: CrawlConfig,
    /// 等待页面加载的超时（毫秒），默认 30000
    pub page_load_timeout_ms: u64,
    /// 等待 network idle 的超时（毫秒），默认 15000
    pub network_idle_timeout_ms: u64,
    /// 额外的 Chrome 启动参数
    pub extra_args: Vec<String>,
    /// Chrome/Chromium 可执行文件路径（None=自动检测）
    pub chrome_executable: Option<String>,
    /// 是否禁用图片加载（提速）
    pub disable_images: bool,
}

impl Default for BrowserCrawlConfig {
    fn default() -> Self {
        Self {
            base: CrawlConfig::default(),
            page_load_timeout_ms: 30_000,
            network_idle_timeout_ms: 15_000,
            extra_args: Vec::new(),
            chrome_executable: None,
            disable_images: true,
        }
    }
}

/// 浏览器爬虫引擎
pub struct BrowserCrawler {
    config: BrowserCrawlConfig,
    visited: HashSet<String>,
    queue: VecDeque<(String, u32)>, // (url, depth)
}

/// 单页渲染结果
pub struct RenderedPage {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub html: String,
    pub links: Vec<String>,
    pub forms: Vec<FormData>,
    pub headers: Vec<(String, String)>,
}

impl BrowserCrawler {
    pub fn new(config: BrowserCrawlConfig) -> Self {
        Self {
            config,
            visited: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// 从 CrawlConfig 快捷构建（使用默认浏览器配置）
    pub fn from_crawl_config(config: CrawlConfig) -> Self {
        Self::new(BrowserCrawlConfig {
            base: config,
            ..Default::default()
        })
    }

    /// 构建 BrowserConfig
    fn build_browser_config(&self) -> Result<BrowserConfig, String> {
        let mut builder = BrowserConfig::builder()
            .no_sandbox()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg(format!("--user-agent={}", self.config.base.user_agent).as_str())
            .launch_timeout(Duration::from_millis(
                self.config.page_load_timeout_ms,
            ))
            .request_timeout(Duration::from_millis(
                self.config.network_idle_timeout_ms,
            ));

        // 指定 Chrome 路径
        if let Some(ref path) = self.config.chrome_executable {
            builder = builder.chrome_executable(path);
        }

        // 禁用图片
        if self.config.disable_images {
            builder = builder.arg("--blink-settings=imagesEnabled=false");
        }

        // 额外参数
        for arg in &self.config.extra_args {
            builder = builder.arg(arg.as_str());
        }

        builder.build().map_err(|e| format!("构建 BrowserConfig 失败: {}", e))
    }

    /// 启动浏览器爬虫
    pub async fn crawl(&mut self, start_url: &str) -> Vec<CrawlResult> {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        self.queue.push_back((start_url.to_string(), 0));

        // 构建浏览器配置
        let browser_config = match self.build_browser_config() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("浏览器配置失败: {}，回退到纯 HTML 爬虫", e);
                return self.fallback_to_html_crawler(start_url).await;
            }
        };

        // 启动浏览器
        let (mut browser, mut handler) = match Browser::launch(browser_config).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    "启动 headless Chrome 失败: {}，回退到纯 HTML 爬虫",
                    e
                );
                return self.fallback_to_html_crawler(start_url).await;
            }
        };

        // 启动 CDP 事件处理循环
        let handler_handle = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        while let Some((url, depth)) = self.queue.pop_front() {
            if self.visited.len() >= self.config.base.max_pages {
                break;
            }
            if depth > self.config.base.max_depth {
                continue;
            }
            if self.visited.contains(&url) {
                continue;
            }
            self.visited.insert(url.clone());

            if self.config.base.same_domain_only && !self.same_domain(&url, start_url) {
                continue;
            }

            match self.render_page(&browser, &url).await {
                Ok(rendered) => {
                    // 提取链接加入队列
                    for link in &rendered.links {
                        if depth + 1 <= self.config.base.max_depth {
                            self.queue.push_back((link.clone(), depth + 1));
                        }
                    }
                    results.push(CrawlResult {
                        url: rendered.url,
                        status: rendered.status,
                        title: rendered.title,
                        links: rendered.links,
                        forms: rendered.forms,
                        headers: rendered.headers,
                        body: rendered.html,
                    });
                }
                Err(e) => {
                    tracing::warn!("浏览器渲染 {} 失败: {}", url, e);
                }
            }
        }

        // 关闭浏览器
        let _ = browser.close().await;
        let _ = handler_handle.await;

        tracing::info!(
            "浏览器爬虫完成: {} 页，耗时 {:.1}s",
            results.len(),
            start.elapsed().as_secs_f64()
        );
        results
    }

    /// 渲染单个页面
    async fn render_page(
        &self,
        browser: &Browser,
        url: &str,
    ) -> Result<RenderedPage, String> {
        let page = browser
            .new_page(url)
            .await
            .map_err(|e| format!("打开页面失败: {}", e))?;

        // 等待页面加载（navigation 或超时）
        let _ = tokio::time::timeout(
            Duration::from_millis(self.config.network_idle_timeout_ms),
            page.wait_for_navigation(),
        )
        .await;

        // 额外等待，确保 SPA 的 JS 执行完成
        tokio::time::sleep(Duration::from_millis(500)).await;

        // 获取渲染后的 HTML
        let html = page
            .content()
            .await
            .map_err(|e| format!("获取页面内容失败: {}", e))?;

        // 获取页面标题
        let title = page
            .evaluate("document.title || ''")
            .await
            .ok()
            .and_then(|v| v.into_value::<String>().ok())
            .unwrap_or_default();

        // 获取响应状态（通过 performance API）
        let status = page
            .evaluate(
                "(() => { const e = performance.getEntriesByType('navigation')[0]; return (e && e.responseStatus) || 200; })()",
            )
            .await
            .ok()
            .and_then(|v| v.into_value::<u16>().ok())
            .unwrap_or(200);

        // 获取响应头（通过 performance API，仅部分）
        let headers = self.extract_headers(&page).await;

        // 解析 HTML 提取链接和表单
        let (links, forms, _) = Crawler::parse_html(&html, url);

        // 提取动态生成的链接（JS 渲染的 DOM 可能包含 data-href 等）
        let dynamic_links = self.extract_dynamic_links(&page).await;
        let mut all_links = links;
        for link in dynamic_links {
            if !all_links.contains(&link) {
                all_links.push(link);
            }
        }

        Ok(RenderedPage {
            url: url.to_string(),
            status,
            title,
            html,
            links: all_links,
            forms,
            headers,
        })
    }

    /// 通过 JS 提取动态链接（包括 data-href、onclick 中的 URL 等）
    async fn extract_dynamic_links(&self, page: &Page) -> Vec<String> {
        let js = r#"
            (function() {
                var links = [];
                document.querySelectorAll('a[href]').forEach(function(a) {
                    links.push(a.href);
                });
                document.querySelectorAll('[data-href]').forEach(function(el) {
                    links.push(el.getAttribute('data-href'));
                });
                document.querySelectorAll('[data-url]').forEach(function(el) {
                    links.push(el.getAttribute('data-url'));
                });
                document.querySelectorAll('area[href]').forEach(function(a) {
                    links.push(a.href);
                });
                return links.filter(function(l) {
                    return l && l.startsWith('http') && !l.startsWith('javascript:');
                });
            })()
        "#;

        page.evaluate(js)
            .await
            .ok()
            .and_then(|v| v.into_value::<Vec<String>>().ok())
            .unwrap_or_default()
    }

    /// 通过 performance API 提取响应头
    async fn extract_headers(&self, page: &Page) -> Vec<(String, String)> {
        let js = r#"
            (function() {
                var entry = performance.getEntriesByType('navigation')[0];
                if (entry) {
                    return [['contentType', entry.name || 'unknown']];
                }
                return [];
            })()
        "#;

        page.evaluate(js)
            .await
            .ok()
            .and_then(|v| v.into_value::<Vec<(String, String)>>().ok())
            .unwrap_or_default()
    }

    /// 回退到纯 HTML 爬虫
    async fn fallback_to_html_crawler(&mut self, start_url: &str) -> Vec<CrawlResult> {
        tracing::info!("使用纯 HTML 爬虫（scraper）作为 fallback");
        let mut crawler = Crawler::new(self.config.base.clone());
        crawler.crawl(start_url).await
    }

    /// 检查是否同域
    fn same_domain(&self, url: &str, base: &str) -> bool {
        let url_host = Url::parse(url).ok().and_then(|u| u.host_str().map(|s| s.to_string()));
        let base_host = Url::parse(base).ok().and_then(|u| u.host_str().map(|s| s.to_string()));
        url_host.is_some() && url_host == base_host
    }

    /// 渲染单个页面并返回截图（为 G7.5 漏洞验证铺垫）
    pub async fn render_and_screenshot(
        url: &str,
        output_path: &str,
    ) -> Result<Vec<u8>, String> {
        let config = BrowserCrawlConfig::default();
        let browser_config = BrowserConfig::builder()
            .no_sandbox()
            .arg("--disable-gpu")
            .launch_timeout(Duration::from_millis(config.page_load_timeout_ms))
            .build()
            .map_err(|e| format!("构建 BrowserConfig 失败: {}", e))?;

        let (mut browser, mut handler) = Browser::launch(browser_config)
            .await
            .map_err(|e| format!("启动 Chrome 失败: {}", e))?;

        let handler_handle = tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        let page = browser
            .new_page(url)
            .await
            .map_err(|e| format!("打开页面失败: {}", e))?;

        // 等待页面加载
        let _ = tokio::time::timeout(
            Duration::from_millis(config.network_idle_timeout_ms),
            page.wait_for_navigation(),
        )
        .await;

        // 截图
        let screenshot_params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build();
        let screenshot = page
            .screenshot(screenshot_params)
            .await
            .map_err(|e| format!("截图失败: {}", e))?;

        let _ = browser.close().await;
        let _ = handler_handle.await;

        // 保存到文件（可选）
        if !output_path.is_empty() {
            std::fs::write(output_path, &screenshot)
                .map_err(|e| format!("保存截图失败: {}", e))?;
        }

        Ok(screenshot)
    }

    /// 获取已访问 URL 数
    pub fn visited_count(&self) -> usize {
        self.visited.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_crawl_config_default() {
        let config = BrowserCrawlConfig::default();
        assert_eq!(config.page_load_timeout_ms, 30_000);
        assert_eq!(config.network_idle_timeout_ms, 15_000);
        assert!(config.disable_images);
        assert!(config.chrome_executable.is_none());
    }

    #[test]
    fn test_from_crawl_config() {
        let crawl_config = CrawlConfig {
            max_depth: 5,
            max_pages: 100,
            ..Default::default()
        };
        let crawler = BrowserCrawler::from_crawl_config(crawl_config);
        assert_eq!(crawler.config.base.max_depth, 5);
        assert_eq!(crawler.config.base.max_pages, 100);
    }

    #[test]
    fn test_build_browser_config() {
        let config = BrowserCrawlConfig {
            extra_args: vec!["--disable-extensions".to_string()],
            chrome_executable: Some("/usr/bin/chromium".to_string()),
            ..Default::default()
        };
        let crawler = BrowserCrawler::new(config);
        let browser_config = crawler.build_browser_config();
        assert!(browser_config.is_ok());
    }

    #[test]
    fn test_build_browser_config_with_disable_images() {
        let config = BrowserCrawlConfig {
            disable_images: true,
            ..Default::default()
        };
        let crawler = BrowserCrawler::new(config);
        let browser_config = crawler.build_browser_config();
        assert!(browser_config.is_ok());
    }

    #[test]
    fn test_same_domain_check() {
        let crawler = BrowserCrawler::new(BrowserCrawlConfig::default());
        assert!(crawler.same_domain("https://example.com/page", "https://example.com/"));
        assert!(!crawler.same_domain("https://other.com/page", "https://example.com/"));
    }

    #[test]
    fn test_visited_count_initial() {
        let crawler = BrowserCrawler::new(BrowserCrawlConfig::default());
        assert_eq!(crawler.visited_count(), 0);
    }

    /// 集成测试：需要系统 Chrome（CI 环境用 `--ignored` 跳过）
    #[tokio::test]
    #[ignore = "需要系统 Chrome，CI 环境跳过"]
    async fn test_browser_crawl_real_page() {
        let mut crawler = BrowserCrawler::from_crawl_config(CrawlConfig {
            max_depth: 1,
            max_pages: 1,
            ..Default::default()
        });
        let results = crawler.crawl("https://example.com").await;
        assert!(!results.is_empty());
        assert!(results[0].url.contains("example.com"));
    }

    /// 集成测试：截图功能
    #[tokio::test]
    #[ignore = "需要系统 Chrome，CI 环境跳过"]
    async fn test_render_and_screenshot() {
        let result = BrowserCrawler::render_and_screenshot(
            "https://example.com",
            "/tmp/argus_test_screenshot.png",
        )
        .await;
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }
}
