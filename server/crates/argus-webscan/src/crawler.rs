//! Web 爬虫（BFS/DFS + HTML 解析）
//!
//! 支持 robots.txt、深度限制、域名过滤、URL 去重。
//! 使用 scraper 库解析 HTML 提取链接和表单。

use crate::types::{CrawlConfig, CrawlResult, FormData, FormField};
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use url::Url;

/// 爬虫引擎
pub struct Crawler {
    config: CrawlConfig,
    http: reqwest::Client,
    visited: HashSet<String>,
    queue: VecDeque<(String, u32)>, // (url, depth)
}

impl Crawler {
    pub fn new(config: CrawlConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            config,
            http,
            visited: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// 启动爬虫，返回所有结果
    pub async fn crawl(&mut self, start_url: &str) -> Vec<CrawlResult> {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        self.queue.push_back((start_url.to_string(), 0));

        while let Some((url, depth)) = self.queue.pop_front() {
            if self.visited.len() >= self.config.max_pages {
                break;
            }
            if depth > self.config.max_depth {
                continue;
            }
            if self.visited.contains(&url) {
                continue;
            }
            self.visited.insert(url.clone());

            if self.config.respect_robots && !self.check_robots(&url).await {
                continue;
            }

            if self.config.same_domain_only && !self.same_domain(&url, start_url) {
                continue;
            }

            match self.fetch_page(&url).await {
                Ok(result) => {
                    // 提取链接加入队列
                    for link in &result.links {
                        if depth + 1 <= self.config.max_depth {
                            self.queue.push_back((link.clone(), depth + 1));
                        }
                    }
                    results.push(result);
                }
                Err(e) => {
                    tracing::warn!("爬取 {} 失败: {}", url, e);
                }
            }
        }

        tracing::info!(
            "爬虫完成: {} 页，耗时 {:.1}s",
            results.len(),
            start.elapsed().as_secs_f64()
        );
        results
    }

    /// 获取单个页面
    async fn fetch_page(&self, url: &str) -> Result<CrawlResult, String> {
        let resp = self.http.get(url).send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.map_err(|e| e.to_string())?;

        let (links, forms, title) = Self::parse_html(&body, url);
        Ok(CrawlResult {
            url: url.to_string(),
            status,
            title,
            links,
            forms,
            headers,
            body,
        })
    }

    /// 解析 HTML 提取链接、表单和标题
    pub fn parse_html(html: &str, base_url: &str) -> (Vec<String>, Vec<FormData>, String) {
        let document = Html::parse_document(html);
        let base = Url::parse(base_url).ok();

        // 提取链接
        let mut links = Vec::new();
        if let Ok(selector) = Selector::parse("a[href]") {
            for element in document.select(&selector) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(resolved) = resolve_url(href, base.as_ref()) {
                        links.push(resolved);
                    }
                }
            }
        }

        // 提取表单
        let mut forms = Vec::new();
        if let Ok(selector) = Selector::parse("form") {
            for element in document.select(&selector) {
                let action = element.value().attr("action").unwrap_or("").to_string();
                let method = element.value().attr("method").unwrap_or("GET").to_uppercase();
                let mut fields = Vec::new();

                if let Ok(input_sel) = Selector::parse("input, textarea, select") {
                    for input in element.select(&input_sel) {
                        let name = input.value().attr("name").unwrap_or("").to_string();
                        if name.is_empty() {
                            continue;
                        }
                        let field_type = input.value().attr("type").unwrap_or("text").to_string();
                        let value = input.value().attr("value").unwrap_or("").to_string();
                        fields.push(FormField { name, field_type, value });
                    }
                }

                let resolved_action = resolve_url(&action, base.as_ref()).unwrap_or(action);
                forms.push(FormData {
                    action: resolved_action,
                    method,
                    fields,
                });
            }
        }

        // 提取标题
        let title = if let Ok(selector) = Selector::parse("title") {
            document
                .select(&selector)
                .next()
                .map(|e| e.text().collect::<String>().trim().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        (links, forms, title)
    }

    /// 检查 robots.txt 是否允许
    async fn check_robots(&self, url: &str) -> bool {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return true,
        };
        let robots_url = format!(
            "{}://{}/robots.txt",
            parsed.scheme(),
            parsed.host_str().unwrap_or("")
        );

        let resp = match self.http.get(&robots_url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => return true, // 无 robots.txt 则允许
        };

        let robots_text = resp.text().await.unwrap_or_default();
        let user_agent = &self.config.user_agent;
        let path = parsed.path();

        // 简化版 robots.txt 解析
        let mut matching = false;
        for line in robots_text.lines() {
            let line = line.trim();
            if line.starts_with("User-agent:") {
                let agent = line.split(':').nth(1).unwrap_or("").trim();
                matching = agent == "*" || agent == user_agent;
            } else if matching && line.starts_with("Disallow:") {
                let disallowed = line.split(':').nth(1).unwrap_or("").trim();
                if !disallowed.is_empty() && path.starts_with(disallowed) {
                    return false;
                }
            }
        }
        true
    }

    /// 检查是否同域
    fn same_domain(&self, url: &str, base: &str) -> bool {
        let url_host = Url::parse(url).ok().and_then(|u| u.host_str().map(|s| s.to_string()));
        let base_host = Url::parse(base).ok().and_then(|u| u.host_str().map(|s| s.to_string()));
        url_host.is_some() && url_host == base_host
    }

    /// 获取已访问 URL 数
    pub fn visited_count(&self) -> usize {
        self.visited.len()
    }
}

/// 解析相对/绝对 URL
fn resolve_url(href: &str, base: Option<&Url>) -> Option<String> {
    // 跳过 javascript:、mailto: 等
    if href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with("tel:") {
        return None;
    }
    if let Some(base_url) = base {
        base_url.join(href).ok().map(|u| u.to_string())
    } else {
        Url::parse(href).ok().map(|u| u.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_html_links() {
        let html = r#"<html><body>
            <a href="/page1">Page 1</a>
            <a href="https://example.com/page2">Page 2</a>
            <a href="javascript:void(0)">JS</a>
        </body></html>"#;
        let (links, _, _) = Crawler::parse_html(html, "https://example.com/");
        assert!(links.contains(&"https://example.com/page1".to_string()));
        assert!(links.contains(&"https://example.com/page2".to_string()));
        assert!(!links.iter().any(|l| l.contains("javascript")));
    }

    #[test]
    fn test_parse_html_forms() {
        let html = r#"<html><body>
            <form action="/login" method="post">
                <input type="text" name="username" value="">
                <input type="password" name="password">
                <input type="hidden" name="csrf" value="abc123">
            </form>
        </body></html>"#;
        let (_, forms, _) = Crawler::parse_html(html, "https://example.com/");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].action, "https://example.com/login");
        assert_eq!(forms[0].fields.len(), 3);
        assert_eq!(forms[0].fields[0].name, "username");
        assert_eq!(forms[0].fields[2].value, "abc123");
    }

    #[test]
    fn test_parse_html_title() {
        let html = r#"<html><head><title>Test Page</title></head><body></body></html>"#;
        let (_, _, title) = Crawler::parse_html(html, "https://example.com/");
        assert_eq!(title, "Test Page");
    }

    #[test]
    fn test_resolve_url_relative() {
        let base = Url::parse("https://example.com/dir/page").unwrap();
        assert_eq!(
            resolve_url("../other", Some(&base)).unwrap(),
            "https://example.com/other"
        );
    }

    #[test]
    fn test_resolve_url_absolute() {
        let base = Url::parse("https://example.com/").unwrap();
        let result = resolve_url("https://other.com/page", Some(&base));
        assert_eq!(result.unwrap(), "https://other.com/page");
    }

    #[test]
    fn test_resolve_url_skip_javascript() {
        let base = Url::parse("https://example.com/").unwrap();
        assert!(resolve_url("javascript:void(0)", Some(&base)).is_none());
        assert!(resolve_url("mailto:test@test.com", Some(&base)).is_none());
    }

    #[test]
    fn test_crawler_config_default() {
        let config = CrawlConfig::default();
        assert_eq!(config.max_depth, 3);
        assert_eq!(config.max_pages, 200);
        assert!(config.same_domain_only);
        assert!(config.respect_robots);
    }

    #[test]
    fn test_same_domain_check() {
        let crawler = Crawler::new(CrawlConfig::default());
        assert!(crawler.same_domain("https://example.com/page", "https://example.com/"));
        assert!(!crawler.same_domain("https://other.com/page", "https://example.com/"));
    }

    #[test]
    fn test_parse_empty_html() {
        let (links, forms, title) = Crawler::parse_html("", "https://example.com/");
        assert!(links.is_empty());
        assert!(forms.is_empty());
        assert!(title.is_empty());
    }
}
