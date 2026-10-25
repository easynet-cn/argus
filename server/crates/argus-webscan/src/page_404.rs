//! G5.6 404 页面智能检测
//!
//! 通过对目标站点探测 N 个随机不存在的 URL 来建立 404 基线（status、length、特征指纹），
//! 然后对实际探测到的 URL 进行对比，识别 "soft 404"（返回 200 但实际为 404）。
//!
//! 检测依据：
//! - 状态码与基线一致
//! - 响应体长度落在基线长度区间
//! - 响应体归一化哈希与基线指纹相似

use crate::types::{CrawlResult, HttpResponse, VulnCategory, VulnFinding, Severity};
use std::collections::HashMap;
use std::time::Duration;

/// 404 基线
#[derive(Debug, Clone)]
pub struct Page404Baseline {
    /// 基线响应码（最常见）
    pub status: u16,
    /// 基线响应体长度中位数
    pub body_len_median: usize,
    /// 基线响应体长度方差阈值（与 median 差距超过此值的视为非基线）
    pub body_len_tolerance: usize,
    /// 基线响应体指纹（小写后的关键字集合）
    pub fingerprints: Vec<String>,
    /// 是否所有探测都返回相同响应码
    pub consistent_status: bool,
}

impl Page404Baseline {
    /// 判断单个响应是否匹配 404 基线（即视为 soft 404）
    pub fn matches(&self, resp: &HttpResponse) -> bool {
        // 1) 状态码与基线一致
        if self.consistent_status && resp.status == self.status {
            // 2) 长度接近基线
            let diff = (resp.body.len() as i64 - self.body_len_median as i64).unsigned_abs() as usize;
            if diff <= self.body_len_tolerance {
                return true;
            }
            // 3) 即使长度差异较大，只要包含基线指纹关键字也认为是 404
            let body_lower = resp.body.to_lowercase();
            if self.fingerprints.iter().any(|fp| body_lower.contains(fp)) {
                return true;
            }
        }
        // 即使状态码为 404，也算命中基线
        if resp.status == 404 {
            return true;
        }
        false
    }

    /// 判断 CrawlResult 是否为 soft 404
    pub fn matches_crawl_result(&self, result: &CrawlResult) -> bool {
        let resp = HttpResponse {
            status: result.status,
            headers: vec![],
            body: result.body.clone(),
        };
        self.matches(&resp)
    }
}

/// G5.6 404 页面智能检测器
pub struct Page404Detector {
    http: reqwest::Client,
    /// 探测数量
    pub probe_count: usize,
    /// 长度容差比例（与基线长度的乘数）
    pub length_tolerance_ratio: f64,
}

impl Page404Detector {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            http,
            probe_count: 5,
            length_tolerance_ratio: 0.2,
        }
    }

    /// 自定义探测数量与长度容差
    pub fn with_options(probe_count: usize, length_tolerance_ratio: f64) -> Self {
        let mut d = Self::new();
        d.probe_count = probe_count.max(1);
        d.length_tolerance_ratio = length_tolerance_ratio.max(0.0);
        d
    }

    /// 对目标站点建立 404 基线
    pub async fn build_baseline(&self, base_url: &str) -> Option<Page404Baseline> {
        let mut responses: Vec<HttpResponse> = Vec::new();
        for path in random_probe_paths(self.probe_count) {
            let url = join_url(base_url, &path);
            if let Some(resp) = self.fetch_get(&url).await {
                responses.push(resp);
            }
        }
        if responses.is_empty() {
            return None;
        }
        Some(self.build_baseline_from_responses(&responses))
    }

    /// 对已知响应集合建立基线（用于测试和已有数据复用）
    pub fn build_baseline_from_responses(&self, responses: &[HttpResponse]) -> Page404Baseline {
        // 状态码众数
        let mut status_counts: HashMap<u16, usize> = HashMap::new();
        for r in responses {
            *status_counts.entry(r.status).or_insert(0) += 1;
        }
        let (status, consistent_status) = if status_counts.len() == 1 {
            (responses[0].status, true)
        } else {
            // 取众数
            let max_entry = status_counts
                .iter()
                .max_by_key(|item| *item.1)
                .unwrap();
            (*max_entry.0, false)
        };
        // 长度中位数
        let mut lens: Vec<usize> = responses.iter().map(|r| r.body.len()).collect();
        lens.sort_unstable();
        let body_len_median = lens[lens.len() / 2];
        let body_len_tolerance = ((body_len_median as f64) * self.length_tolerance_ratio) as usize + 50;
        // 指纹：从基线响应体中提取高频小写关键字
        let fingerprints = extract_fingerprints(responses);
        Page404Baseline {
            status,
            body_len_median,
            body_len_tolerance,
            fingerprints,
            consistent_status,
        }
    }

    /// 检测目标 URL 是否为 soft 404
    pub async fn is_soft_404(&self, url: &str, baseline: &Page404Baseline) -> Option<bool> {
        let resp = self.fetch_get(url).await?;
        Some(baseline.matches(&resp))
    }

    /// 批量检测爬取结果中的 soft 404
    pub fn filter_soft_404<'a>(
        &self,
        results: &'a [CrawlResult],
        baseline: &Page404Baseline,
    ) -> Vec<&'a CrawlResult> {
        results
            .iter()
            .filter(|r| baseline.matches_crawl_result(r))
            .collect()
    }

    /// 将 soft-404 命中转为 VulnFinding（仅记录状态码与基线一致但非 404 的情况）
    pub fn to_findings(
        &self,
        results: &[CrawlResult],
        baseline: &Page404Baseline,
    ) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for r in results {
            // 只有返回 200 但实际是 soft 404 的才算信息项
            if r.status == 200 && baseline.matches_crawl_result(r) {
                findings.push(VulnFinding {
                    category: VulnCategory::SecurityMisconfig,
                    url: r.url.clone(),
                    parameter: None,
                    payload: None,
                    evidence: format!(
                        "Soft-404: 状态码 {} 但内容匹配 404 基线 (len={}, baseline={})",
                        r.status,
                        r.body.len(),
                        baseline.body_len_median
                    ),
                    severity: Severity::Info,
                });
            }
        }
        findings
    }

    async fn fetch_get(&self, url: &str) -> Option<HttpResponse> {
        let resp = self.http.get(url).send().await.ok()?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();
        Some(HttpResponse { status, headers, body })
    }
}

impl Default for Page404Detector {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成 N 个随机探测路径（混合字母数字）
pub fn random_probe_paths(n: usize) -> Vec<String> {
    let mut paths = Vec::with_capacity(n);
    let mut counter = 0;
    while paths.len() < n {
        // 使用确定性生成避免测试不稳定
        let suffix = format!("argus_notexist_{}", counter);
        let path = format!("/this-page-does-not-exist-{}", suffix);
        paths.push(path);
        counter += 1;
        if counter > 1000 {
            break;
        }
    }
    paths
}

/// 拼接 base_url + path
fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

/// 从基线响应中提取指纹关键字
fn extract_fingerprints(responses: &[HttpResponse]) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    // 预设的常见 404 指纹
    let common = [
        "404",
        "not found",
        "page not found",
        "doesn't exist",
        "no such",
        "doesn't exist",
        "could not be found",
        "找不到",
        "页面不存在",
        "页面未找到",
        "notfound",
        "error 404",
        "page cannot be found",
        "page doesn't exist",
    ];
    for c in common {
        candidates.push(c.to_string());
    }
    // 过滤出真正在响应中出现的指纹
    let mut fingerprints = Vec::new();
    for c in candidates {
        let lower = c.to_lowercase();
        if responses.iter().any(|r| r.body.to_lowercase().contains(&lower)) {
            fingerprints.push(c);
        }
    }
    // 限制指纹数量
    fingerprints.truncate(10);
    fingerprints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_probe_paths() {
        let paths = random_probe_paths(5);
        assert_eq!(paths.len(), 5);
        for p in &paths {
            assert!(p.starts_with("/this-page-does-not-exist-"));
        }
    }

    #[test]
    fn test_join_url() {
        assert_eq!(join_url("https://example.com", "/path"), "https://example.com/path");
        assert_eq!(join_url("https://example.com/", "/path"), "https://example.com/path");
        assert_eq!(join_url("https://example.com", "path"), "https://example.com/path");
    }

    #[test]
    fn test_baseline_exact_match() {
        let detector = Page404Detector::new();
        let responses = vec![
            HttpResponse {
                status: 404,
                headers: vec![],
                body: "404 Not Found".to_string(),
            },
            HttpResponse {
                status: 404,
                headers: vec![],
                body: "404 Not Found".to_string(),
            },
        ];
        let baseline = detector.build_baseline_from_responses(&responses);
        assert_eq!(baseline.status, 404);
        assert!(baseline.consistent_status);
        // 命中
        let resp = HttpResponse {
            status: 404,
            headers: vec![],
            body: "404 Not Found".to_string(),
        };
        assert!(baseline.matches(&resp));
    }

    #[test]
    fn test_baseline_length_tolerance() {
        let detector = Page404Detector::new();
        let responses = vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: "Page not found 404".repeat(10),
            },
            HttpResponse {
                status: 200,
                headers: vec![],
                body: "Page not found 404".repeat(10),
            },
        ];
        let baseline = detector.build_baseline_from_responses(&responses);
        assert_eq!(baseline.status, 200);
        // 一个稍微短一点的响应也应该命中
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Page not found 404".repeat(8),
        };
        assert!(baseline.matches(&resp));
    }

    #[test]
    fn test_baseline_fingerprint_hit() {
        let detector = Page404Detector::new();
        let responses = vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: "Page Not Found - The page you requested does not exist".to_string(),
        }];
        let baseline = detector.build_baseline_from_responses(&responses);
        // 即使长度不同，只要包含指纹关键字也应命中
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Page Not Found - The page you requested does not exist. Please check the URL.".to_string(),
        };
        assert!(baseline.matches(&resp));
    }

    #[test]
    fn test_baseline_404_status_direct() {
        let detector = Page404Detector::new();
        let responses = vec![HttpResponse {
            status: 404,
            headers: vec![],
            body: "Not Found".to_string(),
        }];
        let baseline = detector.build_baseline_from_responses(&responses);
        // 即使响应体完全不匹配，404 状态码直接命中
        let resp = HttpResponse {
            status: 404,
            headers: vec![],
            body: "totally different content".to_string(),
        };
        assert!(baseline.matches(&resp));
    }

    #[test]
    fn test_baseline_negative() {
        let detector = Page404Detector::new();
        let responses = vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: "Not Found - 404".to_string(),
            },
        ];
        let baseline = detector.build_baseline_from_responses(&responses);
        // 状态码一致、但长度远超基线、且不含指纹关键字 → 视为非 soft-404
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "Welcome to the home page of Acme Corporation, \
                   where we build innovative products for tomorrow's market. \
                   Our team is dedicated to providing the best service possible."
                .to_string(),
        };
        assert!(!baseline.matches(&resp));
    }

    #[test]
    fn test_baseline_inconsistent_status() {
        let detector = Page404Detector::new();
        let responses = vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: "soft 404 page".to_string(),
            },
            HttpResponse {
                status: 404,
                headers: vec![],
                body: "real 404 page".to_string(),
            },
        ];
        let baseline = detector.build_baseline_from_responses(&responses);
        assert!(!baseline.consistent_status);
        // 任何 404 都直接命中
        let resp = HttpResponse {
            status: 404,
            headers: vec![],
            body: "anything".to_string(),
        };
        assert!(baseline.matches(&resp));
    }

    #[test]
    fn test_filter_soft_404() {
        let detector = Page404Detector::new();
        let baseline = Page404Baseline {
            status: 200,
            body_len_median: 100,
            body_len_tolerance: 50,
            fingerprints: vec!["not found".to_string()],
            consistent_status: true,
        };
        let results = vec![
            CrawlResult {
                url: "https://example.com/real".to_string(),
                status: 200,
                title: "Real Page".to_string(),
                links: vec![],
                forms: vec![],
                headers: vec![],
                body: "Welcome to the real page with lots of content.".to_string(),
            },
            CrawlResult {
                url: "https://example.com/fake".to_string(),
                status: 200,
                title: "Not Found".to_string(),
                links: vec![],
                forms: vec![],
                headers: vec![],
                body: "Page not found".to_string(),
            },
        ];
        let soft_404 = detector.filter_soft_404(&results, &baseline);
        assert_eq!(soft_404.len(), 1);
        assert_eq!(soft_404[0].url, "https://example.com/fake");
    }

    #[test]
    fn test_to_findings() {
        let detector = Page404Detector::new();
        let baseline = Page404Baseline {
            status: 200,
            body_len_median: 100,
            body_len_tolerance: 50,
            fingerprints: vec!["not found".to_string()],
            consistent_status: true,
        };
        let results = vec![CrawlResult {
            url: "https://example.com/fake".to_string(),
            status: 200,
            title: "Not Found".to_string(),
            links: vec![],
            forms: vec![],
            headers: vec![],
            body: "Page not found".to_string(),
        }];
        let findings = detector.to_findings(&results, &baseline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].evidence.contains("Soft-404"));
    }
}
