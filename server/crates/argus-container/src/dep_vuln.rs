//! 镜像依赖漏洞匹配
//!
//! 通过 OSV API 按包名/版本查询漏洞，
//! 并支持本地 CVE 数据库 CPE 匹配

use crate::types::*;
use serde::{Deserialize, Serialize};

/// OSV API 查询请求
#[derive(Debug, Serialize)]
pub struct OsvQuery {
    pub package: OsvPackage,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

/// OSV API 查询响应
#[derive(Debug, Deserialize)]
pub struct OsvResponse {
    pub vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvVuln {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Option<Vec<OsvSeverity>>,
    pub affected: Option<Vec<OsvAffected>>,
    pub references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffected {
    pub package: Option<OsvAffectedPkg>,
    pub ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
pub struct OsvAffectedPkg {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Deserialize)]
pub struct OsvRangeEvent {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

/// 依赖漏洞匹配器
pub struct DepVulnMatcher {
    client: reqwest::Client,
}

impl DepVulnMatcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// 通过 OSV API 查询单个包的漏洞
    pub async fn query_osv(&self, package: &str, ecosystem: &str, version: &str) -> Result<Vec<DepVuln>, String> {
        let query = OsvQuery {
            package: OsvPackage {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: version.to_string(),
        };

        let resp = self.client
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await
            .map_err(|e| format!("OSV API 请求失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("OSV API 错误: {}", resp.status()));
        }

        let osv_resp: OsvResponse = resp.json()
            .await
            .map_err(|e| format!("解析 OSV 响应失败: {e}"))?;

        let mut vulns = Vec::new();
        if let Some(vuln_list) = osv_resp.vulns {
            for v in vuln_list {
                let severity = v.severity
                    .as_ref()
                    .and_then(|s| s.first())
                    .map(|s| s.score.clone())
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                let fixed_version = v.affected
                    .as_ref()
                    .and_then(|a| a.first())
                    .and_then(|a| a.ranges.as_ref())
                    .and_then(|r| r.first())
                    .and_then(|r| r.events.iter().find_map(|e| e.fixed.clone()));

                vulns.push(DepVuln {
                    cve_id: v.id.clone(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version,
                    severity: severity.clone(),
                    cvss: parse_cvss(&severity),
                    description: v.summary.unwrap_or_else(|| v.details.unwrap_or_default()),
                    source: "OSV".to_string(),
                });
            }
        }

        Ok(vulns)
    }

    /// 批量查询多个包
    pub async fn query_batch(&self, packages: &[(String, String, String)]) -> Vec<DepVuln> {
        let mut all_vulns = Vec::new();
        for (pkg, eco, ver) in packages {
            match self.query_osv(pkg, eco, ver).await {
                Ok(vulns) => all_vulns.extend(vulns),
                Err(e) => tracing::warn!("查询 {}/{} 失败: {}", eco, pkg, e),
            }
        }
        all_vulns
    }

    /// 从 OS 包列表匹配漏洞
    /// packages: [("openssl", "1.1.1k"), ("curl", "7.74.0"), ...]
    pub async fn query_os_packages(&self, packages: &[(String, String)]) -> Vec<DepVuln> {
        let batch: Vec<(String, String, String)> = packages
            .iter()
            .map(|(p, v)| {
                let ecosystem = infer_ecosystem(p);
                (p.clone(), ecosystem, v.clone())
            })
            .collect();
        self.query_batch(&batch).await
    }

    /// 已知高危漏洞包的本地匹配（不依赖网络）
    pub fn match_local_known(&self, package: &str, version: &str) -> Vec<DepVuln> {
        let mut vulns = Vec::new();

        // log4j < 2.15.0 (CVE-2021-44228 Log4Shell)
        if package.eq_ignore_ascii_case("log4j") || package.eq_ignore_ascii_case("log4j-core") {
            if is_version_less(version, "2.15.0") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2021-44228".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("2.17.1".to_string()),
                    severity: "CRITICAL".to_string(),
                    cvss: Some(10.0),
                    description: "Log4Shell: Apache Log4j2 JNDI 注入远程代码执行".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        // openssl < 1.1.1i (CVE-2020-1971)
        if package.eq_ignore_ascii_case("openssl") {
            if is_version_less(version, "1.1.1i") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2020-1971".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("1.1.1i".to_string()),
                    severity: "MEDIUM".to_string(),
                    cvss: Some(5.9),
                    description: "OpenSSL EDIPartySS 参数处理 DoS 漏洞".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        // spring4shell (CVE-2022-22965)
        if package.eq_ignore_ascii_case("spring-core") || package.eq_ignore_ascii_case("spring-beans") {
            if is_version_in_range(version, "5.3.0", "5.3.17") || is_version_in_range(version, "5.2.0", "5.2.19") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2022-22965".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("5.3.18".to_string()),
                    severity: "CRITICAL".to_string(),
                    cvss: Some(9.8),
                    description: "Spring4Shell: Spring Framework RCE via data binding".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        // apache commons-collections < 3.2.2 (CVE-2015-7501)
        if package.eq_ignore_ascii_case("commons-collections") {
            if is_version_less(version, "3.2.2") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2015-7501".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("3.2.2".to_string()),
                    severity: "CRITICAL".to_string(),
                    cvss: Some(9.8),
                    description: "Apache Commons Collections 反序列化 RCE".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        // jackson-databind < 2.9.10.8 (多 CVE)
        if package.eq_ignore_ascii_case("jackson-databind") {
            if is_version_less(version, "2.9.10.8") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2020-36550".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("2.10.0".to_string()),
                    severity: "HIGH".to_string(),
                    cvss: Some(7.4),
                    description: "Jackson Databind 反序列化漏洞".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        // nginx < 1.16.1 (CVE-2019-9511)
        if package.eq_ignore_ascii_case("nginx") {
            if is_version_less(version, "1.16.1") {
                vulns.push(DepVuln {
                    cve_id: "CVE-2019-9513".to_string(),
                    package: package.to_string(),
                    version: version.to_string(),
                    fixed_version: Some("1.16.1".to_string()),
                    severity: "HIGH".to_string(),
                    cvss: Some(7.5),
                    description: "nginx HTTP/2 DoS 漏洞".to_string(),
                    source: "Local".to_string(),
                });
            }
        }

        vulns
    }
}

impl Default for DepVulnMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// 从包名推断 OSV 生态系统
fn infer_ecosystem(package: &str) -> String {
    let lower = package.to_lowercase();
    if lower.contains("log4j") || lower.contains("spring") || lower.contains("jackson") {
        return "Maven".to_string();
    }
    if lower.starts_with("py") || lower.contains("django") || lower.contains("flask") {
        return "PyPI".to_string();
    }
    if lower.contains("react") || lower.contains("express") {
        return "npm".to_string();
    }
    if lower.contains("go-") || lower == "go" {
        return "Go".to_string();
    }
    // 默认当作 Linux 发行版包
    "Linux".to_string()
}

/// 简单版本比较: version < threshold
/// 支持数字+字母后缀（如 OpenSSL 1.1.1k < 1.1.1i → false，k > i）
fn is_version_less(version: &str, threshold: &str) -> bool {
    let v_parts: Vec<String> = version.split('.').map(|s| s.to_string()).collect();
    let t_parts: Vec<String> = threshold.split('.').map(|s| s.to_string()).collect();

    for i in 0..t_parts.len().max(v_parts.len()) {
        let v = parse_version_part(v_parts.get(i).map(|s| s.as_str()).unwrap_or("0"));
        let t = parse_version_part(t_parts.get(i).map(|s| s.as_str()).unwrap_or("0"));
        if v < t {
            return true;
        }
        if v > t {
            return false;
        }
    }
    false
}

/// 解析版本片段: "12a" → (12, Some('a'))
/// 字母后缀按 ASCII 排序（a < b < ... < z）
fn parse_version_part(s: &str) -> (u32, Option<char>) {
    let (num_str, suffix) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map(|pos| (&s[..pos], s[pos..].chars().next()))
        .unwrap_or((s, None));
    let num = num_str.parse::<u32>().unwrap_or(0);
    (num, suffix)
}

/// 版本是否在 [start, end) 范围内
fn is_version_in_range(version: &str, start: &str, end: &str) -> bool {
    !is_version_less(version, start) && is_version_less(version, end)
}

/// 解析 CVSS 评分
fn parse_cvss(severity: &str) -> Option<f64> {
    // 尝试解析 "CVSS:3.1/AV:N/AC:L/..." 格式的评分
    if let Some(score_str) = severity.split('/').last() {
        if let Some(score_num) = score_str.strip_prefix("AV:") {
            return score_num.parse().ok();
        }
    }
    severity.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_version_less() {
        assert!(is_version_less("1.1.1h", "1.1.1i"));
        assert!(is_version_less("2.14.0", "2.15.0"));
        assert!(!is_version_less("2.17.1", "2.15.0"));
        assert!(!is_version_less("1.1.1i", "1.1.1i"));
    }

    #[test]
    fn test_is_version_in_range() {
        assert!(is_version_in_range("5.3.10", "5.3.0", "5.3.17"));
        assert!(is_version_in_range("5.2.15", "5.2.0", "5.2.19"));
        assert!(!is_version_in_range("5.3.18", "5.3.0", "5.3.17"));
        assert!(!is_version_in_range("5.1.0", "5.3.0", "5.3.17"));
    }

    #[test]
    fn test_match_local_log4shell() {
        let matcher = DepVulnMatcher::new();
        let vulns = matcher.match_local_known("log4j-core", "2.14.1");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve_id, "CVE-2021-44228");
        assert_eq!(vulns[0].cvss, Some(10.0));
    }

    #[test]
    fn test_match_local_log4j_safe() {
        let matcher = DepVulnMatcher::new();
        let vulns = matcher.match_local_known("log4j-core", "2.17.1");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_match_local_spring4shell() {
        let matcher = DepVulnMatcher::new();
        let vulns = matcher.match_local_known("spring-core", "5.3.10");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve_id, "CVE-2022-22965");
    }

    #[test]
    fn test_match_local_openssl() {
        let matcher = DepVulnMatcher::new();
        let vulns = matcher.match_local_known("openssl", "1.1.1h");
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].cve_id, "CVE-2020-1971");
    }

    #[test]
    fn test_match_local_unknown_package() {
        let matcher = DepVulnMatcher::new();
        let vulns = matcher.match_local_known("unknown-pkg", "1.0.0");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_infer_ecosystem() {
        assert_eq!(infer_ecosystem("log4j-core"), "Maven");
        assert_eq!(infer_ecosystem("spring-core"), "Maven");
        assert_eq!(infer_ecosystem("django"), "PyPI");
        assert_eq!(infer_ecosystem("react"), "npm");
        assert_eq!(infer_ecosystem("nginx"), "Linux");
    }

    #[test]
    fn test_dep_vuln_serialization() {
        let vuln = DepVuln {
            cve_id: "CVE-2021-44228".to_string(),
            package: "log4j".to_string(),
            version: "2.14.0".to_string(),
            fixed_version: Some("2.17.1".to_string()),
            severity: "CRITICAL".to_string(),
            cvss: Some(10.0),
            description: "test".to_string(),
            source: "Local".to_string(),
        };
        let json = serde_json::to_string(&vuln).unwrap();
        assert!(json.contains("CVE-2021-44228"));
        assert!(json.contains("log4j"));
    }
}
