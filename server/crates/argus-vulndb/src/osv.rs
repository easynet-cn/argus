//! OSV (Open Source Vulnerability) 导入器
//!
//! 通过 OSV REST API 按 CPE / 包名查询漏洞，
//! 补充 NVD 未收录的开源软件漏洞。
//!
//! API 文档: https://google.github.io/osv.dev/

use crate::cpe_parser::parse_cpe_uri;
use crate::error::VulnDbError;
use crate::types::OsvStats;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use argus_core::entity::cve as cves;
use std::time::Duration;

/// OSV 查询 API
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// OSV 查询请求
#[derive(Debug, serde::Serialize)]
pub struct OsvQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<OsvPackage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// OSV 包信息
#[derive(Debug, serde::Serialize)]
pub struct OsvPackage {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// OSV 查询响应
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerability>,
}

/// OSV 漏洞条目
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvVulnerability {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

/// OSV 严重程度
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

/// OSV 受影响范围
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvAffectedPackage>,
    #[serde(default)]
    pub ranges: Vec<serde_json::Value>,
}

/// OSV 受影响包信息
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvAffectedPackage {
    pub name: String,
    pub ecosystem: String,
    #[serde(default)]
    pub purl: Option<String>,
}

/// OSV 参考链接
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type", default)]
    pub ref_type: Option<String>,
    pub url: String,
}

/// CPE target_sw → OSV ecosystem 映射
fn target_sw_to_ecosystem(target_sw: &str) -> Option<&'static str> {
    match target_sw.to_lowercase().as_str() {
        "python" => Some("PyPI"),
        "node.js" | "nodejs" | "node" => Some("npm"),
        "java" | "maven" => Some("Maven"),
        "go" | "golang" => Some("Go"),
        "rust" => Some("crates.io"),
        "ruby" => Some("RubyGems"),
        "php" => Some("Packagist"),
        "c" | "c++" => Some("OSS-Fuzz"),
        _ => None,
    }
}

/// OSV 导入器
pub struct OsvImporter {
    db: DatabaseConnection,
    http: reqwest::Client,
}

impl OsvImporter {
    pub fn new(db: DatabaseConnection) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Argus-Scanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { db, http }
    }

    /// 按 CPE URI 查询 OSV 漏洞
    pub async fn query_by_cpe(&self, cpe_uri: &str) -> Result<OsvStats, VulnDbError> {
        let cpe = parse_cpe_uri(cpe_uri)?;
        let pkg_name = format!("{}/{}", cpe.vendor, cpe.product);
        let ecosystem = cpe.target_sw.as_deref().and_then(target_sw_to_ecosystem);

        let query = OsvQuery {
            package: Some(OsvPackage {
                name: pkg_name,
                ecosystem: ecosystem.map(|s| s.to_string()),
                purl: None,
            }),
            version: if cpe.version != "*" && cpe.version != "-" {
                Some(cpe.version)
            } else {
                None
            },
            commit: None,
        };

        self.query_and_save(query).await
    }

    /// 按包名 + 生态系统查询
    pub async fn query_by_package(
        &self,
        name: &str,
        ecosystem: &str,
        version: Option<&str>,
    ) -> Result<OsvStats, VulnDbError> {
        let query = OsvQuery {
            package: Some(OsvPackage {
                name: name.to_string(),
                ecosystem: Some(ecosystem.to_string()),
                purl: None,
            }),
            version: version.map(|s| s.to_string()),
            commit: None,
        };
        self.query_and_save(query).await
    }

    /// 按 Git commit 查询
    pub async fn query_by_commit(&self, commit: &str) -> Result<OsvStats, VulnDbError> {
        let query = OsvQuery {
            package: None,
            version: None,
            commit: Some(commit.to_string()),
        };
        self.query_and_save(query).await
    }

    /// 执行查询并保存结果
    async fn query_and_save(&self, query: OsvQuery) -> Result<OsvStats, VulnDbError> {
        let start = std::time::Instant::now();
        tracing::info!("OSV 查询: {:?}", query);

        let resp = self.http.post(OSV_QUERY_URL).json(&query).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VulnDbError::ApiError(format!(
                "OSV HTTP {}: {}",
                status, body
            )));
        }

        let osv_resp: OsvResponse = resp.json().await?;
        let mut stats = OsvStats {
            total_results: osv_resp.vulns.len(),
            ..Default::default()
        };

        for vuln in &osv_resp.vulns {
            match self.save_osv_vuln(vuln).await {
                Ok(true) => stats.new_cves += 1,
                Ok(false) => stats.updated_cves += 1,
                Err(e) => {
                    tracing::warn!("保存 OSV {} 失败: {}", vuln.id, e);
                    stats.errors += 1;
                }
            }
        }

        stats.elapsed_secs = start.elapsed().as_secs_f64();
        tracing::info!(
            "OSV 导入完成: 新增 {} 条，更新 {} 条，错误 {} 条，耗时 {:.1}s",
            stats.new_cves,
            stats.updated_cves,
            stats.errors,
            stats.elapsed_secs
        );
        Ok(stats)
    }

    /// 保存 OSV 漏洞到数据库
    async fn save_osv_vuln(&self, vuln: &OsvVulnerability) -> Result<bool, VulnDbError> {
        // 优先使用 CVE 别名作为主键
        let cve_id = vuln
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .unwrap_or_else(|| vuln.id.clone());

        let description = if !vuln.summary.is_empty() {
            vuln.summary.clone()
        } else {
            vuln.details.chars().take(2000).collect()
        };

        let (cvss_v3, cvss_vector, severity) = extract_osv_severity(&vuln.severity);
        let published = vuln.published.as_deref().and_then(parse_osv_time);
        let last_modified = vuln.modified.as_deref().and_then(parse_osv_time);

        let references: serde_json::Value =
            serde_json::to_value(vuln.references.iter().map(|r| &r.url).collect::<Vec<_>>())?;

        let existing = cves::Entity::find_by_id(cve_id.clone())
            .one(&self.db)
            .await?;
        let is_new = existing.is_none();

        if is_new {
            let active = cves::ActiveModel {
                id: Set(cve_id),
                source: Set("OSV".to_string()),
                description: Set(description),
                cvss_v2: Set(None),
                cvss_v3: Set(cvss_v3),
                cvss_vector: Set(cvss_vector),
                severity: Set(severity),
                published: Set(published),
                last_modified: Set(last_modified),
                references: Set(references),
                cpe_configurations: Set(serde_json::json!([])),
            };
            cves::Entity::insert(active).exec(&self.db).await?;
        } else {
            // CVE 已存在（可能来自 NVD），不覆盖 NVD 数据
            tracing::debug!("CVE {} 已存在，跳过 OSV 更新", cve_id);
        }

        Ok(is_new)
    }

    /// 解析 OSV JSON 响应（用于测试和离线场景）
    pub fn parse_response(json: &str) -> Result<OsvResponse, VulnDbError> {
        serde_json::from_str(json).map_err(|e| VulnDbError::JsonError(e.to_string()))
    }
}

/// 从 OSV severity 数组提取 CVSS v3 分数
fn extract_osv_severity(
    severity: &[OsvSeverity],
) -> (Option<f64>, Option<String>, Option<String>) {
    for s in severity {
        if s.severity_type == "CVSS_V3" || s.severity_type == "CVSS_V4" {
            // score 格式: "CVSS:3.1/AV:N/AC:L/... 6.5 MEDIUM"
            let parts: Vec<&str> = s.score.split_whitespace().collect();
            let score = parts.iter().filter_map(|p| p.parse::<f64>().ok()).next();
            let vector = if s.score.starts_with("CVSS:") {
                Some(s.score.split_whitespace().next().unwrap_or(&s.score).to_string())
            } else {
                None
            };
            let sev = parts.last().and_then(|p| match *p {
                "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" => Some(p.to_string()),
                _ => score.and_then(|s| match s {
                    s if s >= 9.0 => Some("CRITICAL".to_string()),
                    s if s >= 7.0 => Some("HIGH".to_string()),
                    s if s >= 4.0 => Some("MEDIUM".to_string()),
                    _ => Some("LOW".to_string()),
                }),
            });
            return (score, vector, sev);
        }
    }
    (None, None, None)
}

/// 解析 OSV 时间格式 (RFC 3339)
fn parse_osv_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OSV_RESPONSE: &str = r#"{
        "vulns": [
            {
                "id": "GHSA-1234-5678-9abc",
                "summary": "Remote code execution in foo library",
                "details": "Detailed description of the vulnerability...",
                "published": "2024-01-15T00:00:00Z",
                "modified": "2024-01-16T00:00:00Z",
                "aliases": ["CVE-2024-1234"],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8 CRITICAL"
                    }
                ],
                "affected": [
                    {
                        "package": {
                            "name": "foo",
                            "ecosystem": "PyPI",
                            "purl": "pkg:pypi/foo"
                        }
                    }
                ],
                "references": [
                    {"type": "WEB", "url": "https://example.com/advisory"}
                ]
            }
        ]
    }"#;

    #[test]
    fn test_parse_response() {
        let resp = OsvImporter::parse_response(SAMPLE_OSV_RESPONSE).unwrap();
        assert_eq!(resp.vulns.len(), 1);
        let vuln = &resp.vulns[0];
        assert_eq!(vuln.id, "GHSA-1234-5678-9abc");
        assert_eq!(vuln.summary, "Remote code execution in foo library");
        assert!(vuln.aliases.contains(&"CVE-2024-1234".to_string()));
    }

    #[test]
    fn test_extract_osv_severity() {
        let resp = OsvImporter::parse_response(SAMPLE_OSV_RESPONSE).unwrap();
        let (score, vector, sev) = extract_osv_severity(&resp.vulns[0].severity);
        assert_eq!(score, Some(9.8));
        assert!(vector.is_some());
        assert_eq!(sev, Some("CRITICAL".to_string()));
    }

    #[test]
    fn test_parse_osv_time() {
        let dt = parse_osv_time("2024-01-15T00:00:00Z");
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn test_parse_osv_time_invalid() {
        assert!(parse_osv_time("invalid").is_none());
    }

    #[test]
    fn test_target_sw_mapping() {
        assert_eq!(target_sw_to_ecosystem("Python"), Some("PyPI"));
        assert_eq!(target_sw_to_ecosystem("node.js"), Some("npm"));
        assert_eq!(target_sw_to_ecosystem("java"), Some("Maven"));
        assert_eq!(target_sw_to_ecosystem("rust"), Some("crates.io"));
        assert_eq!(target_sw_to_ecosystem("unknown"), None);
    }

    #[test]
    fn test_parse_empty_response() {
        let resp = OsvImporter::parse_response(r#"{"vulns": []}"#).unwrap();
        assert_eq!(resp.vulns.len(), 0);
    }

    #[test]
    fn test_parse_response_missing_aliases() {
        let json = r#"{"vulns": [{"id": "OSV-001", "summary": "test"}]}"#;
        let resp = OsvImporter::parse_response(json).unwrap();
        assert_eq!(resp.vulns[0].aliases.len(), 0);
    }

    #[test]
    fn test_extract_severity_no_cvss() {
        let severity = vec![];
        let (score, vector, sev) = extract_osv_severity(&severity);
        assert_eq!(score, None);
        assert_eq!(vector, None);
        assert_eq!(sev, None);
    }

    #[test]
    fn test_osv_query_serialization() {
        let query = OsvQuery {
            package: Some(OsvPackage {
                name: "foo".to_string(),
                ecosystem: Some("PyPI".to_string()),
                purl: None,
            }),
            version: Some("1.2.3".to_string()),
            commit: None,
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("foo"));
        assert!(json.contains("PyPI"));
        assert!(json.contains("1.2.3"));
    }
}
