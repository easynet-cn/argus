//! CISA KEV (Known Exploited Vulnerabilities) 导入器
//!
//! 从 CISA 官方 JSON 源拉取被在野利用的漏洞目录，
//! 标记数据库中已存在的 CVE 记录，提高检测优先级。
//!
//! 数据源: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

use crate::error::VulnDbError;
use crate::types::KevStats;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use argus_core::entity::cve as cves;
use std::time::Duration;

/// CISA KEV JSON URL
const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// CISA KEV 目录响应
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KevCatalog {
    pub title: String,
    #[serde(default, rename = "catalog_version")]
    pub catalog_version: String,
    #[serde(default, rename = "date_released")]
    pub date_released: String,
    #[serde(default)]
    pub count: usize,
    pub vulnerabilities: Vec<KevVulnerability>,
}

/// KEV 中的单个漏洞条目
#[derive(Debug, Clone, serde::Deserialize)]
pub struct KevVulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "requiredAction")]
    pub required_action: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub known_ransomware: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "dueDate", default)]
    pub due_date: String,
    #[serde(default)]
    pub notes: String,
}

/// CISA KEV 导入器
pub struct KevImporter {
    db: DatabaseConnection,
    http: reqwest::Client,
}

impl KevImporter {
    pub fn new(db: DatabaseConnection) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("Argus-Scanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { db, http }
    }

    /// 拉取 KEV 目录并标记数据库中的 CVE
    pub async fn import(&self) -> Result<KevStats, VulnDbError> {
        let start = std::time::Instant::now();
        tracing::info!("开始拉取 CISA KEV 目录: {}", KEV_URL);

        let resp = self.http.get(KEV_URL).send().await?;
        if !resp.status().is_success() {
            return Err(VulnDbError::ApiError(format!(
                "KEV API HTTP {}",
                resp.status()
            )));
        }
        let catalog: KevCatalog = resp.json().await?;
        tracing::info!(
            "KEV 目录版本: {}，共 {} 条",
            catalog.catalog_version,
            catalog.count
        );

        let mut stats = KevStats {
            total_kev: catalog.vulnerabilities.len(),
            ..Default::default()
        };

        for vuln in &catalog.vulnerabilities {
            match self.mark_kev(vuln).await {
                Ok(true) => stats.marked += 1,
                Ok(false) => stats.not_found += 1,
                Err(e) => {
                    tracing::warn!("标记 KEV {} 失败: {}", vuln.cve_id, e);
                    stats.errors += 1;
                }
            }
        }

        stats.elapsed_secs = start.elapsed().as_secs_f64();
        tracing::info!(
            "KEV 导入完成: 标记 {} 条，未匹配 {} 条，错误 {} 条，耗时 {:.1}s",
            stats.marked,
            stats.not_found,
            stats.errors,
            stats.elapsed_secs
        );
        Ok(stats)
    }

    /// 标记单个 CVE 为已利用（写入或更新 DB 记录）
    async fn mark_kev(&self, vuln: &KevVulnerability) -> Result<bool, VulnDbError> {
        let existing = cves::Entity::find_by_id(vuln.cve_id.clone())
            .one(&self.db)
            .await?;

        let kev_ref = serde_json::json!([{
            "type": "kev",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities",
            "description": vuln.short_description,
            "required_action": vuln.required_action,
            "date_added": vuln.date_added,
            "due_date": vuln.due_date,
            "ransomware": vuln.known_ransomware,
        }]);

        if existing.is_none() {
            // CVE 不在数据库中，创建一条 KEV 来源的记录
            let active = cves::ActiveModel {
                id: Set(vuln.cve_id.clone()),
                source: Set("CISA-KEV".to_string()),
                description: Set(if vuln.short_description.is_empty() {
                    vuln.vulnerability_name.clone()
                } else {
                    vuln.short_description.clone()
                }),
                cvss_v2: Set(None),
                cvss_v3: Set(None),
                cvss_vector: Set(None),
                severity: Set(Some("HIGH".to_string())),
                published: Set(parse_kev_date(&vuln.date_added)),
                last_modified: Set(parse_kev_date(&vuln.date_added)),
                references: Set(kev_ref),
                cpe_configurations: Set(serde_json::json!([])),
            };
            cves::Entity::insert(active).exec(&self.db).await?;
            return Ok(true);
        }

        // CVE 已存在，更新 source 标记和 references
        let model = existing.unwrap();
        let source = if model.source.contains("KEV") {
            model.source.clone()
        } else {
            format!("{}+KEV", model.source)
        };

        // 将 KEV 信息追加到 references
        let mut refs = model.references.clone();
        if let Some(arr) = refs.as_array_mut() {
            arr.push(serde_json::json!({
                "type": "kev",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities",
                "description": vuln.short_description,
                "required_action": vuln.required_action,
                "date_added": vuln.date_added,
                "due_date": vuln.due_date,
                "ransomware": vuln.known_ransomware,
            }));
        }

        let active = cves::ActiveModel {
            id: Set(vuln.cve_id.clone()),
            source: Set(source),
            description: Set(model.description.clone()),
            cvss_v2: Set(model.cvss_v2),
            cvss_v3: Set(model.cvss_v3),
            cvss_vector: Set(model.cvss_vector.clone()),
            severity: Set(model.severity.clone()),
            published: Set(model.published),
            last_modified: Set(model.last_modified),
            references: Set(refs),
            cpe_configurations: Set(model.cpe_configurations.clone()),
        };
        cves::Entity::update(active).exec(&self.db).await?;
        Ok(true)
    }

    /// 仅获取 KEV CVE ID 列表（不写库），用于扫描时优先级判断
    pub async fn fetch_kev_list(&self) -> Result<Vec<String>, VulnDbError> {
        let resp = self.http.get(KEV_URL).send().await?;
        if !resp.status().is_success() {
            return Err(VulnDbError::ApiError(format!(
                "KEV HTTP {}",
                resp.status()
            )));
        }
        let catalog: KevCatalog = resp.json().await?;
        Ok(catalog.vulnerabilities.into_iter().map(|v| v.cve_id).collect())
    }

    /// 解析 KEV JSON 字符串（用于测试和离线场景）
    pub fn parse_catalog(json: &str) -> Result<KevCatalog, VulnDbError> {
        serde_json::from_str(json).map_err(|e| VulnDbError::JsonError(e.to_string()))
    }
}

/// 解析 CISA KEV 日期格式 (YYYY-MM-DD)
fn parse_kev_date(s: &str) -> Option<DateTime<Utc>> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEV_JSON: &str = r#"{
        "title": "Known Exploited Vulnerabilities Catalog",
        "catalog_version": "2024-01-15",
        "date_released": "2024-01-15",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j2 JNDI Features Remote Code Execution",
                "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
                "requiredAction": "Apply updates per vendor instructions.",
                "knownRansomwareCampaignUse": "Known",
                "dateAdded": "2021-12-11",
                "dueDate": "2021-12-24",
                "notes": ""
            },
            {
                "cveID": "CVE-2023-23397",
                "vendorProject": "Microsoft",
                "product": "Outlook",
                "vulnerabilityName": "Microsoft Outlook Elevation of Privilege Vulnerability",
                "shortDescription": "Microsoft Outlook contains an elevation of privilege vulnerability.",
                "requiredAction": "Apply updates per vendor instructions.",
                "knownRansomwareCampaignUse": "Known",
                "dateAdded": "2023-03-14",
                "dueDate": "2023-04-11",
                "notes": ""
            }
        ]
    }"#;

    #[test]
    fn test_parse_catalog() {
        let catalog = KevImporter::parse_catalog(SAMPLE_KEV_JSON).unwrap();
        assert_eq!(catalog.catalog_version, "2024-01-15");
        assert_eq!(catalog.count, 2);
        assert_eq!(catalog.vulnerabilities.len(), 2);
    }

    #[test]
    fn test_parse_kev_vulnerability() {
        let catalog = KevImporter::parse_catalog(SAMPLE_KEV_JSON).unwrap();
        let vuln = &catalog.vulnerabilities[0];
        assert_eq!(vuln.cve_id, "CVE-2021-44228");
        assert_eq!(vuln.vendor_project, "Apache");
        assert_eq!(vuln.product, "Log4j");
        assert_eq!(vuln.required_action, "Apply updates per vendor instructions.");
        assert_eq!(vuln.known_ransomware, "Known");
        assert_eq!(vuln.date_added, "2021-12-11");
    }

    #[test]
    fn test_parse_kev_date() {
        let dt = parse_kev_date("2024-01-15");
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn test_parse_kev_date_invalid() {
        assert!(parse_kev_date("invalid").is_none());
        assert!(parse_kev_date("").is_none());
    }

    #[test]
    fn test_parse_catalog_invalid_json() {
        assert!(KevImporter::parse_catalog("invalid json").is_err());
    }

    #[test]
    fn test_parse_catalog_missing_fields() {
        let json = r#"{"title": "test", "vulnerabilities": []}"#;
        let catalog = KevImporter::parse_catalog(json).unwrap();
        assert_eq!(catalog.vulnerabilities.len(), 0);
    }
}
