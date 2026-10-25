//! CVE 批量导入逻辑

use crate::error::VulnDbError;
use crate::nvd_client::NvdClient;
use crate::types::{ImportStats, ImportProgress};
use crate::cpe_parser::parse_cpe_uri;
use chrono::{TimeZone, Utc};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use argus_core::entity::{cve as cves, cpe as cpes, cve_cpe};
use tokio::sync::mpsc;

pub struct CveImporter {
    db: DatabaseConnection,
    client: NvdClient,
}

impl CveImporter {
    pub fn new(db: DatabaseConnection, client: NvdClient) -> Self {
        Self { db, client }
    }

    pub async fn import_all(
        &self, start_year: u16, end_year: u16,
        progress_tx: Option<mpsc::Sender<ImportProgress>>,
    ) -> Result<ImportStats, VulnDbError> {
        let start_time = std::time::Instant::now();
        let mut stats = ImportStats { start_year, end_year, ..Default::default() };

        for year in start_year..=end_year {
            let pub_start = Utc.with_ymd_and_hms(year as i32, 1, 1, 0, 0, 0).unwrap();
            let pub_end = Utc.with_ymd_and_hms(year as i32, 12, 31, 23, 59, 59).unwrap();
            let mut start_index = 0i64;
            
            loop {
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(ImportProgress {
                        task_id: uuid::Uuid::new_v4().to_string(),
                        current_year: year,
                        current_page: start_index / 2000,
                        total_processed: stats.total_cves,
                        status: "running".to_string(),
                        error: None,
                    }).await;
                }

                let resp = self.client.fetch_page(start_index, Some(pub_start), Some(pub_end)).await?;
                let page_size = resp.vulnerabilities.len();
                
                for item in &resp.vulnerabilities {
                    match self.save_cve(item).await {
                        Ok(true) => { stats.new_cves += 1; stats.total_cves += 1; }
                        Ok(false) => { stats.updated_cves += 1; stats.total_cves += 1; }
                        Err(e) => tracing::warn!("保存 CVE {} 失败: {}", item.cve.id, e),
                    }
                    if let Ok(cpes_list) = self.extract_cpes(item).await {
                        stats.total_cpes += cpes_list.len();
                    }
                }

                start_index += page_size as i64;
                if start_index >= resp.total_results || page_size == 0 { break; }
            }
            tracing::info!("{} 年完成: {} 条 CVE", year, stats.total_cves);
        }

        stats.elapsed_secs = start_time.elapsed().as_secs_f64();
        Ok(stats)
    }

    async fn save_cve(&self, item: &crate::types::NvdCveItem) -> Result<bool, VulnDbError> {
        let cve = &item.cve;
        let description = cve.descriptions.iter()
            .find(|d| d.lang == "en").map(|d| d.value.clone()).unwrap_or_default();
        let (cvss_v2, cvss_v3, cvss_vector, severity) = extract_cvss(cve);
        let published = parse_nvd_time(&cve.published);
        let last_modified = parse_nvd_time(&cve.last_modified);
        let references: serde_json::Value = serde_json::to_value(
            cve.references.iter().map(|r| &r.url).collect::<Vec<_>>()
        )?;
        let cpe_configs: serde_json::Value = serde_json::to_value(&cve.configurations)?;
        let existing = cves::Entity::find_by_id(cve.id.clone()).one(&self.db).await?;
        let is_new = existing.is_none();
        
        let active_model = cves::ActiveModel {
            id: Set(cve.id.clone()),
            source: Set("NVD".to_string()),
            description: Set(description),
            cvss_v2: Set(cvss_v2),
            cvss_v3: Set(cvss_v3),
            cvss_vector: Set(cvss_vector),
            severity: Set(severity),
            published: Set(published),
            last_modified: Set(last_modified),
            references: Set(references),
            cpe_configurations: Set(cpe_configs),
        };
        
        // 使用 insert 或 update
        if is_new {
            cves::Entity::insert(active_model).exec(&self.db).await?;
        } else {
            cves::Entity::update(active_model).exec(&self.db).await?;
        }
        Ok(is_new)
    }

    async fn extract_cpes(&self, item: &crate::types::NvdCveItem) -> Result<Vec<String>, VulnDbError> {
        let mut cpe_uris = Vec::new();
        for config in &item.cve.configurations {
            for node in &config.nodes {
                for match_item in &node.cpeMatch {
                    let cpe_uri = &match_item.criteria;
                    cpe_uris.push(cpe_uri.clone());
                    if let Ok(entry) = parse_cpe_uri(cpe_uri) {
                        let cpe_id = format!("{}_{}_{}_{}", entry.part, entry.vendor, entry.product, entry.version);
                        let _ = cpes::Entity::insert(cpes::ActiveModel {
                            id: Set(cpe_id),
                            cpe_uri: Set(cpe_uri.clone()),
                            part: Set(entry.part),
                            vendor: Set(entry.vendor),
                            product: Set(entry.product),
                            version: Set(entry.version),
                            target_sw: Set(entry.target_sw),
                            language: Set(entry.language),
                            title: Set(None),
                        }).exec(&self.db).await;
                    }
                    let _ = cve_cpe::Entity::insert(cve_cpe::ActiveModel {
                        id: Set(uuid::Uuid::new_v4()),
                        cve_id: Set(item.cve.id.clone()),
                        cpe_uri: Set(cpe_uri.clone()),
                        vulnerable: Set(match_item.vulnerable),
                        version_end_excluding: Set(match_item.version_end_excluding.clone()),
                        version_end_including: Set(match_item.version_end_including.clone()),
                        version_start_excluding: Set(match_item.version_start_excluding.clone()),
                        version_start_including: Set(match_item.version_start_including.clone()),
                    }).exec(&self.db).await;
                }
            }
        }
        Ok(cpe_uris)
    }
}

fn extract_cvss(cve: &crate::types::NvdCve) -> (Option<f64>, Option<f64>, Option<String>, Option<String>) {
    let cvss_v3 = cve.metrics.cvss_v31.first()
        .or_else(|| cve.metrics.cvss_v30.first())
        .map(|m| m.cvss_data.base_score);
    let cvss_v2 = cve.metrics.cvss_v2.first()
        .map(|m| m.cvss_data.base_score);
    let cvss_vector = cve.metrics.cvss_v31.first()
        .or_else(|| cve.metrics.cvss_v30.first())
        .map(|m| m.cvss_data.vector_string.clone());
    let severity = cve.metrics.cvss_v31.first()
        .or_else(|| cve.metrics.cvss_v30.first())
        .and_then(|m| m.base_severity.clone())
        .or_else(|| cvss_v3.and_then(|s| match s {
            s if s >= 9.0 => Some("CRITICAL".to_string()),
            s if s >= 7.0 => Some("HIGH".to_string()),
            s if s >= 4.0 => Some("MEDIUM".to_string()),
            _ => Some("LOW".to_string()),
        }));
    (cvss_v2, cvss_v3, cvss_vector, severity)
}

fn parse_nvd_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
}
