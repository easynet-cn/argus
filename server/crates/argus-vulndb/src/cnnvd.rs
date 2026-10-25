//! CNNVD (国家信息安全漏洞库) 导入器
//!
//! CNNVD 无公开 REST API，本模块通过本地 JSON 数据文件接入。
//! 数据文件可由 CNNVD 官网公开数据整理生成，或人工补充国产软件漏洞信息。
//!
//! 数据文件格式 (JSON 数组):
//! ```json
//! [
//!   {
//!     "cnnvd_id": "CNNVD-202401-001",
//!     "cve_id": "CVE-2024-1234",
//!     "title": "Apache Log4j 代码注入漏洞",
//!     "description": "中文描述...",
//!     "severity": "高危",
//!     "publish_time": "2024-01-01"
//!   }
//! ]
//! ```

use crate::error::VulnDbError;
use crate::types::CnnvdStats;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use argus_core::entity::cve as cves;
use std::path::Path;

/// CNNVD 条目
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CnnvdEntry {
    /// CNNVD 编号，如 CNNVD-202401-001
    pub cnnvd_id: String,
    /// 关联的 CVE 编号（可选，部分 CNNVD 条目无对应 CVE）
    #[serde(default)]
    pub cve_id: Option<String>,
    /// 漏洞标题（中文）
    pub title: String,
    /// 漏洞描述（中文）
    #[serde(default)]
    pub description: String,
    /// 危险等级: 严重 / 高危 / 中危 / 低危
    #[serde(default)]
    pub severity: String,
    /// 发布时间 (YYYY-MM-DD)
    #[serde(default)]
    pub publish_time: String,
    /// 厂商
    #[serde(default)]
    pub vendor: String,
    /// 产品
    #[serde(default)]
    pub product: String,
}

/// CNNVD 导入器
pub struct CnnvdImporter {
    db: DatabaseConnection,
}

impl CnnvdImporter {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 从本地 JSON 文件导入 CNNVD 数据
    pub async fn import_from_file(&self, path: &str) -> Result<CnnvdStats, VulnDbError> {
        let start = std::time::Instant::now();
        tracing::info!("加载 CNNVD 数据文件: {}", path);

        let content = std::fs::read_to_string(path)
            .map_err(|e| VulnDbError::Import(format!("读取文件失败: {e}")))?;
        let entries: Vec<CnnvdEntry> = serde_json::from_str(&content)
            .map_err(|e| VulnDbError::JsonError(format!("解析 JSON 失败: {e}")))?;

        tracing::info!("CNNVD 条目数: {}", entries.len());
        self.import_entries(&entries, start.elapsed().as_secs_f64()).await
    }

    /// 从 JSON 字符串导入（用于测试和程序化调用）
    pub async fn import_from_json(&self, json: &str) -> Result<CnnvdStats, VulnDbError> {
        let entries: Vec<CnnvdEntry> = serde_json::from_str(json)
            .map_err(|e| VulnDbError::JsonError(format!("解析 JSON 失败: {e}")))?;
        self.import_entries(&entries, 0.0).await
    }

    /// 从目录批量导入（加载目录下所有 .json 文件）
    pub async fn import_from_dir(&self, dir: &str) -> Result<CnnvdStats, VulnDbError> {
        let start = std::time::Instant::now();
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            return Err(VulnDbError::Import(format!("目录不存在: {dir}")));
        }

        let mut all_entries = Vec::new();
        let mut entries = std::fs::read_dir(dir_path)
            .map_err(|e| VulnDbError::Import(format!("读取目录失败: {e}")))?;

        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|e| VulnDbError::Import(format!("读取目录条目失败: {e}")))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| VulnDbError::Import(format!("读取 {} 失败: {e}", path.display())))?;
                let file_entries: Vec<CnnvdEntry> = serde_json::from_str(&content)
                    .map_err(|e| VulnDbError::JsonError(format!("解析 {} 失败: {e}", path.display())))?;
                all_entries.extend(file_entries);
            }
        }

        tracing::info!("从 {} 加载 {} 条 CNNVD 条目", dir, all_entries.len());
        self.import_entries(&all_entries, start.elapsed().as_secs_f64()).await
    }

    /// 内部: 执行批量导入逻辑
    async fn import_entries(
        &self,
        entries: &[CnnvdEntry],
        load_secs: f64,
    ) -> Result<CnnvdStats, VulnDbError> {
        let start = std::time::Instant::now();
        let mut stats = CnnvdStats {
            total_entries: entries.len(),
            ..Default::default()
        };

        for entry in entries {
            match self.update_cve(entry).await {
                Ok(true) => stats.updated += 1,
                Ok(false) => stats.not_found += 1,
                Err(e) => {
                    tracing::warn!("更新 CNNVD {} 失败: {}", entry.cnnvd_id, e);
                    stats.errors += 1;
                }
            }
        }

        stats.elapsed_secs = load_secs + start.elapsed().as_secs_f64();
        tracing::info!(
            "CNNVD 导入完成: 更新 {} 条，未匹配 {} 条，错误 {} 条，耗时 {:.1}s",
            stats.updated,
            stats.not_found,
            stats.errors,
            stats.elapsed_secs
        );
        Ok(stats)
    }

    /// 用 CNNVD 中文信息更新 CVE 记录
    async fn update_cve(&self, entry: &CnnvdEntry) -> Result<bool, VulnDbError> {
        // 确定主键: 优先用 CVE ID，无 CVE 则用 CNNVD ID
        let record_id = entry.cve_id.clone().unwrap_or_else(|| entry.cnnvd_id.clone());

        let existing = cves::Entity::find_by_id(record_id.clone())
            .one(&self.db)
            .await?;

        let severity_en = map_cnnvd_severity(&entry.severity);
        let published = if !entry.publish_time.is_empty() {
            parse_cnnvd_date(&entry.publish_time)
        } else {
            None
        };
        let cnnvd_ref = serde_json::json!([{
            "type": "cnnvd",
            "url": format!("https://www.cnnvd.org.cn/webinfo/show/{}", entry.cnnvd_id),
            "cnnvd_id": entry.cnnvd_id,
            "title": entry.title,
        }]);

        if existing.is_none() {
            // CVE 不在库中，创建一条 CNNVD 来源的记录
            let active = cves::ActiveModel {
                id: Set(record_id),
                source: Set("CNNVD".to_string()),
                description: Set(if entry.description.is_empty() {
                    entry.title.clone()
                } else {
                    entry.description.clone()
                }),
                cvss_v2: Set(None),
                cvss_v3: Set(None),
                cvss_vector: Set(None),
                severity: Set(severity_en),
                published: Set(published),
                last_modified: Set(published),
                references: Set(cnnvd_ref),
                cpe_configurations: Set(serde_json::json!([])),
            };
            cves::Entity::insert(active).exec(&self.db).await?;
            return Ok(true);
        }

        // CVE 已存在，追加 CNNVD 中文信息到 references
        let model = existing.unwrap();
        let source = if model.source.contains("CNNVD") {
            model.source.clone()
        } else {
            format!("{}+CNNVD", model.source)
        };

        let mut refs = model.references.clone();
        if let Some(arr) = refs.as_array_mut() {
            arr.push(serde_json::json!({
                "type": "cnnvd",
                "url": format!("https://www.cnnvd.org.cn/webinfo/show/{}", entry.cnnvd_id),
                "cnnvd_id": entry.cnnvd_id,
                "title": entry.title,
            }));
        }

        let active = cves::ActiveModel {
            id: Set(record_id),
            source: Set(source),
            description: Set(model.description.clone()),
            cvss_v2: Set(model.cvss_v2),
            cvss_v3: Set(model.cvss_v3),
            cvss_vector: Set(model.cvss_vector.clone()),
            severity: Set(model.severity.clone().or(severity_en)),
            published: Set(model.published),
            last_modified: Set(model.last_modified),
            references: Set(refs),
            cpe_configurations: Set(model.cpe_configurations.clone()),
        };
        cves::Entity::update(active).exec(&self.db).await?;
        Ok(true)
    }

    /// 解析 CNNVD JSON（用于测试）
    pub fn parse_entries(json: &str) -> Result<Vec<CnnvdEntry>, VulnDbError> {
        serde_json::from_str(json).map_err(|e| VulnDbError::JsonError(e.to_string()))
    }
}

/// 将 CNNVD 中文危险等级映射为英文
fn map_cnnvd_severity(sev: &str) -> Option<String> {
    match sev.trim() {
        "严重" | "超危" => Some("CRITICAL".to_string()),
        "高危" => Some("HIGH".to_string()),
        "中危" => Some("MEDIUM".to_string()),
        "低危" => Some("LOW".to_string()),
        "" => None,
        _ => Some(sev.to_uppercase()),
    }
}

/// 解析 CNNVD 日期 (YYYY-MM-DD)
fn parse_cnnvd_date(s: &str) -> Option<DateTime<Utc>> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CNNVD_JSON: &str = r#"[
        {
            "cnnvd_id": "CNNVD-202112-1342",
            "cve_id": "CVE-2021-44228",
            "title": "Apache Log4j2 代码注入漏洞",
            "description": "Apache Log4j2 存在代码注入漏洞，攻击者可利用此漏洞执行任意代码。",
            "severity": "高危",
            "publish_time": "2021-12-10",
            "vendor": "Apache",
            "product": "Log4j2"
        },
        {
            "cnnvd_id": "CNNVD-202303-1234",
            "cve_id": "CVE-2023-23397",
            "title": "Microsoft Outlook 权限提升漏洞",
            "description": "Microsoft Outlook 存在权限提升漏洞。",
            "severity": "严重",
            "publish_time": "2023-03-14",
            "vendor": "Microsoft",
            "product": "Outlook"
        },
        {
            "cnnvd_id": "CNNVD-202401-0001",
            "title": "ThinkPHP 远程代码执行漏洞",
            "description": "ThinkPHP 框架存在远程代码执行漏洞。",
            "severity": "高危",
            "publish_time": "2024-01-05",
            "vendor": "ThinkPHP",
            "product": "ThinkPHP"
        }
    ]"#;

    #[test]
    fn test_parse_entries() {
        let entries = CnnvdImporter::parse_entries(SAMPLE_CNNVD_JSON).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_parse_entry_fields() {
        let entries = CnnvdImporter::parse_entries(SAMPLE_CNNVD_JSON).unwrap();
        let e = &entries[0];
        assert_eq!(e.cnnvd_id, "CNNVD-202112-1342");
        assert_eq!(e.cve_id, Some("CVE-2021-44228".to_string()));
        assert_eq!(e.title, "Apache Log4j2 代码注入漏洞");
        assert_eq!(e.severity, "高危");
        assert_eq!(e.vendor, "Apache");
    }

    #[test]
    fn test_entry_without_cve_id() {
        let entries = CnnvdImporter::parse_entries(SAMPLE_CNNVD_JSON).unwrap();
        let e = &entries[2];
        assert_eq!(e.cve_id, None);
        assert_eq!(e.cnnvd_id, "CNNVD-202401-0001");
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(map_cnnvd_severity("严重"), Some("CRITICAL".to_string()));
        assert_eq!(map_cnnvd_severity("超危"), Some("CRITICAL".to_string()));
        assert_eq!(map_cnnvd_severity("高危"), Some("HIGH".to_string()));
        assert_eq!(map_cnnvd_severity("中危"), Some("MEDIUM".to_string()));
        assert_eq!(map_cnnvd_severity("低危"), Some("LOW".to_string()));
        assert_eq!(map_cnnvd_severity(""), None);
    }

    #[test]
    fn test_parse_cnnvd_date() {
        let dt = parse_cnnvd_date("2024-01-15");
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().format("%Y-%m-%d").to_string(), "2024-01-15");
    }

    #[test]
    fn test_parse_cnnvd_date_invalid() {
        assert!(parse_cnnvd_date("invalid").is_none());
        assert!(parse_cnnvd_date("").is_none());
    }

    #[test]
    fn test_parse_empty_array() {
        let entries = CnnvdImporter::parse_entries("[]").unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        assert!(CnnvdImporter::parse_entries("invalid").is_err());
    }

    #[test]
    fn test_entry_minimal_fields() {
        let json = r#"[{"cnnvd_id": "CNNVD-202401-0002", "title": "测试漏洞"}]"#;
        let entries = CnnvdImporter::parse_entries(json).unwrap();
        assert_eq!(entries[0].cve_id, None);
        assert_eq!(entries[0].description, "");
        assert_eq!(entries[0].severity, "");
    }

    #[test]
    fn test_entry_serialization() {
        let entry = CnnvdEntry {
            cnnvd_id: "CNNVD-202401-0003".to_string(),
            cve_id: Some("CVE-2024-9999".to_string()),
            title: "测试".to_string(),
            description: "描述".to_string(),
            severity: "中危".to_string(),
            publish_time: "2024-01-01".to_string(),
            vendor: "TestVendor".to_string(),
            product: "TestProduct".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: CnnvdEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cnnvd_id, entry.cnnvd_id);
        assert_eq!(parsed.cve_id, entry.cve_id);
    }
}
