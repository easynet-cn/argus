//! CVE 漏洞知识库实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// CVE 记录模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "cves")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,                          // CVE-2024-1234
    #[sea_orm(string, default_value = "NVD")]
    pub source: String,                      // NVD/CNVD/CNNVD
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub cvss_v2: Option<f64>,
    pub cvss_v3: Option<f64>,
    #[sea_orm(string, nullable)]
    pub cvss_vector: Option<String>,
    #[sea_orm(string, nullable)]
    pub severity: Option<String>,            // CRITICAL/HIGH/MEDIUM/LOW
    pub published: Option<chrono::DateTime<chrono::Utc>>,
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub references: serde_json::Value,       // JSON array of URLs
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub cpe_configurations: serde_json::Value, // JSON array of CPE configs
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
