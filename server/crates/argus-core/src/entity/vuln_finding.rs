//! 漏洞实例实体（sea-orm）—— 每次扫描命中的具体漏洞

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 漏洞来源
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum FindingSource {
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "cpe_match")]
    CpeMatch,
    #[sea_orm(string_value = "fingerprint")]
    Fingerprint,
}

/// 漏洞实例模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vuln_findings")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub task_id: String,
    #[sea_orm(string, nullable)]
    pub template_id: Option<String>,         // 自研模板 ID
    #[sea_orm(string, nullable)]
    pub cve_id: Option<String>,              // CVE ID
    #[sea_orm(string)]
    pub target_host: String,
    #[sea_orm(string, nullable)]
    pub target_port: Option<i32>,
    #[sea_orm(string, nullable)]
    pub target_service: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub target_cpe: Option<String>,
    #[sea_orm(string, nullable)]
    pub title: Option<String>,           // 漏洞标题
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,     // 漏洞描述
    #[sea_orm(string, nullable)]
    pub vuln_type: Option<String>,       // 漏洞类型：SQL注入/XSS/弱口令/配置错误等
    pub cvss2: Option<f64>,              // CVSS v2 评分
    pub cvss3: Option<f64>,              // CVSS v3 评分
    #[sea_orm(string)]
    pub severity: String,
    pub cvss: Option<f64>,
    #[sea_orm(string, default_value = "active")]
    pub source: String,                      // active / cpe_match / fingerprint
    #[sea_orm(string, default_value = "new")]
    pub status: String,
    #[sea_orm(string, default_value = "new")]
    pub risk_status: String,            // new/processing/deferred/fixed/verified/closed/false_positive/ignored/reopened
    #[sea_orm(string, default_value = "system")]
    pub risk_type: String,              // system/application/database/config
    #[sea_orm(string, nullable)]
    pub assigned_to: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub remediation_note: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub evidence: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub impact_range: Option<String>,       // 影响范围（受影响的系统/组件/数据/业务）
    #[sea_orm(column_type = "Text", nullable)]
    pub fix_advice: Option<String>,
    // 应用漏洞特有字段
    #[sea_orm(string, nullable)]
    pub request_method: Option<String>,    // HTTP 请求方法：GET/POST/PUT/DELETE
    #[sea_orm(column_type = "Text", nullable)]
    pub request_url: Option<String>,       // 漏洞 URL
    #[sea_orm(string, nullable)]
    pub request_params: Option<String>,    // 请求参数
    #[sea_orm(column_type = "Text", nullable)]
    pub payload: Option<String>,           // 攻击 Payload
    // 数据库漏洞特有字段
    #[sea_orm(string, nullable)]
    pub db_instance: Option<String>,       // 数据库实例名
    #[sea_orm(column_type = "Text", nullable)]
    pub sql_statement: Option<String>,     // SQL 语句
    pub first_found: chrono::DateTime<chrono::Utc>,
    pub last_found: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
