//! 扫描结果实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 结果类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum ResultType {
    #[sea_orm(string_value = "port_scan")]
    PortScan,
    #[sea_orm(string_value = "bruteforce")]
    Bruteforce,
    #[sea_orm(string_value = "baseline_check")]
    BaselineCheck,
    #[sea_orm(string_value = "fingerprint")]
    Fingerprint,
    #[sea_orm(string_value = "vuln_detect")]
    VulnDetect,
    #[sea_orm(string_value = "ics_scan")]
    IcsScan,
    #[sea_orm(string_value = "cpe_match")]
    CpeMatch,
}

/// 扫描结果模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_results")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub task_id: String,
    pub result_type: ResultType,
    pub host: String,
    pub port: Option<i32>,
    #[sea_orm(string, nullable)]
    pub protocol: Option<String>,
    #[sea_orm(string, nullable)]
    pub state: Option<String>,
    #[sea_orm(string, nullable)]
    pub service: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub banner: Option<String>,
    #[sea_orm(string, nullable)]
    pub username: Option<String>,
    #[sea_orm(string, nullable)]
    pub password: Option<String>,
    pub success: Option<bool>,
    pub response_time_ms: Option<i64>,
    #[sea_orm(column_type = "Json", nullable)]
    pub raw_data: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
