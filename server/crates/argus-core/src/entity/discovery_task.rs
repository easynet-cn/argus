//! 资产发现任务实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 发现类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum DiscoveryType {
    #[sea_orm(string_value = "ip")]
    Ip,
    #[sea_orm(string_value = "subdomain")]
    Subdomain,
    #[sea_orm(string_value = "traffic")]
    Traffic,
}

/// 发现任务状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum DiscoveryStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "running")]
    Running,
    #[sea_orm(string_value = "completed")]
    Completed,
    #[sea_orm(string_value = "failed")]
    Failed,
}

/// 资产发现任务模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "discovery_tasks")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub discovery_type: DiscoveryType,
    pub status: DiscoveryStatus,
    pub targets: String,
    #[sea_orm(column_type = "Json")]
    pub config: serde_json::Value,
    #[sea_orm(column_type = "Json", nullable)]
    pub result: Option<serde_json::Value>,
    pub gateway: Option<String>,
    pub scan_mode: Option<String>,
    pub exclude_hosts: Option<String>,
    pub threads: Option<i32>,
    pub brute_level: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
