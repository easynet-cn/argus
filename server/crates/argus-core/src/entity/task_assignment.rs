//! 任务分发记录实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 分发状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AssignmentStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "dispatched")]
    Dispatched,
    #[sea_orm(string_value = "running")]
    Running,
    #[sea_orm(string_value = "completed")]
    Completed,
    #[sea_orm(string_value = "failed")]
    Failed,
}

/// 任务分发模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "task_assignments")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub task_id: String,
    #[sea_orm(string)]
    pub node_id: String,
    #[sea_orm(string)]
    pub engine: String,                      // port_scanner / fingerprint_scanner / ...
    #[sea_orm(column_type = "Json")]
    pub config: serde_json::Value,
    #[sea_orm(string, default_value = "pending")]
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub dispatched_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[sea_orm(column_type = "Json", nullable)]
    pub result: Option<serde_json::Value>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
