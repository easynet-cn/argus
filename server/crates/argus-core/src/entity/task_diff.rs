//! 扫描任务对比结果实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 任务对比模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_task_diffs")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub task_id_a: String,
    #[sea_orm(string)]
    pub task_id_b: String,
    #[sea_orm(default_value = 0)]
    pub new_count: i32,
    #[sea_orm(default_value = 0)]
    pub fixed_count: i32,
    #[sea_orm(default_value = 0)]
    pub persistent_count: i32,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub new_findings: serde_json::Value,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub fixed_findings: serde_json::Value,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub persistent_findings: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
