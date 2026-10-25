//! 审计日志实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 审计日志模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub username: String,
    #[sea_orm(string, nullable)]
    pub login_ip: Option<String>,
    #[sea_orm(string)]
    pub log_type: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(string, default_value = "success")]
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
