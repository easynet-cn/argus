//! 告警配置实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 告警配置模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "alert_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    #[sea_orm(string)]
    pub channel: String,
    pub enabled: bool,
    #[sea_orm(column_type = "Json", default_value = "{}")]
    pub config: serde_json::Value,
    #[sea_orm(column_type = "Json", default_value = "{}")]
    pub rules: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
