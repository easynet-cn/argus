//! 参数模板实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "param_templates")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub scan_type: String,
    #[sea_orm(column_type = "Json")]
    pub config: serde_json::Value,
    pub is_builtin: bool,
    pub is_default: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
