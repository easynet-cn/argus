//! 字典实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 字典类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(30))")]
pub enum DictType {
    #[sea_orm(string_value = "username")]
    Username,
    #[sea_orm(string_value = "password")]
    Password,
    #[sea_orm(string_value = "subdomain")]
    Subdomain,
    #[sea_orm(string_value = "sensitive_dir")]
    SensitiveDir,
    #[sea_orm(string_value = "sensitive_keyword")]
    SensitiveKeyword,
}

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dictionaries")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub dict_type: DictType,
    pub content: String,
    pub filename: Option<String>,
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
