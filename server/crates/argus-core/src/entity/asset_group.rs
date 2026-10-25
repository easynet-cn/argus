//! 资产组实体（sea-orm）- 树形结构

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 资产组模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "asset_groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub ip_range: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub location: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
