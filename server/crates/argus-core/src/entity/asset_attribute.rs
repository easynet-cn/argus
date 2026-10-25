//! 资产属性实体（sea-orm）- 标签/业务系统/资产类型统一管理

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 属性类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AttrType {
    #[sea_orm(string_value = "tag")]
    Tag,
    #[sea_orm(string_value = "business_system")]
    BusinessSystem,
    #[sea_orm(string_value = "asset_type")]
    AssetType,
}

/// 资产属性模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "asset_attributes")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub attr_type: AttrType,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
