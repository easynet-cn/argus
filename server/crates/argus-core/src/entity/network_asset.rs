//! 网络资产实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 资产类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AssetType {
    #[sea_orm(string_value = "network")]
    Network,
    #[sea_orm(string_value = "application")]
    Application,
    #[sea_orm(string_value = "database")]
    Database,
}

/// 资产状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AssetStatus {
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "inactive")]
    Inactive,
    #[sea_orm(string_value = "unknown")]
    Unknown,
}

/// 网络资产模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "network_assets")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub ip: String,
    pub mac: Option<String>,
    pub os: Option<String>,
    pub asset_type: AssetType,
    pub status: AssetStatus,
    pub risk_score: f64,
    #[sea_orm(column_type = "Json")]
    pub tags: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // 阶段8 扩展字段
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub network_zone: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub is_industrial: bool,
    pub industrial_vendor: Option<String>,
    pub industrial_model: Option<String>,
    pub industrial_version: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub trusted_device: bool,
    pub industrial_device_type: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
