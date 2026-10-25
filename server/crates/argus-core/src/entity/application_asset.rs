//! 应用资产实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use super::network_asset::AssetStatus;

/// 应用资产模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "application_assets")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub url: String,
    pub title: Option<String>,
    pub server_arch: Option<String>,
    pub status: AssetStatus,
    pub risk_score: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    // 阶段8 扩展字段
    pub page_encoding: Option<String>,
    pub os: Option<String>,
    pub cert_type: Option<String>,
    pub cert_id: Option<String>,
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub ip: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub trusted_device: bool,
    pub asset_type: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    pub auto_fetch: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
