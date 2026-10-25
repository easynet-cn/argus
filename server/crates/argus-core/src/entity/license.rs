//! 许可证实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 许可证模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "licenses")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// 许可证密钥
    pub license_key: String,
    /// 客户名称
    pub customer: String,
    /// 产品标识
    pub product: String,
    /// 版本：community / enterprise / ultimate
    pub edition: String,
    /// 最大节点数
    pub max_nodes: i32,
    /// 最大资产数
    pub max_assets: i32,
    /// 功能特性（JSON 数组）
    #[sea_orm(column_type = "Json")]
    pub features: serde_json::Value,
    /// 签发时间
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// 过期时间
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 状态：active / expired / revoked
    pub status: String,
    /// 签名（HMAC）
    pub signature: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
