//! API Key 实体（sea-orm）
//!
//! APIKey 设置。
//! 用于外部系统集成认证，支持权限范围限制和过期时间。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// Key 名称/描述
    pub name: String,
    /// Key 前缀（用于识别，如 "ak-ab12..."）
    pub key_prefix: String,
    /// Key 的 SHA-256 哈希（不存储明文）
    pub key_hash: String,
    /// 关联用户 ID
    pub user_id: String,
    /// 权限范围（JSON 数组，如 ["scan:read", "asset:write", "*"]）
    #[sea_orm(column_type = "Json", default_value = "[\"*\"]")]
    pub scopes: serde_json::Value,
    /// 过期时间（None 表示永不过期）
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 最后使用时间
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// 是否启用
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
