//! 用户会话实体（sea-orm）
//!
//! 记录每次登录的会话信息，用于会话管理和强制下线。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 用户会话模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    #[sea_orm(string)]
    pub user_id: String,
    #[sea_orm(string)]
    pub username: String,
    /// JWT ID（与 JWT Claims.jti 对应，用于强制下线）
    #[sea_orm(string)]
    pub jti: String,
    /// 登录 IP
    #[sea_orm(string, nullable)]
    pub login_ip: Option<String>,
    /// User-Agent
    #[sea_orm(string, nullable)]
    pub user_agent: Option<String>,
    /// 登录时间
    pub login_at: chrono::DateTime<chrono::Utc>,
    /// 最后活跃时间
    pub last_active_at: chrono::DateTime<chrono::Utc>,
    /// 过期时间（与 JWT exp 一致）
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// 会话是否活跃（false=已下线）
    #[sea_orm(default_value = true)]
    pub is_active: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
