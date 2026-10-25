//! IP 锁定实体（sea-orm）
//!
//! 记录按 IP 维度的登录失败计数和锁定状态，用于防暴力破解。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// IP 锁定模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_lockouts")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    /// 被锁定的 IP
    #[sea_orm(string)]
    pub ip: String,
    /// 连续失败次数
    #[sea_orm(default_value = 0)]
    pub failed_attempts: i32,
    /// 锁定截止时间（null=未锁定）
    #[sea_orm(nullable)]
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    /// 最后失败时间
    #[sea_orm(nullable)]
    pub last_failed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
