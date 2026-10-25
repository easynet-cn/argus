//! 弱密码实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 弱密码模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "weak_passwords")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string, nullable)]
    pub task_id: Option<String>,
    #[sea_orm(string)]
    pub host: String,
    #[sea_orm(string)]
    pub protocol: String,
    pub port: i32,
    #[sea_orm(string)]
    pub username: String,
    #[sea_orm(string)]
    pub password: String,
    #[sea_orm(string, default_value = "new")]
    pub risk_status: String,
    pub first_found: chrono::DateTime<chrono::Utc>,
    pub last_found: chrono::DateTime<chrono::Utc>,
    /// 关联资产组 ID（可选，扫描时关联）
    #[sea_orm(string, nullable)]
    pub asset_group_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
