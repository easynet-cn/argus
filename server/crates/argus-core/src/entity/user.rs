//! 用户实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 用户角色
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum UserRole {
    #[sea_orm(string_value = "admin")]
    Admin,
    #[sea_orm(string_value = "auditor")]
    Auditor,
    #[sea_orm(string_value = "viewer")]
    Viewer,
}

/// 用户状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum UserStatus {
    #[sea_orm(string_value = "active")]
    Active,
    #[sea_orm(string_value = "disabled")]
    Disabled,
}

/// 用户模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub username: String,
    #[sea_orm(column_type = "Text")]
    pub password_hash: String,
    #[sea_orm(nullable)]
    pub email: Option<String>,
    pub role: UserRole,
    pub status: UserStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,

    // 阶段8 第三批新增字段
    #[sea_orm(string, nullable)]
    pub role_id: Option<String>,
    #[sea_orm(string, nullable)]
    pub organization: Option<String>,
    #[sea_orm(string, nullable)]
    pub phone: Option<String>,
    // 补齐：真实姓名与用户来源
    #[sea_orm(string, nullable)]
    pub real_name: Option<String>,           // 真实姓名
    #[sea_orm(string, default_value = "local")]
    pub source: String,                      // 用户来源：local/ldap/oauth
    #[sea_orm(nullable)]
    pub expire_at: Option<chrono::DateTime<chrono::Utc>>,
    #[sea_orm(default_value = false)]
    pub first_login_change: bool,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub scan_target_whitelist: serde_json::Value,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub scan_target_blacklist: serde_json::Value,
    #[sea_orm(default_value = 0)]
    pub max_scan_ips: i32,
    #[sea_orm(default_value = 0)]
    pub max_scan_domains: i32,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub login_ip_whitelist: serde_json::Value,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub login_ip_blacklist: serde_json::Value,
    #[sea_orm(default_value = 0)]
    pub failed_attempts: i32,
    #[sea_orm(nullable)]
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    // 双因素认证
    #[sea_orm(string, nullable)]
    pub totp_secret: Option<String>,
    #[sea_orm(default_value = false)]
    pub totp_enabled: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
