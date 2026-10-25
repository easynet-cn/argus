//! 凭证实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 协议类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum Protocol {
    #[sea_orm(string_value = "ssh")]
    Ssh,
    #[sea_orm(string_value = "telnet")]
    Telnet,
    #[sea_orm(string_value = "smb")]
    Smb,
    #[sea_orm(string_value = "rdp")]
    Rdp,
    #[sea_orm(string_value = "http")]
    Http,
    #[sea_orm(string_value = "winrm")]
    Winrm,
    #[sea_orm(string_value = "pop")]
    Pop,
    #[sea_orm(string_value = "ftp")]
    Ftp,
    #[sea_orm(string_value = "snmp")]
    Snmp,
}

/// 认证方式
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AuthType {
    #[sea_orm(string_value = "password")]
    Password,
    #[sea_orm(string_value = "key")]
    Key,
}

/// 认证结果
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum AuthResult {
    #[sea_orm(string_value = "success")]
    Success,
    #[sea_orm(string_value = "failed")]
    Failed,
    #[sea_orm(string_value = "unknown")]
    Unknown,
}

/// 凭证模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub ip: String,
    pub protocol: Protocol,
    pub port: i32,
    pub auth_type: AuthType,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_username: Option<String>,
    pub enable_password: Option<String>,
    pub web_url: Option<String>,
    pub api_key: Option<String>,
    pub encoding: Option<String>,
    pub auth_result: Option<AuthResult>,
    pub last_auth_at: Option<chrono::DateTime<chrono::Utc>>,
    #[sea_orm(string, nullable)]
    pub asset_id: Option<String>,          // 绑定的资产 ID
    #[sea_orm(string, nullable)]
    pub asset_type: Option<String>,        // network / application / database
    #[sea_orm(column_type = "Text", nullable)]
    pub error_reason: Option<String>,      // 认证失败原因
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
