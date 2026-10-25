//! 协议/服务风险等级实体（sea-orm）
//!
//! 协议/服务风险等级子模块。
//! 预定义常见网络服务的风险等级，作为端口违规配置和风险评分的基础库。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "service_risk_levels")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 服务/协议名称，如 SSH/Telnet/FTP/MySQL/Redis
    pub service_name: String,
    /// 默认端口（部分服务无固定端口时为 None）
    pub default_port: Option<i32>,
    /// 传输层协议：tcp / udp
    pub protocol: String,
    /// 风险等级：low / medium / high / critical
    pub risk_level: String,
    /// 风险说明
    pub description: Option<String>,
    /// 是否内置规则
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
