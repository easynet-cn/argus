//! 端口违规配置规则实体（sea-orm）
//!
//! 违规配置子模块（端口标签特征管理）。
//! 定义哪些端口/服务的开放属于违规，扫描结果比对规则后输出违规清单。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "port_violation_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 规则名称，如 "违规开放 Telnet 服务"
    pub name: String,
    /// 端口号（0 表示匹配任意端口，配合 service_name 使用）
    pub port: i32,
    /// 传输层协议：tcp / udp
    pub protocol: String,
    /// 关联服务名（可选，为空则按端口匹配）
    pub service_name: Option<String>,
    /// 风险等级：low / medium / high / critical
    pub risk_level: String,
    /// 违规说明
    pub description: Option<String>,
    /// 修复建议
    pub remediation: Option<String>,
    /// 是否内置规则
    pub is_builtin: bool,
    /// 是否启用
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
