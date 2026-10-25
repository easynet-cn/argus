//! 分布式扫描节点实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 节点状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum NodeStatus {
    #[sea_orm(string_value = "online")]
    Online,
    #[sea_orm(string_value = "offline")]
    Offline,
    #[sea_orm(string_value = "busy")]
    Busy,
    #[sea_orm(string_value = "decommissioned")]
    Decommissioned,
}

/// 扫描节点模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_nodes")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    #[sea_orm(string)]
    pub name: String,
    #[sea_orm(string)]
    pub endpoint: String,                    // http://node-1:8090
    #[sea_orm(string, nullable)]
    pub region: Option<String>,
    #[sea_orm(string, default_value = "offline")]
    pub status: String,
    #[sea_orm(column_type = "Json", default_value = "[]")]
    pub capabilities: serde_json::Value,      // ["port_scan","fingerprint",...]
    #[sea_orm(default_value = 4)]
    pub max_concurrent: i32,
    #[sea_orm(default_value = 0)]
    pub current_load: i32,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    #[sea_orm(column_type = "Json", nullable)]
    pub metadata: Option<serde_json::Value>,
    // ===== 阶段8 第四批：分布式探针增强 =====
    /// 父节点 ID（上级节点，用于拓扑树）
    #[sea_orm(string, nullable)]
    pub parent_id: Option<String>,
    /// 所属组织
    #[sea_orm(string, nullable)]
    pub organization: Option<String>,
    /// 节点认证 Token
    #[sea_orm(column_type = "Text", nullable)]
    pub token: Option<String>,
    /// 免密登录跳转 URL
    #[sea_orm(string, nullable)]
    pub login_url: Option<String>,
    /// Docker 节点 ID
    #[sea_orm(string, nullable)]
    pub docker_node_id: Option<String>,
    /// CPU 使用率（0-100）
    #[sea_orm(column_type = "Double", nullable)]
    pub cpu_usage: Option<f64>,
    /// 内存使用率（0-100）
    #[sea_orm(column_type = "Double", nullable)]
    pub memory_usage: Option<f64>,
    /// 硬盘使用率（0-100）
    #[sea_orm(column_type = "Double", nullable)]
    pub disk_usage: Option<f64>,
    /// 系统版本
    #[sea_orm(string, nullable)]
    pub system_version: Option<String>,
    /// 规则版本
    #[sea_orm(string, nullable)]
    pub rule_version: Option<String>,
    /// 最后心跳时间
    pub last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
