//! 告警记录实体（sea-orm）
//!
//! 记录由告警规则触发的实际告警事件，支持确认、关闭等操作。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 告警级别
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum AlertLevel {
    #[sea_orm(string_value = "info")]
    Info,
    #[sea_orm(string_value = "warning")]
    Warning,
    #[sea_orm(string_value = "critical")]
    Critical,
}

/// 告警来源
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum AlertSource {
    #[sea_orm(string_value = "vuln_scan")]
    VulnScan,           // 漏洞扫描发现高危漏洞
    #[sea_orm(string_value = "config_change")]
    ConfigChange,       // 高危配置变更
    #[sea_orm(string_value = "system")]
    System,             // 系统事件
    #[sea_orm(string_value = "asset_discovery")]
    AssetDiscovery,     // 资产发现
    #[sea_orm(string_value = "weak_password")]
    WeakPassword,       // 弱口令发现
    #[sea_orm(string_value = "manual")]
    Manual,             // 手动触发
}

/// 告警状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum AlertStatus {
    #[sea_orm(string_value = "pending")]
    Pending,            // 待处理
    #[sea_orm(string_value = "acknowledged")]
    Acknowledged,       // 已确认
    #[sea_orm(string_value = "resolved")]
    Resolved,           // 已解决
    #[sea_orm(string_value = "ignored")]
    Ignored,            // 已忽略
}

/// 告警记录模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "alert_records")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    #[sea_orm(string, nullable)]
    pub alert_config_id: Option<String>,
    pub title: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub content: Option<String>,
    pub level: AlertLevel,
    pub source: AlertSource,
    #[sea_orm(string, nullable)]
    pub source_id: Option<String>,
    pub status: AlertStatus,
    pub triggered_at: chrono::DateTime<chrono::Utc>,
    #[sea_orm(nullable)]
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    #[sea_orm(string, nullable)]
    pub acknowledged_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
