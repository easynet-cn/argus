//! 配置变更记录实体（sea-orm）
//!
//! 记录网络设备、主机、数据库等资产的配置变更历史，
//! 支持变更审计与风险追溯。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 变更类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum ChangeType {
    #[sea_orm(string_value = "network_config")]
    NetworkConfig,     // 网络配置（IP、路由、ACL 等）
    #[sea_orm(string_value = "system_config")]
    SystemConfig,      // 系统配置（OS 参数、服务等）
    #[sea_orm(string_value = "security_config")]
    SecurityConfig,    // 安全配置（防火墙、策略等）
    #[sea_orm(string_value = "account")]
    Account,           // 账号变更
    #[sea_orm(string_value = "config_file")]
    ConfigFile,        // 配置文件变更
    #[sea_orm(string_value = "software")]
    Software,          // 软件安装/卸载
    #[sea_orm(string_value = "other")]
    Other,
}

/// 变更操作类别
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ChangeCategory {
    #[sea_orm(string_value = "add")]
    Add,
    #[sea_orm(string_value = "modify")]
    Modify,
    #[sea_orm(string_value = "delete")]
    Delete,
}

/// 变更来源
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum ChangeSource {
    #[sea_orm(string_value = "auto")]
    Auto,       // 自动采集发现
    #[sea_orm(string_value = "manual")]
    Manual,     // 人工录入
    #[sea_orm(string_value = "scan")]
    Scan,       // 扫描任务发现
    #[sea_orm(string_value = "import")]
    Import,     // 批量导入
}

/// 风险等级
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum RiskLevel {
    #[sea_orm(string_value = "low")]
    Low,
    #[sea_orm(string_value = "medium")]
    Medium,
    #[sea_orm(string_value = "high")]
    High,
    #[sea_orm(string_value = "critical")]
    Critical,
}

/// 配置变更记录模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "config_changes")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub asset_id: String,
    pub asset_type: String,                       // network / application / database
    pub change_type: ChangeType,
    pub change_category: ChangeCategory,
    pub item_name: String,                        // 变更项名称
    #[sea_orm(column_type = "Text", nullable)]
    pub old_value: Option<String>,                // 变更前值
    #[sea_orm(column_type = "Text", nullable)]
    pub new_value: Option<String>,                // 变更后值
    pub change_time: chrono::DateTime<chrono::Utc>,
    #[sea_orm(string, nullable)]
    pub operator: Option<String>,                 // 操作人
    pub source: ChangeSource,
    pub risk_level: RiskLevel,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
