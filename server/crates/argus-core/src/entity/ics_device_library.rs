//! 工控设备信息库实体（sea-orm）
//!
//! 可维护的工控设备指纹知识库，用于工控扫描时的设备识别匹配。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 工控设备信息库模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ics_device_library")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 设备厂商
    pub vendor: String,
    /// 设备型号
    pub model: String,
    /// 设备类型（PLC/RTU/HMI/DCS/SCADA/网关/其他）
    pub device_type: String,
    /// 通信协议（modbus/s7/iec104/profinet/opcua/melsec/fins等）
    pub protocol: String,
    /// 默认端口
    pub default_port: i32,
    /// 固件版本
    #[sea_orm(nullable)]
    pub firmware: Option<String>,
    /// 操作系统
    #[sea_orm(nullable)]
    pub os: Option<String>,
    /// 已知漏洞 CVE 列表
    #[sea_orm(column_type = "Json", nullable)]
    pub known_cves: Option<serde_json::Value>,
    /// 指纹特征（Banner/响应特征）
    #[sea_orm(column_type = "Text", nullable)]
    pub fingerprint: Option<String>,
    /// 设备描述
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 是否内置
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
