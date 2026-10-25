//! 工控设备指纹实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 工控设备模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ics_devices")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub task_id: String,
    #[sea_orm(string)]
    pub host: String,
    pub port: i32,
    #[sea_orm(string)]
    pub protocol: String,                   // modbus / s7 / iec104
    #[sea_orm(string, nullable)]
    pub vendor: Option<String>,
    #[sea_orm(string, nullable)]
    pub model: Option<String>,
    #[sea_orm(string, nullable)]
    pub firmware: Option<String>,
    #[sea_orm(string, nullable)]
    pub device_type: Option<String>,         // PLC / RTU / HMI
    #[sea_orm(column_type = "Json", nullable)]
    pub raw_response: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
