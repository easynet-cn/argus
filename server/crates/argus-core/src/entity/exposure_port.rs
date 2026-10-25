//! 暴露端口实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 暴露端口模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "exposure_ports")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string, nullable)]
    pub task_id: Option<String>,
    #[sea_orm(string)]
    pub host: String,
    pub port: i32,
    #[sea_orm(string, default_value = "tcp")]
    pub protocol: String,
    #[sea_orm(string, nullable)]
    pub service: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub banner: Option<String>,
    pub is_risky: Option<bool>,
    // 补齐：HTTP/Web 服务详情字段
    #[sea_orm(string, nullable)]
    pub version: Option<String>,          // 组件/服务版本
    #[sea_orm(string, nullable)]
    pub response_code: Option<String>,    // HTTP 响应码
    #[sea_orm(string, nullable)]
    pub title: Option<String>,            // 页面标题
    #[sea_orm(string, nullable)]
    pub server_arch: Option<String>,      // 服务器架构（如 nginx/1.20.1）
    #[sea_orm(string, nullable)]
    pub page_encoding: Option<String>,    // 页面编码（如 UTF-8）
    pub first_found: chrono::DateTime<chrono::Utc>,
    pub last_found: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
