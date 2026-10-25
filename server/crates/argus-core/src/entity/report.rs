//! 扫描报告实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 报告格式
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum ReportFormat {
    #[sea_orm(string_value = "html")]
    Html,
    #[sea_orm(string_value = "pdf")]
    Pdf,
    #[sea_orm(string_value = "xlsx")]
    Xlsx,
    #[sea_orm(string_value = "json")]
    Json,
    #[sea_orm(string_value = "xml")]
    Xml,
}

/// 报告状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum ReportStatus {
    #[sea_orm(string_value = "generating")]
    Generating,
    #[sea_orm(string_value = "ready")]
    Ready,
    #[sea_orm(string_value = "failed")]
    Failed,
}

/// 扫描报告模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_reports")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub task_id: String,
    pub name: String,
    pub format: ReportFormat,
    pub status: ReportStatus,
    pub file_size: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
