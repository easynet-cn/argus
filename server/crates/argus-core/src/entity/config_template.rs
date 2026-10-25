//! 配置模板（基线）实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "config_templates")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    #[sea_orm(column_type = "Json")]
    pub rule_set: serde_json::Value,
    pub is_builtin: bool,
    // 补齐：基线规则结构化分类
    /// 配置类型：network/security/system/database/application
    #[sea_orm(string, default_value = "system")]
    pub config_type: String,
    /// 基线类别（如：等保2.0、CIS、自定义）
    #[sea_orm(string, default_value = "custom")]
    pub category: String,
    /// 安全级别：low/medium/high/critical
    #[sea_orm(string, default_value = "low")]
    pub security_level: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
