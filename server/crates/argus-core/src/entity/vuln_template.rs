//! 漏洞模板实体（sea-orm）
//!
//! 将 YAML 漏洞模板持久化到数据库，支持自定义 POC 管理。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 漏洞严重程度
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum Severity {
    #[sea_orm(string_value = "critical")]
    Critical,
    #[sea_orm(string_value = "high")]
    High,
    #[sea_orm(string_value = "medium")]
    Medium,
    #[sea_orm(string_value = "low")]
    Low,
    #[sea_orm(string_value = "info")]
    Info,
}

/// 漏洞模板模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vuln_templates")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 模板名称
    pub name: String,
    /// 模板描述
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    /// 严重程度
    pub severity: Severity,
    /// CVE 编号
    #[sea_orm(nullable)]
    pub cve: Option<String>,
    /// 分类（default_credentials / info_leak / misconfig / known_cve / custom）
    #[sea_orm(nullable)]
    pub category: Option<String>,
    /// 插件类型（http / tcp / poc_yaml / nuclei 等）
    #[sea_orm(nullable)]
    pub plugin_type: Option<String>,
    /// 目标类型（web / network / database / mobile）
    #[sea_orm(nullable)]
    pub target_type: Option<String>,
    /// POC 脚本内容（YAML/JSON）
    #[sea_orm(column_type = "Text", nullable)]
    pub poc_content: Option<String>,
    /// 匹配规则（指纹特征，可选）
    #[sea_orm(column_type = "Text", nullable)]
    pub match_rule: Option<String>,
    /// 修复建议
    #[sea_orm(column_type = "Text", nullable)]
    pub fix_advice: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 是否内置模板
    pub is_builtin: bool,
    /// 创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 更新时间
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
