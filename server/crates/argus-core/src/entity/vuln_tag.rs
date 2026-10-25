//! 漏洞标签实体（sea-orm）
//!
//! 漏洞标签管理。
//! 支持为漏洞模板打标签，实现多维度检索（按标签、严重程度、分类、CVE 等筛选）。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vuln_tags")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 标签名称（唯一）
    pub name: String,
    /// 颜色（用于前端展示，如 "#FF5733"）
    #[sea_orm(nullable)]
    pub color: Option<String>,
    /// 标签描述
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    /// 是否内置标签
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::vuln_template_tag::Entity")]
    VulnTemplateTag,
}

impl Related<super::vuln_template::Entity> for Entity {
    fn to() -> RelationDef {
        super::vuln_template_tag::Relation::VulnTemplate.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::vuln_template_tag::Relation::VulnTag.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
