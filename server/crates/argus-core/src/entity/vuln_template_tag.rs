//! 漏洞模板-标签关联实体（sea-orm）
//!
//! 漏洞模板与标签的多对多关联表。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vuln_template_tags")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 漏洞模板 ID
    pub vuln_template_id: String,
    /// 标签 ID
    pub tag_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::vuln_template::Entity",
        from = "Column::VulnTemplateId",
        to = "super::vuln_template::Column::Id"
    )]
    VulnTemplate,
    #[sea_orm(
        belongs_to = "super::vuln_tag::Entity",
        from = "Column::TagId",
        to = "super::vuln_tag::Column::Id"
    )]
    VulnTag,
}

impl Related<super::vuln_template::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VulnTemplate.def()
    }
}

impl Related<super::vuln_tag::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VulnTag.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
