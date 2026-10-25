//! CVE-CPE 关联实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// CVE-CPE 关联模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "cve_cpe_mappings")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = true)]
    pub id: uuid::Uuid,
    #[sea_orm(string)]
    pub cve_id: String,                      // CVE-2024-1234
    #[sea_orm(column_type = "Text")]
    pub cpe_uri: String,
    #[sea_orm(default_value = true)]
    pub vulnerable: bool,
    #[sea_orm(string, nullable)]
    pub version_end_excluding: Option<String>,
    #[sea_orm(string, nullable)]
    pub version_end_including: Option<String>,
    #[sea_orm(string, nullable)]
    pub version_start_excluding: Option<String>,
    #[sea_orm(string, nullable)]
    pub version_start_including: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
