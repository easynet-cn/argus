//! CPE 字典实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// CPE 记录模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "cpes")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,                          // hash(cpe_uri)
    #[sea_orm(column_type = "Text")]
    pub cpe_uri: String,                     // cpe:2.3:a:apache:http_server:2.4.6:*:*:*:*:*:*:*
    #[sea_orm(string)]
    pub part: String,                         // a/h/o
    #[sea_orm(string)]
    pub vendor: String,
    #[sea_orm(string)]
    pub product: String,
    #[sea_orm(string)]
    pub version: String,
    #[sea_orm(string, nullable)]
    pub target_sw: Option<String>,
    #[sea_orm(string, nullable)]
    pub language: Option<String>,
    #[sea_orm(string, nullable)]
    pub title: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
