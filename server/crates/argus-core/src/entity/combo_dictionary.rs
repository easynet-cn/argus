//! 组合字典实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "combo_dictionaries")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub username_dict_id: Option<String>,
    pub password_dict_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
