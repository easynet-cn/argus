//! 漏洞处置历史记录实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 漏洞处置历史记录
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vuln_disposition_history")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 关联漏洞 ID
    pub vuln_id: String,
    /// 原状态
    pub from_status: String,
    /// 目标状态
    pub to_status: String,
    /// 操作人
    pub operator: String,
    /// 处置原因/备注
    pub reason: Option<String>,
    /// 创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
