//! 指纹规则实体（sea-orm）
//!
//! 自定义服务指纹识别规则库，支持 banner/regex/keyword 等匹配方式。

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 指纹匹配类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum MatchType {
    /// Banner 精确包含
    #[sea_orm(string_value = "banner")]
    Banner,
    /// 正则表达式匹配
    #[sea_orm(string_value = "regex")]
    Regex,
    /// 关键词匹配
    #[sea_orm(string_value = "keyword")]
    Keyword,
    /// 端口-服务映射
    #[sea_orm(string_value = "port_service")]
    PortService,
}

/// 指纹规则模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "fingerprint_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    /// 规则名称
    pub name: String,
    /// 分类（web / database / middleware / os / hardware）
    #[sea_orm(nullable)]
    pub category: Option<String>,
    /// 匹配类型
    pub match_type: MatchType,
    /// 匹配模式（正则/关键词/banner 子串）
    #[sea_orm(column_type = "Text")]
    pub match_pattern: String,
    /// 识别出的服务名称
    pub service_name: String,
    /// 厂商
    #[sea_orm(nullable)]
    pub vendor: Option<String>,
    /// 版本提取正则（可选，第一个捕获组为版本号）
    #[sea_orm(column_type = "Text", nullable)]
    pub version_pattern: Option<String>,
    /// CPE 标识
    #[sea_orm(nullable)]
    pub cpe: Option<String>,
    /// 匹配端口范围（如 "80,443,8080"，可选）
    #[sea_orm(nullable)]
    pub ports: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 是否内置规则
    pub is_builtin: bool,
    /// 优先级（数值越小优先级越高）
    pub priority: i32,
    /// 创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// 更新时间
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
