//! 配置变更记录 API
//!
//! 提供配置变更记录的查询、录入、按资产追溯等能力。

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::config_change::{
    self, ChangeCategory, ChangeSource, ChangeType, Entity as ConfigChangeEntity, RiskLevel,
};
use crate::state::AppState;

// ==================== 请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct ConfigChangeListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub asset_id: Option<String>,
    pub asset_type: Option<String>,
    pub change_type: Option<String>,
    pub risk_level: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateConfigChangeRequest {
    pub asset_id: String,
    pub asset_type: String,
    pub change_type: String,
    pub change_category: String,
    pub item_name: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub change_time: Option<String>,
    pub operator: Option<String>,
    pub source: Option<String>,
    pub risk_level: Option<String>,
    pub description: Option<String>,
}

// ==================== 辅助函数 ====================

fn parse_change_type(s: &str) -> ChangeType {
    match s {
        "network_config" => ChangeType::NetworkConfig,
        "system_config" => ChangeType::SystemConfig,
        "security_config" => ChangeType::SecurityConfig,
        "account" => ChangeType::Account,
        "config_file" => ChangeType::ConfigFile,
        "software" => ChangeType::Software,
        _ => ChangeType::Other,
    }
}

fn parse_change_category(s: &str) -> ChangeCategory {
    match s {
        "add" => ChangeCategory::Add,
        "delete" => ChangeCategory::Delete,
        _ => ChangeCategory::Modify,
    }
}

fn parse_change_source(s: &str) -> ChangeSource {
    match s {
        "manual" => ChangeSource::Manual,
        "scan" => ChangeSource::Scan,
        "import" => ChangeSource::Import,
        _ => ChangeSource::Auto,
    }
}

fn parse_risk_level(s: &str) -> RiskLevel {
    match s {
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Low,
    }
}

// ==================== API 处理函数 ====================

/// 配置变更列表 GET /api/v1/config-changes
pub async fn list_config_changes(
    data: web::Data<AppState>,
    query: web::Query<ConfigChangeListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = ConfigChangeEntity::find();
    if let Some(v) = &query.asset_id {
        q = q.filter(config_change::Column::AssetId.eq(v.clone()));
    }
    if let Some(v) = &query.asset_type {
        q = q.filter(config_change::Column::AssetType.eq(v.clone()));
    }
    if let Some(v) = &query.change_type {
        q = q.filter(config_change::Column::ChangeType.eq(v.clone()));
    }
    if let Some(v) = &query.risk_level {
        q = q.filter(config_change::Column::RiskLevel.eq(v.clone()));
    }
    if let Some(v) = &query.start_time {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
            q = q.filter(config_change::Column::ChangeTime.gte(dt.with_timezone(&chrono::Utc)));
        }
    }
    if let Some(v) = &query.end_time {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
            q = q.filter(config_change::Column::ChangeTime.lte(dt.with_timezone(&chrono::Utc)));
        }
    }

    match q
        .order_by_desc(config_change::Column::ChangeTime)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 配置变更详情 GET /api/v1/config-changes/{id}
pub async fn get_config_change(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ConfigChangeEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(change)) => HttpResponse::Ok().json(change),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "变更记录未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 录入配置变更 POST /api/v1/config-changes
pub async fn create_config_change(
    data: web::Data<AppState>,
    body: web::Json<CreateConfigChangeRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let change_time = body
        .change_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);

    let new = config_change::ActiveModel {
        id: Set(id),
        asset_id: Set(body.asset_id.clone()),
        asset_type: Set(body.asset_type.clone()),
        change_type: Set(parse_change_type(&body.change_type)),
        change_category: Set(parse_change_category(&body.change_category)),
        item_name: Set(body.item_name.clone()),
        old_value: Set(body.old_value.clone()),
        new_value: Set(body.new_value.clone()),
        change_time: Set(change_time),
        operator: Set(body.operator.clone()),
        source: Set(body.source.as_deref().map(parse_change_source).unwrap_or(ChangeSource::Manual)),
        risk_level: Set(body.risk_level.as_deref().map(parse_risk_level).unwrap_or(RiskLevel::Low)),
        description: Set(body.description.clone()),
        created_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(change) => HttpResponse::Created().json(change),
        Err(e) => {
            tracing::error!("创建配置变更记录失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 按资产查询变更历史 GET /api/v1/config-changes/asset/{asset_id}
pub async fn config_changes_by_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let asset_id = path.into_inner();
    match ConfigChangeEntity::find()
        .filter(config_change::Column::AssetId.eq(asset_id))
        .order_by_desc(config_change::Column::ChangeTime)
        .limit(200)
        .all(&data.db)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "count": items.len()})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 配置变更 diff ====================

/// 单行 diff 结果
#[derive(Debug, Serialize)]
struct DiffLine {
    /// diff 类型：add / remove / context
    op: String,
    /// 行内容
    content: String,
    /// 旧版本行号（context/remove 有值）
    old_line_no: Option<usize>,
    /// 新版本行号（context/add 有值）
    new_line_no: Option<usize>,
}

/// 行级 LCS diff：比较 old_value 与 new_value，返回逐行 diff
fn line_diff(old_text: &str, new_text: &str) -> Vec<DiffLine> {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();
    let m = old_lines.len();
    let n = new_lines.len();

    // 构建 LCS 长度表
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if old_lines[i - 1] == new_lines[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }

    // 回溯生成 diff
    let mut result: Vec<DiffLine> = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old_lines[i - 1] == new_lines[j - 1] {
            result.push(DiffLine {
                op: "context".to_string(),
                content: old_lines[i - 1].to_string(),
                old_line_no: Some(i),
                new_line_no: Some(j),
            });
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            result.push(DiffLine {
                op: "add".to_string(),
                content: new_lines[j - 1].to_string(),
                old_line_no: None,
                new_line_no: Some(j),
            });
            j -= 1;
        } else {
            result.push(DiffLine {
                op: "remove".to_string(),
                content: old_lines[i - 1].to_string(),
                old_line_no: Some(i),
                new_line_no: None,
            });
            i -= 1;
        }
    }
    result.reverse();
    result
}

/// 配置变更 diff GET /api/v1/config-changes/{id}/diff
///
/// 对比 old_value 与 new_value，返回逐行 diff（add/remove/context），
/// 同时返回统一 diff 格式文本（unified diff style）。
pub async fn diff_config_change(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let change = match ConfigChangeEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "变更记录未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let old_text = change.old_value.clone().unwrap_or_default();
    let new_text = change.new_value.clone().unwrap_or_default();

    // 逐行 diff
    let diff_lines = line_diff(&old_text, &new_text);

    // 生成 unified diff 文本
    let mut unified = String::new();
    unified.push_str(&format!("--- a/{}\n", change.item_name));
    unified.push_str(&format!("+++ b/{}\n", change.item_name));
    for line in &diff_lines {
        match line.op.as_str() {
            "add" => unified.push_str(&format!("+{}\n", line.content)),
            "remove" => unified.push_str(&format!("-{}\n", line.content)),
            _ => unified.push_str(&format!(" {}\n", line.content)),
        }
    }

    // 统计
    let add_count = diff_lines.iter().filter(|l| l.op == "add").count();
    let remove_count = diff_lines.iter().filter(|l| l.op == "remove").count();

    HttpResponse::Ok().json(serde_json::json!({
        "change_id": change.id,
        "item_name": change.item_name,
        "diff_lines": diff_lines,
        "unified_diff": unified,
        "stats": {
            "added": add_count,
            "removed": remove_count,
            "total": diff_lines.len(),
        },
    }))
}
