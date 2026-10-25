//! 趋势统计 API

use actix_web::{web, HttpResponse, Responder};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use crate::state::AppState;

/// 任务对比 GET /trends/tasks/diff?task_id_a=x&task_id_b=y
pub async fn tasks_diff(
    data: web::Data<AppState>,
    query: web::Query<TasksDiffQuery>,
) -> impl Responder {
    let task_a = match &query.task_id_a {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "task_id_a 必填"})),
    };
    let task_b = match &query.task_id_b {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "task_id_b 必填"})),
    };

    let results_a = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_a))
        .all(&data.db).await.unwrap_or_default();
    let results_b = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_b))
        .all(&data.db).await.unwrap_or_default();

    HttpResponse::Ok().json(serde_json::json!({
        "task_a": {"id": task_a, "count": results_a.len()},
        "task_b": {"id": task_b, "count": results_b.len()},
        "diff": (results_a.len() as i64 - results_b.len() as i64),
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct TasksDiffQuery {
    pub task_id_a: Option<String>,
    pub task_id_b: Option<String>,
}

/// 严重等级分布 GET /trends/severity?task_id=x
pub async fn severity_distribution(
    data: web::Data<AppState>,
    query: web::Query<TaskIdQuery>,
) -> impl Responder {
    let task_id = match &query.task_id {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "task_id 必填"})),
    };
    let results = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::VulnDetect))
        .all(&data.db).await.unwrap_or_default();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in &results {
        if let Some(ref raw) = r.raw_data {
            if let Some(sev) = raw.get("severity").and_then(|s| s.as_str()) {
                *counts.entry(sev.to_string()).or_insert(0) += 1;
            }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "severity": counts}))
}

#[derive(Debug, serde::Deserialize)]
pub struct TaskIdQuery {
    pub task_id: Option<String>,
}

/// Top 漏洞 GET /trends/top_vulns?task_id=x&limit=10
pub async fn top_vulns(
    data: web::Data<AppState>,
    query: web::Query<TopVulnsQuery>,
) -> impl Responder {
    let task_id = match &query.task_id {
        Some(id) => id,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "task_id 必填"})),
    };
    let limit = query.limit.unwrap_or(10);
    let results = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::VulnDetect))
        .all(&data.db).await.unwrap_or_default();
    let mut name_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in &results {
        if let Some(ref raw) = r.raw_data {
            if let Some(name) = raw.get("name").and_then(|s| s.as_str()) {
                *name_counts.entry(name.to_string()).or_insert(0) += 1;
            }
        }
    }
    let mut sorted: Vec<_> = name_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(limit);
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "top_vulns": sorted}))
}

#[derive(Debug, serde::Deserialize)]
pub struct TopVulnsQuery {
    pub task_id: Option<String>,
    pub limit: Option<usize>,
}
