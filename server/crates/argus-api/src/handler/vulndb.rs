//! 漏洞知识库 API

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use argus_vulndb::{CveImporter, repository};
use crate::state::AppState;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    pub start_year: Option<u16>,
    pub end_year: Option<u16>,
}

/// 全局导入状态
static IMPORT_STATUS: std::sync::LazyLock<Arc<RwLock<argus_vulndb::ImportProgress>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(argus_vulndb::ImportProgress {
        task_id: String::new(),
        current_year: 0,
        current_page: 0,
        total_processed: 0,
        status: "idle".to_string(),
        error: None,
    })));

pub async fn import_cves(
    data: web::Data<AppState>,
    body: web::Json<ImportRequest>,
) -> impl Responder {
    let start_year = body.start_year.unwrap_or(2002);
    let end_year = body.end_year.unwrap_or(chrono::Utc::now().format("%Y").to_string().parse().unwrap_or(2024));
    let task_id = uuid::Uuid::new_v4().to_string();

    // 设置初始状态
    {
        let mut status = IMPORT_STATUS.write().await;
        *status = argus_vulndb::ImportProgress {
            task_id: task_id.clone(),
            current_year: start_year,
            current_page: 0,
            total_processed: 0,
            status: "running".to_string(),
            error: None,
        };
    }

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        let client = argus_vulndb::NvdClient::new(None);
        let importer = CveImporter::new(db, client);
        match importer.import_all(start_year, end_year, None).await {
            Ok(stats) => {
                let mut status = IMPORT_STATUS.write().await;
                status.status = "completed".to_string();
                status.total_processed = stats.total_cves;
                tracing::info!("CVE 导入完成: {:?}", stats);
            }
            Err(e) => {
                let mut status = IMPORT_STATUS.write().await;
                status.status = "failed".to_string();
                status.error = Some(e.to_string());
                tracing::error!("CVE 导入失败: {e}");
            }
        }
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "status": "running",
        "message": "CVE 导入已启动，使用 GET /api/v1/vulndb/import/status 查询进度"
    }))
}

pub async fn get_import_status() -> impl Responder {
    let status = IMPORT_STATUS.read().await;
    HttpResponse::Ok().json(serde_json::json!({
        "task_id": status.task_id,
        "current_year": status.current_year,
        "current_page": status.current_page,
        "total_processed": status.total_processed,
        "status": status.status,
        "error": status.error,
    }))
}

pub async fn list_cves(
    data: web::Data<AppState>,
    query: web::Query<CveListQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(20);
    let offset = query.offset.unwrap_or(0);
    let cves = repository::search_by_keyword(&data.db, &query.keyword.clone().unwrap_or_default(), limit as u64, offset as u64).await;
    let total = repository::count_total(&data.db).await;
    HttpResponse::Ok().json(serde_json::json!({"data": cves, "total": total, "limit": limit, "offset": offset}))
}

#[derive(Debug, Deserialize)]
pub struct CveListQuery {
    pub keyword: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn get_cve(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let cve_id = path.into_inner();
    match repository::find_by_cve_id(&data.db, &cve_id).await {
        Some(cve) => HttpResponse::Ok().json(cve),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "CVE 未找到"})),
    }
}

pub async fn search_cves(
    data: web::Data<AppState>,
    query: web::Query<SearchQuery>,
) -> impl Responder {
    let keyword = query.keyword.as_deref().unwrap_or("");
    let limit = query.limit.unwrap_or(20) as u64;
    let offset = query.offset.unwrap_or(0) as u64;
    let cves = repository::search_by_keyword(&data.db, keyword, limit, offset).await;
    HttpResponse::Ok().json(serde_json::json!({"data": cves, "keyword": keyword}))
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub keyword: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn get_stats(data: web::Data<AppState>) -> impl Responder {
    let total = repository::count_total(&data.db).await;
    let by_year = repository::stats_by_year(&data.db).await;
    let by_severity = repository::stats_by_severity(&data.db).await;
    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "by_year": by_year,
        "by_severity": by_severity,
    }))
}
