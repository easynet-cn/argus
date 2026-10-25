//! 指纹扫描 API

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use argus_core::entity::task::{self, Entity as ScanTaskEntity, TaskStatus, TaskType, LaunchMode};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use argus_scanner::{ScanConfig, Target};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FingerprintRequest {
    pub hosts: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
}

pub async fn scan_fingerprint(
    data: web::Data<AppState>,
    body: web::Json<FingerprintRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let targets: Vec<Target> = body.hosts.iter().map(|h| Target {
        host: h.clone(),
        ports: body.ports.clone(),
        credentials: None,
    }).collect();

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("fingerprint-{}", &task_id[..8])),
        task_type: Set(TaskType::Fingerprint),
        status: Set(TaskStatus::Running),
        launch_mode: Set(LaunchMode::Manual),
        targets: Set(serde_json::to_value(&body.hosts).unwrap_or_default()),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(None),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("创建任务失败: {e}")}));
    }

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(100),
        timeout_secs: body.timeout_ms.unwrap_or(3000) / 1000,
        extra_params: serde_json::json!({}),
    };

    let scanner = match data.registry.get("fingerprint_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "指纹扫描引擎未注册"}));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("指纹扫描失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };
        let fp_results: Vec<argus_fingerprint::types::FingerprintResult> = result.raw_data
            .as_ref()
            .and_then(|raw| serde_json::from_value(raw.clone()).ok())
            .unwrap_or_default();
        if let Err(e) = save_fingerprint_results(&db, &task_id_bg, &fp_results).await {
            tracing::error!("保存指纹结果失败: {e}");
        }
        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "status": "running",
        "message": "指纹扫描已提交，使用 GET /api/v1/scan/status/{task_id} 查询进度"
    }))
}

async fn save_fingerprint_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    results: &[argus_fingerprint::types::FingerprintResult],
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = results.iter().flat_map(|fp| {
        fp.services.iter().map(|s| scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id.to_string()),
            result_type: Set(ResultType::Fingerprint),
            host: Set(fp.host.clone()),
            port: Set(Some(s.port as i32)),
            protocol: Set(Some("tcp".to_string())),
            state: Set(Some("open".to_string())),
            service: Set(Some(s.service.clone())),
            banner: Set(s.banner.clone()),
            username: Set(None),
            password: Set(None),
            success: Set(None),
            response_time_ms: Set(None),
            raw_data: Set(Some(serde_json::to_value(s).unwrap_or_default())),
            created_at: Set(now),
        })
    }).collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

pub async fn get_fingerprint_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(&task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::Fingerprint))
        .all(&data.db).await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("查询失败: {e}")})),
    };
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "count": results.len(), "results": results}))
}

async fn update_task_status(db: &sea_orm::DatabaseConnection, task_id: &str, status: TaskStatus) -> Result<(), sea_orm::DbErr> {
    let task = ScanTaskEntity::find_by_id(task_id.to_string()).one(db).await?;
    if let Some(task) = task {
        let mut active: task::ActiveModel = task.into();
        active.status = Set(status.clone());
        if status == TaskStatus::Completed || status == TaskStatus::Failed {
            active.finished_at = Set(Some(chrono::Utc::now()));
        }
        active.update(db).await?;
    }
    Ok(())
}

// ==================== 自定义指纹规则管理 ====================

use argus_core::entity::fingerprint_rule::{self, Entity as FpRuleEntity, MatchType};
use sea_orm::{PaginatorTrait, QueryOrder};

/// 指纹规则创建/更新请求
#[derive(Debug, Deserialize)]
pub struct FingerprintRuleRequest {
    pub name: String,
    pub category: Option<String>,
    pub match_type: String,
    pub match_pattern: String,
    pub service_name: String,
    pub vendor: Option<String>,
    pub version_pattern: Option<String>,
    pub cpe: Option<String>,
    pub ports: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
}

fn parse_match_type(s: &str) -> Result<MatchType, String> {
    match s.to_lowercase().as_str() {
        "banner" => Ok(MatchType::Banner),
        "regex" => Ok(MatchType::Regex),
        "keyword" => Ok(MatchType::Keyword),
        "port_service" => Ok(MatchType::PortService),
        _ => Err(format!("无效的匹配类型: {s}")),
    }
}

/// 指纹规则列表 GET /api/v1/asset/fingerprint-rules
pub async fn list_fp_rules(
    data: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let page: u64 = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: u64 = query.get("page_size").and_then(|v| v.parse().ok()).unwrap_or(20);

    let mut q = FpRuleEntity::find();
    if let Some(category) = query.get("category") {
        q = q.filter(fingerprint_rule::Column::Category.eq(category.as_str()));
    }
    if let Some(service) = query.get("service_name") {
        q = q.filter(fingerprint_rule::Column::ServiceName.eq(service.as_str()));
    }
    if let Some(enabled) = query.get("enabled") {
        q = q.filter(fingerprint_rule::Column::Enabled.eq(enabled == "true"));
    }

    let paginator = q
        .order_by_asc(fingerprint_rule::Column::Priority)
        .order_by_desc(fingerprint_rule::Column::CreatedAt)
        .paginate(&data.db, page_size);

    let total = paginator.num_items().await.unwrap_or(0);
    let items = match paginator.fetch_page(page - 1).await {
        Ok(i) => i,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    }))
}

/// 指纹规则详情 GET /api/v1/asset/fingerprint-rules/{id}
pub async fn get_fp_rule(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match FpRuleEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(r)) => HttpResponse::Ok().json(r),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "规则不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建指纹规则 POST /api/v1/asset/fingerprint-rules
pub async fn create_fp_rule(
    data: web::Data<AppState>,
    body: web::Json<FingerprintRuleRequest>,
) -> impl Responder {
    let match_type = match parse_match_type(&body.match_type) {
        Ok(m) => m,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    let now = chrono::Utc::now();
    let id = uuid::Uuid::new_v4().to_string();

    let active = fingerprint_rule::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        category: Set(body.category.clone()),
        match_type: Set(match_type),
        match_pattern: Set(body.match_pattern.clone()),
        service_name: Set(body.service_name.clone()),
        vendor: Set(body.vendor.clone()),
        version_pattern: Set(body.version_pattern.clone()),
        cpe: Set(body.cpe.clone()),
        ports: Set(body.ports.clone()),
        enabled: Set(body.enabled.unwrap_or(true)),
        is_builtin: Set(false),
        priority: Set(body.priority.unwrap_or(100)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match active.insert(&data.db).await {
        Ok(r) => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新指纹规则 PUT /api/v1/asset/fingerprint-rules/{id}
pub async fn update_fp_rule(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<FingerprintRuleRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match FpRuleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "规则不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let match_type = match parse_match_type(&body.match_type) {
        Ok(m) => m,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    let mut active: fingerprint_rule::ActiveModel = existing.into();
    active.name = Set(body.name.clone());
    active.category = Set(body.category.clone());
    active.match_type = Set(match_type);
    active.match_pattern = Set(body.match_pattern.clone());
    active.service_name = Set(body.service_name.clone());
    active.vendor = Set(body.vendor.clone());
    active.version_pattern = Set(body.version_pattern.clone());
    active.cpe = Set(body.cpe.clone());
    active.ports = Set(body.ports.clone());
    active.enabled = Set(body.enabled.unwrap_or(true));
    active.priority = Set(body.priority.unwrap_or(100));
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(r) => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除指纹规则 DELETE /api/v1/asset/fingerprint-rules/{id}
pub async fn delete_fp_rule(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match FpRuleEntity::delete_by_id(id).exec(&data.db).await {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已删除"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "规则不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 启用/禁用规则 PATCH /api/v1/asset/fingerprint-rules/{id}/toggle
pub async fn toggle_fp_rule(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match FpRuleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "规则不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: fingerprint_rule::ActiveModel = existing.clone().into();
    active.enabled = Set(!existing.enabled);
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(r) => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
