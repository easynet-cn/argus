//! 扫描任务管理 CRUD + 生命周期 API

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder, ActiveValue::Set};
use serde::Deserialize;
use argus_core::entity::task::{self, Entity as ScanTaskEntity, LaunchMode, TaskStatus, TaskType};
use crate::state::AppState;
use crate::handler::asset::ListQuery;

#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
    pub name: String,
    pub task_type: String,
    pub launch_mode: Option<String>,
    pub targets: Vec<String>,
    pub priority: Option<String>,
    pub schedule_config: Option<serde_json::Value>,
    pub params: Option<serde_json::Value>,
    pub node_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTaskRequest {
    pub name: Option<String>,
    pub status: Option<String>,
    pub progress: Option<f32>,
    pub priority: Option<String>,
    pub schedule_config: Option<serde_json::Value>,
    pub params: Option<serde_json::Value>,
    pub node_id: Option<String>,
}

fn parse_task_type(s: &str) -> TaskType {
    match s {
        "port_scan" | "PortScan" => TaskType::PortScan,
        "host_discovery" | "HostDiscovery" => TaskType::HostDiscovery,
        "bruteforce" | "Bruteforce" => TaskType::Bruteforce,
        "baseline_check" | "BaselineCheck" => TaskType::BaselineCheck,
        "system_scan" | "SystemScan" => TaskType::SystemScan,
        "app_scan" | "AppScan" => TaskType::AppScan,
        "db_scan" | "DbScan" => TaskType::DbScan,
        "image_scan" | "ImageScan" => TaskType::ImageScan,
        "mobile_scan" | "MobileScan" => TaskType::MobileScan,
        "vuln_verify" | "VulnVerify" => TaskType::VulnVerify,
        "fingerprint" | "Fingerprint" => TaskType::Fingerprint,
        "vuln_detect" | "VulnDetect" => TaskType::VulnDetect,
        "ics_scan" | "IcsScan" => TaskType::IcsScan,
        _ => TaskType::PortScan,
    }
}

fn parse_priority(s: &str) -> String {
    match s {
        "low" | "normal" | "high" | "critical" => s.to_string(),
        _ => "normal".to_string(),
    }
}

/// 构建一个带默认新字段的任务 ActiveModel（供 create 与 copy 复用）
fn default_new_task_fields(now: chrono::DateTime<chrono::Utc>) -> task::ActiveModel {
    task::ActiveModel {
        id: Set(String::new()),
        name: Set(String::new()),
        task_type: Set(TaskType::PortScan),
        status: Set(TaskStatus::Pending),
        launch_mode: Set(LaunchMode::Manual),
        targets: Set(serde_json::json!([])),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(None),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(None),
        node_id: Set(None),
    }
}

/// 创建扫描任务 POST /api/v1/tasks
pub async fn create_task(
    data: web::Data<AppState>,
    body: web::Json<CreateTaskRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let task_type = parse_task_type(&body.task_type);
    let launch_mode = match body.launch_mode.as_deref() {
        Some("scheduled") => LaunchMode::Scheduled,
        Some("periodic") => LaunchMode::Periodic,
        _ => LaunchMode::Manual,
    };
    let priority = body.priority.as_deref().map(parse_priority).unwrap_or_else(|| "normal".to_string());

    let mut new = default_new_task_fields(now);
    new.id = Set(id);
    new.name = Set(body.name.clone());
    new.task_type = Set(task_type);
    new.launch_mode = Set(launch_mode);
    new.targets = Set(serde_json::to_value(body.targets.clone()).unwrap_or_default());
    new.priority = Set(priority);
    new.schedule_config = Set(body.schedule_config.clone());
    new.params = Set(body.params.clone());
    new.node_id = Set(body.node_id.clone());

    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 列出扫描任务 GET /api/v1/tasks
pub async fn list_tasks(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match ScanTaskEntity::find()
        .order_by_desc(task::Column::CreatedAt)
        .paginate(&data.db, page_size as u64)
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

/// 获取单个任务 GET /api/v1/tasks/{id}
pub async fn get_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ScanTaskEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新任务状态/进度 PUT /api/v1/tasks/{id}
pub async fn update_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateTaskRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ScanTaskEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: task::ActiveModel = t.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = body.progress { active.progress = Set(v); }
    if let Some(v) = &body.priority { active.priority = Set(parse_priority(v)); }
    if body.schedule_config.is_some() { active.schedule_config = Set(body.schedule_config.clone()); }
    if body.params.is_some() { active.params = Set(body.params.clone()); }
    if body.node_id.is_some() { active.node_id = Set(body.node_id.clone()); }
    if let Some(v) = &body.status {
        let st = match v.as_str() {
            "running" | "Running" => { active.started_at = Set(Some(chrono::Utc::now())); TaskStatus::Running }
            "completed" | "Completed" => { active.finished_at = Set(Some(chrono::Utc::now())); TaskStatus::Completed }
            "stopped" | "Stopped" => { active.finished_at = Set(Some(chrono::Utc::now())); TaskStatus::Stopped }
            "paused" | "Paused" => TaskStatus::Paused,
            "failed" | "Failed" => { active.finished_at = Set(Some(chrono::Utc::now())); TaskStatus::Failed }
            _ => TaskStatus::Pending,
        };
        active.status = Set(st);
    }
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除任务 DELETE /api/v1/tasks/{id}
pub async fn delete_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ScanTaskEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) if t.locked => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "任务已锁定，无法删除"}));
        }
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
        _ => {}
    }
    match ScanTaskEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 任务生命周期 ====================

/// 加载任务（带 404 处理）
async fn load_task(db: &sea_orm::DatabaseConnection, id: &str) -> Result<task::Model, HttpResponse> {
    match ScanTaskEntity::find_by_id(id.to_string()).one(db).await {
        Ok(Some(t)) => Ok(t),
        Ok(None) => Err(HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"}))),
        Err(e) => Err(HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))),
    }
}

/// 锁定检查：所有生命周期操作（除 unlock）都拒绝锁定任务
fn check_locked(t: &task::Model) -> Result<(), HttpResponse> {
    if t.locked {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({"error": "任务已锁定，请先解锁"})));
    }
    Ok(())
}

/// 尝试取消底层扫描引擎的执行（复用 cancel 机制）
async fn cancel_engine(state: &AppState, t: &task::Model) {
    let scanner_name = match t.task_type {
        TaskType::PortScan => Some("port_scanner"),
        TaskType::Bruteforce => Some("brute_force"),
        TaskType::BaselineCheck => Some("baseline_scanner"),
        _ => None,
    };
    if let Some(name) = scanner_name {
        if let Some(scanner) = state.registry.get(name) {
            let _ = scanner.cancel(&t.id).await;
        }
    }
}

/// 启动任务 POST /api/v1/tasks/{id}/start
pub async fn start_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    if let Err(e) = check_locked(&t) { return e; }
    if t.status != TaskStatus::Pending {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("仅 pending 状态可启动，当前状态: {:?}", t.status)
        }));
    }
    let mut active: task::ActiveModel = t.into();
    active.status = Set(TaskStatus::Running);
    active.started_at = Set(Some(chrono::Utc::now()));
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 暂停任务 POST /api/v1/tasks/{id}/pause
pub async fn pause_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    if let Err(e) = check_locked(&t) { return e; }
    if t.status != TaskStatus::Running {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("仅 running 状态可暂停，当前状态: {:?}", t.status)
        }));
    }
    // 底层扫描引擎不支持真正暂停，先尝试取消引擎执行并标记状态为 paused
    cancel_engine(&data, &t).await;
    let mut active: task::ActiveModel = t.into();
    active.status = Set(TaskStatus::Paused);
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 继续任务 POST /api/v1/tasks/{id}/resume
pub async fn resume_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    if let Err(e) = check_locked(&t) { return e; }
    if t.status != TaskStatus::Paused {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("仅 paused 状态可继续，当前状态: {:?}", t.status)
        }));
    }
    let mut active: task::ActiveModel = t.into();
    active.status = Set(TaskStatus::Running);
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 停止任务 POST /api/v1/tasks/{id}/stop
pub async fn stop_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    if let Err(e) = check_locked(&t) { return e; }
    if !matches!(t.status, TaskStatus::Running | TaskStatus::Paused) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("仅 running/paused 状态可停止，当前状态: {:?}", t.status)
        }));
    }
    cancel_engine(&data, &t).await;
    let mut active: task::ActiveModel = t.into();
    active.status = Set(TaskStatus::Stopped);
    active.finished_at = Set(Some(chrono::Utc::now()));
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 复制任务 POST /api/v1/tasks/{id}/copy
pub async fn copy_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let new_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let new = task::ActiveModel {
        id: Set(new_id),
        name: Set(format!("{} (副本)", t.name)),
        task_type: Set(t.task_type),
        status: Set(TaskStatus::Pending),
        launch_mode: Set(t.launch_mode),
        targets: Set(t.targets),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(None),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set(t.priority),
        schedule_config: Set(t.schedule_config),
        params: Set(t.params),
        node_id: Set(t.node_id),
    };
    match new.insert(&data.db).await {
        Ok(created) => HttpResponse::Created().json(created),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 锁定任务 POST /api/v1/tasks/{id}/lock
pub async fn lock_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let mut active: task::ActiveModel = t.into();
    active.locked = Set(true);
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 解锁任务 POST /api/v1/tasks/{id}/unlock
pub async fn unlock_task(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match load_task(&data.db, &id).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let mut active: task::ActiveModel = t.into();
    active.locked = Set(false);
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
