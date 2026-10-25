//! 漏洞扫描 API

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use argus_core::entity::task::{self, Entity as ScanTaskEntity, TaskStatus, TaskType, LaunchMode};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use argus_scanner::{ScanConfig, Target};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct VulnScanRequest {
    pub hosts: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub mode: Option<String>,  // active / passive / hybrid
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
}

pub async fn scan_vuln(
    data: web::Data<AppState>,
    body: web::Json<VulnScanRequest>,
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
        name: Set(format!("vuln-scan-{}", &task_id[..8])),
        task_type: Set(TaskType::VulnDetect),
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

    let _mode = match body.mode.as_deref().unwrap_or("hybrid") {
        "active" => argus_sysvuln::ScanMode::Active,
        "passive" => argus_sysvuln::ScanMode::Passive,
        _ => argus_sysvuln::ScanMode::Hybrid,
    };

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(10),
        timeout_secs: body.timeout_ms.unwrap_or(5000) / 1000,
        extra_params: serde_json::json!({"mode": body.mode.clone().unwrap_or_default()}),
    };

    let scanner = match data.registry.get("vulnerability_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "漏洞扫描引擎未注册"}));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("漏洞扫描失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };
        // 保存 active 发现
        for vuln in &result.vulnerabilities {
            let model = scan_result::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                task_id: Set(task_id_bg.clone()),
                result_type: Set(ResultType::VulnDetect),
                host: Set(vuln.target.clone()),
                port: Set(vuln.port.map(|p| p as i32)),
                protocol: Set(None),
                state: Set(Some("vulnerable".to_string())),
                service: Set(vuln.service.clone()),
                banner: Set(None),
                username: Set(None),
                password: Set(None),
                success: Set(Some(true)),
                response_time_ms: Set(None),
                raw_data: Set(Some(serde_json::to_value(vuln).unwrap_or_default())),
                created_at: Set(chrono::Utc::now()),
            };
            let _ = model.insert(&db).await;
        }
        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "status": "running",
        "message": "漏洞扫描已提交，使用 GET /api/v1/scan/vuln/report/{task_id} 查询报告"
    }))
}

pub async fn get_vuln_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(&task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::VulnDetect))
        .all(&data.db).await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("查询失败: {e}")})),
    };
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "count": results.len(), "findings": results}))
}

pub async fn get_vuln_findings(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(&task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::VulnDetect))
        .all(&data.db).await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("查询失败: {e}")})),
    };
    let findings: Vec<serde_json::Value> = results.into_iter().map(|r| {
        r.raw_data.unwrap_or(serde_json::Value::Null)
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "findings": findings}))
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

// ==================== 漏洞模板管理 ====================

use argus_core::entity::vuln_template::{self, Entity as VulnTemplateEntity, Severity};
use argus_core::entity::vuln_tag::{self, Entity as VulnTagEntity};
use argus_core::entity::vuln_template_tag::{self, Entity as VulnTemplateTagEntity};
use sea_orm::{PaginatorTrait, QueryOrder, QuerySelect, JoinType, RelationTrait};

/// 漏洞模板创建/更新请求
#[derive(Debug, Deserialize)]
pub struct VulnTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub cve: Option<String>,
    pub category: Option<String>,
    pub plugin_type: Option<String>,
    pub target_type: Option<String>,
    pub poc_content: Option<String>,
    pub match_rule: Option<String>,
    pub fix_advice: Option<String>,
    pub enabled: Option<bool>,
}

/// 解析严重程度
fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => Err(format!("无效的严重程度: {s}")),
    }
}

/// 漏洞模板列表 GET /api/v1/risk/vuln-templates
/// 支持多维检索：name（名称模糊）、cve（CVE 模糊）、severity（严重程度）、
/// category（分类）、target_type（目标类型）、enabled（启用状态）、tag_id（标签 ID）
pub async fn list_vuln_templates(
    data: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let page: u64 = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: u64 = query.get("page_size").and_then(|v| v.parse().ok()).unwrap_or(20);

    let mut q = VulnTemplateEntity::find();
    if let Some(severity) = query.get("severity") {
        q = q.filter(vuln_template::Column::Severity.eq(severity.as_str()));
    }
    if let Some(category) = query.get("category") {
        q = q.filter(vuln_template::Column::Category.eq(category.as_str()));
    }
    if let Some(target_type) = query.get("target_type") {
        q = q.filter(vuln_template::Column::TargetType.eq(target_type.as_str()));
    }
    if let Some(enabled) = query.get("enabled") {
        q = q.filter(vuln_template::Column::Enabled.eq(enabled == "true"));
    }
    if let Some(name) = query.get("name") {
        q = q.filter(vuln_template::Column::Name.contains(name.as_str()));
    }
    if let Some(cve) = query.get("cve") {
        q = q.filter(vuln_template::Column::Cve.contains(cve.as_str()));
    }
    // 按标签 ID 筛选：通过 JOIN vuln_template_tags 关联表
    if let Some(tag_id) = query.get("tag_id") {
        q = q
            .join(JoinType::InnerJoin, vuln_template_tag::Relation::VulnTemplate.def())
            .filter(vuln_template_tag::Column::TagId.eq(tag_id.as_str()));
    }

    let paginator = q
        .order_by_desc(vuln_template::Column::CreatedAt)
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

/// 漏洞模板详情 GET /api/v1/risk/vuln-templates/{id}
pub async fn get_vuln_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match VulnTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "模板不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建漏洞模板 POST /api/v1/risk/vuln-templates
pub async fn create_vuln_template(
    data: web::Data<AppState>,
    body: web::Json<VulnTemplateRequest>,
) -> impl Responder {
    let severity = match parse_severity(&body.severity) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    let now = chrono::Utc::now();
    let id = uuid::Uuid::new_v4().to_string();

    let active = vuln_template::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        description: Set(body.description.clone()),
        severity: Set(severity),
        cve: Set(body.cve.clone()),
        category: Set(body.category.clone()),
        plugin_type: Set(body.plugin_type.clone()),
        target_type: Set(body.target_type.clone()),
        poc_content: Set(body.poc_content.clone()),
        match_rule: Set(body.match_rule.clone()),
        fix_advice: Set(body.fix_advice.clone()),
        enabled: Set(body.enabled.unwrap_or(true)),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match active.insert(&data.db).await {
        Ok(t) => HttpResponse::Ok().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新漏洞模板 PUT /api/v1/risk/vuln-templates/{id}
pub async fn update_vuln_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VulnTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match VulnTemplateEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "模板不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let severity = match parse_severity(&body.severity) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    };

    let mut active: vuln_template::ActiveModel = existing.into();
    active.name = Set(body.name.clone());
    active.description = Set(body.description.clone());
    active.severity = Set(severity);
    active.cve = Set(body.cve.clone());
    active.category = Set(body.category.clone());
    active.plugin_type = Set(body.plugin_type.clone());
    active.target_type = Set(body.target_type.clone());
    active.poc_content = Set(body.poc_content.clone());
    active.match_rule = Set(body.match_rule.clone());
    active.fix_advice = Set(body.fix_advice.clone());
    active.enabled = Set(body.enabled.unwrap_or(true));
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(t) => HttpResponse::Ok().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除漏洞模板 DELETE /api/v1/risk/vuln-templates/{id}
pub async fn delete_vuln_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match VulnTemplateEntity::delete_by_id(id).exec(&data.db).await {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已删除"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "模板不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 启用/禁用模板 PATCH /api/v1/risk/vuln-templates/{id}/toggle
pub async fn toggle_vuln_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match VulnTemplateEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "模板不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: vuln_template::ActiveModel = existing.clone().into();
    active.enabled = Set(!existing.enabled);
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(t) => HttpResponse::Ok().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 漏洞标签管理（7.5） ====================

/// 标签创建/更新请求
#[derive(Debug, Deserialize)]
pub struct VulnTagRequest {
    pub name: String,
    pub color: Option<String>,
    pub description: Option<String>,
}

/// 标签列表 GET /api/v1/risk/vuln-tags
pub async fn list_vuln_tags(
    data: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let page: u64 = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: u64 = query.get("page_size").and_then(|v| v.parse().ok()).unwrap_or(50);

    let mut q = VulnTagEntity::find();
    if let Some(name) = query.get("name") {
        q = q.filter(vuln_tag::Column::Name.contains(name.as_str()));
    }

    let paginator = q
        .order_by_asc(vuln_tag::Column::Name)
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

/// 标签详情 GET /api/v1/risk/vuln-tags/{id}
pub async fn get_vuln_tag(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match VulnTagEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "标签不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建标签 POST /api/v1/risk/vuln-tags
pub async fn create_vuln_tag(
    data: web::Data<AppState>,
    body: web::Json<VulnTagRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let active = vuln_tag::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        color: Set(body.color.clone()),
        description: Set(body.description.clone()),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match active.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新标签 PUT /api/v1/risk/vuln-tags/{id}
pub async fn update_vuln_tag(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<VulnTagRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match VulnTagEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "标签不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    if existing.is_builtin {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "内置标签不允许修改"}));
    }
    let mut active: vuln_tag::ActiveModel = existing.into();
    active.name = Set(body.name.clone());
    active.color = Set(body.color.clone());
    active.description = Set(body.description.clone());
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(t) => HttpResponse::Ok().json(t),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除标签 DELETE /api/v1/risk/vuln-tags/{id}
pub async fn delete_vuln_tag(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match VulnTagEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "标签不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    if existing.is_builtin {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "内置标签不允许删除"}));
    }
    // 删除标签前先清理关联表
    let _ = VulnTemplateTagEntity::delete_many()
        .filter(vuln_template_tag::Column::TagId.eq(&id))
        .exec(&data.db)
        .await;
    match VulnTagEntity::delete_by_id(id).exec(&data.db).await {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已删除"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "标签不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 为漏洞模板打标签 POST /api/v1/risk/vuln-templates/{id}/tags
#[derive(Debug, Deserialize)]
pub struct AssignTagsRequest {
    pub tag_ids: Vec<String>,
}

pub async fn assign_tags_to_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AssignTagsRequest>,
) -> impl Responder {
    let template_id = path.into_inner();
    // 验证模板存在
    if let Ok(None) = VulnTemplateEntity::find_by_id(template_id.clone()).one(&data.db).await {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "漏洞模板不存在"}));
    }
    let now = chrono::Utc::now();
    let mut added = 0usize;
    for tag_id in &body.tag_ids {
        // 检查是否已关联
        let exists = VulnTemplateTagEntity::find()
            .filter(vuln_template_tag::Column::VulnTemplateId.eq(&template_id))
            .filter(vuln_template_tag::Column::TagId.eq(tag_id))
            .one(&data.db)
            .await;
        if matches!(exists, Ok(Some(_))) {
            continue;
        }
        let active = vuln_template_tag::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            vuln_template_id: Set(template_id.clone()),
            tag_id: Set(tag_id.clone()),
            created_at: Set(now),
        };
        if active.insert(&data.db).await.is_ok() {
            added += 1;
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "template_id": template_id,
        "assigned": added,
        "total_requested": body.tag_ids.len(),
    }))
}

/// 移除漏洞模板的标签 DELETE /api/v1/risk/vuln-templates/{id}/tags/{tag_id}
pub async fn remove_tag_from_template(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (template_id, tag_id) = path.into_inner();
    match VulnTemplateTagEntity::delete_many()
        .filter(vuln_template_tag::Column::VulnTemplateId.eq(&template_id))
        .filter(vuln_template_tag::Column::TagId.eq(&tag_id))
        .exec(&data.db)
        .await
    {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已移除标签"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "关联不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 查询漏洞模板的标签列表 GET /api/v1/risk/vuln-templates/{id}/tags
pub async fn list_template_tags(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let template_id = path.into_inner();
    // 通过关联表获取标签 ID 列表
    let links = match VulnTemplateTagEntity::find()
        .filter(vuln_template_tag::Column::VulnTemplateId.eq(&template_id))
        .all(&data.db)
        .await
    {
        Ok(l) => l,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let tag_ids: Vec<String> = links.iter().map(|l| l.tag_id.clone()).collect();
    if tag_ids.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({"template_id": template_id, "tags": []}));
    }
    let tags = match VulnTagEntity::find()
        .filter(vuln_tag::Column::Id.is_in(tag_ids))
        .all(&data.db)
        .await
    {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    HttpResponse::Ok().json(serde_json::json!({
        "template_id": template_id,
        "tags": tags,
    }))
}
