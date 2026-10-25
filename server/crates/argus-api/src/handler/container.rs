//! 容器扫描 API

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use argus_core::entity::task::{self, Entity as ScanTaskEntity, TaskStatus, TaskType, LaunchMode};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use argus_scanner::{ScanConfig, Target};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ContainerScanRequest {
    pub image: String,
    pub harbor_url: Option<String>,
    pub harbor_username: Option<String>,
    pub harbor_password: Option<String>,
    pub scan_vulns: Option<bool>,
    pub scan_sensitive: Option<bool>,
}

pub async fn scan_container(
    data: web::Data<AppState>,
    body: web::Json<ContainerScanRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("container-scan-{}", &task_id[..8])),
        task_type: Set(TaskType::IcsScan), // 复用 IcsScan 类型
        status: Set(TaskStatus::Running),
        launch_mode: Set(LaunchMode::Manual),
        targets: Set(serde_json::to_value(&body.image).unwrap_or_default()),
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

    let extra_params = serde_json::json!({
        "image": body.image,
        "harbor_url": body.harbor_url,
        "harbor_username": body.harbor_username,
        "harbor_password": body.harbor_password,
        "scan_vulns": body.scan_vulns.unwrap_or(true),
        "scan_sensitive": body.scan_sensitive.unwrap_or(true),
    });

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets: vec![Target {
            host: body.image.clone(),
            ports: None,
            credentials: None,
        }],
        concurrency: 1,
        timeout_secs: 30,
        extra_params,
    };

    let scanner = match data.registry.get("container_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "容器扫描引擎未注册"}));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("容器扫描失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };
        // 保存扫描结果
        let now = chrono::Utc::now();
        let model = scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id_bg.clone()),
            result_type: Set(ResultType::IcsScan),
            host: Set("container".to_string()),
            port: Set(None),
            protocol: Set(None),
            state: Set(None),
            service: Set(None),
            banner: Set(None),
            username: Set(None),
            password: Set(None),
            success: Set(None),
            response_time_ms: Set(Some((result.duration_secs * 1000.0) as i64)),
            raw_data: Set(Some(result.raw_data.unwrap_or(serde_json::Value::Null))),
            created_at: Set(now),
        };
        if let Err(e) = ScanResultEntity::insert(model).exec(&db).await {
            tracing::error!("保存容器扫描结果失败: {e}");
        }
        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "status": "running",
        "message": "容器扫描已提交，使用 GET /api/v1/scan/container/report/{task_id} 查询报告"
    }))
}

pub async fn get_container_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(&task_id))
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
