//! 工控扫描 API

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use argus_core::entity::task::{self, Entity as ScanTaskEntity, TaskStatus, TaskType, LaunchMode};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use argus_scanner::{ScanConfig, Target};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set};
use crate::state::AppState;

/// 工控扫描模式
///
/// 6.2：
/// - remote: 远程扫描（主动发包探测各工控协议端口）
/// - non_invasive: 无损扫描（零发包指纹匹配，只读取设备信息不修改状态）
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IcsScanMode {
    Remote,
    NonInvasive,
}

/// 工控扫描请求（扩展版）
#[derive(Debug, Deserialize, Serialize)]
pub struct IcsScanRequest {
    pub hosts: Vec<String>,
    pub ports: Option<Vec<u16>>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    /// 扫描模式: remote（远程主动扫描，默认）/ non_invasive（无损扫描）
    pub scan_mode: Option<IcsScanMode>,
    /// 工控协议选择（为空则扫描全部协议）
    ///
    /// 合法值: modbus / s7 / iec104 / profinet-dcp / melsec / fins / hart-ip / fieldbus-hse
    pub protocols: Option<Vec<String>>,
}

pub async fn scan_ics(
    data: web::Data<AppState>,
    body: web::Json<IcsScanRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let scan_mode_str = match &body.scan_mode {
        Some(IcsScanMode::NonInvasive) => "non_invasive",
        _ => "remote",
    };

    let targets: Vec<Target> = body.hosts.iter().map(|h| Target {
        host: h.clone(),
        ports: body.ports.clone().or_else(|| Some(vec![502, 102, 2404])),
        credentials: None,
    }).collect();

    let params = serde_json::json!({
        "scan_mode": scan_mode_str,
        "protocols": body.protocols.clone().unwrap_or_default(),
    });

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("ics-scan-{}-{}", scan_mode_str, &task_id[..8])),
        task_type: Set(TaskType::IcsScan),
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
        params: Set(Some(params)),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("创建任务失败: {e}")}));
    }

    // 无损模式：直接调用 NonIntrusiveScanner，不经过 scanner registry
    let is_non_invasive = matches!(body.scan_mode, Some(IcsScanMode::NonInvasive));
    let timeout_ms = body.timeout_ms.unwrap_or(3000);
    let protocols = body.protocols.clone();

    if is_non_invasive {
        let db = data.db.clone();
        let task_id_bg = task_id.clone();
        let hosts = body.hosts.clone();
        tokio::spawn(async move {
            use argus_ics::nonintrusive::NonIntrusiveScanner;
            let scanner = NonIntrusiveScanner::new().with_timeout(timeout_ms);
            let mut all_results: Vec<argus_ics::nonintrusive::NonIntrusiveScanResult> = Vec::new();

            for host in &hosts {
                let result = scanner.scan_host(host).await;
                tracing::info!("无损扫描 {} 完成: {} 设备, {} 发现", host, result.devices.len(), result.findings.len());
                all_results.push(result);
            }

            // 保存结果
            if let Err(e) = save_nonintrusive_results(&db, &task_id_bg, &all_results, &protocols).await {
                tracing::error!("保存无损扫描结果失败: {e}");
            }
            let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
        });

        return HttpResponse::Accepted().json(serde_json::json!({
            "task_id": task_id,
            "scan_mode": scan_mode_str,
            "status": "running",
            "message": "工控无损扫描已提交，使用 GET /api/v1/scan/ics/report/{task_id} 查询报告"
        }));
    }

    // 远程模式：使用 scanner registry
    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(50),
        timeout_secs: timeout_ms / 1000,
        extra_params: serde_json::json!({
            "scan_mode": scan_mode_str,
            "protocols": body.protocols.clone().unwrap_or_default(),
        }),
    };

    let scanner = match data.registry.get("ics_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "工控扫描引擎未注册"}));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("工控扫描失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };
        let ics_results: Vec<argus_ics::IcsScanResult> = result.raw_data
            .as_ref()
            .and_then(|raw| serde_json::from_value(raw.clone()).ok())
            .unwrap_or_default();
        if let Err(e) = save_ics_results(&db, &task_id_bg, &ics_results).await {
            tracing::error!("保存工控结果失败: {e}");
        }
        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "scan_mode": scan_mode_str,
        "status": "running",
        "message": "工控远程扫描已提交，使用 GET /api/v1/scan/ics/report/{task_id} 查询报告"
    }))
}

/// 保存无损扫描结果
async fn save_nonintrusive_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    results: &[argus_ics::nonintrusive::NonIntrusiveScanResult],
    _protocols_filter: &Option<Vec<String>>,
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let mut models: Vec<scan_result::ActiveModel> = Vec::new();

    for r in results {
        // 保存设备信息
        for dev in &r.devices {
            models.push(scan_result::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                task_id: Set(task_id.to_string()),
                result_type: Set(ResultType::IcsScan),
                host: Set(dev.host.clone()),
                port: Set(Some(dev.port as i32)),
                protocol: Set(Some(dev.protocol.as_str().to_string())),
                state: Set(Some("identified".to_string())),
                service: Set(Some(dev.vendor.clone().unwrap_or_default())),
                banner: Set(Some(serde_json::to_string(dev).unwrap_or_default())),
                username: Set(None),
                password: Set(None),
                success: Set(Some(true)),
                response_time_ms: Set(None),
                raw_data: Set(Some(serde_json::to_value(dev).unwrap_or_default())),
                created_at: Set(now),
            });
        }
        // 保存发现项
        for f in &r.findings {
            models.push(scan_result::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                task_id: Set(task_id.to_string()),
                result_type: Set(ResultType::IcsScan),
                host: Set(r.host.clone()),
                port: Set(None),
                protocol: Set(None),
                state: Set(Some(f.severity.clone())),
                service: Set(Some(f.protocol.clone())),
                banner: Set(Some(f.description.clone())),
                username: Set(None),
                password: Set(None),
                success: Set(None),
                response_time_ms: Set(None),
                raw_data: Set(Some(serde_json::to_value(f).unwrap_or_default())),
                created_at: Set(now),
            });
        }
    }

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

async fn save_ics_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    results: &[argus_ics::IcsScanResult],
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = results.iter().flat_map(|r| {
        r.devices.iter().map(|d| scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id.to_string()),
            result_type: Set(ResultType::IcsScan),
            host: Set(r.host.clone()),
            port: Set(Some(d.protocol.port() as i32)),
            protocol: Set(Some(d.protocol.as_str().to_string())),
            state: Set(Some("ics_device".to_string())),
            service: Set(d.device_type.clone()),
            banner: Set(d.vendor.clone()),
            username: Set(None),
            password: Set(None),
            success: Set(None),
            response_time_ms: Set(None),
            raw_data: Set(Some(serde_json::to_value(d).unwrap_or_default())),
            created_at: Set(now),
        })
    }).collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

pub async fn get_ics_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(&task_id))
        .filter(scan_result::Column::ResultType.eq(ResultType::IcsScan))
        .all(&data.db).await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("查询失败: {e}")})),
    };
    HttpResponse::Ok().json(serde_json::json!({"task_id": task_id, "count": results.len(), "devices": results}))
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
