//! API 处理函数

pub mod auth;
pub mod system;
pub mod asset;
pub mod task;
pub mod scan;
pub mod fingerprint;
pub mod ics_device_library;
pub mod vuln;
pub mod vulndb;
pub mod template;
pub mod ics;
pub mod container;
pub mod node;
pub mod trend;
pub mod credential;
pub mod asset_group;
pub mod discovery;
pub mod risk;
pub mod audit;
pub mod admin;
pub mod alert;
pub mod diagnostic;
pub mod config_change;
pub mod report;
pub mod license;
pub mod upgrade;
pub mod dashboard;

use actix_web::{web, HttpResponse, Responder};
use sea_orm::ConnectionTrait;
use crate::state::AppState;

/// 健康检查（含数据库连通性）GET /api/v1/health
pub async fn health(data: web::Data<AppState>) -> impl Responder {
    let db_ok = data.db.execute_unprepared("SELECT 1").await.is_ok();
    let db_status = if db_ok { "ok" } else { "error" };
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "argus",
        "version": env!("CARGO_PKG_VERSION"),
        "database": db_status,
    }))
}
