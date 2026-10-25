//! Argus Web API
//!
//! 基于 actix-web 的 RESTful API 服务

pub mod handler;
pub mod route;
pub mod state;
pub mod middleware;
pub mod scheduler;

pub use state::AppState;

use actix_web::{web, App, HttpServer};
use std::sync::Arc;
use std::collections::HashSet;
use std::sync::Mutex;
use argus_core::{config::AppConfig, db_connect};
use argus_scanner::ScannerRegistry;
use argus_portscanner::PortScanner;
use argus_bruteforce::BruteForce;
use argus_baseline::BaselineScanner;
use argus_fingerprint::FingerprintScanner;
use argus_sysvuln::VulnerabilityScanner;
use argus_ics::IcsScanner;
use argus_container::ContainerScanner;
// P0 #7: 补注册三个适配器，修复统一扫描执行链路
use argus_mobile::MobileScanner;
use argus_webscan::WebScanner;
use argus_sysvuln::{DbScanner, VulnVerifyScanner};
use middleware::AuthMiddleware;

/// 启动 API 服务（使用环境变量配置）
pub async fn run_server() -> std::io::Result<()> {
    let config = AppConfig::from_env();
    run_server_with_config(&config).await
}

/// 使用指定配置启动 API 服务
pub async fn run_server_with_config(config: &AppConfig) -> std::io::Result<()> {
    // 建立数据库连接
    let db = db_connect(&config.database).await
        .map_err(|e| {
            tracing::error!("数据库连接失败: {e}");
            std::io::Error::new(std::io::ErrorKind::Other, format!("数据库连接失败: {e}"))
        })?;

    // 执行迁移（自动建表）
    argus_core::run_migrations(&db).await
        .map_err(|e| {
            tracing::error!("数据库迁移失败: {e}");
            std::io::Error::new(std::io::ErrorKind::Other, format!("数据库迁移失败: {e}"))
        })?;

    // 创建并注册扫描引擎
    let mut registry = ScannerRegistry::new();
    registry.register(Arc::new(PortScanner::new()));
    registry.register(Arc::new(BruteForce::new()));
    registry.register(Arc::new(BaselineScanner::new()));
    registry.register(Arc::new(FingerprintScanner::new()));
    registry.register(Arc::new(VulnerabilityScanner::default()));
    registry.register(Arc::new(IcsScanner::new()));
    registry.register(Arc::new(ContainerScanner::new()));
    // P0 #7: 补注册 MobileScanner/WebScanner/DbScanner/VulnVerifyScanner
    // 修正统一扫描 scanner_key 映射：system→vulnerability_scanner / mobile→mobile_scanner
    // / application→app_scanner / database→db_scanner / vuln_verify→vuln_verify_scanner
    registry.register(Arc::new(MobileScanner::new()));
    registry.register(Arc::new(WebScanner::new()));
    registry.register(Arc::new(DbScanner::new()));
    registry.register(Arc::new(VulnVerifyScanner::new()));
    let registry = Arc::new(registry);

    let state = web::Data::new(AppState {
        registry,
        db,
        revoked_sessions: Arc::new(Mutex::new(HashSet::new())),
    });
    let config_data = web::Data::new(config.clone());
    let auth_middleware = AuthMiddleware::new(config.clone());

    // 启动任务调度后台循环（定时/周期任务）
    let scheduler_db = state.db.clone();
    tokio::spawn(async move {
        scheduler::run_scheduler(scheduler_db).await;
    });

    let host = config.server.host.clone();
    let port = config.server.port;
    tracing::info!("Argus API 监听 {}:{}", host, port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(config_data.clone())
            .wrap(auth_middleware.clone())
            .configure(route::configure_routes)
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
