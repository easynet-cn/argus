//! 数据库连接管理

use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;

use crate::config::DatabaseConfig;
use crate::error::CoreError;

/// 建立数据库连接池
pub async fn connect(config: &DatabaseConfig) -> Result<DatabaseConnection, CoreError> {
    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(config.max_connections)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .sqlx_logging(tracing::level_enabled!(tracing::Level::DEBUG));

    let conn = Database::connect(opt).await?;
    tracing::info!(
        "数据库连接池已建立: {} (max_connections={})",
        config.url,
        config.max_connections
    );
    Ok(conn)
}
