//! Argus 核心领域模型
//! 包含资产、漏洞、任务、报告、用户等实体定义 + 数据库迁移管理 + 连接池 + 认证

pub mod entity;
pub mod error;
pub mod config;
pub mod db;
pub mod auth;
pub mod crypto;
pub mod migration;
pub mod scan_param_config;

pub use error::CoreError;
pub use db::connect as db_connect;
pub use migration::{Migrator, run_migrations, rollback_migration, refresh_database, reset_database};
