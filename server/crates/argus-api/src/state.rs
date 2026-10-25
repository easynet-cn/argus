//! 应用状态

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use sea_orm::DatabaseConnection;
use argus_scanner::ScannerRegistry;

pub struct AppState {
    pub registry: Arc<ScannerRegistry>,
    pub db: DatabaseConnection,
    /// 已撤销的会话 JTI 集合（内存级快速查询，用于强制下线）
    pub revoked_sessions: Arc<Mutex<HashSet<String>>>,
}
