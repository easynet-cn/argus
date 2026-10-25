//! 任务调度器
//!
//! 管理扫描任务的生命周期

use std::sync::Arc;
use crate::scanner::{Scanner, ScanConfig, ScanResult};
use crate::registry::ScannerRegistry;

pub struct TaskScheduler {
    registry: Arc<ScannerRegistry>,
}

impl TaskScheduler {
    pub fn new(registry: Arc<ScannerRegistry>) -> Self {
        Self { registry }
    }

    pub async fn dispatch(
        &self,
        engine_name: &str,
        config: ScanConfig,
    ) -> Result<ScanResult, crate::ScannerError> {
        let scanner = self.registry.get(engine_name)
            .ok_or_else(|| crate::ScannerError::EngineNotFound(engine_name.to_string()))?;

        tracing::info!("调度任务 {} 到引擎 {}", config.task_id, engine_name);
        scanner.execute(&config).await
    }
}
