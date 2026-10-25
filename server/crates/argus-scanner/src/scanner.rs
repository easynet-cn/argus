//! 扫描引擎核心 trait

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;

/// 扫描目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub ports: Option<Vec<u16>>,
    pub credentials: Option<Credentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub auth_type: Option<String>,
}

/// 扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub task_id: String,
    pub targets: Vec<Target>,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub extra_params: serde_json::Value,
}

/// 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub task_id: String,
    pub status: TaskStatus,
    pub hosts_scanned: usize,
    pub vulnerabilities: Vec<PluginResult>,
    pub duration_secs: f64,
    pub raw_data: Option<serde_json::Value>,
}

/// 扫描引擎统一接口
///
/// 所有扫描引擎（端口扫描、口令猜解、基线核查等）实现此 trait
#[async_trait]
pub trait Scanner: Send + Sync {
    /// 引擎名称
    fn name(&self) -> &str;

    /// 引擎版本
    fn version(&self) -> &str;

    /// 执行扫描
    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, crate::ScannerError>;

    /// 查询任务进度 (0.0 - 1.0)
    async fn progress(&self, task_id: &str) -> Result<f32, crate::ScannerError>;

    /// 取消任务
    async fn cancel(&self, task_id: &str) -> Result<(), crate::ScannerError>;
}
