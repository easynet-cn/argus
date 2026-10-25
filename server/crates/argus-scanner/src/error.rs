//! 扫描引擎错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("引擎未找到: {0}")]
    EngineNotFound(String),

    #[error("扫描执行错误: {0}")]
    Execution(String),

    #[error("任务取消: {0}")]
    Cancelled(String),

    #[error("配置错误: {0}")]
    Config(String),
}
