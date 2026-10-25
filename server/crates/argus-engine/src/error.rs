//! 插件引擎错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("模板解析错误: {0}")]
    TemplateParse(String),

    #[error("脚本执行错误: {0}")]
    ScriptExec(String),

    #[error("WASM 执行错误: {0}")]
    WasmExec(String),

    #[error("插件未找到: {0}")]
    NotFound(String),

    #[error("沙箱违规: {0}")]
    SandboxViolation(String),

    #[error("超时")]
    Timeout,
}
