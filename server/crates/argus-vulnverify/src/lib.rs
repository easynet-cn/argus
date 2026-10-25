//! Argus 漏洞验证引擎
//!
//! Phase 7.4-7.7: 漏洞验证
//! - HTTP 重放引擎（构造请求 + 捕获响应）
//! - SQL 注入利用验证（基于错误/布尔盲注/时间盲注）
//! - 命令执行验证（命令注入回显）
//! - 文件读取验证（路径遍历/任意文件读取）
//! - 浏览器验证模式（G7.5：headless Chrome 渲染验证 XSS 等）

pub mod types;
pub mod engine;
pub mod sqli;
pub mod cmd_exec;
pub mod file_read;
pub mod browser_verify;

pub use types::*;
pub use engine::{VerifyEngine, EngineError};
pub use sqli::SqliVerifier;
pub use cmd_exec::CmdExecVerifier;
pub use file_read::FileReadVerifier;
pub use browser_verify::{BrowserVerifier, BrowserVerifyConfig, BrowserVerifyError, RenderedPage};
