//! Argus 指纹识别引擎
//!
//! 服务指纹（banner 解析 + 版本提取 + CPE 生成）
//! OS 指纹（TTL 推测 + banner 线索）
//! Web 应用指纹（框架检测）

pub mod types;
pub mod service;
pub mod os_detect;
pub mod web_fingerprint;
pub mod signature_db;
pub mod scanner;

pub use types::*;
pub use scanner::FingerprintScanner;
pub use signature_db::{ServiceSignatureDb, WebAppSignatureDb, OsSignatureDb};
