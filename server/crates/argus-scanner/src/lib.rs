//! Argus 扫描引擎框架
//!
//! 定义所有扫描引擎的统一接口

pub mod scanner;
pub mod scheduler;
pub mod registry;
mod error;

pub use scanner::{Scanner, ScanConfig, ScanResult, Target, Credentials};
pub use registry::ScannerRegistry;
pub use scheduler::TaskScheduler;
pub use error::ScannerError;
