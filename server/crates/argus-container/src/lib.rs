//! Argus 容器/镜像扫描引擎
//!
//! 功能:
//! - 6.4 Docker 镜像层分析 + 敏感文件检测
//! - 6.5 Harbor 仓库 API 集成
//! - 6.6 镜像依赖漏洞匹配 (OSV/NVD 按 CPE 匹配)

pub mod types;
pub mod image_scan;
pub mod harbor;
pub mod dep_vuln;
pub mod scanner;

pub use types::*;
pub use image_scan::ImageScanner;
pub use harbor::HarborClient;
pub use dep_vuln::DepVulnMatcher;
pub use scanner::ContainerScanner;
