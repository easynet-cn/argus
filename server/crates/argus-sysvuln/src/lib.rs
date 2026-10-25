//! Argus 系统漏洞检测引擎
//!
//! 插件运行时 + CPE 匹配 + Top 500 漏洞模板
//!
//! 支持两种扫描模式：
//! - Active：主动模板探测（发送 HTTP 请求 + 响应匹配）
//! - Passive：被动 CPE 匹配（基于指纹 + CVE 知识库）

pub mod types;
pub mod host_api_impl;
pub mod runtime;
pub mod cpe_matcher;
pub mod template_loader;
pub mod scanner;
pub mod db_vuln;
pub mod db_scanner;
// G6.5 数据库登录扫描（认证后执行审计 SQL 查询）
pub mod db_auth_scan;
pub mod verify_scanner;
// G4.1: IoT 设备漏洞检测 / G4.2: 大数据组件漏洞检测 / G4.4: 网络设备漏洞检测
pub mod iot_vuln;
pub mod bigdata_vuln;
pub mod network_device_vuln;
// G4.3: 安全设备漏洞检测 / G4.8: 危险漏洞插件（DoS 类）
pub mod security_device_vuln;
pub mod dos_vuln;
// G4.5: OpenSSH 版本扫描 / G4.6: 网站漏洞联动扫描
pub mod ssh_version;
pub mod web_linkage;

pub use types::*;
pub use scanner::VulnerabilityScanner;
pub use db_scanner::DbScanner;
pub use verify_scanner::VulnVerifyScanner;
pub use host_api_impl::DefaultHostApi;
pub use runtime::VulnPluginRuntime;
pub use template_loader::TemplateLoader;
pub use db_vuln::{DbVulnScanner, DbVulnFinding, DbType};
pub use iot_vuln::{IoTDeviceScanner, IoTDeviceFinding, IoTDeviceType};
pub use bigdata_vuln::{BigDataVulnScanner, BigDataVulnFinding, BigDataComponent};
pub use network_device_vuln::{NetworkDeviceScanner, NetworkDeviceFinding, NetworkDeviceVendor};
pub use security_device_vuln::{SecurityDeviceScanner, SecurityDeviceFinding, SecurityDeviceType};
pub use dos_vuln::{DosScanner, DosFinding, DosPluginType};
pub use ssh_version::{SshVersionFinding, SshCveInfo, scan_ssh_version};
pub use web_linkage::{WebScanTarget, PortScanResultItem, extract_web_targets, WebLinkageConfig};
