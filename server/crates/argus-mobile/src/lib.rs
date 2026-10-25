//! Argus 移动安全扫描引擎
//!
//! Phase 7.1-7.4: 移动扫描
//! - APK 解析 (ZIP + DEX + AndroidManifest.xml AXML)
//! - Android 组件安全检测 (Activity/Service/Receiver/Provider)
//! - Android 配置安全检测 (allowBackup/debuggable/cleartext/permissions)
//! - G7.1: iOS IPA 应用扫描 (Info.plist + embedded.mobileprovision + Mach-O)
//! - G7.2: HarmonyOS HAP 应用扫描 (module.json / config.json + 危险权限)
//! - G7.3: 数据安全检测 (DEX 字符串 / SharedPreferences / SQLite 明文敏感数据)
//! - G7.4: 恶意行为检测 (DEX 字节码 SmsManager/CallLog/Contacts 等危险 API 调用分析)

pub mod types;
pub mod axml;
pub mod dex;
pub mod apk;
pub mod component_check;
pub mod config_check;
pub mod scanner;

pub mod ios_scan;
pub mod harmonyos_scan;
pub mod data_security;
pub mod malicious_behavior;

pub use types::*;
pub use apk::{ApkParser, ApkError};
pub use axml::{AxmlNode, AxmlError, parse_axml};
pub use dex::{DexInfo, DexHeader, parse_dex, DexError};
pub use component_check::ComponentChecker;
pub use config_check::ConfigChecker;
pub use scanner::MobileScanner;

// G7.1: iOS IPA 扫描
pub use ios_scan::{IosScanner, IosScanResult, IpaInfo, ProvisioningProfile, IosScanError};
// G7.2: HarmonyOS HAP 扫描
pub use harmonyos_scan::{
    HarmonyScanner, HarmonyScanResult, HapInfo, HapPermission, HapAbility, HarmonyScanError,
};
// G7.3: 数据安全检测
pub use data_security::{DataSecurityScanner, DataSecurityResult, DataSecurityError};
// G7.4: 恶意行为检测
pub use malicious_behavior::{
    MaliciousBehaviorScanner, MaliciousScanResult, BehaviorSummary, MaliciousScanError,
};
