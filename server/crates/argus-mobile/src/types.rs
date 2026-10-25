//! 移动安全扫描类型定义

use serde::{Deserialize, Serialize};

/// APK 解析结果
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApkInfo {
    /// 包名 (package)
    pub package: String,
    /// 版本名 (versionName)
    pub version_name: String,
    /// 版本号 (versionCode)
    pub version_code: i64,
    /// 最低 SDK 版本
    pub min_sdk: i32,
    /// 目标 SDK 版本
    pub target_sdk: i32,
    /// 编译 SDK 版本
    pub compile_sdk: i32,
    /// 应用标签
    pub app_name: String,
    /// 主 Activity
    pub main_activity: Option<String>,
    /// DEX 文件列表
    pub dex_files: Vec<DexFileInfo>,
    /// 权限列表
    pub permissions: Vec<String>,
    /// Android 组件
    pub components: AndroidComponents,
    /// 元数据
    pub meta_data: std::collections::HashMap<String, String>,
    /// 文件大小 (bytes)
    pub file_size: u64,
    /// 签名信息
    pub signatures: Vec<SignatureInfo>,
}

/// DEX 文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFileInfo {
    /// 文件路径 (如 classes.dex, classes2.dex)
    pub path: String,
    /// 文件大小
    pub size: u64,
    /// 类数量
    pub class_count: u32,
    /// 方法数量
    pub method_count: u32,
}

/// Android 四大组件集合
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AndroidComponents {
    pub activities: Vec<ComponentInfo>,
    pub services: Vec<ComponentInfo>,
    pub receivers: Vec<ComponentInfo>,
    pub providers: Vec<ComponentInfo>,
}

/// 组件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// 组件名 (完整类名)
    pub name: String,
    /// 是否导出
    pub exported: bool,
    /// 权限
    pub permission: Option<String>,
    /// Intent Filter 数量
    pub intent_filters: Vec<IntentFilter>,
    /// 是否有 LAUNCHER Intent
    pub has_launcher: bool,
    /// 是否是主 Activity
    pub is_main: bool,
    /// taskAffinity 属性（R7.2: 劫持风险检测）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_affinity: Option<String>,
}

/// Intent Filter
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
}

/// 签名信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// 签名算法
    pub algorithm: String,
    /// 证书指纹 (SHA-256)
    pub cert_fingerprint: String,
    /// 颁发者
    pub issuer: String,
    /// 主体
    pub subject: String,
    /// 有效期起始
    pub not_before: String,
    /// 有效期截止
    pub not_after: String,
}

/// 移动安全扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileScanResult {
    /// APK 信息
    pub apk_info: ApkInfo,
    /// 组件安全检测结果
    pub component_findings: Vec<MobileFinding>,
    /// 配置安全检测结果
    pub config_findings: Vec<MobileFinding>,
    /// 漏洞总数
    pub total_vulns: usize,
}

/// 移动安全发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileFinding {
    /// 漏洞 ID
    pub id: String,
    /// 标题
    pub title: String,
    /// 严重级别 (critical/high/medium/low/info)
    pub severity: String,
    /// 分类 (component/config)
    pub category: String,
    /// 描述
    pub description: String,
    /// 证据 (组件名/配置项)
    pub evidence: String,
    /// 修复建议
    pub fix_advice: String,
}

/// 移动扫描参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileScanParams {
    /// APK/IPA 文件路径
    pub apk_path: String,
    /// 是否检测组件
    pub scan_components: bool,
    /// 是否检测配置
    pub scan_config: bool,
    /// 平台类型: android（默认）/ ios
    ///
    /// 6.8：区分 Android APK 和 iOS IPA 扫描
    #[serde(default)]
    pub platform: String,
    /// 检测项配置（6.8 检测项选择）
    ///
    /// 指定后仅执行列出的检测项。可选值：
    /// - android: permissions, components, config, dex, manifest, network
    /// - ios: info_plist, entitlements, binary_protections, sensitive_data, transport_security
    /// 未指定时执行全部检测项。
    #[serde(default)]
    pub check_items: Option<Vec<String>>,
}

impl Default for MobileScanParams {
    fn default() -> Self {
        Self {
            apk_path: String::new(),
            scan_components: true,
            scan_config: true,
            platform: "android".to_string(),
            check_items: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_scan_params_default() {
        let p = MobileScanParams::default();
        assert!(p.scan_components);
        assert!(p.scan_config);
    }

    #[test]
    fn test_component_info_new() {
        let c = ComponentInfo {
            name: "com.example.MainActivity".to_string(),
            exported: true,
            permission: None,
            intent_filters: vec![],
            has_launcher: true,
            is_main: true,
            task_affinity: None,
        };
        assert!(c.exported);
        assert!(c.is_main);
    }
}
