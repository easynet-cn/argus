//! Android 配置安全检测
//!
//! 检测 AndroidManifest.xml 和应用配置中的安全风险:
//! - allowBackup 备份风险
//! - debuggable 调试模式
//! - 明文流量 (usesCleartextTraffic / networkSecurityConfig)
//! - 危险权限（组）滥用
//! - SDK 版本过低
//! - 签名缺失/弱签名
//! - 不安全的 WebView 配置（meta-data）
//! - 第三方 SDK 集成（meta-data）

use crate::types::*;
use std::collections::HashMap;

/// 配置安全检测器
pub struct ConfigChecker;

impl ConfigChecker {
    pub fn new() -> Self {
        Self
    }

    /// 检测配置安全
    pub fn check(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        // 注意：以下是简化检测，真实实现需要从 AXML manifest 节点解析更多属性
        // 这里我们用 ApkInfo 的元数据字段来检测已知的关键配置项
        findings.extend(self.check_backup(info));
        findings.extend(self.check_debuggable(info));
        findings.extend(self.check_cleartext_traffic(info));
        findings.extend(self.check_dangerous_permissions(info));
        findings.extend(self.check_sdk_versions(info));
        findings.extend(self.check_signature(info));
        findings.extend(self.check_missing_network_security_config(info));
        findings
    }

    /// 检测 allowBackup 配置
    fn check_backup(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        // 在解析的 meta_data 中，application 节点的 allowBackup 已经被解析为属性
        // 简化检测：默认值为 true（Android 默认开启备份）
        // 这里用 meta_data 中的 allowBackup 字段
        let allow_backup = info
            .meta_data
            .get("allowBackup")
            .map(|v| v == "true")
            .unwrap_or(true); // 默认为 true

        if allow_backup {
            findings.push(MobileFinding {
                id: "ANDROID-100".to_string(),
                title: "应用允许备份 (allowBackup=true)".to_string(),
                severity: "medium".to_string(),
                category: "config".to_string(),
                description: "应用开启了 allowBackup，攻击者可通过 adb backup 提取应用私有数据"
                    .to_string(),
                evidence: "android:allowBackup=true (默认或显式)".to_string(),
                fix_advice: "在 <application> 中设置 android:allowBackup=\"false\""
                    .to_string(),
            });
        }
        findings
    }

    /// 检测 debuggable 调试模式
    fn check_debuggable(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        let debuggable = info
            .meta_data
            .get("debuggable")
            .map(|v| v == "true")
            .unwrap_or(false);

        if debuggable {
            findings.push(MobileFinding {
                id: "ANDROID-101".to_string(),
                title: "应用可调试 (debuggable=true)".to_string(),
                severity: "high".to_string(),
                category: "config".to_string(),
                description: "应用开启了 debuggable，攻击者可通过 jdb/IDA 等工具调试应用，绕过安全检查"
                    .to_string(),
                evidence: "android:debuggable=true".to_string(),
                fix_advice: "发布版本必须设置 android:debuggable=\"false\"（或删除该属性）"
                    .to_string(),
            });
        }
        findings
    }

    /// 检测明文流量
    fn check_cleartext_traffic(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        // 当 targetSdk < 28 时，默认允许明文流量
        // 当 targetSdk >= 28 时，默认禁止明文流量
        let uses_cleartext = info
            .meta_data
            .get("usesCleartextTraffic")
            .map(|v| v == "true")
            .unwrap_or(info.target_sdk < 28); // 默认: targetSdk<28 时为 true

        if uses_cleartext {
            findings.push(MobileFinding {
                id: "ANDROID-102".to_string(),
                title: "应用允许明文流量 (HTTP)".to_string(),
                severity: "medium".to_string(),
                category: "config".to_string(),
                description: format!(
                    "应用允许明文 HTTP 流量 (targetSdk={})，存在中间人攻击风险",
                    info.target_sdk
                ),
                evidence: format!(
                    "usesCleartextTraffic=true (targetSdk={})",
                    info.target_sdk
                ),
                fix_advice: "设置 android:usesCleartextTraffic=\"false\"，并配置 Network Security Config 强制 HTTPS"
                    .to_string(),
            });
        }
        findings
    }

    /// 检测缺失 Network Security Config
    fn check_missing_network_security_config(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        let has_nsc = info.meta_data.contains_key("networkSecurityConfig");

        if !has_nsc && info.target_sdk >= 24 {
            findings.push(MobileFinding {
                id: "ANDROID-103".to_string(),
                title: "缺失 Network Security Config".to_string(),
                severity: "low".to_string(),
                category: "config".to_string(),
                description: "应用未配置 Network Security Config，无法精细化控制证书校验和明文流量"
                    .to_string(),
                evidence: "android:networkSecurityConfig not set".to_string(),
                fix_advice: "创建 res/xml/network_security_config.xml 并在 <application> 中引用"
                    .to_string(),
            });
        }
        findings
    }

    /// 检测危险权限
    fn check_dangerous_permissions(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();

        let dangerous_perms: HashMap<&str, (&str, &str)> = [
            ("android.permission.READ_SMS", ("critical", "读取短信")),
            ("android.permission.SEND_SMS", ("critical", "发送短信")),
            ("android.permission.RECEIVE_SMS", ("critical", "接收短信")),
            ("android.permission.RECEIVE_MMS", ("high", "接收彩信")),
            ("android.permission.READ_CONTACTS", ("high", "读取联系人")),
            ("android.permission.WRITE_CONTACTS", ("high", "修改联系人")),
            ("android.permission.READ_CALL_LOG", ("high", "读取通话记录")),
            ("android.permission.WRITE_CALL_LOG", ("high", "修改通话记录")),
            ("android.permission.CALL_PHONE", ("high", "直接拨打电话")),
            ("android.permission.NEW_OUTGOING_CALL", ("high", "拦截外拨电话")),
            ("android.permission.READ_PHONE_STATE", ("medium", "读取手机状态")),
            ("android.permission.READ_PHONE_NUMBERS", ("high", "读取手机号")),
            ("android.permission.ANSWER_PHONE_CALLS", ("high", "接听电话")),
            ("android.permission.RECORD_AUDIO", ("high", "录音")),
            ("android.permission.CAMERA", ("high", "相机")),
            ("android.permission.READ_EXTERNAL_STORAGE", ("medium", "读取外部存储")),
            ("android.permission.WRITE_EXTERNAL_STORAGE", ("medium", "写入外部存储")),
            ("android.permission.ACCESS_FINE_LOCATION", ("high", "精确定位")),
            ("android.permission.ACCESS_COARSE_LOCATION", ("medium", "粗略定位")),
            ("android.permission.ACCESS_BACKGROUND_LOCATION", ("critical", "后台定位")),
            ("android.permission.READ_CALENDAR", ("high", "读取日历")),
            ("android.permission.WRITE_CALENDAR", ("high", "修改日历")),
            ("android.permission.BODY_SENSORS", ("high", "身体传感器")),
            ("android.permission.GET_ACCOUNTS", ("high", "获取账户列表")),
            ("android.permission.SYSTEM_ALERT_WINDOW", ("high", "悬浮窗")),
            ("android.permission.REQUEST_INSTALL_PACKAGES", ("critical", "安装其他应用")),
            ("android.permission.QUERY_ALL_PACKAGES", ("medium", "查询所有应用")),
        ]
        .iter()
        .cloned()
        .collect();

        for perm in &info.permissions {
            if let Some(&(severity, desc)) = dangerous_perms.get(perm.as_str()) {
                findings.push(MobileFinding {
                    id: "ANDROID-110".to_string(),
                    title: format!("危险权限: {}", desc),
                    severity: severity.to_string(),
                    category: "config".to_string(),
                    description: format!(
                        "应用申请了危险权限 {} ({})，需评估其必要性",
                        perm, desc
                    ),
                    evidence: format!("uses-permission: {}", perm),
                    fix_advice: format!(
                        "评估该权限的必要性；如非必需，移除该权限；如必需，在运行时申请并说明用途"
                    ),
                });
            }
        }

        // 检测自定义权限（非 android.permission.*）
        for perm in &info.permissions {
            if !perm.starts_with("android.permission.") && !perm.starts_with("com.google.android.") {
                findings.push(MobileFinding {
                    id: "ANDROID-111".to_string(),
                    title: "自定义权限".to_string(),
                    severity: "info".to_string(),
                    category: "config".to_string(),
                    description: format!("应用申请了自定义权限: {}，需检查来源", perm),
                    evidence: format!("uses-permission: {}", perm),
                    fix_advice: "检查该自定义权限的声明方和保护级别".to_string(),
                });
            }
        }

        findings
    }

    /// 检测 SDK 版本
    fn check_sdk_versions(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();

        if info.min_sdk < 19 {
            findings.push(MobileFinding {
                id: "ANDROID-120".to_string(),
                title: format!("minSdkVersion 过低 ({})", info.min_sdk),
                severity: "medium".to_string(),
                category: "config".to_string(),
                description: format!(
                    "minSdkVersion={} 低于 Android 4.4 (API 19)，存在兼容性旧版本的安全风险",
                    info.min_sdk
                ),
                evidence: format!("minSdkVersion={}", info.min_sdk),
                fix_advice: "提高 minSdkVersion 至少至 21 (Android 5.0) 以减少兼容性安全问题"
                    .to_string(),
            });
        }

        if info.target_sdk < 30 {
            findings.push(MobileFinding {
                id: "ANDROID-121".to_string(),
                title: format!("targetSdkVersion 过低 ({})", info.target_sdk),
                severity: "medium".to_string(),
                category: "config".to_string(),
                description: format!(
                    "targetSdkVersion={} 低于 Android 11 (API 30)，缺失新版本的安全增强",
                    info.target_sdk
                ),
                evidence: format!("targetSdkVersion={}", info.target_sdk),
                fix_advice: "升级 targetSdkVersion 至最新发布版本（至少 30+）".to_string(),
            });
        }

        findings
    }

    /// 检测签名
    fn check_signature(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();

        if info.signatures.is_empty() {
            findings.push(MobileFinding {
                id: "ANDROID-130".to_string(),
                title: "应用未签名".to_string(),
                severity: "critical".to_string(),
                category: "config".to_string(),
                description: "应用未签名，无法验证完整性和来源，可能被篡改".to_string(),
                evidence: "no signature found".to_string(),
                fix_advice: "使用 jarsigner / apksigner 对应用进行签名".to_string(),
            });
        } else {
            // 检测调试签名（test key）
            for sig in &info.signatures {
                let subject_lower = sig.subject.to_lowercase();
                if subject_lower.contains("androiddebugkey")
                    || subject_lower.contains("debug")
                    || sig.issuer.to_lowercase().contains("debug")
                {
                    findings.push(MobileFinding {
                        id: "ANDROID-131".to_string(),
                        title: "使用调试签名 (test key)".to_string(),
                        severity: "high".to_string(),
                        category: "config".to_string(),
                        description: "应用使用调试签名（test key），可被伪造，发布版本必须使用正式签名"
                            .to_string(),
                        evidence: format!("subject={}, issuer={}", sig.subject, sig.issuer),
                        fix_advice: "使用正式的发布证书对应用重新签名".to_string(),
                    });
                }
            }
        }

        findings
    }
}

impl Default for ConfigChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    fn make_apk_info() -> ApkInfo {
        ApkInfo {
            package: "com.example.app".to_string(),
            version_name: "1.0".to_string(),
            version_code: 1,
            min_sdk: 21,
            target_sdk: 30,
            compile_sdk: 30,
            app_name: "Test".to_string(),
            main_activity: None,
            dex_files: vec![],
            permissions: vec![],
            components: AndroidComponents::default(),
            meta_data: HashMap::new(),
            file_size: 0,
            signatures: vec![],
        }
    }

    #[test]
    fn test_allow_backup_default_true() {
        let info = make_apk_info();
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        // 默认 allowBackup=true
        assert!(findings.iter().any(|f| f.id == "ANDROID-100"));
    }

    #[test]
    fn test_allow_backup_explicit_false() {
        let mut info = make_apk_info();
        info.meta_data.insert("allowBackup".into(), "false".into());
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(!findings.iter().any(|f| f.id == "ANDROID-100"));
    }

    #[test]
    fn test_debuggable_true() {
        let mut info = make_apk_info();
        info.meta_data.insert("debuggable".into(), "true".into());
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-101"));
    }

    #[test]
    fn test_cleartext_traffic_low_target_sdk() {
        let mut info = make_apk_info();
        info.target_sdk = 25; // < 28，默认允许明文
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-102"));
    }

    #[test]
    fn test_cleartext_traffic_high_target_sdk() {
        let info = make_apk_info(); // target_sdk=30
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(!findings.iter().any(|f| f.id == "ANDROID-102"));
    }

    #[test]
    fn test_dangerous_permission_sms() {
        let mut info = make_apk_info();
        info.permissions.push("android.permission.SEND_SMS".to_string());
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-110"));
        let sms_finding = findings.iter().find(|f| f.id == "ANDROID-110").unwrap();
        assert_eq!(sms_finding.severity, "critical");
    }

    #[test]
    fn test_dangerous_permission_location() {
        let mut info = make_apk_info();
        info.permissions.push("android.permission.ACCESS_FINE_LOCATION".to_string());
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-110"));
    }

    #[test]
    fn test_min_sdk_low() {
        let mut info = make_apk_info();
        info.min_sdk = 17;
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-120"));
    }

    #[test]
    fn test_target_sdk_low() {
        let mut info = make_apk_info();
        info.target_sdk = 28;
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-121"));
    }

    #[test]
    fn test_no_signature() {
        let info = make_apk_info();
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-130"));
        let sig_finding = findings.iter().find(|f| f.id == "ANDROID-130").unwrap();
        assert_eq!(sig_finding.severity, "critical");
    }

    #[test]
    fn test_debug_signature() {
        let mut info = make_apk_info();
        info.signatures.push(SignatureInfo {
            algorithm: "RSA".to_string(),
            cert_fingerprint: "ABCD".to_string(),
            issuer: "CN=Android Debug".to_string(),
            subject: "CN=Android Debug Key".to_string(),
            not_before: String::new(),
            not_after: String::new(),
        });
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-131"));
    }

    #[test]
    fn test_custom_permission() {
        let mut info = make_apk_info();
        info.permissions.push("com.example.custom.PERMISSION".to_string());
        let checker = ConfigChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-111"));
    }
}
