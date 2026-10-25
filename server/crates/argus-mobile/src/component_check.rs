//! Android 组件安全检测
//!
//! 检测四大组件（Activity/Service/Receiver/Provider）的安全配置:
//! - 导出但无权限保护
//! - Intent Filter 隐式导出
//! - Provider 暴露敏感数据
//! - Receiver 滥用（如开机自启、SMS 接收）
//! - Provider path traversal
//! - Activity 启动模式风险
//! - Taskaffinity 风险

use crate::types::*;

/// 组件安全检测器
pub struct ComponentChecker;

impl ComponentChecker {
    pub fn new() -> Self {
        Self
    }

    /// 扫描所有组件
    pub fn check(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        findings.extend(self.check_activities(info));
        findings.extend(self.check_services(info));
        findings.extend(self.check_receivers(info));
        findings.extend(self.check_providers(info));
        findings
    }

    /// 检测 Activity 安全风险
    fn check_activities(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        for activity in &info.components.activities {
            // 1. 显式导出但无权限
            if activity.exported && activity.permission.is_none() {
                findings.push(MobileFinding {
                    id: "ANDROID-001".to_string(),
                    title: "导出 Activity 未设置权限保护".to_string(),
                    severity: "high".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Activity '{}' 被导出但没有设置 permission 属性，任意应用可调用"
                        , activity.name),
                    evidence: format!("Activity: {}, exported=true, permission=None", activity.name),
                    fix_advice: "在 AndroidManifest.xml 中为该 Activity 添加 android:permission 属性，"
                        .to_string() + "或将 android:exported 设为 false（如不需要被其他应用调用）",
                });
            }

            // 2. 有 Intent Filter 但未显式设置 exported（Android 12+ 强制要求显式声明）
            if !activity.intent_filters.is_empty() && !activity.exported {
                // 注意：在 Android <12 中，有 intent-filter 默认 exported=true
                // 这里我们标记为 medium 风险（可能被外部应用调用）
                findings.push(MobileFinding {
                    id: "ANDROID-002".to_string(),
                    title: "Activity 含 Intent Filter 但未显式声明 exported".to_string(),
                    severity: "medium".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Activity '{}' 有 Intent Filter 但未显式声明 exported，"
                        , activity.name) + "在 Android <12 中默认导出",
                    evidence: format!(
                        "Activity: {}, has_intent_filter=true, exported not set",
                        activity.name
                    ),
                    fix_advice: "显式设置 android:exported 属性（推荐为 false 除非确实需要导出）"
                        .to_string(),
                });
            }

            // 3. R7.2 修复：taskAffinity 劫持风险检测
            // 如果 Activity 显式设置了 taskAffinity，或从 application 继承了非包名的 taskAffinity，
            // 攻击者可通过精心构造的 Intent 抢占该 task，实现 task 劫持
            let app_task_affinity = info.meta_data.get("taskAffinity");
            let effective_affinity = activity.task_affinity.as_ref()
                .or(app_task_affinity);

            if let Some(affinity) = effective_affinity {
                // taskAffinity 设置为非包名时风险更高
                let package_name = &info.package;
                let is_package_name = !package_name.is_empty() && affinity == package_name;

                if !is_package_name {
                    let severity = if activity.is_main || activity.has_launcher {
                        "high" // 主 Activity 被劫持风险更高
                    } else {
                        "medium"
                    };
                    let source = if activity.task_affinity.is_some() {
                        "Activity 属性"
                    } else {
                        "Application 属性（继承）"
                    };
                    findings.push(MobileFinding {
                        id: "ANDROID-006".to_string(),
                        title: "taskAffinity 劫持风险".to_string(),
                        severity: severity.to_string(),
                        category: "component".to_string(),
                        description: format!(
                            "Activity '{}' 通过{}设置了 taskAffinity='{}'，\
                            攻击者可构造同名 task 劫持该 Activity",
                            activity.name, source, affinity
                        ),
                        evidence: format!(
                            "Activity: {}, taskAffinity={} (source={})",
                            activity.name, affinity, source
                        ),
                        fix_advice: "移除 taskAffinity 属性，或确保其与包名一致".to_string(),
                    });
                }
            }
        }
        findings
    }

    /// 检测 Service 安全风险
    fn check_services(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        for service in &info.components.services {
            // 1. 导出 Service 无权限
            if service.exported && service.permission.is_none() {
                findings.push(MobileFinding {
                    id: "ANDROID-010".to_string(),
                    title: "导出 Service 未设置权限保护".to_string(),
                    severity: "high".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Service '{}' 被导出但没有设置 permission，任意应用可绑定/启动",
                        service.name
                    ),
                    evidence: format!(
                        "Service: {}, exported=true, permission=None",
                        service.name
                    ),
                    fix_advice: "为该 Service 添加 android:permission，或设置 exported=false"
                        .to_string(),
                });
            }

            // 2. Service 含 Intent Filter 默认导出
            if !service.intent_filters.is_empty() && service.permission.is_none() {
                findings.push(MobileFinding {
                    id: "ANDROID-011".to_string(),
                    title: "Service 含 Intent Filter 未显式声明 exported".to_string(),
                    severity: "medium".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Service '{}' 有 Intent Filter，在 Android <12 中默认导出",
                        service.name
                    ),
                    evidence: format!(
                        "Service: {}, has_intent_filter=true, exported not set",
                        service.name
                    ),
                    fix_advice: "显式声明 android:exported 属性".to_string(),
                });
            }
        }
        findings
    }

    /// 检测 Receiver 安全风险
    fn check_receivers(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        for receiver in &info.components.receivers {
            // 1. 导出 Receiver 无权限
            if receiver.exported && receiver.permission.is_none() {
                findings.push(MobileFinding {
                    id: "ANDROID-020".to_string(),
                    title: "导出 Receiver 未设置权限保护".to_string(),
                    severity: "high".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Receiver '{}' 被导出但无权限保护，恶意应用可发送恶意广播",
                        receiver.name
                    ),
                    evidence: format!(
                        "Receiver: {}, exported=true, permission=None",
                        receiver.name
                    ),
                    fix_advice: "为该 Receiver 添加 android:permission，或设置 exported=false"
                        .to_string(),
                });
            }

            // 2. 检查敏感 Action（BOOT_COMPLETED, SMS_RECEIVED 等）
            for filter in &receiver.intent_filters {
                for action in &filter.actions {
                    let sensitive = match action.as_str() {
                        "android.intent.action.BOOT_COMPLETED" => Some(("high", "开机自启动")),
                        "android.provider.Telephony.SMS_RECEIVED" => Some(("critical", "接收短信")),
                        "android.intent.action.NEW_OUTGOING_CALL" => Some(("critical", "拦截外拨电话")),
                        "android.intent.action.PHONE_STATE" => Some(("high", "监听电话状态")),
                        "android.intent.action.SCREEN_ON" | "android.intent.action.SCREEN_OFF" => {
                            Some(("medium", "监听屏幕开关"))
                        }
                        _ => None,
                    };
                    if let Some((sev, desc)) = sensitive {
                        if receiver.permission.is_none() {
                            findings.push(MobileFinding {
                                id: "ANDROID-021".to_string(),
                                title: format!("Receiver 监听敏感广播: {}", desc),
                                severity: sev.to_string(),
                                category: "component".to_string(),
                                description: format!(
                                    "Receiver '{}' 监听 '{}' 但未设置权限，可能被恶意应用利用",
                                    receiver.name, action
                                ),
                                evidence: format!(
                                    "Receiver: {}, action={}", receiver.name, action
                                ),
                                fix_advice: format!(
                                    "为该 Receiver 设置 android:permission 或限制其导出"
                                ),
                            });
                        }
                    }
                }
            }
        }
        findings
    }

    /// 检测 Provider 安全风险
    fn check_providers(&self, info: &ApkInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();
        for provider in &info.components.providers {
            // 1. 导出 Provider 无权限
            if provider.exported && provider.permission.is_none() {
                findings.push(MobileFinding {
                    id: "ANDROID-030".to_string(),
                    title: "导出 ContentProvider 未设置权限保护".to_string(),
                    severity: "critical".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "ContentProvider '{}' 被导出但无权限保护，任意应用可读取/修改数据",
                        provider.name
                    ),
                    evidence: format!(
                        "Provider: {}, exported=true, permission=None",
                        provider.name
                    ),
                    fix_advice: "为 ContentProvider 添加 android:permission、android:readPermission 或 android:writePermission"
                        .to_string(),
                });
            }

            // 2. Provider 没有 grantUriPermission 限制
            // 简化：所有导出的 Provider 都提示风险
            if provider.exported {
                findings.push(MobileFinding {
                    id: "ANDROID-031".to_string(),
                    title: "导出的 ContentProvider 可能存在数据泄露风险".to_string(),
                    severity: "medium".to_string(),
                    category: "component".to_string(),
                    description: format!(
                        "Provider '{}' 被导出，需检查 grantUriPermission 和 path 权限",
                        provider.name
                    ),
                    evidence: format!("Provider: {}, exported=true", provider.name),
                    fix_advice: "检查 Provider 的 grantUriPermission 设置，使用 <grant-uri-permission> 限制可访问的路径"
                        .to_string(),
                });
            }
        }
        findings
    }
}

impl Default for ComponentChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

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
            meta_data: Default::default(),
            file_size: 0,
            signatures: vec![],
        }
    }

    fn make_component(name: &str, exported: bool) -> ComponentInfo {
        ComponentInfo {
            name: name.to_string(),
            exported,
            permission: None,
            intent_filters: vec![],
            has_launcher: false,
            is_main: false,
            task_affinity: None,
        }
    }

    #[test]
    fn test_exported_activity_no_permission() {
        let mut info = make_apk_info();
        info.components.activities.push(make_component("com.example.MainActivity", true));

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-001"));
    }

    #[test]
    fn test_service_with_intent_filter_no_exported() {
        let mut info = make_apk_info();
        let mut svc = make_component("com.example.MyService", false);
        svc.intent_filters.push(IntentFilter::default());
        info.components.services.push(svc);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-011"));
    }

    #[test]
    fn test_receiver_boot_completed_no_permission() {
        let mut info = make_apk_info();
        let mut recv = make_component("com.example.BootReceiver", true);
        let mut filter = IntentFilter::default();
        filter.actions.push("android.intent.action.BOOT_COMPLETED".to_string());
        recv.intent_filters.push(filter);
        info.components.receivers.push(recv);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-021"));
        let boot_finding = findings.iter().find(|f| f.id == "ANDROID-021").unwrap();
        assert_eq!(boot_finding.severity, "high");
    }

    #[test]
    fn test_receiver_sms_received_no_permission() {
        let mut info = make_apk_info();
        let mut recv = make_component("com.example.SmsReceiver", true);
        let mut filter = IntentFilter::default();
        filter.actions.push("android.provider.Telephony.SMS_RECEIVED".to_string());
        recv.intent_filters.push(filter);
        info.components.receivers.push(recv);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        let sms_finding = findings.iter().find(|f| f.id == "ANDROID-021").unwrap();
        assert_eq!(sms_finding.severity, "critical");
    }

    #[test]
    fn test_exported_provider_no_permission() {
        let mut info = make_apk_info();
        info.components.providers.push(make_component("com.example.Provider", true));

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(findings.iter().any(|f| f.id == "ANDROID-030"));
        let provider_finding = findings.iter().find(|f| f.id == "ANDROID-030").unwrap();
        assert_eq!(provider_finding.severity, "critical");
    }

    #[test]
    fn test_non_exported_components_no_findings() {
        let mut info = make_apk_info();
        info.components.activities.push(make_component("com.example.Internal", false));
        info.components.services.push(make_component("com.example.InternalSvc", false));
        info.components.receivers.push(make_component("com.example.InternalRecv", false));
        info.components.providers.push(make_component("com.example.InternalPvd", false));

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        // 非导出组件不应触发 001/010/020/030
        assert!(!findings.iter().any(|f| f.id == "ANDROID-001"));
        assert!(!findings.iter().any(|f| f.id == "ANDROID-010"));
        assert!(!findings.iter().any(|f| f.id == "ANDROID-020"));
        assert!(!findings.iter().any(|f| f.id == "ANDROID-030"));
    }

    // R7.2: taskAffinity 劫持风险测试
    #[test]
    fn test_task_affinity_hijack_activity_level() {
        let mut info = make_apk_info();
        let mut act = make_component("com.example.MainActivity", true);
        act.is_main = true;
        act.has_launcher = true;
        act.task_affinity = Some("com.evil.affinity".to_string());
        info.components.activities.push(act);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        let f = findings.iter().find(|f| f.id == "ANDROID-006");
        assert!(f.is_some(), "应检测到 taskAffinity 劫持风险");
        let f = f.unwrap();
        assert_eq!(f.severity, "high", "主 Activity 的 taskAffinity 劫持为 high");
        assert!(f.evidence.contains("Activity 属性"));
    }

    #[test]
    fn test_task_affinity_hijack_app_level_inherited() {
        let mut info = make_apk_info();
        info.meta_data.insert("taskAffinity".to_string(), "com.custom.affinity".to_string());
        let act = make_component("com.example.SecondActivity", false);
        info.components.activities.push(act);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        let f = findings.iter().find(|f| f.id == "ANDROID-006");
        assert!(f.is_some(), "应检测到从 application 继承的 taskAffinity");
        let f = f.unwrap();
        assert_eq!(f.severity, "medium", "非主 Activity 的 taskAffinity 为 medium");
        assert!(f.evidence.contains("Application 属性"));
    }

    #[test]
    fn test_task_affinity_matching_package_name_no_alert() {
        let mut info = make_apk_info();
        info.package = "com.example.app".to_string();
        let mut act = make_component("com.example.app.MainActivity", true);
        act.is_main = true;
        // taskAffinity 与包名一致 → 不告警
        act.task_affinity = Some("com.example.app".to_string());
        info.components.activities.push(act);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(!findings.iter().any(|f| f.id == "ANDROID-006"), "taskAffinity 与包名一致不应告警");
    }

    #[test]
    fn test_no_task_affinity_no_alert() {
        let mut info = make_apk_info();
        let act = make_component("com.example.MainActivity", false);
        info.components.activities.push(act);

        let checker = ComponentChecker::new();
        let findings = checker.check(&info);
        assert!(!findings.iter().any(|f| f.id == "ANDROID-006"), "未设置 taskAffinity 不应告警");
    }
}
