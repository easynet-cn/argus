//! 移动安全扫描引擎
//!
//! 实现 Scanner trait，统筹 APK 解析 + 组件检测 + 配置检测

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError};
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::apk::ApkParser;
use crate::component_check::ComponentChecker;
use crate::config_check::ConfigChecker;
use crate::types::*;

/// 移动安全扫描引擎
pub struct MobileScanner {
    progress: RwLock<HashMap<String, f32>>,
    cancel_flags: RwLock<HashMap<String, Arc<AtomicBool>>>,
}

impl MobileScanner {
    pub fn new() -> Self {
        Self {
            progress: RwLock::new(HashMap::new()),
            cancel_flags: RwLock::new(HashMap::new()),
        }
    }

    fn parse_params(config: &ScanConfig) -> MobileScanParams {
        tracing::info!("解析移动扫描参数: {}", config.extra_params);
        match serde_json::from_value(config.extra_params.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("移动参数解析失败: {e}");
                MobileScanParams::default()
            }
        }
    }

    async fn run_scan(&self, params: &MobileScanParams, task_id: &str) -> Result<MobileScanResult, ScannerError> {
        let cancel_flag = {
            let map = self.cancel_flags.read().await;
            map.get(task_id).cloned().unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };

        // 根据平台类型选择扫描器（6.8: Android APK vs iOS IPA）
        let is_ios = params.platform.eq_ignore_ascii_case("ios");

        if is_ios {
            // iOS IPA 扫描
            let ios_scanner = crate::ios_scan::IosScanner::new();
            let ios_result = ios_scanner.scan_file(&params.apk_path).map_err(|e| {
                ScannerError::Execution(format!("IPA 解析失败: {}", e))
            })?;

            {
                let mut map = self.progress.write().await;
                map.insert(task_id.to_string(), 0.9);
            }

            // 将 IpaInfo 转换为 ApkInfo 以兼容 MobileScanResult
            let apk_info = crate::types::ApkInfo {
                package: ios_result.info.bundle_id.clone(),
                version_name: ios_result.info.short_version.clone(),
                version_code: ios_result.info.bundle_version.parse().unwrap_or(0),
                file_size: ios_result.info.file_size,
                ..Default::default()
            };

            let total_vulns = ios_result.findings.len();
            Ok(MobileScanResult {
                apk_info,
                component_findings: ios_result.findings,
                config_findings: Vec::new(),
                total_vulns,
            })
        } else {
            // Android APK 扫描（原有逻辑）
            let parser = ApkParser::new();
            let apk_info = parser.parse_file(&params.apk_path).map_err(|e| {
                ScannerError::Execution(format!("APK 解析失败: {}", e))
            })?;

            {
                let mut map = self.progress.write().await;
                map.insert(task_id.to_string(), 0.3);
            }

            if cancel_flag.load(Ordering::Relaxed) {
                return Err(ScannerError::Cancelled("扫描被取消".to_string()));
            }

            let mut component_findings = Vec::new();
            if params.scan_components {
                let checker = ComponentChecker::new();
                component_findings = checker.check(&apk_info);
                {
                    let mut map = self.progress.write().await;
                    map.insert(task_id.to_string(), 0.6);
                }
            }

            if cancel_flag.load(Ordering::Relaxed) {
                return Err(ScannerError::Cancelled("扫描被取消".to_string()));
            }

            let mut config_findings = Vec::new();
            if params.scan_config {
                let checker = ConfigChecker::new();
                config_findings = checker.check(&apk_info);
            }

            {
                let mut map = self.progress.write().await;
                map.insert(task_id.to_string(), 0.9);
            }

            let total_vulns = component_findings.len() + config_findings.len();

            Ok(MobileScanResult {
                apk_info,
                component_findings,
                config_findings,
                total_vulns,
            })
        }
    }
}

impl Default for MobileScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for MobileScanner {
    fn name(&self) -> &str {
        "mobile_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let params = Self::parse_params(config);
        let start = std::time::Instant::now();

        // 注册取消标志
        let cancel_flag = Arc::new(AtomicBool::new(false));
        {
            let mut map = self.cancel_flags.write().await;
            map.insert(task_id.clone(), cancel_flag);
        }

        match self.run_scan(&params, &task_id).await {
            Ok(scan_result) => {
                let mut all_vulns = Vec::new();

                // 组件漏洞
                for finding in &scan_result.component_findings {
                    let mut pr = PluginResult::new(
                        scan_result.apk_info.package.clone(),
                        finding.title.clone(),
                        finding.severity.clone(),
                    );
                    pr.evidence = format!(
                        "{} | {} | 建议: {}",
                        finding.description, finding.evidence, finding.fix_advice
                    );
                    pr.service = Some("android-component".to_string());
                    all_vulns.push(pr);
                }

                // 配置漏洞
                for finding in &scan_result.config_findings {
                    let mut pr = PluginResult::new(
                        scan_result.apk_info.package.clone(),
                        finding.title.clone(),
                        finding.severity.clone(),
                    );
                    pr.evidence = format!(
                        "{} | {} | 建议: {}",
                        finding.description, finding.evidence, finding.fix_advice
                    );
                    pr.service = Some("android-config".to_string());
                    all_vulns.push(pr);
                }

                let duration = start.elapsed().as_secs_f64();
                let raw_data = serde_json::to_value(&scan_result).ok();

                // 标记完成
                {
                    let mut map = self.progress.write().await;
                    map.insert(task_id.clone(), 1.0);
                }

                Ok(ScanResult {
                    task_id,
                    status: TaskStatus::Completed,
                    hosts_scanned: 1,
                    vulnerabilities: all_vulns,
                    duration_secs: duration,
                    raw_data,
                })
            }
            Err(e) => {
                let mut map = self.progress.write().await;
                map.insert(task_id.clone(), -1.0);
                Err(e)
            }
        }
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        let map = self.progress.read().await;
        Ok(map.get(task_id).copied().unwrap_or(0.0))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        let map = self.cancel_flags.read().await;
        if let Some(flag) = map.get(task_id) {
            flag.store(true, Ordering::Relaxed);
        }
        let mut pmap = self.progress.write().await;
        pmap.insert(task_id.to_string(), -1.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_scanner_name() {
        let s = MobileScanner::new();
        assert_eq!(s.name(), "mobile_scanner");
        assert_eq!(s.version(), "0.1.0");
    }

    #[test]
    fn test_parse_params_default() {
        let config = ScanConfig {
            task_id: "test".to_string(),
            targets: vec![],
            concurrency: 1,
            timeout_secs: 60,
            extra_params: serde_json::json!({}),
        };
        let params = MobileScanner::parse_params(&config);
        assert!(params.scan_components);
        assert!(params.scan_config);
    }
}
