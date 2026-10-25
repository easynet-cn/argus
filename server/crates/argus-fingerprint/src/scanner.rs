//! FingerprintScanner 实现 Scanner trait

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use argus_scanner::{Scanner, ScanConfig, ScanResult, ScannerError};
use argus_engine::PluginResult;
use crate::types::*;
use crate::service::*;
use crate::os_detect::*;
use crate::web_fingerprint::*;
use crate::signature_db::*;

pub struct FingerprintScanner {
    progress: Arc<RwLock<HashMap<String, f32>>>,
    service_db: ServiceSignatureDb,
    web_db: WebAppSignatureDb,
    os_db: OsSignatureDb,
}

impl FingerprintScanner {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RwLock::new(HashMap::new())),
            service_db: ServiceSignatureDb::builtin(),
            web_db: WebAppSignatureDb::builtin(),
            os_db: OsSignatureDb::builtin(),
        }
    }
}

impl Default for FingerprintScanner {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Scanner for FingerprintScanner {
    fn name(&self) -> &str { "fingerprint_scanner" }

    fn version(&self) -> &str { "0.1.0" }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();
        let total = config.targets.len();

        // 从 extra_params 获取端口扫描结果（可选）
        let pre_scanned: Option<serde_json::Value> = config.extra_params.get("port_scan_results").cloned();

        let mut all_results = Vec::new();
        let mut all_vulns = Vec::new();

        for (i, target) in config.targets.iter().enumerate() {
            let mut fp_result = FingerprintResult::new(&target.host);

            // 获取端口列表
            let ports: Vec<u16> = if let Some(ports) = &target.ports {
                ports.clone()
            } else if let Some(ref ps) = pre_scanned {
                // 从预扫结果中提取端口
                ps.as_array()
                    .and_then(|arr| arr.iter().find(|v| v.get("host").and_then(|h| h.as_str()) == Some(&target.host)))
                    .and_then(|h| h.get("ports"))
                    .and_then(|p| p.as_array())
                    .map(|arr| arr.iter().filter_map(|p| p.as_u64().map(|n| n as u16)).collect())
                    .unwrap_or_default()
            } else {
                // 默认常用端口
                vec![22, 80, 443, 8080, 8443, 3306, 6379, 5432, 21, 25, 445, 3389]
            };

            let mut banners: Vec<(u16, String)> = vec![];

            for port in &ports {
                let fp = fingerprint_service(
                    &target.host, *port, None,
                    &self.service_db, (config.timeout_secs * 1000) as u64,
                ).await;

                if let Some(ref banner) = fp.banner {
                    banners.push((*port, banner.clone()));
                }

                // 对 HTTP 端口检测 Web 应用
                if matches!(*port, 80 | 443 | 8080 | 8443 | 8000 | 8888) {
                    let web_apps = detect_web_apps(
                        &target.host, *port, (config.timeout_secs * 1000) as u64, &self.web_db,
                    ).await;
                    fp_result.web_apps.extend(web_apps);
                }

                // 生成 info 级 PluginResult
                if let Some(ref product) = fp.product {
                    let mut pr = PluginResult::new(
                        format!("{}:{}", target.host, port),
                        format!("服务识别: {} {}", product, fp.version.as_deref().unwrap_or("")),
                        "info".to_string(),
                    );
                    pr.port = Some(*port);
                    pr.service = Some(fp.service.clone());
                    pr.evidence = format!(
                        "Banner: {}", fp.banner.as_deref().unwrap_or("N/A")
                    );
                    if let Some(ref cpe) = fp.cpe_uri {
                        pr.cve = Some(cpe.clone()); // 暂存 CPE URI 在 cve 字段
                    }
                    all_vulns.push(pr);
                }

                fp_result.services.push(fp);
            }

            // OS 猜测
            if !banners.is_empty() {
                fp_result.os_guess = guess_os_by_banner(&target.host, &banners, &self.os_db).await;
            }

            all_results.push(fp_result);

            // 更新进度
            let progress = ((i + 1) as f32) / total as f32;
            if let Ok(mut map) = self.progress.write() {
                map.insert(task_id.clone(), progress * 0.9);
            }
        }

        let duration = start.elapsed().as_secs_f64();

        // 更新进度完成
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: argus_core::entity::task::TaskStatus::Completed,
            hosts_scanned: total,
            vulnerabilities: all_vulns,
            duration_secs: duration,
            raw_data: Some(serde_json::to_value(&all_results).unwrap_or(serde_json::Value::Null)),
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        if let Ok(map) = self.progress.read() {
            Ok(map.get(task_id).copied().unwrap_or(0.0))
        } else {
            Ok(0.0)
        }
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.to_string(), -1.0); // -1 表示已取消
        }
        Ok(())
    }
}
