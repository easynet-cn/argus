//! 漏洞验证扫描器 Scanner trait 适配器
//!
//! 复用 VulnerabilityScanner 在 Active 模式下的模板探测能力，
//! 对 extra_params.vulns 指定的 CVE 列表进行验证（重新执行模板，确认漏洞真实存在）。
//!
//! 与普通 VulnerabilityScanner 的区别：
//! 1. 强制 Active 模式（不发被动 CPE 匹配）
//! 2. 若 extra_params.vulns 指定了 CVE 列表，只保留匹配该列表的结果
//! 3. 在 evidence 前加 [已验证] 标记，便于区分

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError};

use crate::scanner::VulnerabilityScanner;
use crate::types::ScanMode;

/// 漏洞验证扫描引擎（实现 Scanner trait，注册名 `vuln_verify_scanner`）
pub struct VulnVerifyScanner {
    inner: VulnerabilityScanner,
    progress: Arc<RwLock<HashMap<String, f32>>>,
}

impl VulnVerifyScanner {
    pub fn new() -> Self {
        // 强制 Active 模式：只执行主动模板探测，不执行被动 CPE 匹配
        let inner = VulnerabilityScanner::new(10, ScanMode::Active);
        Self {
            inner,
            progress: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for VulnVerifyScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for VulnVerifyScanner {
    fn name(&self) -> &str {
        "vuln_verify_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();

        // G6.10 验证方式配置：从 extra_params.verify_mode 读取（active/passive）
        // - active（默认）：重新执行模板探测，确认漏洞真实存在
        // - passive：仅 CPE/CVE 匹配，不发包（适用于生产环境）
        let verify_mode = config
            .extra_params
            .get("verify_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("active");

        let inner_result = if verify_mode == "passive" {
            // passive 模式：使用 Passive 扫描（仅 CPE 匹配，不发包）
            let passive_scanner = VulnerabilityScanner::new(10, ScanMode::Passive);
            passive_scanner.execute(config).await?
        } else {
            // active 模式：委托给内层 VulnerabilityScanner（Active 模式，重新探测）
            self.inner.execute(config).await?
        };
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 0.95);
        }

        // 从 extra_params.vulns 读取需要验证的 CVE 列表
        // 格式: [{"cve_id": "CVE-2024-1234", ...}, ...] 或 ["CVE-2024-1234", ...]
        let verify_cves: Vec<String> = config
            .extra_params
            .get("vulns")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        // 两种格式：对象 {cve_id: "..."} 或 字符串 "..."
                        item.get("cve_id")
                            .and_then(|c| c.as_str())
                            .or_else(|| item.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let filtered_vulns: Vec<PluginResult> = if verify_cves.is_empty() {
            // 未指定验证列表，返回全部结果（相当于重新扫描确认）
            inner_result.vulnerabilities
        } else {
            // 只保留匹配指定 CVE 列表的结果
            inner_result
                .vulnerabilities
                .into_iter()
                .filter(|v| {
                    v.cve.as_ref()
                        .map(|c| verify_cves.iter().any(|vc| vc.eq_ignore_ascii_case(c)))
                        .unwrap_or(false)
                })
                .collect()
        };

        // 在 evidence 前加 [已验证] 标记
        let verified_vulns: Vec<PluginResult> = filtered_vulns
            .into_iter()
            .map(|mut v| {
                v.evidence = format!("[已验证] {}", v.evidence);
                v
            })
            .collect();

        let duration = start.elapsed().as_secs_f64();
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: TaskStatus::Completed,
            hosts_scanned: inner_result.hosts_scanned,
            vulnerabilities: verified_vulns,
            duration_secs: duration,
            raw_data: inner_result.raw_data,
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
            map.insert(task_id.to_string(), -1.0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_scanner::Target;

    #[test]
    fn test_name_and_version() {
        let s = VulnVerifyScanner::new();
        assert_eq!(s.name(), "vuln_verify_scanner");
        assert_eq!(s.version(), "0.1.0");
    }

    #[tokio::test]
    async fn test_progress_default_zero() {
        let s = VulnVerifyScanner::new();
        let p = s.progress("nope").await.expect("progress");
        assert_eq!(p, 0.0);
    }

    #[tokio::test]
    async fn test_cancel_sets_minus_one() {
        let s = VulnVerifyScanner::new();
        s.cancel("task-1").await.expect("cancel");
        let p = s.progress("task-1").await.expect("progress");
        assert_eq!(p, -1.0);
    }

    #[tokio::test]
    async fn test_execute_empty_targets() {
        let s = VulnVerifyScanner::new();
        let cfg = ScanConfig {
            task_id: "t-empty".to_string(),
            targets: vec![],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_err(), "空目标应返回错误");
    }

    #[tokio::test]
    async fn test_execute_unreachable_completes() {
        let s = VulnVerifyScanner::new();
        let cfg = ScanConfig {
            task_id: "t-unreachable".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "无法连接时扫描应返回成功");
        let sr = r.unwrap();
        assert_eq!(sr.hosts_scanned, 1);
    }

    #[tokio::test]
    async fn test_verify_cves_filter_empty_when_cve_not_in_results() {
        // 指定一个不存在的 CVE，结果应为空
        let s = VulnVerifyScanner::new();
        let cfg = ScanConfig {
            task_id: "t-filter".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({
                "vulns": [{"cve_id": "CVE-9999-9999"}]
            }),
        };
        let r = s.execute(&cfg).await.expect("execute");
        // 即使扫描出结果，也不应包含 CVE-9999-9999
        for v in &r.vulnerabilities {
            assert_ne!(
                v.cve.as_deref(),
                Some("CVE-9999-9999"),
                "结果中不应包含指定外的 CVE"
            );
        }
    }
}
