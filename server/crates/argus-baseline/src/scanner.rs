//! 基线核查扫描引擎
//!
//! 实现 Scanner trait，统筹采集器 + 规则引擎 + 报告生成

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError};
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::collector::{create_collector, Collector};
use crate::report::BaselineReport;
use crate::rule_engine::RuleEngine;
use crate::rules::{load_rule_set, RuleSet};
use crate::types::{BaselineParams, CheckResult, CollectMethod, ComplianceLevel};

/// 基线核查引擎
pub struct BaselineScanner {
    /// 进度跟踪
    progress: RwLock<HashMap<String, f32>>,
    /// 取消标志
    cancel_flags: RwLock<HashMap<String, Arc<AtomicBool>>>,
}

impl BaselineScanner {
    pub fn new() -> Self {
        Self {
            progress: RwLock::new(HashMap::new()),
            cancel_flags: RwLock::new(HashMap::new()),
        }
    }

    /// 从 ScanConfig 解析基线核查参数
    fn parse_params(config: &ScanConfig) -> BaselineParams {
        tracing::info!("解析基线核查参数: {}", config.extra_params);
        let mut params: BaselineParams = match serde_json::from_value(config.extra_params.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("基线参数解析失败: {e}");
                BaselineParams::default()
            }
        };

        // 从第一个 target 取 host
        if !config.targets.is_empty() && params.host.is_empty() {
            params.host = config.targets[0].host.clone();
        }

        // 从 credentials 取用户名密码
        if let Some(creds) = &config.targets.first().and_then(|t| t.credentials.clone()) {
            if params.username.is_empty() {
                params.username = creds.username.clone();
            }
            if params.password.is_empty() {
                params.password = creds.password.clone();
            }
        }

        params
    }

    /// 执行基线核查
    ///
    /// `task_id` 用于在循环中实时更新 progress map；
    /// `cancel_flag` 由 `execute` 创建并按 task_id 注册，此处直接复用，
    /// 避免 cancel(task_id) 请求与循环内读取的标志错位导致无法中断。
    async fn run_baseline_check(
        &self,
        params: &BaselineParams,
        task_id: &str,
        cancel_flag: Arc<AtomicBool>,
    ) -> Result<Vec<CheckResult>, ScannerError> {
        // 1. 加载规则集
        let rule_set_name = params.rule_set.as_deref().unwrap_or("gbt22239_l3_linux");
        let rule_set = load_rule_set(rule_set_name).ok_or_else(|| {
            ScannerError::Config(format!("未知规则集: {rule_set_name}"))
        })?;

        tracing::info!(
            "加载规则集 {} 共 {} 采集项 {} 规则",
            rule_set.name,
            rule_set.collect_items.len(),
            rule_set.rules.len()
        );

        // 2. 创建采集器（离线模式不创建采集器）
        let method = CollectMethod::from_str(&params.method)
            .unwrap_or(CollectMethod::Ssh);
        let is_offline = method == CollectMethod::Offline;
        let collector = if is_offline {
            None
        } else {
            Some(create_collector(&method))
        };
        let port = params.port.unwrap_or_else(|| match method {
            CollectMethod::Ssh => 22,
            CollectMethod::Smb => 445,
            CollectMethod::Telnet => 23,
            CollectMethod::Agent => 22,
            CollectMethod::Offline => 0,
        });
        let timeout_ms = params.timeout_ms.unwrap_or(10000);

        // 3. 逐个采集项执行采集 + 规则判定
        let mut all_results: Vec<CheckResult> = Vec::new();
        let total_items = rule_set.collect_items.len();
        // 进度区间映射到 [0.1, 0.9]：execute 起始写入 0.1，核查循环填中间值，结束后写 0.9
        let progress_start = 0.1f32;
        let progress_span = 0.8f32; // 0.9 - 0.1

        for (idx, item) in rule_set.collect_items.iter().enumerate() {
            // 检查取消（使用 execute 注册的 task_id 级别标志）
            if cancel_flag.load(Ordering::Relaxed) {
                tracing::info!("基线核查任务 {task_id} 已取消，已完成 {}/{}", idx, total_items);
                break;
            }

            // 实时更新进度（线性映射到 [0.1, 0.9)）
            let progress = progress_start + progress_span * (idx as f32 / total_items as f32);
            self.progress.write().await.insert(task_id.to_string(), progress);

            tracing::info!(
                "采集项 {}/{}: {} ({})",
                idx + 1,
                total_items,
                item.name,
                item.command
            );

            // 执行采集（离线模式从 offline_data 获取，否则调用采集器）
            let output = if is_offline {
                // 离线模式：从 offline_data 中按 item_id 查找采集结果
                params.offline_data.as_ref()
                    .and_then(|d| d.get(&item.id))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            } else {
                match collector.as_ref().unwrap()
                    .collect_one(
                        &params.host,
                        port,
                        &params.username,
                        &params.password,
                        item,
                        timeout_ms,
                    )
                    .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::warn!("采集项 {} 失败: {e}", item.id);
                        String::new()
                    }
                }
            };

            // 执行规则判定
            let rules = rule_set.rules_for_item(&item.id);
            let engine = RuleEngine::new();
            for rule in rules {
                let result = engine.evaluate(rule, &output);
                all_results.push(result);
            }
        }

        Ok(all_results)
    }
}

impl Default for BaselineScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for BaselineScanner {
    fn name(&self) -> &str {
        "baseline_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let start = Instant::now();
        let task_id = config.task_id.clone();

        // 初始化进度
        self.progress.write().await.insert(task_id.clone(), 0.0);

        let params = Self::parse_params(config);

        let is_offline = params.method == "offline";

        if params.host.is_empty() {
            return Err(ScannerError::Config("目标主机不能为空".to_string()));
        }
        // 离线模式不要求用户名密码，但要求提供 offline_data
        if !is_offline {
            if params.username.is_empty() || params.password.is_empty() {
                return Err(ScannerError::Config("用户名或密码不能为空".to_string()));
            }
        } else if params.offline_data.is_none() {
            return Err(ScannerError::Config("离线模式必须提供 offline_data".to_string()));
        }

        // 设置取消标志的 task_id 关联
        let cancel_flag = Arc::new(AtomicBool::new(false));
        self.cancel_flags.write().await.insert(task_id.clone(), cancel_flag.clone());

        self.progress.write().await.insert(task_id.clone(), 0.1);

        // 执行核查
        let results = self.run_baseline_check(&params, &task_id, cancel_flag.clone()).await?;

        self.progress.write().await.insert(task_id.clone(), 0.9);

        // 生成报告
        let report = BaselineReport::new(
            params.host.clone(),
            params.rule_set.clone().unwrap_or_default(),
            results.clone(),
        );

        // 生成漏洞项（不合规项视为漏洞/风险）
        let vulnerabilities: Vec<PluginResult> = results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::NonCompliant)
            .map(|r| {
                let mut vuln = PluginResult::new(
                    params.host.clone(),
                    format!("基线不合规: {}", r.rule_name),
                    r.severity.clone(),
                );
                vuln.evidence = format!(
                    "条款={} 类别={} 规则ID={}",
                    r.requirement_id, r.category, r.rule_id
                );
                vuln.fix_advice = r.fix_advice.clone();
                vuln
            })
            .collect();

        self.progress.write().await.insert(task_id.clone(), 1.0);

        let duration = start.elapsed().as_secs_f64();
        let non_compliant_count = vulnerabilities.len();

        tracing::info!(
            "基线核查完成: {} 项不合规，耗时 {:.2}s",
            non_compliant_count,
            duration
        );

        Ok(ScanResult {
            task_id: task_id.clone(),
            status: TaskStatus::Completed,
            hosts_scanned: 1,
            vulnerabilities,
            duration_secs: duration,
            raw_data: Some(serde_json::to_value(&report).unwrap_or_default()),
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        Ok(self.progress.read().await.get(task_id).copied().unwrap_or(0.0))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        let flags = self.cancel_flags.read().await;
        if let Some(flag) = flags.get(task_id) {
            flag.store(true, Ordering::Relaxed);
            tracing::info!("基线核查任务 {task_id} 已请求取消");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_scanner::{ScanConfig, Target};

    fn make_config(host: &str, user: &str, pass: &str, rule_set: &str) -> ScanConfig {
        let params = BaselineParams {
            host: host.to_string(),
            port: Some(22),
            method: "ssh".to_string(),
            username: user.to_string(),
            password: pass.to_string(),
            rule_set: Some(rule_set.to_string()),
            timeout_ms: Some(5000),
            offline_data: None,
        };
        ScanConfig {
            task_id: "test-task".to_string(),
            targets: vec![Target {
                host: host.to_string(),
                ports: None,
                credentials: Some(argus_scanner::Credentials {
                    username: user.to_string(),
                    password: pass.to_string(),
                    auth_type: None,
                }),
            }],
            concurrency: 1,
            timeout_secs: 5,
            extra_params: serde_json::to_value(&params).unwrap(),
        }
    }

    #[test]
    fn test_scanner_name() {
        let s = BaselineScanner::new();
        assert_eq!(s.name(), "baseline_scanner");
        assert_eq!(s.version(), "0.1.0");
    }

    #[tokio::test]
    async fn test_progress_default() {
        let s = BaselineScanner::new();
        let p = s.progress("nonexistent").await.unwrap();
        assert_eq!(p, 0.0);
    }

    #[tokio::test]
    async fn test_cancel_nonexistent() {
        let s = BaselineScanner::new();
        assert!(s.cancel("nonexistent").await.is_ok());
    }

    #[tokio::test]
    async fn test_execute_missing_host() {
        let s = BaselineScanner::new();
        let config = ScanConfig {
            task_id: "t1".to_string(),
            targets: vec![],
            concurrency: 1,
            timeout_secs: 5,
            extra_params: serde_json::json!({}),
        };
        let result = s.execute(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_missing_credentials() {
        let s = BaselineScanner::new();
        let config = ScanConfig {
            task_id: "t1".to_string(),
            targets: vec![Target {
                host: "192.168.1.1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 1,
            timeout_secs: 5,
            extra_params: serde_json::json!({}),
        };
        let result = s.execute(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_unknown_rule_set() {
        let s = BaselineScanner::new();
        let config = make_config("192.168.1.1", "root", "pass", "unknown_set");
        let result = s.execute(&config).await;
        assert!(result.is_err());
    }

    /// P0 回归：progress 写入后 progress(task_id) 应能读到中间值，
    /// 而非只有 0.1/0.9/1.0 跳变。
    #[tokio::test]
    async fn test_progress_set_get() {
        let s = BaselineScanner::new();
        // 模拟 run_baseline_check 循环内写入的中间进度
        s.progress.write().await.insert("t-prog".to_string(), 0.45);
        let p = s.progress("t-prog").await.unwrap();
        assert!((p - 0.45).abs() < 1e-6, "progress 应返回写入的中间值，实际: {p}");
    }

    /// P0 回归：cancel(task_id) 应能设置 execute 注册的 task_id 级别标志，
    /// 保证循环内的 cancel_flag.load() 能感知到取消请求。
    #[tokio::test]
    async fn test_cancel_sets_flag_by_task_id() {
        let s = BaselineScanner::new();
        // 模拟 execute() 注册的取消标志
        let flag = Arc::new(AtomicBool::new(false));
        s.cancel_flags.write().await.insert("t-cancel".to_string(), flag.clone());
        // 请求取消
        s.cancel("t-cancel").await.unwrap();
        assert!(flag.load(Ordering::Relaxed), "cancel(task_id) 必须设置对应标志");
    }
}
