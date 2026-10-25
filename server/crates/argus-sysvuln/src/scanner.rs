//! VulnerabilityScanner 实现 Scanner trait
//!
//! 主动模板探测 + 被动 CPE 匹配（基于指纹 + CVE 知识库）

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use argus_scanner::{Scanner, ScanConfig, ScanResult, ScannerError};
use argus_engine::PluginResult;
use argus_engine::template::{PluginTemplate, DetectionConfig, MatchRule, MatchType, TemplateMetadata};
use argus_core::entity::task::TaskStatus;
use crate::types::{VulnScanResult, ScanMode};
use crate::runtime::VulnPluginRuntime;
use crate::cpe_matcher::CpeMatcher;
use crate::template_loader::TemplateLoader;
use crate::dos_vuln::DosScanner;

/// 漏洞扫描引擎
pub struct VulnerabilityScanner {
    progress: Arc<RwLock<HashMap<String, f32>>>,
    mode: ScanMode,
    runtime: Arc<RwLock<Option<VulnPluginRuntime>>>,
    templates: Arc<RwLock<Vec<PluginTemplate>>>,
    cpe_matcher: Arc<RwLock<Option<CpeMatcher>>>,
    /// G4.7: 深度扫描模式 - 启用后增加插件覆盖范围（更多 payload 变体、更全面检测）
    pub deep_scan: bool,
    /// G4.8: 是否执行危险漏洞插件（DoS 类），默认 false
    pub run_dangerous: bool,
}

impl VulnerabilityScanner {
    /// 用 DefaultHostApi + 内置模板构造
    pub fn new(timeout_secs: u64, mode: ScanMode) -> Self {
        let mut loader = TemplateLoader::new();
        let _ = loader.load_builtin();
        let templates: Vec<_> = loader.templates().to_vec();
        Self {
            progress: Arc::new(RwLock::new(HashMap::new())),
            mode,
            runtime: Arc::new(RwLock::new(Some(VulnPluginRuntime::with_default(timeout_secs)))),
            templates: Arc::new(RwLock::new(templates)),
            cpe_matcher: Arc::new(RwLock::new(None)),
            deep_scan: false,
            run_dangerous: false,
        }
    }

    /// 配置 DB 连接（启用被动 CPE 匹配）
    pub fn with_db(mut self, db: DatabaseConnection) -> Self {
        self.cpe_matcher = Arc::new(RwLock::new(Some(CpeMatcher::new(db))));
        self
    }

    /// 从目录加载自定义模板（叠加到内置模板之上）
    pub async fn with_templates_dir(self, dir: &str) -> Result<Self, ScannerError> {
        let mut loader = TemplateLoader::new();
        loader.load_builtin().map_err(|e| ScannerError::Config(e.to_string()))?;
        loader.load_dir(dir).await.map_err(|e| ScannerError::Config(e.to_string()))?;
        if let Ok(mut t) = self.templates.write() {
            *t = loader.templates().to_vec();
        }
        Ok(self)
    }

    /// G4.7: 启用深度扫描模式
    pub fn with_deep_scan(mut self, deep_scan: bool) -> Self {
        self.deep_scan = deep_scan;
        self
    }

    /// G4.8: 启用危险漏洞插件（DoS 类）执行
    pub fn with_run_dangerous(mut self, run_dangerous: bool) -> Self {
        self.run_dangerous = run_dangerous;
        self
    }

    /// 当前加载的模板数量
    pub fn template_count(&self) -> usize {
        self.templates.read().map(|t| t.len()).unwrap_or(0)
    }

    /// G4.7: 获取深度扫描专用模板（仅在 deep_scan=true 时加载）
    ///
    /// 这些模板包含更多 payload 变体和更全面的检测路径，
    /// 例如：额外的默认凭证组合、更多的敏感路径探测、已知 CVE 的额外检测点。
    fn deep_scan_templates() -> Vec<PluginTemplate> {
        vec![
            // 深度扫描: 额外的默认凭证路径探测
            PluginTemplate {
                id: "deepscan-default-creds-admin123".to_string(),
                name: "深度扫描-默认凭证 admin/admin123".to_string(),
                severity: "high".to_string(),
                author: Some("Argus".to_string()),
                description: Some("深度扫描模式下检测默认凭证 admin/admin123".to_string()),
                cve: None,
                cvss: None,
                fix_advice: Some("修改默认密码为强密码".to_string()),
                detection: DetectionConfig {
                    method: "GET".to_string(),
                    path: "/admin/login".to_string(),
                    headers: Some(vec![(
                        "Authorization".to_string(),
                        "Basic YWRtaW46YWRtaW4xMjM=".to_string(), // admin:admin123
                    )]),
                    body: None,
                    match_rule: MatchRule {
                        match_type: MatchType::Status,
                        pattern: "200".to_string(),
                    },
                },
                metadata: TemplateMetadata {
                    category: "deepscan".to_string(),
                    tags: vec!["default_credentials".to_string(), "deepscan".to_string()],
                    cpe: None,
                    reference_urls: vec![],
                    port: None,
                    service: Some("http".to_string()),
                },
            },
            // 深度扫描: 敏感文件路径探测
            PluginTemplate {
                id: "deepscan-sensitive-paths".to_string(),
                name: "深度扫描-敏感路径探测".to_string(),
                severity: "medium".to_string(),
                author: Some("Argus".to_string()),
                description: Some("深度扫描模式下探测常见敏感文件路径".to_string()),
                cve: None,
                cvss: None,
                fix_advice: Some("限制敏感文件访问".to_string()),
                detection: DetectionConfig {
                    method: "GET".to_string(),
                    path: "/.git/config".to_string(),
                    headers: None,
                    body: None,
                    match_rule: MatchRule {
                        match_type: MatchType::Body,
                        pattern: "[core]".to_string(),
                    },
                },
                metadata: TemplateMetadata {
                    category: "deepscan".to_string(),
                    tags: vec!["info_leak".to_string(), "deepscan".to_string()],
                    cpe: None,
                    reference_urls: vec![],
                    port: None,
                    service: Some("http".to_string()),
                },
            },
            // 深度扫描: 备份文件探测
            PluginTemplate {
                id: "deepscan-backup-files".to_string(),
                name: "深度扫描-备份文件探测".to_string(),
                severity: "medium".to_string(),
                author: Some("Argus".to_string()),
                description: Some("深度扫描模式下探测常见备份文件".to_string()),
                cve: None,
                cvss: None,
                fix_advice: Some("删除公开目录下的备份文件".to_string()),
                detection: DetectionConfig {
                    method: "GET".to_string(),
                    path: "/backup.zip".to_string(),
                    headers: None,
                    body: None,
                    match_rule: MatchRule {
                        match_type: MatchType::Status,
                        pattern: "200".to_string(),
                    },
                },
                metadata: TemplateMetadata {
                    category: "deepscan".to_string(),
                    tags: vec!["info_leak".to_string(), "deepscan".to_string()],
                    cpe: None,
                    reference_urls: vec![],
                    port: None,
                    service: Some("http".to_string()),
                },
            },
            // 深度扫描: Swagger/API 文档暴露
            PluginTemplate {
                id: "deepscan-swagger-exposed".to_string(),
                name: "深度扫描-Swagger API 文档暴露".to_string(),
                severity: "low".to_string(),
                author: Some("Argus".to_string()),
                description: Some("深度扫描模式下探测 Swagger/OpenAPI 文档是否暴露".to_string()),
                cve: None,
                cvss: None,
                fix_advice: Some("生产环境禁用 Swagger 文档".to_string()),
                detection: DetectionConfig {
                    method: "GET".to_string(),
                    path: "/swagger-ui.html".to_string(),
                    headers: None,
                    body: None,
                    match_rule: MatchRule {
                        match_type: MatchType::Status,
                        pattern: "200".to_string(),
                    },
                },
                metadata: TemplateMetadata {
                    category: "deepscan".to_string(),
                    tags: vec!["info_leak".to_string(), "deepscan".to_string()],
                    cpe: None,
                    reference_urls: vec![],
                    port: None,
                    service: Some("http".to_string()),
                },
            },
            // 深度扫描: 额外的 CVE 检测点 - Apache 路径穿越
            PluginTemplate {
                id: "deepscan-apache-path-traversal".to_string(),
                name: "深度扫描-Apache 路径穿越".to_string(),
                severity: "high".to_string(),
                author: Some("Argus".to_string()),
                description: Some("深度扫描模式下检测 Apache 路径穿越".to_string()),
                cve: Some("CVE-2021-41773".to_string()),
                cvss: Some(7.5),
                fix_advice: Some("升级 Apache httpd 到最新版本".to_string()),
                detection: DetectionConfig {
                    method: "GET".to_string(),
                    path: "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd".to_string(),
                    headers: None,
                    body: None,
                    match_rule: MatchRule {
                        match_type: MatchType::Body,
                        pattern: "root:".to_string(),
                    },
                },
                metadata: TemplateMetadata {
                    category: "deepscan".to_string(),
                    tags: vec!["cve".to_string(), "deepscan".to_string()],
                    cpe: None,
                    reference_urls: vec![],
                    port: None,
                    service: Some("http".to_string()),
                },
            },
        ]
    }

    /// 主动探测阶段：执行模板扫描
    async fn run_active(
        &self,
        target: &argus_scanner::Target,
        timeout_secs: u64,
        deep_scan: bool,
    ) -> (Vec<PluginResult>, Vec<String>) {
        let mut templates = match self.templates.read() {
            Ok(t) => t.clone(),
            Err(_) => return (vec![], vec![]),
        };

        // G4.7: 深度扫描模式 - 追加深度扫描专用模板
        if deep_scan {
            templates.extend(Self::deep_scan_templates());
        }

        if templates.is_empty() {
            return (vec![], vec![]);
        }
        let runtime = match self.runtime.read() {
            Ok(r) => match r.as_ref() {
                Some(rt) => rt.clone(),
                None => VulnPluginRuntime::with_default(timeout_secs),
            },
            Err(_) => return (vec![], vec![]),
        };
        // 构造目标（host:port 或 URL）
        let target_str = match &target.ports {
            Some(ports) if !ports.is_empty() => {
                // 对每个端口分别探测；返回第一个端口的主结果（简化实现）
                let mut all = vec![];
                let mut used_ids = vec![];
                for p in ports {
                    let url = format!("{}:{}", target.host, p);
                    let r = runtime.execute_batch(&templates, &url, 5).await;
                    for pr in r {
                        used_ids.push(pr.vuln_id.clone());
                        all.push(pr);
                    }
                }
                return (all, used_ids);
            }
            _ => target.host.clone(),
        };
        let used: Vec<String> = templates.iter().map(|t| t.id.clone()).collect();
        let results = runtime.execute_batch(&templates, &target_str, 5).await;
        (results, used)
    }

    /// 被动匹配阶段：基于指纹查 CVE
    async fn run_passive(
        &self,
        target: &argus_scanner::Target,
        fingerprints: &[argus_fingerprint::types::ServiceFingerprint],
    ) -> Vec<crate::types::MatchedCve> {
        let matcher = match self.cpe_matcher.read() {
            Ok(guard) => match guard.as_ref() {
                Some(m) => m.clone(),
                None => return vec![],
            },
            Err(_) => return vec![],
        };
        if fingerprints.is_empty() {
            tracing::debug!(
                "目标 {} 无指纹数据，跳过被动 CPE 匹配",
                target.host
            );
            return vec![];
        }
        matcher.match_fingerprints(fingerprints).await
    }

    /// G4.8: 执行危险漏洞插件（DoS 类）
    async fn run_dangerous_plugins(
        &self,
        host: &str,
        port: u16,
        timeout_secs: u64,
    ) -> Vec<PluginResult> {
        let scanner = DosScanner::new();
        let findings = scanner
            .scan(host, port, timeout_secs * 1000)
            .await;

        findings
            .into_iter()
            .map(|f| {
                let mut pr = PluginResult::new(
                    host.to_string(),
                    f.title,
                    f.severity,
                );
                pr.evidence = f.evidence;
                pr.fix_advice = f.fix_advice;
                pr.port = Some(port);
                pr.service = Some(f.plugin.as_str().to_string());
                pr.timestamp = chrono::Utc::now();
                pr
            })
            .collect()
    }
}

impl Default for VulnerabilityScanner {
    fn default() -> Self {
        Self::new(10, ScanMode::default())
    }
}

#[async_trait]
impl Scanner for VulnerabilityScanner {
    fn name(&self) -> &str {
        "vulnerability_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();
        let total = config.targets.len();
        if total == 0 {
            return Err(ScannerError::Config("没有扫描目标".to_string()));
        }

        // 从 extra_params 获取可选的指纹结果（被动匹配需要）
        let fingerprints_json = config.extra_params.get("fingerprints");
        let fingerprints: Vec<argus_fingerprint::types::ServiceFingerprint> =
            fingerprints_json
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

        // G4.7 & G4.8: 从 extra_params 读取 deep_scan / run_dangerous 覆盖配置
        let deep_scan = config
            .extra_params
            .get("deep_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(self.deep_scan);

        let run_dangerous = config
            .extra_params
            .get("run_dangerous")
            .and_then(|v| v.as_bool())
            .unwrap_or(self.run_dangerous);

        if deep_scan {
            tracing::info!("深度扫描模式已启用，将执行额外的 payload 变体检测");
        }
        if run_dangerous {
            tracing::warn!("危险漏洞插件（DoS 类）已启用，将执行 DoS 探测插件");
        }

        let mut all_results: Vec<VulnScanResult> = Vec::with_capacity(total);
        let mut all_vulns: Vec<PluginResult> = Vec::new();
        let passive_mode = matches!(self.mode, ScanMode::Passive);
        let active_mode = matches!(self.mode, ScanMode::Active);
        let hybrid = matches!(self.mode, ScanMode::Hybrid);

        for (i, target) in config.targets.iter().enumerate() {
            let mut vsr = VulnScanResult::new(&target.host);

            // active
            if active_mode || hybrid {
                let (results, used) = self.run_active(target, config.timeout_secs, deep_scan).await;
                for pr in results {
                    all_vulns.push(pr.clone());
                    vsr.active_findings.push(pr);
                }
                vsr.fingerprints_used.extend(used);
            }

            // passive
            if passive_mode || hybrid {
                let target_fps: Vec<_> = fingerprints
                    .iter()
                    .filter(|f| f.host == target.host)
                    .cloned()
                    .collect();
                let matched = self.run_passive(target, &target_fps).await;
                vsr.passive_findings.extend(matched);
            }

            // G4.8: 危险漏洞插件（DoS 类）
            if run_dangerous {
                // 对目标的每个端口执行 DoS 探测
                let ports: Vec<u16> = match &target.ports {
                    Some(p) if !p.is_empty() => p.clone(),
                    _ => vec![80],
                };
                for port in ports {
                    let dos_results = self
                        .run_dangerous_plugins(&target.host, port, config.timeout_secs)
                        .await;
                    for pr in dos_results {
                        all_vulns.push(pr.clone());
                        vsr.active_findings.push(pr);
                    }
                }
            }

            all_results.push(vsr);

            // 更新进度
            let progress = ((i + 1) as f32) / total as f32;
            if let Ok(mut map) = self.progress.write() {
                map.insert(task_id.clone(), progress * 0.9);
            }
        }

        let duration = start.elapsed().as_secs_f64();

        // 完成进度
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: TaskStatus::Completed,
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
            map.insert(task_id.to_string(), -1.0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_scanner::{ScanConfig, Target};

    #[test]
    fn test_default_constructor() {
        let s = VulnerabilityScanner::default();
        assert_eq!(s.name(), "vulnerability_scanner");
        assert_eq!(s.version(), "0.1.0");
        assert!(s.template_count() > 0, "应该加载内置模板");
    }

    #[test]
    fn test_with_custom_mode() {
        let s = VulnerabilityScanner::new(5, ScanMode::Active);
        assert_eq!(s.mode, ScanMode::Active);
    }

    #[tokio::test]
    async fn test_progress_default_zero() {
        let s = VulnerabilityScanner::default();
        let p = s.progress("nonexistent-task").await.expect("progress");
        assert_eq!(p, 0.0);
    }

    #[tokio::test]
    async fn test_cancel_sets_minus_one() {
        let s = VulnerabilityScanner::default();
        s.cancel("task-1").await.expect("cancel");
        let p = s.progress("task-1").await.expect("progress");
        assert_eq!(p, -1.0);
    }

    #[tokio::test]
    async fn test_execute_empty_targets_returns_err() {
        let s = VulnerabilityScanner::default();
        let cfg = ScanConfig {
            task_id: "t1".to_string(),
            targets: vec![],
            concurrency: 5,
            timeout_secs: 2,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_err(), "空目标应该返回错误");
    }

    #[tokio::test]
    async fn test_execute_active_mode_unreachable_target() {
        // 即使无法连接，扫描应该正常完成（结果为空，不报错）
        let s = VulnerabilityScanner::new(1, ScanMode::Active);
        let cfg = ScanConfig {
            task_id: "t-active".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "active 扫描应返回成功（即使无目标可达）");
        let sr = r.unwrap();
        assert_eq!(sr.hosts_scanned, 1);
    }

    #[tokio::test]
    async fn test_execute_passive_mode_no_fingerprints() {
        let s = VulnerabilityScanner::new(1, ScanMode::Passive);
        let cfg = ScanConfig {
            task_id: "t-passive".to_string(),
            targets: vec![Target {
                host: "127.0.0.1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "passive 扫描应返回成功");
        let sr = r.unwrap();
        assert_eq!(sr.hosts_scanned, 1);
    }

    // ============== G4.7: 深度扫描模式测试 ==============

    #[test]
    fn test_deep_scan_default_false() {
        let s = VulnerabilityScanner::default();
        assert!(!s.deep_scan, "deep_scan 默认为 false");
    }

    #[test]
    fn test_with_deep_scan_true() {
        let s = VulnerabilityScanner::default().with_deep_scan(true);
        assert!(s.deep_scan, "with_deep_scan(true) 应设置为 true");
    }

    #[test]
    fn test_deep_scan_templates_nonempty() {
        let templates = VulnerabilityScanner::deep_scan_templates();
        assert!(!templates.is_empty(), "深度扫描模板列表不应为空");
        // 验证所有模板都有正确的元数据
        for t in &templates {
            assert!(t.id.starts_with("deepscan-"), "模板 ID 应以 deepscan- 开头: {}", t.id);
            assert_eq!(t.metadata.category, "deepscan");
            assert!(t.metadata.tags.iter().any(|tag| tag == "deepscan"));
        }
    }

    #[test]
    fn test_deep_scan_templates_count() {
        let templates = VulnerabilityScanner::deep_scan_templates();
        // 深度扫描应包含至少 5 个模板（默认凭证、敏感路径、备份文件、Swagger、CVE）
        assert!(templates.len() >= 5, "深度扫描模板数量应 >= 5");
    }

    #[test]
    fn test_deep_scan_template_cve_fields() {
        let templates = VulnerabilityScanner::deep_scan_templates();
        // 验证 CVE 模板有 cve 和 cvss 字段
        let cve_templates: Vec<_> = templates.iter().filter(|t| t.cve.is_some()).collect();
        assert!(!cve_templates.is_empty(), "应至少有一个 CVE 模板");
        for t in &cve_templates {
            assert!(t.cvss.is_some(), "CVE 模板应设置 cvss");
        }
    }

    #[tokio::test]
    async fn test_execute_with_deep_scan_via_extra_params() {
        // 通过 extra_params 启用深度扫描
        let s = VulnerabilityScanner::new(1, ScanMode::Active);
        let cfg = ScanConfig {
            task_id: "t-deepscan".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({"deep_scan": true}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "深度扫描应返回成功");
    }

    #[tokio::test]
    async fn test_execute_with_deep_scan_via_builder() {
        // 通过 builder 启用深度扫描
        let s = VulnerabilityScanner::new(1, ScanMode::Active).with_deep_scan(true);
        assert!(s.deep_scan);
        let cfg = ScanConfig {
            task_id: "t-deepscan-builder".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "深度扫描应返回成功");
    }

    #[test]
    fn test_deep_scan_extra_params_overrides_builder() {
        // extra_params 中的 deep_scan 应覆盖 builder 设置
        let s = VulnerabilityScanner::default().with_deep_scan(true);
        // 模拟 execute 中的逻辑
        let extra_params = serde_json::json!({"deep_scan": false});
        let deep_scan = extra_params
            .get("deep_scan")
            .and_then(|v| v.as_bool())
            .unwrap_or(s.deep_scan);
        assert!(!deep_scan, "extra_params 中的 false 应覆盖 builder 的 true");
    }

    // ============== G4.8: 危险漏洞插件测试 ==============

    #[test]
    fn test_run_dangerous_default_false() {
        let s = VulnerabilityScanner::default();
        assert!(!s.run_dangerous, "run_dangerous 默认为 false");
    }

    #[test]
    fn test_with_run_dangerous_true() {
        let s = VulnerabilityScanner::default().with_run_dangerous(true);
        assert!(s.run_dangerous, "with_run_dangerous(true) 应设置为 true");
    }

    #[tokio::test]
    async fn test_execute_with_run_dangerous_via_extra_params() {
        // 通过 extra_params 启用危险插件
        let s = VulnerabilityScanner::new(1, ScanMode::Active);
        let cfg = ScanConfig {
            task_id: "t-dangerous".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({"run_dangerous": true}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "危险插件扫描应返回成功");
    }

    #[tokio::test]
    async fn test_execute_with_run_dangerous_via_builder() {
        // 通过 builder 启用危险插件
        let s = VulnerabilityScanner::new(1, ScanMode::Active).with_run_dangerous(true);
        assert!(s.run_dangerous);
        let cfg = ScanConfig {
            task_id: "t-dangerous-builder".to_string(),
            targets: vec![Target {
                host: "127.0.0.1:1".to_string(),
                ports: None,
                credentials: None,
            }],
            concurrency: 5,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "危险插件扫描应返回成功");
    }

    #[test]
    fn test_run_dangerous_extra_params_overrides_builder() {
        let s = VulnerabilityScanner::default().with_run_dangerous(true);
        let extra_params = serde_json::json!({"run_dangerous": false});
        let run_dangerous = extra_params
            .get("run_dangerous")
            .and_then(|v| v.as_bool())
            .unwrap_or(s.run_dangerous);
        assert!(!run_dangerous, "extra_params 中的 false 应覆盖 builder 的 true");
    }

    #[test]
    fn test_deep_scan_and_run_dangerous_independent() {
        // deep_scan 和 run_dangerous 应独立设置
        let s = VulnerabilityScanner::default()
            .with_deep_scan(true)
            .with_run_dangerous(false);
        assert!(s.deep_scan);
        assert!(!s.run_dangerous);

        let s2 = VulnerabilityScanner::default()
            .with_deep_scan(false)
            .with_run_dangerous(true);
        assert!(!s2.deep_scan);
        assert!(s2.run_dangerous);
    }
}
