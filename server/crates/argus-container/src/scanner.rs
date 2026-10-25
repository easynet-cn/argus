//! 容器扫描引擎
//!
//! 实现 Scanner trait，统筹镜像扫描 + Harbor 集成 + 依赖漏洞匹配

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError};
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::types::*;
use crate::image_scan::ImageScanner;
use crate::harbor::HarborClient;
use crate::dep_vuln::DepVulnMatcher;

/// 容器扫描引擎
pub struct ContainerScanner {
    progress: RwLock<HashMap<String, f32>>,
    cancel_flags: RwLock<HashMap<String, Arc<AtomicBool>>>,
}

impl ContainerScanner {
    pub fn new() -> Self {
        Self {
            progress: RwLock::new(HashMap::new()),
            cancel_flags: RwLock::new(HashMap::new()),
        }
    }

    /// 从 ScanConfig 解析容器扫描参数
    fn parse_params(config: &ScanConfig) -> ContainerScanParams {
        tracing::info!("解析容器扫描参数: {}", config.extra_params);
        match serde_json::from_value(config.extra_params.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("容器参数解析失败: {e}");
                ContainerScanParams::default()
            }
        }
    }

    /// 执行镜像扫描
    async fn run_scan(&self, params: &ContainerScanParams, task_id: &str) -> Result<ImageScanResult, ScannerError> {
        let cancel_flag = {
            let map = self.cancel_flags.read().await;
            map.get(task_id).cloned().unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
        };

        // 解析镜像名 (格式: project/repo:tag)
        let (image, tag) = parse_image_tag(&params.image);
        let mut result = ImageScanResult::new(&image, &tag);

        // 1. 从 Harbor 获取 manifest (如果提供了 Harbor URL)
        if let (Some(harbor_url), username, password) = (&params.harbor_url, &params.harbor_username, &params.harbor_password) {
            let client = HarborClient::new(harbor_url, username.as_deref().unwrap_or(""), password.as_deref().unwrap_or(""));

            // 解析 Harbor project/repo
            let parts: Vec<&str> = image.splitn(2, '/').collect();
            if parts.len() == 2 {
                let project = parts[0];
                let repo = parts[1];

                // 获取 manifest
                match client.get_manifest(project, repo, &tag).await {
                    Ok(manifest_str) => {
                        // 尝试解析 manifest
                        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&manifest_str) {
                            if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
                                for layer in layers {
                                    let digest = layer.get("digest").and_then(|d| d.as_str()).unwrap_or("");
                                    let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                                    result.layers.push(ImageLayer {
                                        id: digest.to_string(),
                                        command: None,
                                        size,
                                        files: vec![],
                                    });
                                }
                            }
                            // R6.2 修复：获取 config blob，解析环境变量/CMD/ENTRYPOINT
                            if let Some(config_digest) = manifest.get("config").and_then(|c| c.get("digest")).and_then(|d| d.as_str()) {
                                tracing::info!("镜像 config digest: {}", config_digest);
                                match client.get_config_blob(project, repo, config_digest).await {
                                    Ok(config_json) => {
                                        // 解析 config JSON 中的 history 字段（Docker config blob 结构）
                                        if let Some(history) = config_json.get("history").and_then(|h| h.as_array()) {
                                            for layer in history {
                                                if let Some(empty_layer) = layer.get("empty_layer").and_then(|e| e.as_bool()) {
                                                    if empty_layer { continue; }
                                                }
                                                if let Some(created_by) = layer.get("created_by").and_then(|c| c.as_str()) {
                                                    // 记录 Dockerfile 层命令
                                                    if !result.layers.is_empty() {
                                                        let layer_idx = result.layers.len().saturating_sub(1);
                                                        if result.layers[layer_idx].command.is_none() {
                                                            result.layers[layer_idx].command = Some(created_by.to_string());
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // 解析 config 中的环境变量
                                        if let Some(config) = config_json.get("config") {
                                            if let Some(env) = config.get("Env").and_then(|e| e.as_array()) {
                                                let mut sensitive_envs: Vec<String> = Vec::new();
                                                for env_var in env {
                                                    if let Some(var_str) = env_var.as_str() {
                                                        // 检测敏感环境变量
                                                        let lower = var_str.to_lowercase();
                                                        let is_sensitive = lower.contains("password")
                                                            || lower.contains("passwd")
                                                            || lower.contains("secret")
                                                            || lower.contains("token")
                                                            || lower.contains("api_key")
                                                            || lower.contains("apikey")
                                                            || lower.contains("access_key")
                                                            || lower.contains("private_key")
                                                            || lower.contains("credential");
                                                        if is_sensitive {
                                                            sensitive_envs.push(var_str.to_string());
                                                        }
                                                    }
                                                }
                                                if !sensitive_envs.is_empty() {
                                                    result.sensitive_env = sensitive_envs;
                                                }
                                            }
                                            // 解析 CMD/ENTRYPOINT
                                            if let Some(cmd) = config.get("Cmd").and_then(|c| c.as_array()) {
                                                let cmd_str: Vec<String> = cmd.iter()
                                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                    .collect();
                                                if !cmd_str.is_empty() && !result.layers.is_empty() {
                                                    result.layers[0].command = Some(cmd_str.join(" "));
                                                }
                                            }
                                            if let Some(entrypoint) = config.get("Entrypoint").and_then(|e| e.as_array()) {
                                                let ep_str: Vec<String> = entrypoint.iter()
                                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                                    .collect();
                                                if !ep_str.is_empty() {
                                                    result.entrypoint = Some(ep_str.join(" "));
                                                }
                                            }
                                            if let Some(workdir) = config.get("WorkingDir").and_then(|w| w.as_str()) {
                                                result.working_dir = Some(workdir.to_string());
                                            }
                                        }
                                        tracing::info!("镜像 config blob 解析完成: {} 个环境变量",
                                            config_json.get("config")
                                                .and_then(|c| c.get("Env"))
                                                .and_then(|e| e.as_array())
                                                .map(|v| v.len())
                                                .unwrap_or(0));
                                    }
                                    Err(e) => {
                                        tracing::warn!("获取镜像 config blob 失败: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("获取 Harbor manifest 失败: {}", e);
                    }
                }

                // 触发 Harbor 漏洞扫描
                if params.scan_vulns {
                    if let Err(e) = client.trigger_scan(project, repo, &tag).await {
                        tracing::warn!("触发 Harbor 扫描失败: {}", e);
                    }
                }
            }
        }

        // 2. 敏感文件检测
        if params.scan_sensitive {
            // 对已知层文件列表进行检测
            let scanner = ImageScanner::new();
            for layer in &result.layers {
                for file_path in &layer.files {
                    if cancel_flag.load(Ordering::Relaxed) {
                        return Err(ScannerError::Cancelled("扫描被取消".to_string()));
                    }
                    if let Some(sf) = scanner.check_sensitive_path(file_path) {
                        result.sensitive_files.push(sf);
                    }
                }
            }
        }

        // 3. 依赖漏洞匹配
        if params.scan_vulns {
            let matcher = DepVulnMatcher::new();
            // 本地已知漏洞匹配（不依赖网络）
            // 从镜像层文件中提取包信息（简化版）
            let packages = extract_packages_from_layers(&result.layers);
            for (pkg, ver) in &packages {
                if cancel_flag.load(Ordering::Relaxed) {
                    return Err(ScannerError::Cancelled("扫描被取消".to_string()));
                }
                let vulns = matcher.match_local_known(pkg, ver);
                result.vulnerabilities.extend(vulns);
            }

            // OSV API 查询（如果网络可用）
            if !packages.is_empty() {
                let os_vulns = matcher.query_os_packages(&packages).await;
                result.vulnerabilities.extend(os_vulns);
            }
        }

        Ok(result)
    }
}

impl Default for ContainerScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for ContainerScanner {
    fn name(&self) -> &str {
        "container_scanner"
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

        let mut all_vulns = Vec::new();

        match self.run_scan(&params, &task_id).await {
            Ok(scan_result) => {
                // 将漏洞转为 PluginResult
                for vuln in &scan_result.vulnerabilities {
                    let mut pr = PluginResult::new(
                        scan_result.image.clone(),
                        format!("{}: {} {}", vuln.cve_id, vuln.package, vuln.version),
                        map_severity(&vuln.severity),
                    );
                    pr.evidence = format!(
                        "CVE: {} | 包: {} {} | 修复: {} | 来源: {}",
                        vuln.cve_id,
                        vuln.package,
                        vuln.version,
                        vuln.fixed_version.as_deref().unwrap_or("无修复版本"),
                        vuln.source,
                    );
                    all_vulns.push(pr);
                }

                // 敏感文件也作为发现
                for sf in &scan_result.sensitive_files {
                    let mut pr = PluginResult::new(
                        scan_result.image.clone(),
                        format!("敏感文件: {}", sf.path),
                        map_severity(&sf.severity),
                    );
                    pr.evidence = format!("{} | 类型: {}", sf.description, sf.file_type);
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

/// 解析镜像名和标签
/// "library/nginx:latest" → ("library/nginx", "latest")
/// "nginx" → ("nginx", "latest")
fn parse_image_tag(image: &str) -> (String, String) {
    if let Some((name, tag)) = image.rsplit_once(':') {
        // 确保冒号后面不是端口（简单判断: 包含 / 的不是标签）
        if !tag.contains('/') {
            return (name.to_string(), tag.to_string());
        }
    }
    (image.to_string(), "latest".to_string())
}

/// 从镜像层提取包名和版本
fn extract_packages_from_layers(layers: &[ImageLayer]) -> Vec<(String, String)> {
    let mut packages = Vec::new();
    for layer in layers {
        // 从命令中提取包安装信息
        if let Some(cmd) = &layer.command {
            // apt-get install xxx=1.2.3
            let apt_re = regex::Regex::new(r"(\S+)=([\d.]+)").ok();
            if let Some(re) = apt_re {
                for cap in re.captures_iter(cmd) {
                    packages.push((cap[1].to_string(), cap[2].to_string()));
                }
            }
            // apk add xxx-1.2.3
            let apk_re = regex::Regex::new(r"(\S+)-([\d.]+)").ok();
            if let Some(re) = apk_re {
                for cap in re.captures_iter(cmd) {
                    packages.push((cap[1].to_string(), cap[2].to_string()));
                }
            }
        }
    }
    packages
}

/// 映射严重级别
fn map_severity(severity: &str) -> String {
    let lower = severity.to_lowercase();
    match lower.as_str() {
        "critical" | "10.0" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "info",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_tag_with_tag() {
        let (name, tag) = parse_image_tag("library/nginx:1.21");
        assert_eq!(name, "library/nginx");
        assert_eq!(tag, "1.21");
    }

    #[test]
    fn test_parse_image_tag_no_tag() {
        let (name, tag) = parse_image_tag("nginx");
        assert_eq!(name, "nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_image_tag_with_registry() {
        let (name, tag) = parse_image_tag("registry.example.com:5000/nginx:latest");
        assert_eq!(name, "registry.example.com:5000/nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(map_severity("CRITICAL"), "critical");
        assert_eq!(map_severity("high"), "high");
        assert_eq!(map_severity("unknown"), "info");
    }
}
