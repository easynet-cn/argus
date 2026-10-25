//! Argus 端口扫描引擎
//!
//! 实现端口扫描、主机存活探测、服务指纹识别

pub mod types;
pub mod port_list;
pub mod host;
pub mod tcp;
pub mod udp;
pub mod fingerprint;
pub mod rate;
pub mod raw;
// G1.1-G1.3: 主机探测方式
pub mod arp_discovery;
pub mod udp_ping;
pub mod icmp_ping;
// G1.4: 网络抓包（扫描期间捕获流量，任务结束保存 pcap 文件）
pub mod pcap_capture;
// G4.5: 拓扑 Trace 路径数据采集
pub mod traceroute;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use rand::seq::SliceRandom;
use tokio::sync::RwLock;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError, Target};

use crate::fingerprint::fingerprint_port;
use crate::host::{ping_hosts, resolve_host};
use crate::pcap_capture::PcapCapture;
use crate::port_list::{get_ports_by_template, PortTemplate, top100_udp_ports};
use crate::rate::RateLimiter;
use crate::tcp::scan_tcp_ports;
use crate::types::{PortScanParams, PortScanResult, PortState, Protocol};
use crate::udp::scan_udp_ports_with_limiter;

/// 端口扫描引擎
pub struct PortScanner {
    /// 任务进度存储: task_id -> progress (0.0 - 1.0)
    progress: Arc<RwLock<HashMap<String, f32>>>,
    /// 运行中的任务
    running_tasks: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl PortScanner {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RwLock::new(HashMap::new())),
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 从 ScanConfig 解析端口扫描参数
    fn parse_params(config: &ScanConfig) -> PortScanParams {
        // 尝试从 extra_params 解析
        serde_json::from_value::<PortScanParams>(config.extra_params.clone())
            .unwrap_or_default()
    }

    /// 获取要扫描的端口列表
    fn get_ports(params: &PortScanParams) -> Vec<u16> {
        if let Some(ports) = &params.ports {
            return ports.clone();
        }
        // 默认使用 top 100
        get_ports_by_template(&PortTemplate::Top100)
    }

    /// 执行单个主机的完整端口扫描
    async fn scan_host(
        &self,
        host: &str,
        params: &PortScanParams,
        rate_limiter: Arc<RateLimiter>,
        _task_id: String,
        _progress: Arc<RwLock<HashMap<String, f32>>>,
    ) -> Vec<PortScanResult> {
        let ip = match resolve_host(host).await {
            Some(ip) => ip,
            None => return Vec::new(),
        };

        let mut all_results = Vec::new();
        let ports = Self::get_ports(params);

        // TCP 扫描（每个端口 acquire，并基于结果反馈给 RateLimiter）
        let tcp_ports = ports.clone();
        let tcp_results = scan_tcp_ports(
            &ip,
            &tcp_ports,
            params.tcp_scan_type,
            params.timeout_ms,
            params.concurrency,
            Some(rate_limiter.as_ref()),
        )
        .await;

        // 对开放端口进行指纹识别
        let mut tcp_results: Vec<PortScanResult> = tcp_results
            .into_iter()
            .filter(|r| r.state == PortState::Open)
            .collect();

        if params.fingerprint {
            for result in tcp_results.iter_mut() {
                fingerprint_port(result, params.timeout_ms).await;
            }
        }

        all_results.extend(tcp_results);

        // UDP 扫描（带协议特定 probe + 速率反馈）
        if params.scan_udp {
            let udp_ports = top100_udp_ports();
            let udp_results = scan_udp_ports_with_limiter(
                &ip,
                &udp_ports,
                params.timeout_ms,
                params.concurrency.min(100), // UDP 扫描并发低一些
                Some(rate_limiter.as_ref()),
            )
            .await;

            let open_udp: Vec<PortScanResult> = udp_results
                .into_iter()
                .filter(|r| {
                    r.state == PortState::Open || r.state == PortState::OpenFiltered
                })
                .collect();

            all_results.extend(open_udp);
        }

        all_results
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for PortScanner {
    fn name(&self) -> &str {
        "port_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let start = Instant::now();
        let task_id = config.task_id.clone();
        let params = Self::parse_params(config);

        // G1.4: 启动网络抓包（如果启用）
        let mut pcap_capture: Option<PcapCapture> = if params.pcap_enabled {
            let interface = params
                .pcap_interface
                .clone()
                .unwrap_or_else(|| "any".to_string());
            let filter = params.pcap_filter.as_deref();
            let mut cap = PcapCapture::new(&interface, filter);
            if let Err(e) = cap.start() {
                tracing::warn!("启动抓包失败，跳过抓包: {}", e);
                None
            } else {
                tracing::info!(
                    "任务 {}: 已启动抓包 (接口={}, 过滤={:?})",
                    task_id,
                    interface,
                    filter
                );
                Some(cap)
            }
        } else {
            None
        };

        // 初始化进度
        self.progress.write().await.insert(task_id.clone(), 0.0);

        // 创建限流器
        let rate_limiter = if params.rate_limit > 0 {
            RateLimiter::new(params.rate_limit)
        } else {
            RateLimiter::unlimited()
        };

        // 随机打乱目标顺序，避免顺序扫描被检测
        let mut targets: Vec<Target> = config.targets.clone();
        targets.shuffle(&mut rand::rng());

        // 1. 主机存活探测
        let hosts: Vec<String> = targets.iter().map(|t| t.host.clone()).collect();
        let alive_results = ping_hosts(&hosts, params.timeout_ms, params.concurrency).await;
        let alive_hosts: Vec<String> = alive_results
            .iter()
            .filter(|r| r.alive)
            .map(|r| r.host.clone())
            .collect();

        tracing::info!(
            "端口扫描任务 {}: 存活主机 {}/{}",
            task_id,
            alive_hosts.len(),
            hosts.len()
        );

        // 2. 对存活主机进行端口扫描
        let total_hosts = alive_hosts.len();
        let mut all_results: Vec<PortScanResult> = Vec::new();
        let progress = self.progress.clone();

        for (idx, host) in alive_hosts.iter().enumerate() {
            let results = self
                .scan_host(
                    host,
                    &params,
                    rate_limiter.clone(),
                    task_id.clone(),
                    progress.clone(),
                )
                .await;

            let open_count = results
                .iter()
                .filter(|r| r.state == PortState::Open)
                .count();
            tracing::info!(
                "主机 {}: 发现 {} 个开放端口",
                host,
                open_count
            );

            all_results.extend(results);

            // 更新进度
            let p = if total_hosts > 0 {
                (idx + 1) as f32 / total_hosts as f32
            } else {
                1.0
            };
            progress.write().await.insert(task_id.clone(), p);
        }

        // 3. 构建扫描结果
        let duration = start.elapsed().as_secs_f64();
        let open_ports: Vec<&PortScanResult> = all_results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .collect();

        // 将开放端口转换为 PluginResult（漏洞视角：开放端口即信息泄露风险）
        let vulnerabilities: Vec<PluginResult> = open_ports
            .iter()
            .map(|r| PluginResult {
                vuln_id: format!("port-{}-{}", r.protocol_to_string(), r.port),
                name: format!(
                    "端口开放: {}/{} ({})",
                    r.port,
                    r.protocol_to_string(),
                    r.service.clone().unwrap_or_else(|| "unknown".to_string())
                ),
                severity: "info".to_string(),
                evidence: r.banner.clone().unwrap_or_default(),
                cvss: None,
                cve: None,
                fix_advice: Some(format!(
                    "如非必要，请关闭端口 {} 或限制访问来源",
                    r.port
                )),
                target: r.host.clone(),
                port: Some(r.port),
                service: r.service.clone(),
                timestamp: chrono::Utc::now(),
            })
            .collect();

        let raw_data = serde_json::to_value(&all_results).ok();

        // 标记完成
        progress.write().await.insert(task_id.clone(), 1.0);

        // G1.4: 停止抓包并保存 pcap 文件
        if let Some(ref mut cap) = pcap_capture {
            cap.stop();
            let output_path = params
                .pcap_output
                .clone()
                .unwrap_or_else(|| format!("/tmp/argus_scan_{}.pcap", task_id));
            let packet_count = cap.packet_count();
            match cap.save(&output_path) {
                Ok(()) => {
                    tracing::info!(
                        "任务 {}: 抓包已保存到 {} ({} 个包)",
                        task_id,
                        output_path,
                        packet_count
                    );
                }
                Err(e) => {
                    tracing::error!("任务 {}: 保存抓包文件失败: {}", task_id, e);
                }
            }
        }

        Ok(ScanResult {
            task_id: task_id.clone(),
            status: TaskStatus::Completed,
            hosts_scanned: total_hosts,
            vulnerabilities,
            duration_secs: duration,
            raw_data,
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        let progress = self.progress.read().await;
        Ok(*progress.get(task_id).unwrap_or(&0.0))
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        let mut tasks = self.running_tasks.write().await;
        if let Some(handle) = tasks.remove(task_id) {
            handle.abort();
            tracing::info!("任务 {} 已取消", task_id);
        }
        self.progress.write().await.remove(task_id);
        Ok(())
    }
}

// 为 Protocol 添加辅助方法
impl Protocol {
    pub fn to_string(&self) -> String {
        match self {
            Protocol::Tcp => "tcp".to_string(),
            Protocol::Udp => "udp".to_string(),
        }
    }
}

// 为 PortScanResult 添加辅助方法
impl PortScanResult {
    pub fn protocol_to_string(&self) -> String {
        self.protocol.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::port_list::*;
    use crate::types::TcpScanType;

    #[test]
    fn test_port_range_parse_single() {
        let ports = parse_port_range("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_port_range_parse_range() {
        let ports = parse_port_range("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_port_range_parse_mixed() {
        let ports = parse_port_range("1-3,80,443,8080-8082").unwrap();
        assert_eq!(ports.len(), 8);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&8081));
    }

    #[test]
    fn test_port_range_parse_invalid() {
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("100-50").is_err()); // start > end
    }

    #[test]
    fn test_top100_ports() {
        let ports = get_ports_by_template(&PortTemplate::Top100);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&22));
        assert!(ports.len() >= 90);
    }

    #[test]
    fn test_top1000_ports() {
        let ports = get_ports_by_template(&PortTemplate::Top1000);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.len() > 100);
    }

    #[test]
    fn test_full_ports() {
        let ports = get_ports_by_template(&PortTemplate::Full);
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn test_custom_ports() {
        let custom = vec![1, 2, 3];
        let ports = get_ports_by_template(&PortTemplate::Custom(custom.clone()));
        assert_eq!(ports, custom);
    }

    #[test]
    fn test_port_state_as_str() {
        assert_eq!(PortState::Open.as_str(), "open");
        assert_eq!(PortState::Closed.as_str(), "closed");
        assert_eq!(PortState::Filtered.as_str(), "filtered");
    }

    #[test]
    fn test_protocol_to_string() {
        assert_eq!(Protocol::Tcp.to_string(), "tcp");
        assert_eq!(Protocol::Udp.to_string(), "udp");
    }

    #[test]
    fn test_port_scan_params_default() {
        let params = PortScanParams::default();
        assert!(params.ports.is_none());
        assert_eq!(params.tcp_scan_type, TcpScanType::Connect);
        assert!(!params.scan_udp);
        assert!(params.fingerprint);
        assert_eq!(params.concurrency, 1000);
        assert_eq!(params.timeout_ms, 1000);
        assert_eq!(params.rate_limit, 0);
    }
}
