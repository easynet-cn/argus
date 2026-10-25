//! 端口扫描相关数据类型

use serde::{Deserialize, Serialize};

/// 扫描协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// TCP 扫描方式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpScanType {
    /// Connect 扫描（完整三次握手，无需 root）
    Connect,
    /// SYN 半开扫描（需 raw socket）
    Syn,
    /// ACK 扫描（探测防火墙规则）
    Ack,
    /// Null 扫描（无标志位）
    Null,
    /// Xmas 扫描（FIN+PSH+URG）
    Xmas,
    /// Fin 扫描（仅 FIN）
    Fin,
    /// Window 扫描
    Window,
}

/// 端口状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::ClosedFiltered => "closed|filtered",
        }
    }
}

/// 端口扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub response_time_ms: u64,
}

/// 主机存活状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAliveResult {
    pub host: String,
    pub ip: String,
    pub alive: bool,
    pub response_time_ms: Option<u64>,
}

/// 端口扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanParams {
    /// 目标端口列表，为空则使用默认端口
    pub ports: Option<Vec<u16>>,
    /// TCP 扫描方式
    pub tcp_scan_type: TcpScanType,
    /// 是否扫描 UDP
    pub scan_udp: bool,
    /// 是否进行服务指纹识别
    pub fingerprint: bool,
    /// 并发数
    pub concurrency: usize,
    /// 超时（毫秒）
    pub timeout_ms: u64,
    /// 发包速率（包/秒），0 表示不限速
    pub rate_limit: u32,
    /// G1.4: 是否启用网络抓包
    pub pcap_enabled: bool,
    /// G1.4: 抓包网络接口（如 "eth0"、"en0"）
    pub pcap_interface: Option<String>,
    /// G1.4: BPF 过滤规则（如 "tcp port 80"）
    pub pcap_filter: Option<String>,
    /// G1.4: pcap 文件保存路径
    pub pcap_output: Option<String>,
}

impl Default for PortScanParams {
    fn default() -> Self {
        Self {
            ports: None,
            tcp_scan_type: TcpScanType::Connect,
            scan_udp: false,
            fingerprint: true,
            concurrency: 1000,
            timeout_ms: 1000,
            rate_limit: 0,
            pcap_enabled: false,
            pcap_interface: None,
            pcap_filter: None,
            pcap_output: None,
        }
    }
}
