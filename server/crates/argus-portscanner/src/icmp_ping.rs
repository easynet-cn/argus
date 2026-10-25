//! G1.3 实时 ICMP Ping 监控
//!
//! 在扫描期间周期性发送 ICMP Echo Request，如果主机停止响应则标记为死亡并停止扫描。
//! 使用 pnet transport channel 发送/接收原始 ICMP 包。
//! 限制：需要 root 权限创建 raw socket。

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, ipv4_packet_iter};

use tokio::task::JoinHandle;

use crate::host::resolve_host;
use crate::types::HostAliveResult;

// ==================== 协议常量 ====================

/// ICMP Type: Echo Reply
const ICMP_TYPE_ECHO_REPLY: u8 = 0;

/// ICMP Type: Echo Request
const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

/// ICMP 协议号
const IP_PROTOCOL_ICMP: u8 = 1;

// ==================== 纯函数（可测试） ====================

/// 计算 ICMP 校验和（RFC 1071 Internet checksum）
///
/// 将数据按 16-bit 字累加，折叠进位，最后取反。
pub fn compute_icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // 按 16-bit 字累加
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }

    // 处理奇数长度（最后一个字节按高位处理）
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    // 折叠进位
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 取反得到校验和
    (!sum & 0xFFFF) as u16
}

/// 构造 ICMP Echo Request 包
///
/// 包结构:
/// - Type(1): 8 (Echo Request)
/// - Code(1): 0
/// - Checksum(2): 自动计算
/// - Identifier(2)
/// - Sequence(2)
/// - Payload(变长)
pub fn build_icmp_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    packet.push(ICMP_TYPE_ECHO_REQUEST); // Type: Echo Request
    packet.push(0); // Code: 0
    packet.extend_from_slice(&[0u8, 0u8]); // Checksum 占位符
    packet.extend_from_slice(&identifier.to_be_bytes()); // Identifier
    packet.extend_from_slice(&sequence.to_be_bytes()); // Sequence
    packet.extend_from_slice(payload); // Payload

    // 计算并设置校验和
    let checksum = compute_icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xFF) as u8;

    packet
}

/// 检查 ICMP 类型是否为 Echo Reply (type=0)
pub fn is_icmp_echo_reply(icmp_type: u8) -> bool {
    icmp_type == ICMP_TYPE_ECHO_REPLY
}

/// 从 ICMP 数据中解析 Echo Reply 的标识符和序列号
///
/// 返回 (identifier, sequence) 如果是有效的 Echo Reply。
pub fn parse_icmp_echo_reply(data: &[u8]) -> Option<(u16, u16)> {
    // ICMP 头部至少 8 字节
    if data.len() < 8 {
        return None;
    }
    // 检查类型是否为 Echo Reply
    if data[0] != ICMP_TYPE_ECHO_REPLY {
        return None;
    }
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    Some((identifier, sequence))
}

/// 从 IPv4 数据包中解析 ICMP 类型和代码
///
/// 返回 (源 IP, ICMP 类型, ICMP 代码)。
pub fn parse_icmp_from_ipv4(data: &[u8]) -> Option<(Ipv4Addr, u8, u8)> {
    if data.len() < 20 {
        return None;
    }
    if (data[0] >> 4) != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    if data[9] != IP_PROTOCOL_ICMP {
        return None;
    }
    if data.len() < header_len + 2 {
        return None;
    }
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let icmp_type = data[header_len];
    let icmp_code = data[header_len + 1];
    Some((src_ip, icmp_type, icmp_code))
}

// ==================== 网络函数 ====================

/// ICMP Ping 探测单个主机
///
/// 发送 ICMP Echo Request 并等待 Echo Reply。
/// 如果收到回复则主机存活。
pub async fn icmp_ping(host: &str, timeout_ms: u64) -> HostAliveResult {
    // 先在异步上下文中解析主机名
    let ip = match resolve_host(host).await {
        Some(ip) => ip,
        None => {
            return HostAliveResult {
                host: host.to_string(),
                ip: host.to_string(),
                alive: false,
                response_time_ms: None,
            }
        }
    };
    let host = host.to_string();
    let host_clone = host.clone();
    let ip_clone = ip.clone();
    tokio::task::spawn_blocking(move || icmp_ping_blocking(&host, &ip, timeout_ms))
        .await
        .unwrap_or_else(|_| HostAliveResult {
            host: host_clone,
            ip: ip_clone,
            alive: false,
            response_time_ms: None,
        })
}

/// ICMP Ping 阻塞版本
fn icmp_ping_blocking(host: &str, ip_str: &str, timeout_ms: u64) -> HostAliveResult {
    let dst_ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // 创建 ICMP transport channel（需要 root 权限）
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(65535, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            tracing::debug!("创建 ICMP raw socket 失败（可能无 root 权限）: {e}");
            return HostAliveResult {
                host: host.to_string(),
                ip: ip_str.to_string(),
                alive: false,
                response_time_ms: None,
            };
        }
    };

    // 构造 ICMP Echo Request
    let identifier: u16 = rand::random();
    let sequence: u16 = 1;
    let payload = b"argus-ping".to_vec();
    let echo_request = build_icmp_echo_request(identifier, sequence, &payload);

    // 发送 ICMP Echo Request（使用 IcmpPacket 包装以满足 Packet trait）
    let start = Instant::now();
    if let Some(icmp_packet) = IcmpPacket::new(&echo_request) {
        if let Err(e) = tx.send_to(icmp_packet, dst_ip) {
            tracing::debug!("发送 ICMP Echo Request 到 {dst_ip} 失败: {e}");
            let elapsed = start.elapsed().as_millis() as u64;
            return HostAliveResult {
                host: host.to_string(),
                ip: ip_str.to_string(),
                alive: false,
                response_time_ms: Some(elapsed),
            };
        }
    } else {
        tracing::debug!("构造 ICMP Echo Request 包失败");
        let elapsed = start.elapsed().as_millis() as u64;
        return HostAliveResult {
            host: host.to_string(),
            ip: ip_str.to_string(),
            alive: false,
            response_time_ms: Some(elapsed),
        };
    }

    // 等待 ICMP Echo Reply
    let timeout = Duration::from_millis(timeout_ms);
    let mut iter = ipv4_packet_iter(&mut rx);
    loop {
        match iter.next_with_timeout(timeout) {
            Ok(Some((ipv4, src_addr))) => {
                // 检查源 IP 是否来自目标主机
                if src_addr == dst_ip {
                    // 获取 ICMP payload
                    let icmp_data = ipv4.payload();
                    if icmp_data.len() >= 8 {
                        let icmp_type = icmp_data[0];
                        // 检查是否为 Echo Reply
                        if is_icmp_echo_reply(icmp_type) {
                            // 解析 identifier 和 sequence
                            if let Some((resp_id, _resp_seq)) = parse_icmp_echo_reply(icmp_data) {
                                // 验证 identifier 是否匹配
                                if resp_id == identifier {
                                    let elapsed = start.elapsed().as_millis() as u64;
                                    return HostAliveResult {
                                        host: host.to_string(),
                                        ip: ip_str.to_string(),
                                        alive: true,
                                        response_time_ms: Some(elapsed),
                                    };
                                }
                            }
                        }
                    }
                }
                // 不是我们要找的包，继续等待
            }
            Ok(None) => break, // 超时
            Err(_) => break,    // 错误
        }
    }

    // 超时，主机未响应
    let elapsed = start.elapsed().as_millis() as u64;
    HostAliveResult {
        host: host.to_string(),
        ip: ip_str.to_string(),
        alive: false,
        response_time_ms: Some(elapsed),
    }
}

// ==================== 主机存活监控器 ====================

/// 主机存活监控器
///
/// 在扫描期间周期性发送 ICMP Echo Request。
/// 如果主机停止响应，标记为死亡，调用方可据此停止该主机的后续扫描。
pub struct HostMonitor {
    /// 主机是否存活（共享标志，线程安全）
    alive: Arc<AtomicBool>,
    /// 后台监控任务句柄
    handle: Option<JoinHandle<()>>,
}

impl HostMonitor {
    /// 启动主机存活监控
    ///
    /// 参数:
    /// - `host`: 目标主机
    /// - `interval`: 两次 ping 之间的间隔
    /// - `timeout`: 单次 ping 的超时时间
    ///
    /// 首次 ping 在 `interval` 时间后执行。
    pub fn start(host: String, interval: Duration, timeout: Duration) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_clone = alive.clone();

        let handle = tokio::spawn(async move {
            loop {
                // 先等待 interval 再 ping
                tokio::time::sleep(interval).await;

                let result = icmp_ping(&host, timeout.as_millis() as u64).await;
                if !result.alive {
                    alive_clone.store(false, Ordering::Relaxed);
                    tracing::warn!("主机 {host} 已停止响应 ICMP Ping，标记为死亡");
                    break;
                }
            }
        });

        Self {
            alive,
            handle: Some(handle),
        }
    }

    /// 检查主机是否存活
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// 停止监控
    pub async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for HostMonitor {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_icmp_checksum_empty() {
        // 空数据的校验和应为 0xFFFF
        let checksum = compute_icmp_checksum(&[]);
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_compute_icmp_checksum_known_value() {
        // 构造 ICMP Echo Request: type=8, code=0, checksum=0, id=1, seq=1
        let packet = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = compute_icmp_checksum(&packet);
        // 手动计算: 0x0800 + 0x0000 + 0x0001 + 0x0001 = 0x0802
        // 取反: ~0x0802 = 0xF7FD
        assert_eq!(checksum, 0xF7FD);
    }

    #[test]
    fn test_compute_icmp_checksum_with_payload() {
        // 构造 ICMP Echo Request: type=8, code=0, checksum=0, id=0xABCD, seq=0x1234
        // Payload: 0xDEADBEEF
        let packet = [
            0x08, 0x00, 0x00, 0x00, 0xAB, 0xCD, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let checksum = compute_icmp_checksum(&packet);
        // 手动计算:
        // 0x0800 + 0x0000 + 0xABCD + 0x1234 + 0xDEAD + 0xBEEF
        // = 0x0800 + 0xABCD = 0xB3CD
        // + 0x1234 = 0xC601
        // + 0xDEAD = 0x1A4AE → fold: 0xA4AE + 1 = 0xA4AF
        // + 0xBEEF = 0x1639E → fold: 0x639E + 1 = 0x639F
        // ~0x639F = 0x9C60
        assert_eq!(checksum, 0x9C60);
    }

    #[test]
    fn test_compute_icmp_checksum_odd_length() {
        // 奇数长度数据
        let data = [0x08, 0x00, 0xFF]; // 3 bytes
        let checksum = compute_icmp_checksum(&data);
        // 0x0800 + 0xFF00 = 0x10700 → fold: 0x0700 + 1 = 0x0701
        // ~0x0701 = 0xF8FE
        assert_eq!(checksum, 0xF8FE);
    }

    #[test]
    fn test_compute_icmp_checksum_self_verify() {
        // 验证：包含正确校验和的包，重新计算应得 0（全零）
        let packet = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = compute_icmp_checksum(&packet);
        // 设置校验和后重新计算
        let mut verified = packet;
        verified[2] = (checksum >> 8) as u8;
        verified[3] = (checksum & 0xFF) as u8;
        let recheck = compute_icmp_checksum(&verified);
        assert_eq!(recheck, 0);
    }

    #[test]
    fn test_build_icmp_echo_request_structure() {
        let payload = b"test";
        let packet = build_icmp_echo_request(0x1234, 0x5678, payload);

        // 检查长度: 8 (header) + 4 (payload) = 12
        assert_eq!(packet.len(), 12);
        // Type: Echo Request (8)
        assert_eq!(packet[0], ICMP_TYPE_ECHO_REQUEST);
        // Code: 0
        assert_eq!(packet[1], 0);
        // Identifier
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0x1234);
        // Sequence
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x5678);
        // Payload
        assert_eq!(&packet[8..], payload);
    }

    #[test]
    fn test_build_icmp_echo_request_checksum_valid() {
        let packet = build_icmp_echo_request(1, 1, b"argus");
        // 验证校验和：重新计算应得 0
        let recheck = compute_icmp_checksum(&packet);
        assert_eq!(recheck, 0, "ICMP 校验和不正确");
    }

    #[test]
    fn test_build_icmp_echo_request_empty_payload() {
        let packet = build_icmp_echo_request(0xFFFF, 0x0001, &[]);
        assert_eq!(packet.len(), 8); // 仅头部
        assert_eq!(packet[0], ICMP_TYPE_ECHO_REQUEST);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 0xFFFF);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0x0001);
    }

    #[test]
    fn test_is_icmp_echo_reply_valid() {
        assert!(is_icmp_echo_reply(0)); // Echo Reply
    }

    #[test]
    fn test_is_icmp_echo_reply_invalid() {
        assert!(!is_icmp_echo_reply(8)); // Echo Request
        assert!(!is_icmp_echo_reply(3)); // Destination Unreachable
        assert!(!is_icmp_echo_reply(11)); // Time Exceeded
    }

    #[test]
    fn test_parse_icmp_echo_reply_valid() {
        let mut packet = vec![0u8; 8];
        packet[0] = ICMP_TYPE_ECHO_REPLY; // Type: Echo Reply
        packet[4..6].copy_from_slice(&0xABCDu16.to_be_bytes()); // Identifier
        packet[6..8].copy_from_slice(&0x1234u16.to_be_bytes()); // Sequence

        let result = parse_icmp_echo_reply(&packet);
        assert!(result.is_some());
        let (id, seq) = result.unwrap();
        assert_eq!(id, 0xABCD);
        assert_eq!(seq, 0x1234);
    }

    #[test]
    fn test_parse_icmp_echo_reply_wrong_type() {
        let mut packet = vec![0u8; 8];
        packet[0] = ICMP_TYPE_ECHO_REQUEST; // Echo Request, not Reply
        assert!(parse_icmp_echo_reply(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_echo_reply_too_short() {
        let packet = vec![0u8; 4]; // 太短
        assert!(parse_icmp_echo_reply(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_echo_reply_with_payload() {
        let mut packet = vec![0u8; 16];
        packet[0] = ICMP_TYPE_ECHO_REPLY;
        packet[4..6].copy_from_slice(&0x0001u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x0002u16.to_be_bytes());
        // Payload 在 offset 8+
        packet[8] = 0xDE;
        packet[9] = 0xAD;

        let result = parse_icmp_echo_reply(&packet);
        assert!(result.is_some());
        let (id, seq) = result.unwrap();
        assert_eq!(id, 1);
        assert_eq!(seq, 2);
    }

    #[test]
    fn test_parse_icmp_from_ipv4_echo_reply() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[9] = IP_PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        packet[16..20].copy_from_slice(&[192, 168, 1, 100]);
        packet[20] = ICMP_TYPE_ECHO_REPLY;
        packet[21] = 0;

        let result = parse_icmp_from_ipv4(&packet);
        assert!(result.is_some());
        let (ip, icmp_type, _) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(icmp_type, ICMP_TYPE_ECHO_REPLY);
    }

    #[test]
    fn test_parse_icmp_from_ipv4_too_short() {
        assert!(parse_icmp_from_ipv4(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_icmp_from_ipv4_wrong_version() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x60; // IPv6
        assert!(parse_icmp_from_ipv4(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_from_ipv4_wrong_protocol() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 6; // TCP
        assert!(parse_icmp_from_ipv4(&packet).is_none());
    }

    #[test]
    fn test_icmp_constants() {
        assert_eq!(ICMP_TYPE_ECHO_REPLY, 0);
        assert_eq!(ICMP_TYPE_ECHO_REQUEST, 8);
        assert_eq!(IP_PROTOCOL_ICMP, 1);
    }

    #[tokio::test]
    async fn test_host_monitor_initial_alive() {
        // 使用长间隔，确保首次 ping 不会在测试期间执行
        let mut monitor = HostMonitor::start(
            "127.0.0.1".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(1),
        );
        // 初始状态应为存活
        assert!(monitor.is_alive());
        monitor.stop().await;
    }

    #[tokio::test]
    async fn test_host_monitor_stop() {
        let mut monitor = HostMonitor::start(
            "127.0.0.1".to_string(),
            Duration::from_secs(3600),
            Duration::from_secs(1),
        );
        monitor.stop().await;
        // 停止后 handle 应为 None（通过 is_alive 间接验证不 panic）
        let _ = monitor.is_alive();
    }
}
