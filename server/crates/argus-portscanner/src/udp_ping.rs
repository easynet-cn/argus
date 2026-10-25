//! G1.2 UDP PING 主机探测
//!
//! 发送空 UDP 包到高端口（33434+），检查是否收到 ICMP Port Unreachable 响应。
//! 原理：如果目标主机的 UDP 端口关闭，内核会发送 ICMP Destination Unreachable
//! (Port Unreachable, type=3 code=3)。收到该 ICMP 响应说明主机存活。
//! 限制：需要 root 权限创建 raw socket 来接收 ICMP 响应。

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, ipv4_packet_iter};

use crate::host::resolve_host;
use crate::types::HostAliveResult;

// ==================== 协议常量 ====================

/// UDP PING 起始端口（与 traceroute 相同的高端口范围）
const UDP_PING_BASE_PORT: u16 = 33434;

/// UDP PING 端口随机范围
const UDP_PING_PORT_RANGE: u16 = 10;

/// ICMP Type: Destination Unreachable
const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;

/// ICMP Code: Port Unreachable
const ICMP_CODE_PORT_UNREACHABLE: u8 = 3;

/// ICMP 协议号
const IP_PROTOCOL_ICMP: u8 = 1;

// ==================== 纯函数（可测试） ====================

/// 检查 ICMP 类型/代码是否为 Port Unreachable (type=3, code=3)
pub fn is_icmp_port_unreachable(icmp_type: u8, icmp_code: u8) -> bool {
    icmp_type == ICMP_TYPE_DEST_UNREACHABLE && icmp_code == ICMP_CODE_PORT_UNREACHABLE
}

/// 从 IPv4 数据包中解析 ICMP 类型和代码
///
/// 返回 (源 IP, ICMP 类型, ICMP 代码)。
/// 如果数据不是有效的 IPv4+ICMP 包则返回 None。
pub fn parse_icmp_from_ipv4(data: &[u8]) -> Option<(Ipv4Addr, u8, u8)> {
    // 检查最小 IPv4 头部长度（20 字节）
    if data.len() < 20 {
        return None;
    }
    // 检查 IP 版本是否为 4
    if (data[0] >> 4) != 4 {
        return None;
    }
    // 获取 IHL（Internet Header Length，以 4 字节为单位）
    let ihl = (data[0] & 0x0F) as usize;
    let header_len = ihl * 4;
    // 检查协议是否为 ICMP (1)
    if data[9] != IP_PROTOCOL_ICMP {
        return None;
    }
    // 确保有足够的空间存放 ICMP 类型和代码
    if data.len() < header_len + 2 {
        return None;
    }
    // 提取源 IP（offset 12-15）
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    // 提取 ICMP 类型和代码（紧跟在 IP 头部之后）
    let icmp_type = data[header_len];
    let icmp_code = data[header_len + 1];
    Some((src_ip, icmp_type, icmp_code))
}

/// 构造 UDP PING payload（空包）
pub fn build_udp_ping_payload() -> Vec<u8> {
    Vec::new()
}

// ==================== 网络函数 ====================

/// UDP PING 探测单个主机
///
/// 向目标主机的高端口发送空 UDP 包，并监听 ICMP Port Unreachable 响应。
/// 如果收到 ICMP Port Unreachable，说明主机存活（端口关闭但主机在线）。
pub async fn udp_ping(host: &str, timeout_ms: u64) -> HostAliveResult {
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
    tokio::task::spawn_blocking(move || udp_ping_blocking(&host, &ip, timeout_ms))
        .await
        .unwrap_or_else(|_| HostAliveResult {
            host: host_clone,
            ip: ip_clone,
            alive: false,
            response_time_ms: None,
        })
}

/// UDP PING 阻塞版本
fn udp_ping_blocking(host: &str, ip_str: &str, timeout_ms: u64) -> HostAliveResult {
    let dst_ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // 创建 ICMP raw socket（需要 root 权限）
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (_tx, mut rx) = match transport_channel(65535, channel_type) {
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

    // 发送空 UDP 包到高端口
    let src_port = 1024 + rand::random::<u16>() % 1000;
    let target_port = UDP_PING_BASE_PORT + rand::random::<u16>() % UDP_PING_PORT_RANGE;
    let udp_socket = match UdpSocket::bind(format!("0.0.0.0:{src_port}")) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("绑定 UDP socket 失败: {e}");
            return HostAliveResult {
                host: host.to_string(),
                ip: ip_str.to_string(),
                alive: false,
                response_time_ms: None,
            };
        }
    };

    let _ = udp_socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let start = Instant::now();
    let payload = build_udp_ping_payload();
    let send_addr = format!("{dst_ip}:{target_port}");
    if let Err(e) = udp_socket.send_to(&payload, &send_addr) {
        tracing::debug!("UDP PING 发送到 {send_addr} 失败: {e}");
        let elapsed = start.elapsed().as_millis() as u64;
        return HostAliveResult {
            host: host.to_string(),
            ip: ip_str.to_string(),
            alive: false,
            response_time_ms: Some(elapsed),
        };
    }

    // 监听 ICMP Port Unreachable 响应
    let timeout = Duration::from_millis(timeout_ms);
    let mut iter = ipv4_packet_iter(&mut rx);
    while start.elapsed() < timeout {
        let remaining = timeout - start.elapsed();
        match iter.next_with_timeout(remaining) {
            Ok(Some((ipv4, src_addr))) => {
                // 检查源 IP 是否来自目标主机
                if src_addr == dst_ip {
                    // 获取 ICMP payload
                    let icmp_data = ipv4.payload();
                    if icmp_data.len() >= 2 {
                        let icmp_type = icmp_data[0];
                        let icmp_code = icmp_data[1];
                        // 检查是否为 ICMP Port Unreachable
                        if is_icmp_port_unreachable(icmp_type, icmp_code) {
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
                // 不是我们要找的包，继续等待
            }
            Ok(None) => break, // 超时
            Err(_) => break,   // 错误
        }
    }

    // 未收到 ICMP Port Unreachable 响应，主机可能不存活或端口开放
    let elapsed = start.elapsed().as_millis() as u64;
    HostAliveResult {
        host: host.to_string(),
        ip: ip_str.to_string(),
        alive: false,
        response_time_ms: Some(elapsed),
    }
}

/// 批量 UDP PING 探测
///
/// 并发探测多个主机的存活状态。
pub async fn udp_ping_hosts(
    hosts: &[String],
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<HostAliveResult> {
    use futures_util::stream::{self, StreamExt};

    let owned_hosts: Vec<String> = hosts.to_vec();
    let results: Vec<HostAliveResult> = stream::iter(owned_hosts)
        .map(|host| async move { udp_ping(&host, timeout_ms).await })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_icmp_port_unreachable_valid() {
        assert!(is_icmp_port_unreachable(3, 3));
    }

    #[test]
    fn test_is_icmp_port_unreachable_wrong_type() {
        assert!(!is_icmp_port_unreachable(0, 3));
        assert!(!is_icmp_port_unreachable(8, 3));
    }

    #[test]
    fn test_is_icmp_port_unreachable_wrong_code() {
        assert!(!is_icmp_port_unreachable(3, 0));
        assert!(!is_icmp_port_unreachable(3, 1));
        assert!(!is_icmp_port_unreachable(3, 2));
    }

    #[test]
    fn test_is_icmp_port_unreachable_completely_wrong() {
        assert!(!is_icmp_port_unreachable(0, 0));
        assert!(!is_icmp_port_unreachable(8, 0));
    }

    #[test]
    fn test_parse_icmp_from_ipv4_port_unreachable() {
        // 构造模拟 IPv4 + ICMP Port Unreachable 包
        let mut packet = vec![0u8; 28]; // 20 (IP) + 8 (ICMP)
        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = IP_PROTOCOL_ICMP; // Protocol: ICMP
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
        packet[16..20].copy_from_slice(&[192, 168, 1, 100]); // Dest IP
        // ICMP (at offset 20)
        packet[20] = ICMP_TYPE_DEST_UNREACHABLE; // Type: Destination Unreachable
        packet[21] = ICMP_CODE_PORT_UNREACHABLE; // Code: Port Unreachable

        let result = parse_icmp_from_ipv4(&packet);
        assert!(result.is_some());
        let (ip, icmp_type, icmp_code) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(icmp_type, ICMP_TYPE_DEST_UNREACHABLE);
        assert_eq!(icmp_code, ICMP_CODE_PORT_UNREACHABLE);
    }

    #[test]
    fn test_parse_icmp_from_ipv4_echo_reply() {
        // 构造模拟 IPv4 + ICMP Echo Reply 包
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = IP_PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20] = 0; // Type: Echo Reply
        packet[21] = 0; // Code: 0

        let result = parse_icmp_from_ipv4(&packet);
        assert!(result.is_some());
        let (ip, icmp_type, icmp_code) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(icmp_type, 0);
        assert_eq!(icmp_code, 0);
    }

    #[test]
    fn test_parse_icmp_from_ipv4_too_short() {
        let packet = vec![0u8; 10]; // 太短
        assert!(parse_icmp_from_ipv4(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_from_ipv4_wrong_version() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x60; // Version 6 (IPv6)
        packet[9] = IP_PROTOCOL_ICMP;
        assert!(parse_icmp_from_ipv4(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_from_ipv4_wrong_protocol() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 6; // Protocol: TCP, not ICMP
        assert!(parse_icmp_from_ipv4(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_from_ipv4_with_options() {
        // IPv4 包带选项（IHL > 5）
        let ihl = 6; // 24 bytes header
        let header_len = ihl * 4;
        let mut packet = vec![0u8; header_len + 8]; // IP header + ICMP
        packet[0] = (4 << 4) | (ihl as u8); // Version 4, IHL 6
        packet[9] = IP_PROTOCOL_ICMP;
        packet[12..16].copy_from_slice(&[172, 16, 0, 1]);
        packet[16..20].copy_from_slice(&[172, 16, 0, 2]);
        // ICMP 在 offset 24
        packet[header_len] = ICMP_TYPE_DEST_UNREACHABLE;
        packet[header_len + 1] = ICMP_CODE_PORT_UNREACHABLE;

        let result = parse_icmp_from_ipv4(&packet);
        assert!(result.is_some());
        let (ip, icmp_type, _) = result.unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(icmp_type, ICMP_TYPE_DEST_UNREACHABLE);
    }

    #[test]
    fn test_build_udp_ping_payload_empty() {
        let payload = build_udp_ping_payload();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_udp_ping_constants() {
        // 确保 UDP PING 端口范围合理
        assert!(UDP_PING_BASE_PORT >= 33434);
        assert!(UDP_PING_PORT_RANGE > 0);
        // ICMP 常量
        assert_eq!(ICMP_TYPE_DEST_UNREACHABLE, 3);
        assert_eq!(ICMP_CODE_PORT_UNREACHABLE, 3);
        assert_eq!(IP_PROTOCOL_ICMP, 1);
    }
}
