//! G1.1 ARP 主机探测
//!
//! 使用 pnet_datalink 发送 ARP Request 帧来发现局域网内的存活主机。
//! 原理：发送广播 ARP Request，目标主机如果存活会回复 ARP Reply。
//! 限制：需要 root 权限或 CAP_NET_RAW；仅在局域网内有效。

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet_datalink::interfaces;

use crate::types::HostAliveResult;

// ==================== 协议常量 ====================

/// ARP Ethertype
const ETHERTYPE_ARP: u16 = 0x0806;

/// 广播 MAC 地址
const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// ARP 操作码: Request
const ARP_OPERATION_REQUEST: u16 = 1;

/// ARP 操作码: Reply
const ARP_OPERATION_REPLY: u16 = 2;

/// 硬件类型: Ethernet
const ARP_HW_TYPE_ETHERNET: u16 = 1;

/// 协议类型: IPv4
const ARP_PROTO_TYPE_IPV4: u16 = 0x0800;

// ==================== ARP 帧构造 ====================

/// 构造 ARP Request 以太网帧
///
/// 帧结构:
/// - Ethernet Header (14 bytes): Dst MAC(6) + Src MAC(6) + Ethertype(2)
/// - ARP Packet (28 bytes): HW Type(2) + Proto Type(2) + HW Len(1) + Proto Len(1)
///   + Op(2) + SHA(6) + SPA(4) + THA(6) + TPA(4)
pub fn build_arp_request(
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);

    // === Ethernet Header ===
    frame.extend_from_slice(&BROADCAST_MAC); // Dst MAC: 广播
    frame.extend_from_slice(&src_mac); // Src MAC: 本机接口 MAC
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    // === ARP Packet ===
    frame.extend_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes()); // 硬件类型
    frame.extend_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes()); // 协议类型
    frame.push(6); // 硬件地址长度
    frame.push(4); // 协议地址长度
    frame.extend_from_slice(&ARP_OPERATION_REQUEST.to_be_bytes()); // 操作码
    frame.extend_from_slice(&src_mac); // 发送方硬件地址
    frame.extend_from_slice(&src_ip.octets()); // 发送方协议地址
    frame.extend_from_slice(&[0u8; 6]); // 目标硬件地址（未知，填零）
    frame.extend_from_slice(&target_ip.octets()); // 目标协议地址

    // 填充到最小以太网帧长度（60 字节，不含 FCS）
    while frame.len() < 60 {
        frame.push(0x00);
    }

    frame
}

// ==================== ARP 响应解析 ====================

/// ARP 发现结果
#[derive(Debug, Clone)]
pub struct ArpHostResult {
    /// 主机 IP
    pub ip: String,
    /// 主机 MAC 地址
    pub mac: String,
    /// 响应时间（毫秒）
    pub response_time_ms: Option<u64>,
}

impl ArpHostResult {
    /// 转换为 HostAliveResult
    pub fn to_host_alive_result(&self) -> HostAliveResult {
        HostAliveResult {
            host: self.ip.clone(),
            ip: self.ip.clone(),
            alive: true,
            response_time_ms: self.response_time_ms,
        }
    }
}

/// 解析 ARP Reply 以太网帧
///
/// 从完整的以太网帧中提取发送方 IP 和 MAC 地址。
/// 返回 (sender_ip, sender_mac) 如果是有效的 ARP Reply。
pub fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    // 最小帧长度: Ethernet(14) + ARP(28) = 42
    if frame.len() < 42 {
        return None;
    }

    // 检查 Ethertype 是否为 ARP
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_ARP {
        return None;
    }

    // ARP 包从 offset 14 开始
    let arp = &frame[14..];

    // 检查硬件类型和协议类型
    let hw_type = u16::from_be_bytes([arp[0], arp[1]]);
    let proto_type = u16::from_be_bytes([arp[2], arp[3]]);
    if hw_type != ARP_HW_TYPE_ETHERNET || proto_type != ARP_PROTO_TYPE_IPV4 {
        return None;
    }

    // 检查地址长度
    if arp[4] != 6 || arp[5] != 4 {
        return None;
    }

    // 检查操作码是否为 Reply
    let operation = u16::from_be_bytes([arp[6], arp[7]]);
    if operation != ARP_OPERATION_REPLY {
        return None;
    }

    // 提取发送方 MAC (offset 8-13) 和 IP (offset 14-17)
    let sender_mac: [u8; 6] = arp[8..14].try_into().ok()?;
    let sender_ip_bytes: [u8; 4] = arp[14..18].try_into().ok()?;
    let sender_ip = Ipv4Addr::from(sender_ip_bytes);

    Some((sender_ip, sender_mac))
}

/// 格式化 MAC 地址为 "XX:XX:XX:XX:XX:XX" 格式
fn format_mac(mac: &[u8]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// ==================== ARP 发现执行 ====================

/// 在指定网络接口上执行 ARP 主机发现
///
/// 发送 ARP Request 广播，收集 ARP Reply 并返回存活主机列表。
///
/// 参数:
/// - `interface_name`: 网络接口名（如 "eth0"、"en0"）
/// - `target_ips`: 要探测的目标 IP 列表
/// - `timeout`: 等待响应的超时时间
///
/// 注意: 需要 root 权限才能发送/接收原始以太网帧
pub fn discover_hosts(
    interface_name: &str,
    target_ips: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<ArpHostResult>, String> {
    // 获取网络接口
    let ifaces = interfaces();
    let interface = ifaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| format!("网络接口 '{interface_name}' 不存在"))?;

    // 获取接口 MAC
    let src_mac = interface
        .mac
        .ok_or_else(|| format!("接口 '{interface_name}' 无 MAC 地址"))?
        .octets();

    // 获取接口 IPv4 地址（使用方法调用避免直接引用私有的 IpNetwork 类型）
    let src_ip = interface
        .ips
        .iter()
        .find_map(|ip| {
            let addr = ip.ip();
            if let std::net::IpAddr::V4(ipv4) = addr {
                Some(ipv4)
            } else {
                None
            }
        })
        .ok_or_else(|| format!("接口 '{interface_name}' 无 IPv4 地址"))?;

    // 打开数据链路层通道
    let config = pnet_datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(timeout),
        write_timeout: Some(timeout),
        channel_type: pnet_datalink::ChannelType::Layer2,
        ..Default::default()
    };

    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("不支持的链路层类型".to_string()),
        Err(e) => return Err(format!("打开接口 '{interface_name}' 失败: {e}")),
    };

    // 发送 ARP Request 到所有目标 IP
    let send_start = Instant::now();
    for &target_ip in target_ips {
        let request = build_arp_request(src_mac, src_ip, target_ip);
        match tx.send_to(&request, None) {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                tracing::debug!("ARP 请求发送到 {target_ip} 失败: {e}");
            }
            None => {
                tracing::debug!("ARP 请求发送到 {target_ip} 失败: 缓冲区不足");
            }
        }
    }

    // 收集 ARP Reply
    let mut results = Vec::new();
    let target_set: std::collections::HashSet<Ipv4Addr> = target_ips.iter().copied().collect();

    while send_start.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some((sender_ip, sender_mac)) = parse_arp_reply(packet) {
                    if target_set.contains(&sender_ip) {
                        let elapsed = send_start.elapsed().as_millis() as u64;
                        // 去重：同一个 IP 只记录一次
                        if !results
                            .iter()
                            .any(|r: &ArpHostResult| r.ip == sender_ip.to_string())
                        {
                            results.push(ArpHostResult {
                                ip: sender_ip.to_string(),
                                mac: format_mac(&sender_mac),
                                response_time_ms: Some(elapsed),
                            });
                        }
                    }
                }
            }
            Err(_) => break, // 超时或错误
        }
    }

    tracing::info!(
        "ARP 发现在接口 {interface_name} 上发现 {} 台存活主机",
        results.len()
    );

    Ok(results)
}

/// 自动选择接口并执行 ARP 发现
///
/// 根据目标 IP 自动选择第一个有 MAC 和 IPv4 地址的非环回接口。
pub fn discover_hosts_auto(
    target_ips: &[Ipv4Addr],
    timeout: Duration,
) -> Result<Vec<ArpHostResult>, String> {
    let ifaces = interfaces();
    let interface = ifaces
        .into_iter()
        .filter(|i| i.mac.is_some() && !i.is_loopback())
        .find(|i| i.ips.iter().any(|ip| ip.is_ipv4()))
        .ok_or_else(|| "未找到合适的网络接口".to_string())?;

    discover_hosts(&interface.name, target_ips, timeout)
}

/// 列出所有可用的网络接口（有 MAC 且非环回）
pub fn list_interfaces() -> Vec<String> {
    interfaces()
        .into_iter()
        .filter(|i| i.mac.is_some() && !i.is_loopback())
        .map(|i| i.name)
        .collect()
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_build_arp_request_structure() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);

        let frame = build_arp_request(src_mac, src_ip, target_ip);

        // 最小以太网帧长度 60 bytes
        assert!(frame.len() >= 60);

        // 目标 MAC = 广播
        assert_eq!(&frame[0..6], &BROADCAST_MAC);
        // 源 MAC
        assert_eq!(&frame[6..12], &src_mac);
        // Ethertype = ARP
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_ARP);

        // ARP 包检查（从 offset 14 开始）
        let arp = &frame[14..];
        // 硬件类型 = Ethernet
        assert_eq!(u16::from_be_bytes([arp[0], arp[1]]), ARP_HW_TYPE_ETHERNET);
        // 协议类型 = IPv4
        assert_eq!(u16::from_be_bytes([arp[2], arp[3]]), ARP_PROTO_TYPE_IPV4);
        // 硬件地址长度 = 6
        assert_eq!(arp[4], 6);
        // 协议地址长度 = 4
        assert_eq!(arp[5], 4);
        // 操作码 = Request
        assert_eq!(u16::from_be_bytes([arp[6], arp[7]]), ARP_OPERATION_REQUEST);
        // 发送方 MAC
        assert_eq!(&arp[8..14], &src_mac);
        // 发送方 IP
        assert_eq!(&arp[14..18], &src_ip.octets());
        // 目标 MAC = 全零
        assert_eq!(&arp[18..24], &[0u8; 6]);
        // 目标 IP
        assert_eq!(&arp[24..28], &target_ip.octets());
    }

    #[test]
    fn test_build_arp_request_padding() {
        let src_mac = [0xFF; 6];
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let target_ip = Ipv4Addr::new(10, 0, 0, 2);

        let frame = build_arp_request(src_mac, src_ip, target_ip);
        // 帧长度应至少为 60（最小以太网帧）
        assert!(frame.len() >= 60);
        // 填充部分应为 0
        for &b in &frame[42..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_parse_arp_reply_valid() {
        let sender_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let sender_ip = Ipv4Addr::new(192, 168, 1, 50);

        let mut frame = Vec::new();
        // Ethernet Header
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC
        frame.extend_from_slice(&sender_mac); // Src MAC
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        // ARP Packet
        frame.extend_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes());
        frame.push(6); // HW Len
        frame.push(4); // Proto Len
        frame.extend_from_slice(&ARP_OPERATION_REPLY.to_be_bytes());
        frame.extend_from_slice(&sender_mac);
        frame.extend_from_slice(&sender_ip.octets());
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[192, 168, 1, 1]);

        let result = parse_arp_reply(&frame);
        assert!(result.is_some());
        let (ip, mac) = result.unwrap();
        assert_eq!(ip, sender_ip);
        assert_eq!(mac, sender_mac);
    }

    #[test]
    fn test_parse_arp_reply_wrong_ethertype() {
        let mut frame = vec![0u8; 42];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4, not ARP
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn test_parse_arp_reply_request_not_reply() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&BROADCAST_MAC);
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes());
        frame.push(6);
        frame.push(4);
        frame.extend_from_slice(&ARP_OPERATION_REQUEST.to_be_bytes()); // Request, not Reply
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame.extend_from_slice(&[192, 168, 1, 50]);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&[192, 168, 1, 1]);

        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn test_parse_arp_reply_too_short() {
        let frame = vec![0u8; 10];
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn test_parse_arp_reply_wrong_hw_type() {
        let mut frame = vec![0u8; 42];
        frame[12] = (ETHERTYPE_ARP >> 8) as u8;
        frame[13] = ETHERTYPE_ARP as u8;
        // HW Type = 0 (not Ethernet)
        frame[14] = 0;
        frame[15] = 0;
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn test_parse_arp_reply_wrong_addr_len() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&BROADCAST_MAC);
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame.extend_from_slice(&ARP_HW_TYPE_ETHERNET.to_be_bytes());
        frame.extend_from_slice(&ARP_PROTO_TYPE_IPV4.to_be_bytes());
        frame.push(8); // Wrong HW len
        frame.push(4);
        frame.extend_from_slice(&ARP_OPERATION_REPLY.to_be_bytes());
        frame.extend_from_slice(&[0u8; 14]); // rest
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_format_mac_all_zeros() {
        let mac = [0x00; 6];
        assert_eq!(format_mac(&mac), "00:00:00:00:00:00");
    }

    #[test]
    fn test_arp_host_result_to_host_alive() {
        let result = ArpHostResult {
            ip: "192.168.1.50".to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            response_time_ms: Some(10),
        };
        let alive = result.to_host_alive_result();
        assert!(alive.alive);
        assert_eq!(alive.ip, "192.168.1.50");
        assert_eq!(alive.host, "192.168.1.50");
        assert_eq!(alive.response_time_ms, Some(10));
    }

    #[test]
    fn test_list_interfaces() {
        // 仅验证函数可调用，不检查具体接口
        let _ = list_interfaces();
    }
}
