//! 拓扑 Trace 路径数据采集
//!
//! 资产发现中的"拓扑 Trace 路径图"。
//!
//! 实现：通过递增 TTL 的 ICMP Echo Request 探测目标路径上的每一跳路由器。
//! - TTL=1 时，第一个路由器收到包后返回 ICMP Time Exceeded
//! - TTL=2 时，第二个路由器返回 Time Exceeded
//! - 依此类推，直到收到目标的 ICMP Echo Reply 或达到最大跳数
//!
//! 注意：需要 root 权限创建 raw socket（与 SYN 扫描相同）。

use serde::{Deserialize, Serialize};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

/// 单跳信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    /// 跳数（从 1 开始）
    pub hop: u8,
    /// 该跳的 IP 地址（None = 超时未响应）
    pub ip: Option<String>,
    /// 该跳的主机名（反向 DNS，可选）
    pub hostname: Option<String>,
    /// 响应时间（毫秒）
    pub rtt_ms: Option<u64>,
}

/// Traceroute 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRouteResult {
    /// 目标主机
    pub target: String,
    /// 目标 IP
    pub target_ip: String,
    /// 是否到达目标
    pub reached: bool,
    /// 总跳数
    pub total_hops: usize,
    /// 路径上的每一跳
    pub hops: Vec<TraceHop>,
    /// 错误信息（如果有）
    pub error: Option<String>,
}

/// 执行 traceroute
///
/// 参数：
/// - `target`: 目标主机（域名或 IP）
/// - `max_hops`: 最大跳数（默认 30）
/// - `timeout_ms`: 每跳超时毫秒（默认 1000）
///
/// 返回 TraceRouteResult，包含每一跳的 IP 和延迟。
pub async fn traceroute(target: &str, max_hops: u8, timeout_ms: u64) -> TraceRouteResult {
    let target_owned = target.to_string();
    tokio::task::spawn_blocking(move || traceroute_blocking(&target_owned, max_hops, timeout_ms))
        .await
        .unwrap_or_else(|e| TraceRouteResult {
            target: target.to_string(),
            target_ip: String::new(),
            reached: false,
            total_hops: 0,
            hops: vec![],
            error: Some(format!("任务调度失败: {e}")),
        })
}

/// Traceroute 阻塞实现
fn traceroute_blocking(target: &str, max_hops: u8, timeout_ms: u64) -> TraceRouteResult {
    // 解析目标 IP
    let target_ip: IpAddr = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => match (target, 0).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr.ip(),
                None => {
                    return fail_result(target, "", format!("DNS 解析失败: 无地址"));
                }
            },
            Err(e) => {
                return fail_result(target, "", format!("DNS 解析失败: {e}"));
            }
        },
    };

    let target_ip_str = target_ip.to_string();
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut reached = false;

    // 使用 socket2 创建 raw ICMP socket
    let domain = match target_ip {
        IpAddr::V4(_) => socket2::Domain::IPV4,
        IpAddr::V6(_) => socket2::Domain::IPV6,
    };

    let socket = match socket2::Socket::new(domain, socket2::Type::RAW, None) {
        Ok(s) => s,
        Err(e) => {
            return fail_result(
                target,
                &target_ip_str,
                format!("创建 raw socket 失败（需要 root 权限）: {e}"),
            );
        }
    };

    // 设置接收超时
    let _ = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)));

    let identifier: u16 = rand::random();
    let mut sequence: u16 = 0;

    // 目标 SocketAddr（端口 0 用于 ICMP）
    let target_sockaddr = SocketAddr::new(target_ip, 0);

    for ttl in 1..=max_hops {
        sequence += 1;

        // 设置 TTL（IPv4 用 set_ttl_v4，IPv6 用 set_unicast_hops_v6）
        let set_result = match target_ip {
            IpAddr::V4(_) => socket.set_ttl_v4(ttl as u32),
            IpAddr::V6(_) => socket.set_unicast_hops_v6(ttl as u32),
        };
        if let Err(e) = set_result {
            tracing::debug!("设置 TTL={} 失败: {e}", ttl);
        }

        // 构造 ICMP Echo Request
        let echo_request = build_icmp_echo_request(identifier, sequence);

        let start = Instant::now();

        // 发送
        let send_addr = socket2::SockAddr::from(target_sockaddr);
        if let Err(e) = socket.send_to(&echo_request, &send_addr) {
            tracing::debug!("发送 ICMP 到 {} TTL={} 失败: {e}", target_ip, ttl);
            hops.push(TraceHop {
                hop: ttl,
                ip: None,
                hostname: None,
                rtt_ms: None,
            });
            continue;
        }

        // 接收响应：socket2 0.6 要求 MaybeUninit 缓冲区
        let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::new(0); 65535];
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let rtt = start.elapsed().as_millis() as u64;
                let src_ip = src_addr.as_socket().map(|s| s.ip());

                // 将 MaybeUninit 缓冲区读出
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, len) };

                let icmp_type = parse_icmp_type(data, target_ip);

                let hop_ip = src_ip.map(|ip| ip.to_string());
                let hostname = hop_ip.as_deref().and_then(reverse_dns);

                hops.push(TraceHop {
                    hop: ttl,
                    ip: hop_ip,
                    hostname,
                    rtt_ms: Some(rtt),
                });

                if icmp_type == IcmpResponseType::EchoReply {
                    reached = true;
                    break;
                }
            }
            Err(_) => {
                // 超时
                hops.push(TraceHop {
                    hop: ttl,
                    ip: None,
                    hostname: None,
                    rtt_ms: None,
                });
            }
        }
    }

    TraceRouteResult {
        target: target.to_string(),
        target_ip: target_ip_str,
        reached,
        total_hops: hops.len(),
        hops,
        error: None,
    }
}

/// 失败时构造结果
fn fail_result(target: &str, target_ip: &str, error: String) -> TraceRouteResult {
    TraceRouteResult {
        target: target.to_string(),
        target_ip: target_ip.to_string(),
        reached: false,
        total_hops: 0,
        hops: vec![],
        error: Some(error),
    }
}

/// ICMP 响应类型
#[derive(Debug, PartialEq)]
enum IcmpResponseType {
    EchoReply,
    TimeExceeded,
    Other,
}

/// 解析 ICMP 响应类型
fn parse_icmp_type(data: &[u8], target_ip: IpAddr) -> IcmpResponseType {
    match target_ip {
        IpAddr::V4(_) => {
            // IPv4: IP header (最少 20 字节) + ICMP header
            // IP header 长度由 IHL 字段（低 4 位）决定
            if data.len() < 21 {
                return IcmpResponseType::Other;
            }
            let ihl = (data[0] & 0x0F) as usize;
            let icmp_offset = ihl * 4;
            if data.len() < icmp_offset + 1 {
                return IcmpResponseType::Other;
            }
            let icmp_type = data[icmp_offset];
            match icmp_type {
                0 => IcmpResponseType::EchoReply,
                11 => IcmpResponseType::TimeExceeded,
                _ => IcmpResponseType::Other,
            }
        }
        IpAddr::V6(_) => {
            // IPv6: ICMPv6 type 在第一个字节
            if data.is_empty() {
                return IcmpResponseType::Other;
            }
            match data[0] {
                129 => IcmpResponseType::EchoReply, // ICMPv6 Echo Reply
                3 => IcmpResponseType::TimeExceeded, // ICMPv6 Time Exceeded
                _ => IcmpResponseType::Other,
            }
        }
    }
}

/// 构造 ICMP Echo Request
fn build_icmp_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![
        8, // Type: Echo Request
        0, // Code: 0
        0, 0, // Checksum (placeholder)
        (identifier >> 8) as u8,
        (identifier & 0xff) as u8,
        (sequence >> 8) as u8,
        (sequence & 0xff) as u8,
    ];
    // Payload
    packet.extend_from_slice(b"argus-trace");
    // 计算校验和
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;
    packet
}

/// 计算 ICMP 校验和（RFC 1071 Internet checksum）
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// 反向 DNS 解析（best-effort，失败返回 None）
///
/// 注意：`to_socket_addrs` 对 IP 字符串不做反向 DNS 查询，
/// 此处仅作为占位实现。完整实现需要查询 PTR 记录。
fn reverse_dns(_ip: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum() {
        let data = vec![8, 0, 0, 0, 0, 1, 0, 1];
        let cs = icmp_checksum(&data);
        assert!(cs != 0);
    }

    #[test]
    fn test_build_echo_request() {
        let req = build_icmp_echo_request(0x1234, 0x0001);
        assert_eq!(req[0], 8); // Type
        assert_eq!(req[1], 0); // Code
        assert_eq!(req[4], 0x12); // Identifier high
        assert_eq!(req[5], 0x34); // Identifier low
    }

    #[test]
    fn test_parse_icmp_type_v4() {
        // 构造一个 Echo Reply (type=0)，使用最小 IP 头 20 字节
        let mut data = vec![0u8; 28];
        data[0] = 0x45; // Version=4, IHL=5 → 20 字节头
        data[20] = 0; // ICMP type = Echo Reply
        assert_eq!(
            parse_icmp_type(&data, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            IcmpResponseType::EchoReply
        );

        // Time Exceeded (type=11)
        data[20] = 11;
        assert_eq!(
            parse_icmp_type(&data, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            IcmpResponseType::TimeExceeded
        );
    }

    #[test]
    fn test_parse_icmp_type_v4_with_options() {
        // 带选项的 IP 头（IHL=6 → 24 字节头）
        let mut data = vec![0u8; 32];
        data[0] = 0x46; // Version=4, IHL=6
        data[24] = 11; // ICMP type = Time Exceeded
        assert_eq!(
            parse_icmp_type(&data, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            IcmpResponseType::TimeExceeded
        );
    }

    #[test]
    fn test_parse_icmp_type_v6() {
        // ICMPv6 Echo Reply (type=129)
        let mut data = vec![0u8; 8];
        data[0] = 129;
        assert_eq!(
            parse_icmp_type(&data, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            IcmpResponseType::EchoReply
        );

        // ICMPv6 Time Exceeded (type=3)
        data[0] = 3;
        assert_eq!(
            parse_icmp_type(&data, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            IcmpResponseType::TimeExceeded
        );
    }

    #[test]
    fn test_fail_result() {
        let r = fail_result("example.com", "1.2.3.4", "test error".to_string());
        assert_eq!(r.target, "example.com");
        assert_eq!(r.target_ip, "1.2.3.4");
        assert!(!r.reached);
        assert_eq!(r.total_hops, 0);
        assert_eq!(r.error, Some("test error".to_string()));
    }

    #[test]
    fn test_reverse_dns_returns_none() {
        assert_eq!(reverse_dns("8.8.8.8"), None);
    }
}
