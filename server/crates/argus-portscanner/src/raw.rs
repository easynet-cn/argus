//! Raw socket 扫描（SYN/ACK/Null/Xmas/Fin/Window）
//!
//! 使用 pnet transport channel 发送/接收原始 TCP 包。
//! 需要 root 权限或 CAP_NET_RAW。无权限时自动降级为 Connect 扫描。

use std::net::IpAddr;
use std::time::{Duration, Instant};
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{tcp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};

use crate::types::{PortScanResult, PortState, Protocol, TcpScanType};

/// 根据扫描类型返回 TCP 标志位
fn flags_for_scan_type(scan_type: TcpScanType) -> u8 {
    match scan_type {
        TcpScanType::Syn => TcpFlags::SYN,
        TcpScanType::Ack => TcpFlags::ACK,
        TcpScanType::Null => 0,
        TcpScanType::Xmas => TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        TcpScanType::Fin => TcpFlags::FIN,
        TcpScanType::Window => TcpFlags::ACK,
        TcpScanType::Connect => TcpFlags::SYN, // 不会走到这里
    }
}

/// 解释响应包的标志位，确定端口状态
fn interpret_response(flags: u8, scan_type: TcpScanType, window: u16) -> PortState {
    let is_rst = (flags & TcpFlags::RST) != 0;
    let is_syn = (flags & TcpFlags::SYN) != 0;
    let is_ack = (flags & TcpFlags::ACK) != 0;

    match scan_type {
        TcpScanType::Syn => {
            if is_syn && is_ack {
                PortState::Open
            } else if is_rst {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        TcpScanType::Ack => {
            // ACK 扫描：收到 RST 说明端口可达（unfiltered）
            if is_rst {
                PortState::ClosedFiltered
            } else {
                PortState::Filtered
            }
        }
        TcpScanType::Window => {
            // Window 扫描：通过 RST 中的 window 值判断
            if is_rst {
                if window > 0 {
                    PortState::Open
                } else {
                    PortState::Closed
                }
            } else {
                PortState::Filtered
            }
        }
        TcpScanType::Null | TcpScanType::Xmas | TcpScanType::Fin => {
            // Null/Xmas/Fin 扫描：收到 RST 说明 closed，无响应说明 open|filtered
            if is_rst {
                PortState::Closed
            } else {
                PortState::OpenFiltered
            }
        }
        TcpScanType::Connect => PortState::Open,
    }
}

/// 超时时的端口状态
fn interpret_timeout(scan_type: TcpScanType) -> PortState {
    match scan_type {
        TcpScanType::Null | TcpScanType::Xmas | TcpScanType::Fin => PortState::OpenFiltered,
        _ => PortState::Filtered,
    }
}

/// 尝试用 raw socket 扫描单个 TCP 端口
/// 如果 raw socket 不可用（无权限），返回 None 以便降级为 Connect
pub async fn scan_tcp_raw_port(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    port: u16,
    scan_type: TcpScanType,
    timeout_ms: u64,
) -> Option<PortScanResult> {
    tokio::task::spawn_blocking(move || {
        scan_tcp_raw_port_blocking(src_ip, dst_ip, port, scan_type, timeout_ms)
    })
    .await
    .ok()
    .flatten()
}

/// 阻塞版本的 raw socket 扫描
fn scan_tcp_raw_port_blocking(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    port: u16,
    scan_type: TcpScanType,
    timeout_ms: u64,
) -> Option<PortScanResult> {
    // 创建 transport channel（需要 root 权限）
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut tx, mut rx) = match transport_channel(65535, channel_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            tracing::debug!("创建 raw transport channel 失败（可能无 root 权限）: {e}");
            return None; // 降级为 Connect
        }
    };

    // 随机源端口和序列号
    let src_port: u16 = 1024 + rand::random::<u16>() % (65535 - 1024);
    let seq: u32 = rand::random();
    let flags = flags_for_scan_type(scan_type);

    // 构造 TCP 包
    let mut buf = [0u8; 20]; // 最小 TCP 头部 20 字节
    let mut tcp = MutableTcpPacket::new(&mut buf)?;
    tcp.set_source(src_port);
    tcp.set_destination(port);
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5); // 20 bytes / 4 = 5
    tcp.set_flags(flags);
    tcp.set_window(1024);
    tcp.set_urgent_ptr(0);

    // 计算 checksum（需要伪头部：源 IP + 目标 IP + 协议号 + TCP 长度）
    let checksum = compute_tcp_checksum(&tcp, src_ip, dst_ip);
    tcp.set_checksum(checksum);

    // 发送 TCP 包
    let start = Instant::now();
    if let Err(e) = tx.send_to(tcp.to_immutable(), dst_ip) {
        tracing::debug!("发送 raw TCP 包失败: {e}");
        return None;
    }

    // 创建 TCP 包迭代器接收响应
    let mut iter = tcp_packet_iter(&mut rx);
    let timeout = Duration::from_millis(timeout_ms);

    loop {
        match iter.next_with_timeout(timeout) {
            Ok(Some((tcp_resp, addr))) => {
                if addr != dst_ip {
                    continue;
                }
                if tcp_resp.get_destination() != src_port {
                    continue;
                }
                // 匹配到响应
                let resp_flags = tcp_resp.get_flags();
                let window = tcp_resp.get_window();
                let state = interpret_response(resp_flags, scan_type, window);
                let elapsed = start.elapsed().as_millis() as u64;
                return Some(PortScanResult {
                    host: dst_ip.to_string(),
                    port,
                    protocol: Protocol::Tcp,
                    state,
                    service: None,
                    banner: None,
                    response_time_ms: elapsed,
                });
            }
            Ok(None) => {
                // 超时
                let state = interpret_timeout(scan_type);
                let elapsed = start.elapsed().as_millis() as u64;
                return Some(PortScanResult {
                    host: dst_ip.to_string(),
                    port,
                    protocol: Protocol::Tcp,
                    state,
                    service: None,
                    banner: None,
                    response_time_ms: elapsed,
                });
            }
            Err(e) => {
                tracing::debug!("接收 raw TCP 响应失败: {e}");
                let state = interpret_timeout(scan_type);
                let elapsed = start.elapsed().as_millis() as u64;
                return Some(PortScanResult {
                    host: dst_ip.to_string(),
                    port,
                    protocol: Protocol::Tcp,
                    state,
                    service: None,
                    banner: None,
                    response_time_ms: elapsed,
                });
            }
        }
    }
}

/// 计算 TCP 校验和（含伪头部）
fn compute_tcp_checksum(tcp: &MutableTcpPacket, src_ip: IpAddr, dst_ip: IpAddr) -> u16 {
    use pnet::util::checksum;

    let src_bytes = match src_ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let dst_bytes = match dst_ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };

    // 伪头部: src_ip(4/16) + dst_ip(4/16) + zero(1) + protocol(1) + tcp_length(2)
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&src_bytes);
    pseudo_header.extend_from_slice(&dst_bytes);
    pseudo_header.push(0); // zero
    pseudo_header.push(6); // TCP protocol number
    let tcp_len = tcp.packet().len() as u16;
    pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());

    // 合并伪头部和 TCP 包
    let mut full_packet = pseudo_header;
    full_packet.extend_from_slice(tcp.packet());

    // 注意：checksum 期望 data 的长度是偶数
    if full_packet.len() % 2 != 0 {
        full_packet.push(0);
    }

    checksum(&full_packet, full_packet.len())
}

/// 尝试用 raw socket 扫描多个 TCP 端口
/// 返回扫描结果列表，如果 raw socket 不可用返回 None
pub async fn scan_tcp_ports_raw(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ports: &[u16],
    scan_type: TcpScanType,
    timeout_ms: u64,
    concurrency: usize,
) -> Option<Vec<PortScanResult>> {
    use futures_util::stream::{self, StreamExt};

    // 先测试一个端口确认 raw socket 可用
    let test_result = scan_tcp_raw_port(src_ip, dst_ip, ports[0], scan_type, timeout_ms).await?;

    // raw socket 可用，并发扫描剩余端口
    let mut results: Vec<PortScanResult> = vec![test_result];

    let remaining: Vec<u16> = ports.iter().copied().filter(|&p| p != ports[0]).collect();
    if !remaining.is_empty() {
        let other_results: Vec<PortScanResult> = stream::iter(remaining.into_iter())
            .map(|port| async move {
                scan_tcp_raw_port(src_ip, dst_ip, port, scan_type, timeout_ms)
                    .await
                    .unwrap_or_else(|| PortScanResult {
                        host: dst_ip.to_string(),
                        port,
                        protocol: Protocol::Tcp,
                        state: PortState::Filtered,
                        service: None,
                        banner: None,
                        response_time_ms: timeout_ms,
                    })
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        results.extend(other_results);
    }

    Some(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_for_syn() {
        assert_eq!(flags_for_scan_type(TcpScanType::Syn), TcpFlags::SYN);
    }

    #[test]
    fn test_flags_for_null() {
        assert_eq!(flags_for_scan_type(TcpScanType::Null), 0);
    }

    #[test]
    fn test_flags_for_xmas() {
        let flags = flags_for_scan_type(TcpScanType::Xmas);
        assert_ne!(flags & TcpFlags::FIN, 0);
        assert_ne!(flags & TcpFlags::PSH, 0);
        assert_ne!(flags & TcpFlags::URG, 0);
    }

    #[test]
    fn test_interpret_syn_response_synack() {
        let state = interpret_response(
            TcpFlags::SYN | TcpFlags::ACK,
            TcpScanType::Syn,
            0,
        );
        assert_eq!(state, PortState::Open);
    }

    #[test]
    fn test_interpret_syn_response_rst() {
        let state = interpret_response(TcpFlags::RST, TcpScanType::Syn, 0);
        assert_eq!(state, PortState::Closed);
    }

    #[test]
    fn test_interpret_null_response_rst() {
        let state = interpret_response(TcpFlags::RST, TcpScanType::Null, 0);
        assert_eq!(state, PortState::Closed);
    }

    #[test]
    fn test_interpret_null_timeout() {
        let state = interpret_timeout(TcpScanType::Null);
        assert_eq!(state, PortState::OpenFiltered);
    }

    #[test]
    fn test_interpret_window_rst_nonzero() {
        let state = interpret_response(TcpFlags::RST, TcpScanType::Window, 1024);
        assert_eq!(state, PortState::Open);
    }

    #[test]
    fn test_interpret_window_rst_zero() {
        let state = interpret_response(TcpFlags::RST, TcpScanType::Window, 0);
        assert_eq!(state, PortState::Closed);
    }
}
