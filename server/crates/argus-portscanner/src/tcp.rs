//! TCP 端口扫描
//!
//! 支持 Connect 扫描（无需 root 权限）
//! SYN/ACK/Null/Xmas/Fin/Window 通过 pnet raw socket 实现（需 root 权限）
//! 无 root 权限时自动降级为 Connect
//! 带 RateLimiter 反馈，自适应调整发包速率

use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use futures_util::stream::{self, StreamExt};

use crate::rate::RateLimiter;
use crate::types::{PortScanResult, PortState, Protocol, TcpScanType};

/// 扫描单个 TCP 端口（Connect 方式）
/// 带可选速率限制器反馈
pub async fn scan_tcp_port_connect(
    host: &str,
    port: u16,
    timeout_ms: u64,
    rate_limiter: Option<&RateLimiter>,
) -> PortScanResult {
    if let Some(rl) = rate_limiter {
        rl.acquire().await;
    }

    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    let result = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await;
    let elapsed = start.elapsed().as_millis() as u64;

    let scan_result = match result {
        Ok(Ok(_stream)) => {
            // 成功连接 → 反馈成功
            if let Some(rl) = rate_limiter {
                rl.record_success().await;
            }
            PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                banner: None,
                response_time_ms: elapsed,
            }
        }
        Ok(Err(e)) => {
            let state = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                // 明确拒绝 → 端口关闭，不算网络问题
                PortState::Closed
            } else {
                // 其他错误（如防火墙 drop）→ filtered，反馈失败（影响速率）
                if let Some(rl) = rate_limiter {
                    rl.record_failure().await;
                }
                PortState::Filtered
            };
            PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Tcp,
                state,
                service: None,
                banner: None,
                response_time_ms: elapsed,
            }
        }
        Err(_) => {
            // 超时 → filtered，反馈失败
            if let Some(rl) = rate_limiter {
                rl.record_failure().await;
            }
            PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Tcp,
                state: PortState::Filtered,
                service: None,
                banner: None,
                response_time_ms: elapsed,
            }
        }
    };

    scan_result
}

/// 扫描 TCP 端口列表（Connect 方式，并发）
pub async fn scan_tcp_ports_connect(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
    rate_limiter: Option<&RateLimiter>,
) -> Vec<PortScanResult> {
    let results: Vec<PortScanResult> = stream::iter(ports.iter().copied())
        .map(|port| async move { scan_tcp_port_connect(host, port, timeout_ms, rate_limiter).await })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

/// 根据扫描类型调度 TCP 扫描
/// 非 Connect 类型先尝试 raw socket（SYN/ACK/Null/Xmas/Fin/Window），失败降级为 Connect
pub async fn scan_tcp_port(
    host: &str,
    port: u16,
    scan_type: TcpScanType,
    timeout_ms: u64,
    rate_limiter: Option<&RateLimiter>,
) -> PortScanResult {
    match scan_type {
        TcpScanType::Connect => {
            scan_tcp_port_connect(host, port, timeout_ms, rate_limiter).await
        }
        other => {
            // 尝试 raw socket 扫描
            if let Ok(dst_ip) = host.parse::<std::net::IpAddr>() {
                // 已解析的 IP，直接扫描
                let src_ip = guess_src_ip();
                if let Some(result) = crate::raw::scan_tcp_raw_port(
                    src_ip,
                    dst_ip,
                    port,
                    other,
                    timeout_ms,
                ).await {
                    if let Some(rl) = rate_limiter {
                        match result.state {
                            PortState::Open | PortState::OpenFiltered => {
                                rl.record_success().await;
                            }
                            PortState::Filtered => {
                                rl.record_failure().await;
                            }
                            _ => {}
                        }
                    }
                    return result;
                }
            }

            // raw socket 不可用或 IP 解析失败，降级为 Connect
            if let Some(rl) = rate_limiter {
                tracing::debug!("Raw socket 不可用，降级为 Connect 扫描");
            }
            scan_tcp_port_connect(host, port, timeout_ms, rate_limiter).await
        }
    }
}

/// 尝试猜测本机出站 IP 地址
fn guess_src_ip() -> std::net::IpAddr {
    use std::net::UdpSocket;
    // 用 UDP socket 连接公共 IP 来获取本机出站 IP
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => {
            if s.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = s.local_addr() {
                    return addr.ip();
                }
            }
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        }
        Err(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    }
}

/// 扫描 TCP 端口列表（按扫描类型，并发）
pub async fn scan_tcp_ports(
    host: &str,
    ports: &[u16],
    scan_type: TcpScanType,
    timeout_ms: u64,
    concurrency: usize,
    rate_limiter: Option<&RateLimiter>,
) -> Vec<PortScanResult> {
    let results: Vec<PortScanResult> = stream::iter(ports.iter().copied())
        .map(|port| {
            scan_tcp_port(host, port, scan_type, timeout_ms, rate_limiter)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_to_closed_port_returns_closed_or_filtered() {
        // 端口 1 通常没有进程监听
        let result = scan_tcp_port_connect("127.0.0.1", 1, 500, None).await;
        assert!(matches!(
            result.state,
            PortState::Closed | PortState::Filtered
        ));
    }

    #[tokio::test]
    async fn test_connect_with_limiter_does_not_panic() {
        let rl = RateLimiter::new(100);
        let result = scan_tcp_port_connect("127.0.0.1", 1, 500, Some(&rl)).await;
        assert!(matches!(
            result.state,
            PortState::Closed | PortState::Filtered
        ));
    }
}
