//! 主机存活探测

use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use crate::types::HostAliveResult;

/// TCP Ping 常用端口
const TCP_PING_PORTS: [u16; 8] = [80, 443, 22, 21, 25, 3389, 8080, 8443];

/// 解析主机名为 IP 地址（使用 tokio 的 lookup_host）
pub async fn resolve_host(host: &str) -> Option<String> {
    // 如果已经是 IP 地址，直接返回
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    // DNS 解析
    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip().to_string()),
        Err(_) => None,
    }
}

/// TCP Ping 探测主机是否存活
/// 尝试连接多个常用端口，任一成功即认为存活
pub async fn tcp_ping(host: &str, timeout_ms: u64) -> HostAliveResult {
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

    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    // 并发尝试多个端口
    let mut handles = Vec::new();
    for port in TCP_PING_PORTS.iter() {
        let addr = format!("{}:{}", ip, port);
        handles.push(tokio::spawn(async move {
            match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => true,
                _ => false,
            }
        }));
    }

    let mut alive = false;
    let mut best_time = None;
    for handle in handles {
        if let Ok(success) = handle.await {
            if success {
                alive = true;
                let elapsed = start.elapsed().as_millis() as u64;
                if best_time.is_none() || elapsed < best_time.unwrap() {
                    best_time = Some(elapsed);
                }
            }
        }
    }

    let elapsed = start.elapsed().as_millis() as u64;
    HostAliveResult {
        host: host.to_string(),
        ip,
        alive,
        response_time_ms: best_time.or(Some(elapsed)),
    }
}

/// 批量探测主机存活
pub async fn ping_hosts(hosts: &[String], timeout_ms: u64, concurrency: usize) -> Vec<HostAliveResult> {
    use futures_util::stream::{self, StreamExt};

    let owned_hosts: Vec<String> = hosts.to_vec();
    let results: Vec<HostAliveResult> = stream::iter(owned_hosts)
        .map(|host| async move { tcp_ping(&host, timeout_ms).await })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}
