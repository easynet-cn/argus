//! 服务指纹识别（Banner 抓取 + 端口匹配）

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::PortScanResult;

/// 基于端口号的服务名映射
fn service_by_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 | 8080 | 8000 | 8888 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 | 8443 => Some("https"),
        445 => Some("smb"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        27017 => Some("mongodb"),
        9200 => Some("elasticsearch"),
        _ => None,
    }
}

/// 抓取 TCP Banner
pub async fn grab_banner_tcp(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut buf = vec![0u8; 2048];

    // 先尝试读取服务主动发送的 banner
    let read_future = tokio::time::timeout(
        Duration::from_millis(timeout_ms.min(2000)),
        stream.read(&mut buf),
    );

    match read_future.await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if !banner.is_empty() {
                return Some(banner);
            }
        }
        _ => {}
    }

    // 对于 HTTP 服务，发送 GET 请求
    if matches!(port, 80 | 8080 | 8000 | 8888 | 443 | 8443) {
        let probe = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
            host
        );
        if stream.write_all(probe.as_bytes()).await.is_ok() {
            let _ = stream.flush().await;
            let mut response = Vec::new();
            let read_timeout = Duration::from_millis(timeout_ms.min(2000));
            loop {
                let mut chunk = vec![0u8; 1024];
                match tokio::time::timeout(read_timeout, stream.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        response.extend_from_slice(&chunk[..n]);
                        if response.len() > 4096 {
                            break;
                        }
                    }
                    _ => break,
                }
                if start.elapsed().as_millis() > timeout_ms as u128 {
                    break;
                }
            }
            if !response.is_empty() {
                return Some(String::from_utf8_lossy(&response).trim().to_string());
            }
        }
    }

    None
}

/// 对开放端口进行服务指纹识别
pub async fn fingerprint_port(result: &mut PortScanResult, timeout_ms: u64) {
    // 先基于端口识别服务名
    if result.service.is_none() {
        result.service = service_by_port(result.port).map(|s| s.to_string());
    }

    // 抓取 banner
    if result.banner.is_none() {
        result.banner = grab_banner_tcp(&result.host, result.port, timeout_ms).await;
    }

    // 根据 banner 内容进一步识别服务
    if let Some(banner) = &result.banner {
        let lower = banner.to_lowercase();
        if lower.contains("ssh") {
            result.service = Some("ssh".to_string());
        } else if lower.contains("http") {
            result.service = Some("http".to_string());
        } else if lower.contains("ftp") {
            result.service = Some("ftp".to_string());
        } else if lower.contains("smtp") {
            result.service = Some("smtp".to_string());
        } else if lower.contains("mysql") {
            result.service = Some("mysql".to_string());
        } else if lower.contains("redis") {
            result.service = Some("redis".to_string());
        } else if lower.contains("postgresql") {
            result.service = Some("postgresql".to_string());
        } else if lower.contains("mongodb") {
            result.service = Some("mongodb".to_string());
        }
    }
}
