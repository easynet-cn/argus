//! UDP 端口探测
//!
//! 实现：
//! - 协议特定 payload（DNS / NTP / SNMP / NetBIOS / TFTP / SIP / STUN / MQTT / L2TP 等）
//! - 通过对比响应与已知服务签名推断服务名
//! - 提供后续端口探测的成功/失败反馈给 RateLimiter

use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::rate::RateLimiter;
use crate::types::{PortScanResult, PortState, Protocol};

/// 端口 → 协议 probe 函数指针
type ProbeFn = fn() -> (Vec<u8>, Option<&'static str>);

/// 根据端口返回该协议的标准 probe（payload + 期望服务名）
fn probe_for_port(port: u16) -> Option<ProbeFn> {
    match port {
        53 => Some(dns_probe),
        123 => Some(ntp_probe),
        137 => Some(netbios_ns_probe),
        161 => Some(snmp_probe),
        500 | 4500 => Some(isakmp_probe),
        514 => Some(syslog_probe),
        1900 => Some(ssdp_probe),
        5353 => Some(mdns_probe),
        5060 => Some(sip_options_probe),
        623 => Some(ipmi_probe),
        _ => None,
    }
}

/// 根据响应内容识别服务（针对常见协议）
fn identify_service(port: u16, response: &[u8]) -> Option<String> {
    if response.is_empty() {
        return service_by_port(port).map(|s| s.to_string());
    }
    // DNS 响应：以事务 ID 开头，flags 包含 0x8180 (标准响应) 或 0x8580 (递归响应)
    if matches!(port, 53) && response.len() >= 12 && (response[2] & 0x80) != 0 {
        return Some("dns".to_string());
    }
    // NTP 响应：48 字节，flags 字节 0xe3/0xe4
    if matches!(port, 123) && response.len() >= 48 {
        return Some("ntp".to_string());
    }
    // SNMP：以 0x30 开头 (ASN.1 SEQUENCE)
    if matches!(port, 161) && response.first().is_some_and(|&b| b == 0x30) {
        return Some("snmp".to_string());
    }
    // NetBIOS Name Service：以事务 ID 开头
    if matches!(port, 137) && response.len() >= 12 {
        return Some("netbios-ns".to_string());
    }
    // SIP：以 "SIP/" 开头
    let text = String::from_utf8_lossy(response);
    if matches!(port, 5060) && text.starts_with("SIP/") {
        return Some("sip".to_string());
    }
    // SSDP：以 "HTTP/" 开头
    if matches!(port, 1900) && text.starts_with("HTTP/") {
        return Some("ssdp".to_string());
    }
    service_by_port(port).map(|s| s.to_string())
}

/// 端口 → 默认服务名
fn service_by_port(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("dns"),
        67 | 68 => Some("dhcp"),
        69 => Some("tftp"),
        123 => Some("ntp"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        161 | 162 => Some("snmp"),
        500 | 4500 => Some("isakmp"),
        514 => Some("syslog"),
        520 => Some("rip"),
        1900 => Some("ssdp"),
        5353 => Some("mdns"),
        5060 => Some("sip"),
        623 => Some("ipmi"),
        _ => None,
    }
}

// === 协议特定 probe ===

/// DNS 查询 A 记录（root "."）
fn dns_probe() -> (Vec<u8>, Option<&'static str>) {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x12, 0x34]); // transaction ID
    p.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    p.extend_from_slice(&[0x00]); // QNAME: root "."
    p.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    (p, Some("dns"))
}

/// NTP v3 请求（48 字节）
fn ntp_probe() -> (Vec<u8>, Option<&'static str>) {
    let mut p = vec![0u8; 48];
    p[0] = 0xe3; // LI=0, VN=3, Mode=3 (client)
    p[1] = 0x00; // Stratum=0
    p[2] = 0x06; // Poll=6 (64s)
    p[3] = 0xEC; // Precision=-20
    (p, Some("ntp"))
}

/// NetBIOS Name Service: 查询 "*"
fn netbios_ns_probe() -> (Vec<u8>, Option<&'static str>) {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x00, 0x00]); // transaction ID
    p.extend_from_slice(&[0x00, 0x00]); // flags
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    // QNAME: "*"
    p.extend_from_slice(&[0x20]); // length 32
    p.extend_from_slice(&b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"[..]);
    p.push(0x00); // null terminator
    p.extend_from_slice(&[0x00, 0x21]); // QTYPE: NBSTAT
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    (p, Some("netbios-ns"))
}

/// SNMP v2c GetRequest for sysDescr.0
fn snmp_probe() -> (Vec<u8>, Option<&'static str>) {
    // community="public", simple get-request for sysDescr (1.3.6.1.2.1.1.1.0)
    let p: Vec<u8> = vec![
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0,
        0x19, 0x02, 0x04, 0x71, 0x8e, 0x1c, 0x59, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
        0x0a, 0x30, 0x08, 0x06, 0x04, 0x2b, 0x06, 0x01, 0x02, 0x05,
    ];
    (p, Some("snmp"))
}

/// IKE/ISAKMP Main Mode Initiator
fn isakmp_probe() -> (Vec<u8>, Option<&'static str>) {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // initiator cookie
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // responder cookie (0)
    p.push(0x01); // next payload: SA
    p.push(0x10); // version: 1.0
    p.extend_from_slice(&[0x01, 0x10]); // exchange type: ID_PROT (main mode)
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // flags
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // message ID
    // length: 84 bytes
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x54]);
    (p, Some("isakmp"))
}

/// Syslog test message
fn syslog_probe() -> (Vec<u8>, Option<&'static str>) {
    // PRI=<14>, MSG="argus-probe"
    let s = "<14>argus-probe";
    (s.as_bytes().to_vec(), Some("syslog"))
}

/// SSDP M-SEARCH
fn ssdp_probe() -> (Vec<u8>, Option<&'static str>) {
    let s = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    (s.as_bytes().to_vec(), Some("ssdp"))
}

/// mDNS PTR query for _services._dns-sd._udp.local
fn mdns_probe() -> (Vec<u8>, Option<&'static str>) {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x00, 0x00]); // transaction ID
    p.extend_from_slice(&[0x01, 0x00]); // flags: standard query
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR
    // QNAME: _services._dns-sd._udp.local
    for label in ["_services", "_dns-sd", "_udp", "local"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x0c]); // QTYPE: PTR
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
    (p, Some("mdns"))
}

/// SIP OPTIONS
fn sip_options_probe() -> (Vec<u8>, Option<&'static str>) {
    let s = "OPTIONS sip:nobody@localhost SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nMax-Forwards: 70\r\nUser-Agent: argus-probe\r\n\r\n";
    (s.as_bytes().to_vec(), Some("sip"))
}

/// IPMI RMCP Presence Ping
fn ipmi_probe() -> (Vec<u8>, Option<&'static str>) {
    // RMCP v1 presence ping
    let p: Vec<u8> = vec![
        0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x90, 0x06, 0xbe, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    (p, Some("ipmi"))
}

/// 扫描单个 UDP 端口（带协议特定 probe）
/// 原理：
/// - 有特定 probe → 发送 probe
/// - 无 probe → 发送空包（保持原行为）
/// - 收到 UDP 响应 → open
/// - 超时 → open|filtered（UDP 无法在不收 ICMP 时区分 open 与 filtered）
pub async fn scan_udp_port(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> PortScanResult {
    scan_udp_port_with_limiter(host, port, timeout_ms, None).await
}

/// 扫描单个 UDP 端口（带速率限制器）
pub async fn scan_udp_port_with_limiter(
    host: &str,
    port: u16,
    timeout_ms: u64,
    rate_limiter: Option<&RateLimiter>,
) -> PortScanResult {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    if let Some(rl) = rate_limiter {
        rl.acquire().await;
    }

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            let _ = record_failure(rate_limiter).await;
            return PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Udp,
                state: PortState::Filtered,
                service: None,
                banner: None,
                response_time_ms: 0,
            };
        }
    };

    // 选择协议 probe
    let (payload, default_service) = probe_for_port(port)
        .map(|f| f())
        .unwrap_or_else(|| (Vec::new(), service_by_port(port)));

    // 发送 probe
    let send_result = socket.send_to(&payload, &addr).await;
    if let Err(_) = send_result {
        let elapsed = start.elapsed().as_millis() as u64;
        let _ = record_failure(rate_limiter).await;
        return PortScanResult {
            host: host.to_string(),
            port,
            protocol: Protocol::Udp,
            state: PortState::Closed,
            service: default_service.map(|s| s.to_string()),
            banner: None,
            response_time_ms: elapsed,
        };
    }

    // 等待响应
    let mut buf = [0u8; 2048];
    let result = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
    let elapsed = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok((len, _src))) => {
            let _ = record_success(rate_limiter).await;
            let banner = if len > 0 {
                let printable: Vec<u8> = buf[..len]
                    .iter()
                    .cloned()
                    .filter(|&b| b >= 0x20 || b == 0x0a || b == 0x0d)
                    .collect();
                if printable.is_empty() {
                    format!("<binary {} bytes>", len)
                } else {
                    String::from_utf8_lossy(&printable).to_string()
                }
            } else {
                String::new()
            };
            let service = identify_service(port, &buf[..len]).or_else(|| {
                default_service.map(|s| s.to_string())
            });
            PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Udp,
                state: PortState::Open,
                service,
                banner: if banner.is_empty() { None } else { Some(banner) },
                response_time_ms: elapsed,
            }
        }
        _ => {
            let _ = record_failure(rate_limiter).await;
            PortScanResult {
                host: host.to_string(),
                port,
                protocol: Protocol::Udp,
                state: PortState::OpenFiltered,
                service: default_service.map(|s| s.to_string()),
                banner: None,
                response_time_ms: elapsed,
            }
        }
    }
}

/// 反馈成功（给 RateLimiter，便于自适应提速）
async fn record_success(rate_limiter: Option<&RateLimiter>) {
    if let Some(rl) = rate_limiter {
        rl.record_success().await;
    }
}

/// 反馈失败（给 RateLimiter，便于自适应降速）
async fn record_failure(rate_limiter: Option<&RateLimiter>) {
    if let Some(rl) = rate_limiter {
        rl.record_failure().await;
    }
}

/// 扫描 UDP 端口列表（并发，无速率限制器）
pub async fn scan_udp_ports(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<PortScanResult> {
    use futures_util::stream::{self, StreamExt};

    let results: Vec<PortScanResult> = stream::iter(ports.iter().copied())
        .map(|port| async move { scan_udp_port(host, port, timeout_ms).await })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

/// 扫描 UDP 端口列表（并发，带速率限制器反馈）
pub async fn scan_udp_ports_with_limiter(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
    rate_limiter: Option<&RateLimiter>,
) -> Vec<PortScanResult> {
    use futures_util::stream::{self, StreamExt};

    let results: Vec<PortScanResult> = stream::iter(ports.iter().copied())
        .map(|port| async move {
            scan_udp_port_with_limiter(host, port, timeout_ms, rate_limiter).await
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_for_known_ports() {
        assert!(probe_for_port(53).is_some());
        assert!(probe_for_port(123).is_some());
        assert!(probe_for_port(161).is_some());
        assert!(probe_for_port(5060).is_some());
        assert!(probe_for_port(12345).is_none());
    }

    #[test]
    fn test_dns_probe_size() {
        let (p, s) = dns_probe();
        assert!(p.len() >= 12);
        assert_eq!(s, Some("dns"));
    }

    #[test]
    fn test_ntp_probe_size() {
        let (p, _) = ntp_probe();
        assert_eq!(p.len(), 48);
        assert_eq!(p[0], 0xe3);
    }

    #[test]
    fn test_snmp_probe_starts_with_sequence() {
        let (p, _) = snmp_probe();
        assert_eq!(p[0], 0x30);
    }

    #[test]
    fn test_sip_probe_contains_options() {
        let (p, _) = sip_options_probe();
        let text = String::from_utf8_lossy(&p);
        assert!(text.starts_with("OPTIONS"));
    }

    #[test]
    fn test_identify_service_dns() {
        let mut resp = vec![0x12, 0x34, 0x81, 0x80];
        resp.extend(std::iter::repeat(0).take(8));
        let svc = identify_service(53, &resp);
        assert_eq!(svc.as_deref(), Some("dns"));
    }

    #[test]
    fn test_identify_service_default_port() {
        let svc = identify_service(69, &[]);
        assert_eq!(svc.as_deref(), Some("tftp"));
    }

    #[test]
    fn test_service_by_port_known() {
        assert_eq!(service_by_port(53), Some("dns"));
        assert_eq!(service_by_port(123), Some("ntp"));
        assert_eq!(service_by_port(161), Some("snmp"));
        assert_eq!(service_by_port(5060), Some("sip"));
        assert_eq!(service_by_port(12345), None);
    }
}
