//! 增强服务指纹：banner 解析 + 版本提取 + CPE 生成

use crate::types::*;
use crate::signature_db::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 按端口号推测服务名
fn service_by_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"), 22 => Some("ssh"), 23 => Some("telnet"),
        25 => Some("smtp"), 53 => Some("dns"), 80 | 8080 | 8000 | 8888 => Some("http"),
        110 => Some("pop3"), 143 => Some("imap"), 443 | 8443 => Some("https"),
        445 => Some("smb"), 3306 => Some("mysql"), 3389 => Some("rdp"),
        5432 => Some("postgresql"), 6379 => Some("redis"), 27017 => Some("mongodb"),
        9200 => Some("elasticsearch"), 502 => Some("modbus"), 102 => Some("s7"),
        2404 => Some("iec104"), 161 => Some("snmp"), 389 => Some("ldap"),
        636 => Some("ldaps"), 1433 => Some("mssql"), 1521 => Some("oracle"),
        5985 | 5986 => Some("winrm"), 9090 => Some("prometheus"),
        _ => None,
    }
}

/// 抓取 TCP Banner（复用 argus-portscanner 的逻辑）
pub async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);
    let start = std::time::Instant::now();

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut buf = vec![0u8; 2048];

    // 先尝试读取服务主动发送的 banner
    let read_timeout = Duration::from_millis(timeout_ms.min(2000));
    match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            if !banner.is_empty() {
                return Some(banner);
            }
        }
        _ => {}
    }

    // 对 HTTP 服务，发送 GET 请求
    if matches!(port, 80 | 8080 | 8000 | 8888 | 443 | 8443 | 9090) {
        let probe = format!(
            "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(probe.as_bytes()).await.is_ok() {
            let _ = stream.flush().await;
            let mut response = Vec::new();
            loop {
                let mut chunk = vec![0u8; 1024];
                match tokio::time::timeout(read_timeout, stream.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        response.extend_from_slice(&chunk[..n]);
                        if response.len() > 4096 { break; }
                    }
                    _ => break,
                }
                if start.elapsed().as_millis() > timeout_ms as u128 { break; }
            }
            if !response.is_empty() {
                return Some(String::from_utf8_lossy(&response).trim().to_string());
            }
        }
    }

    None
}

/// 对目标端口进行服务指纹识别
pub async fn fingerprint_service(
    host: &str,
    port: u16,
    banner: Option<String>,
    signatures: &ServiceSignatureDb,
    timeout_ms: u64,
) -> ServiceFingerprint {
    // 先基于端口识别服务名
    let mut service = service_by_port(port).map(|s| s.to_string());
    let banner = match banner {
            Some(b) => Some(b),
            None => grab_banner(host, port, timeout_ms).await,
        };

    // 用签名库匹配 banner
    let (product, version, vendor, cpe) = if let Some(ref banner_str) = banner {
        if let Some(sig) = signatures.match_banner(banner_str) {
            let version = sig.version_regex.as_ref()
                .and_then(|re| regex::Regex::new(re).ok())
                .and_then(|r| {
                    r.captures(banner_str)
                        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                });
            let cpe = sig.cpe_template.as_ref()
                .and_then(|t| version.as_ref().map(|v| t.replace("{version}", v)));
            (sig.product.clone(), version, sig.vendor.clone(), cpe)
        } else {
            // fallback: 内置关键字匹配
            banner_keyword_match(banner_str)
        }
    } else {
        (None, None, None, None)
    };

    if service.is_none() {
        // 从 product 推测 service
        service = product.as_ref().map(|p| {
            let p = p.to_lowercase();
            if p.contains("ssh") { "ssh".to_string() }
            else if p.contains("http") || p.contains("nginx") || p.contains("apache") { "http".to_string() }
            else if p.contains("mysql") { "mysql".to_string() }
            else if p.contains("redis") { "redis".to_string() }
            else if p.contains("ftp") { "ftp".to_string() }
            else if p.contains("smtp") { "smtp".to_string() }
            else { p }
        });
    }

    let method = if banner.is_some() { FingerprintMethod::Banner }
                 else { FingerprintMethod::Port };

    ServiceFingerprint {
        host: host.to_string(),
        port,
        service: service.unwrap_or_else(|| "unknown".to_string()),
        product,
        version,
        vendor,
        cpe_uri: cpe,
        banner,
        confidence: if method == FingerprintMethod::Banner { 0.85 } else { 0.5 },
        method,
    }
}

/// Banner 关键字匹配（内置 fallback）
fn banner_keyword_match(banner: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let lower = banner.to_lowercase();

    // SSH: OpenSSH_7.4
    if lower.contains("openssh") {
        let version = extract_version(&lower, "openssh_");
        return (Some("OpenSSH".to_string()), version, Some("OpenBSD".to_string()), None);
    }
    // Apache: Apache/2.4.6
    if lower.contains("apache/") {
        let version = extract_version(&lower, "apache/");
        let cpe = version.as_ref().map(|v| format!("cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*", v));
        return (Some("Apache HTTP Server".to_string()), version, Some("Apache".to_string()), cpe);
    }
    // nginx: nginx/1.18.0
    if lower.contains("nginx/") {
        let version = extract_version(&lower, "nginx/");
        let cpe = version.as_ref().map(|v| format!("cpe:2.3:a:nginx:nginx:{}:*:*:*:*:*:*:*", v));
        return (Some("nginx".to_string()), version, Some("Nginx".to_string()), cpe);
    }
    // MySQL: 5.7.33
    if lower.contains("mysql") {
        let version = extract_version(&lower, "mysql");
        return (Some("MySQL".to_string()), version, Some("Oracle".to_string()), None);
    }
    // Redis: -REDIS
    if lower.contains("redis") {
        let version = extract_version(&lower, "redis_version:");
        return (Some("Redis".to_string()), version, Some("Redis".to_string()), None);
    }
    // PostgreSQL
    if lower.contains("postgresql") || lower.contains("postgre") {
        let version = extract_version(&lower, "postgre");
        return (Some("PostgreSQL".to_string()), version, Some("PostgreSQL".to_string()), None);
    }
    // vsftpd
    if lower.contains("vsftpd") {
        let version = extract_version(&lower, "vsftpd");
        return (Some("vsftpd".to_string()), version, Some("vsftpd".to_string()), None);
    }
    // ProFTPD
    if lower.contains("proftpd") {
        let version = extract_version(&lower, "proftpd");
        return (Some("ProFTPD".to_string()), version, Some("ProFTPD".to_string()), None);
    }
    // Postfix
    if lower.contains("postfix") {
        let version = extract_version(&lower, "postfix");
        return (Some("Postfix".to_string()), version, Some("Postfix".to_string()), None);
    }
    // Microsoft IIS
    if lower.contains("microsoft-iis") {
        let version = extract_version(&lower, "microsoft-iis/");
        return (Some("Microsoft IIS".to_string()), version, Some("Microsoft".to_string()), None);
    }
    (None, None, None, None)
}

/// 从字符串中提取版本号
fn extract_version(lower: &str, prefix: &str) -> Option<String> {
    if let Some(pos) = lower.find(prefix) {
        let after = &lower[pos + prefix.len()..];
        let version: String = after.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let version = version.trim_end_matches('.');
        if !version.is_empty() {
            return Some(version.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_apache_banner() {
        let (product, version, vendor, _) = banner_keyword_match("Apache/2.4.6 (Ubuntu)");
        assert_eq!(product, Some("Apache HTTP Server".to_string()));
        assert_eq!(version, Some("2.4.6".to_string()));
        assert_eq!(vendor, Some("Apache".to_string()));
    }

    #[test]
    fn test_extract_openssh_banner() {
        let (product, version, vendor, _) = banner_keyword_match("SSH-2.0-OpenSSH_7.4");
        assert_eq!(product, Some("OpenSSH".to_string()));
        assert_eq!(version, Some("7.4".to_string()));
        assert_eq!(vendor, Some("OpenBSD".to_string()));
    }

    #[test]
    fn test_extract_nginx_banner() {
        let (product, version, _, cpe) = banner_keyword_match("nginx/1.18.0");
        assert_eq!(product, Some("nginx".to_string()));
        assert_eq!(version, Some("1.18.0".to_string()));
        assert!(cpe.is_some());
        assert!(cpe.unwrap().contains("1.18.0"));
    }

    #[test]
    fn test_cpe_uri_construction() {
        let cpe = format!("cpe:2.3:a:apache:http_server:{}:*:*:*:*:*:*:*", "2.4.6");
        assert_eq!(cpe, "cpe:2.3:a:apache:http_server:2.4.6:*:*:*:*:*:*:*");
    }

    #[test]
    fn test_service_by_port() {
        assert_eq!(service_by_port(22), Some("ssh"));
        assert_eq!(service_by_port(443), Some("https"));
        assert_eq!(service_by_port(80), Some("http"));
        assert_eq!(service_by_port(12345), None);
    }
}
