//! G4.8: 危险漏洞插件（DoS 类）
//!
//! ⚠️ **风险警告**: 本模块包含 DoS（拒绝服务）类检测插件。
//!
//! 这些插件通过发送**少量畸形/异常请求**来探测目标是否存在 DoS 漏洞，
//! **不会**进行真正的泛洪攻击（Flood）。但仍可能对目标服务造成短暂影响。
//!
//! 默认情况下（`run_dangerous=false`）这些插件**不会**执行。
//! 仅当显式设置 `run_dangerous=true` 时才会运行。
//!
//! 包含的检测项:
//! - `SynFloodProbe`: SYN Flood 风险探测（检测目标 TCP 栈对 SYN 包的处理行为）
//! - `ApacheKillerProbe`: Apache Killer (CVE-2011-3192) 畸形 Range Header 探测
//! - `MalformedRequestProbe`: 畸形 HTTP 请求崩溃探测（检测服务对畸形输入的容错性）
//! - `SlowlorisProbe`: Slowloris 慢速攻击风险探测（检测服务器并发连接处理）

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// DoS 检测插件类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DosPluginType {
    /// SYN Flood 风险探测
    #[serde(rename = "syn_flood_probe")]
    SynFloodProbe,
    /// Apache Killer 畸形 Range Header 探测
    #[serde(rename = "apache_killer_probe")]
    ApacheKillerProbe,
    /// 畸形 HTTP 请求崩溃探测
    #[serde(rename = "malformed_request_probe")]
    MalformedRequestProbe,
    /// Slowloris 慢速攻击风险探测
    #[serde(rename = "slowloris_probe")]
    SlowlorisProbe,
}

impl DosPluginType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DosPluginType::SynFloodProbe => "syn_flood_probe",
            DosPluginType::ApacheKillerProbe => "apache_killer_probe",
            DosPluginType::MalformedRequestProbe => "malformed_request_probe",
            DosPluginType::SlowlorisProbe => "slowloris_probe",
        }
    }

    /// 风险等级描述
    pub fn risk_level(&self) -> &'static str {
        match self {
            DosPluginType::SynFloodProbe => "low",
            DosPluginType::ApacheKillerProbe => "low",
            DosPluginType::MalformedRequestProbe => "low",
            DosPluginType::SlowlorisProbe => "low",
        }
    }
}

/// DoS 检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosFinding {
    /// 目标 host:port
    pub target: String,
    /// 插件类型
    pub plugin: DosPluginType,
    /// 漏洞标题
    pub title: String,
    /// 严重级别 (critical/high/medium/low/info)
    pub severity: String,
    /// 漏洞描述
    pub description: String,
    /// 修复建议
    pub fix_advice: Option<String>,
    /// 证据
    pub evidence: String,
    /// 风险警告
    pub risk_warning: String,
}

/// DoS 漏洞扫描器
///
/// ⚠️ 仅当 `run_dangerous=true` 时才应执行此扫描器
pub struct DosScanner;

impl DosScanner {
    pub fn new() -> Self {
        Self
    }

    /// 对单个目标执行所有 DoS 探测插件
    ///
    /// ⚠️ 调用前应确认 `run_dangerous` 已启用
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        timeout_ms: u64,
    ) -> Vec<DosFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        findings.extend(syn_flood_probe(host, port, &target, dur).await);
        findings.extend(apache_killer_probe(host, port, &target, dur).await);
        findings.extend(malformed_request_probe(host, port, &target, dur).await);
        findings.extend(slowloris_probe(host, port, &target, dur).await);

        findings
    }

    /// 对单个目标执行指定的 DoS 探测插件
    pub async fn scan_with_plugins(
        &self,
        host: &str,
        port: u16,
        plugins: &[DosPluginType],
        timeout_ms: u64,
    ) -> Vec<DosFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        for plugin in plugins {
            match plugin {
                DosPluginType::SynFloodProbe => {
                    findings.extend(syn_flood_probe(host, port, &target, dur).await);
                }
                DosPluginType::ApacheKillerProbe => {
                    findings.extend(apache_killer_probe(host, port, &target, dur).await);
                }
                DosPluginType::MalformedRequestProbe => {
                    findings.extend(malformed_request_probe(host, port, &target, dur).await);
                }
                DosPluginType::SlowlorisProbe => {
                    findings.extend(slowloris_probe(host, port, &target, dur).await);
                }
            }
        }

        findings
    }
}

impl Default for DosScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== SYN Flood 风险探测 ==============

/// SYN Flood 风险探测
///
/// 原理: 发送少量 SYN 包（通过完整 TCP 握手模拟），观察目标的响应行为。
/// 如果目标对快速连续的连接请求无任何限流或返回异常，说明可能缺乏 SYN Flood 防护。
///
/// 注意: 此探测**不会**进行真正的 SYN Flood 攻击，仅发送少量连接请求。
async fn syn_flood_probe(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DosFinding> {
    let mut findings = Vec::new();

    // 发送少量快速连接请求（仅 3 次，模拟 SYN 行为）
    let mut success_count = 0;
    let mut timeout_count = 0;

    for _ in 0..3 {
        match timeout(dur, TcpStream::connect((host, port))).await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(_)) => {}
            Err(_) => timeout_count += 1,
        }
    }

    // 如果所有连接都成功且无超时，目标可能缺乏 SYN 速率限制
    if success_count == 3 && timeout_count == 0 {
        findings.push(DosFinding {
            target: target.to_string(),
            plugin: DosPluginType::SynFloodProbe,
            title: "目标可能缺乏 SYN Flood 防护".to_string(),
            severity: "medium".to_string(),
            description: "目标对快速连续的 TCP 连接请求无明显限流，可能存在 SYN Flood 攻击风险".to_string(),
            fix_advice: Some("1. 启用 TCP SYN Cookie 2. 配置 SYN 速率限制 3. 部署 DDoS 防护设备".to_string()),
            evidence: format!("3 次快速连接请求全部成功，无超时或拒绝"),
            risk_warning: "此探测仅发送 3 次连接请求，不会造成实际 DoS 影响".to_string(),
        });
    }

    findings
}

// ============== Apache Killer 畸形 Range Header 探测 ==============

/// Apache Killer (CVE-2011-3192) 探测
///
/// 原理: 发送带有畸形 Range Header 的 HTTP 请求，检测服务器是否返回 200/206 且包含大量分段。
/// 如果服务器对畸形 Range 处理不当，可能存在 Apache Killer DoS 漏洞。
///
/// 注意: 此探测仅发送**单个**畸形请求，不会进行多次请求泛洪。
async fn apache_killer_probe(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DosFinding> {
    let mut findings = Vec::new();

    // 构造畸形 Range Header (CVE-2011-3192)
    // 仅发送一个请求，range 数量控制在安全范围内
    let range_header = "bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9";
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nRange: {}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
        host, port, range_header
    );

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    if stream.write_all(req.as_bytes()).await.is_err() {
        return findings;
    }

    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 8192 {
                    break;
                }
            }
            _ => break,
        }
    }

    let resp_str = String::from_utf8_lossy(&response).to_string();
    let first_line = resp_str.lines().next().unwrap_or("");

    // 检查响应状态码和 Content-Type
    // 如果返回 206 Partial Content 且包含 multipart/byteranges，说明服务器处理了畸形 Range
    if first_line.contains("206") && resp_str.to_lowercase().contains("multipart/byteranges") {
        findings.push(DosFinding {
            target: target.to_string(),
            plugin: DosPluginType::ApacheKillerProbe,
            title: "Apache Killer DoS 疑似漏洞 (CVE-2011-3192)".to_string(),
            severity: "high".to_string(),
            description: "服务器对畸形 Range Header 返回 multipart/byteranges 响应，可能存在 Apache Killer DoS 漏洞 (CVE-2011-3192)".to_string(),
            fix_advice: Some("1. 升级 Apache httpd 到 2.2.20 或更高版本 2. 配置 Range Header 过滤规则 3. 禁用不必要的 Range 请求".to_string()),
            evidence: "畸形 Range Header 请求返回 206 + multipart/byteranges".to_string(),
            risk_warning: "此探测仅发送单个畸形请求，不会造成实际 DoS 影响".to_string(),
        });
    }

    findings
}

// ============== 畸形 HTTP 请求崩溃探测 ==============

/// 畸形 HTTP 请求崩溃探测
///
/// 原理: 发送格式错误的 HTTP 请求，观察服务器是否返回异常状态码或连接被异常关闭。
/// 如果服务器对畸形输入处理不当（如返回 500 或连接重置），可能存在崩溃漏洞。
///
/// 注意: 此探测仅发送**单个**畸形请求。
async fn malformed_request_probe(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DosFinding> {
    let mut findings = Vec::new();

    // 发送畸形请求: 无效的 HTTP 方法 + 超长 Host
    let req = format!(
        "GARBAGE / HTTP/1.1\r\nHost: {}\r\n\r\n",
        "A".repeat(1024)
    );

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    if stream.write_all(req.as_bytes()).await.is_err() {
        return findings;
    }

    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 8192 {
                    break;
                }
            }
            _ => break,
        }
    }

    let resp_str = String::from_utf8_lossy(&response).to_string();
    let first_line = resp_str.lines().next().unwrap_or("");

    // 如果服务器返回 500 Internal Server Error 或响应为空但连接正常关闭，
    // 可能存在畸形请求处理漏洞
    if first_line.contains("500") {
        findings.push(DosFinding {
            target: target.to_string(),
            plugin: DosPluginType::MalformedRequestProbe,
            title: "服务对畸形 HTTP 请求处理异常".to_string(),
            severity: "medium".to_string(),
            description: "服务器对畸形 HTTP 请求返回 500 Internal Server Error，可能存在请求解析漏洞".to_string(),
            fix_advice: Some("1. 升级服务软件到最新版本 2. 配置 WAF 过滤畸形请求 3. 启用输入验证".to_string()),
            evidence: "畸形 HTTP 请求返回 500 Internal Server Error".to_string(),
            risk_warning: "此探测仅发送单个畸形请求，不会造成实际 DoS 影响".to_string(),
        });
    }

    findings
}

// ============== Slowloris 慢速攻击风险探测 ==============

/// Slowloris 慢速攻击风险探测
///
/// 原理: 建立连接后缓慢发送不完整的 HTTP 请求头，观察服务器是否保持连接过长时间。
/// 如果服务器对慢速连接无超时限制，可能存在 Slowloris 攻击风险。
///
/// 注意: 此探测仅建立**单个**连接并短暂保持，不会占用大量并发连接。
async fn slowloris_probe(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DosFinding> {
    let mut findings = Vec::new();

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 发送部分 HTTP 请求头（不完整）
    let partial_req = format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Argus-Scanner\r\n",
        host, port
    );

    if stream.write_all(partial_req.as_bytes()).await.is_err() {
        return findings;
    }

    // 短暂等待，观察连接是否被服务器主动关闭
    let short_dur = Duration::from_millis(500);
    let mut buf = vec![0u8; 1024];
    let connection_kept = match timeout(short_dur, stream.read(&mut buf)).await {
        // 服务器返回了响应（可能是错误响应），连接未保持
        Ok(Ok(0)) => false,
        Ok(Ok(_)) => false,
        // 超时说明连接保持（服务器未主动关闭）
        Err(_) => true,
        Ok(Err(_)) => false,
    };

    if connection_kept {
        findings.push(DosFinding {
            target: target.to_string(),
            plugin: DosPluginType::SlowlorisProbe,
            title: "目标可能存在 Slowloris 慢速攻击风险".to_string(),
            severity: "medium".to_string(),
            description: "服务器对不完整的 HTTP 请求保持连接时间过长，可能存在 Slowloris 慢速攻击风险".to_string(),
            fix_advice: Some("1. 配置 HTTP 请求头超时（如 Apache 的 RequestReadTimeout）2. 使用 nginx 等反向代理 3. 限制并发连接数".to_string()),
            evidence: "不完整 HTTP 请求连接保持超过 500ms 未被关闭".to_string(),
            risk_warning: "此探测仅建立单个连接并保持 500ms，不会造成实际 DoS 影响".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_plugin_type_as_str() {
        assert_eq!(DosPluginType::SynFloodProbe.as_str(), "syn_flood_probe");
        assert_eq!(DosPluginType::ApacheKillerProbe.as_str(), "apache_killer_probe");
        assert_eq!(DosPluginType::MalformedRequestProbe.as_str(), "malformed_request_probe");
        assert_eq!(DosPluginType::SlowlorisProbe.as_str(), "slowloris_probe");
    }

    #[test]
    fn test_dos_plugin_type_risk_level() {
        // 所有探测插件风险等级都应为 low（因为只是探测，不是真正攻击）
        assert_eq!(DosPluginType::SynFloodProbe.risk_level(), "low");
        assert_eq!(DosPluginType::ApacheKillerProbe.risk_level(), "low");
        assert_eq!(DosPluginType::MalformedRequestProbe.risk_level(), "low");
        assert_eq!(DosPluginType::SlowlorisProbe.risk_level(), "low");
    }

    #[test]
    fn test_dos_finding_serialization() {
        let finding = DosFinding {
            target: "192.168.1.1:80".to_string(),
            plugin: DosPluginType::ApacheKillerProbe,
            title: "测试 DoS 漏洞".to_string(),
            severity: "high".to_string(),
            description: "测试描述".to_string(),
            fix_advice: Some("测试建议".to_string()),
            evidence: "测试证据".to_string(),
            risk_warning: "测试警告".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("apache_killer_probe"));
        assert!(json.contains("high"));
        assert!(json.contains("测试 DoS 漏洞"));
        assert!(json.contains("测试警告"));
    }

    #[test]
    fn test_dos_plugin_type_clone_eq() {
        let p1 = DosPluginType::SynFloodProbe;
        let p2 = p1.clone();
        assert_eq!(p1, p2);
        assert_ne!(p1, DosPluginType::ApacheKillerProbe);
    }

    #[test]
    fn test_dos_scanner_default() {
        let _ = DosScanner::default();
        let _ = DosScanner::new();
    }

    /// 验证 Apache Killer 畸形 Range Header 构造正确
    #[test]
    fn test_apache_killer_range_header() {
        let range_header = "bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9";
        // 验证包含 10 个 range 段
        let segments: Vec<&str> = range_header.trim_start_matches("bytes=").split(',').collect();
        assert_eq!(segments.len(), 10);
    }

    /// 验证畸形请求构造
    #[test]
    fn test_malformed_request_construction() {
        let req = format!(
            "GARBAGE / HTTP/1.1\r\nHost: {}\r\n\r\n",
            "A".repeat(1024)
        );
        assert!(req.starts_with("GARBAGE / HTTP/1.1"));
        assert!(req.contains("Host: "));
        // Host 值应为 1024 个 A
        let host_val = req.split("Host: ").nth(1).unwrap().split("\r\n").next().unwrap();
        assert_eq!(host_val.len(), 1024);
    }

    /// 验证 Slowloris 不完整请求构造
    #[test]
    fn test_slowloris_partial_request() {
        let partial_req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\nUser-Agent: Argus-Scanner\r\n";
        // 不完整请求不应以 \r\n\r\n 结尾
        assert!(!partial_req.ends_with("\r\n\r\n"));
        assert!(partial_req.starts_with("GET / HTTP/1.1"));
    }

    /// 验证 Apache Killer 响应判定逻辑
    #[test]
    fn test_apache_killer_response_detection() {
        // 模拟易受攻击的响应
        let resp = "HTTP/1.1 206 Partial Content\r\nContent-Type: multipart/byteranges; boundary=test\r\n\r\n--test\r\n";
        let first_line = resp.lines().next().unwrap_or("");
        let is_vulnerable = first_line.contains("206") && resp.to_lowercase().contains("multipart/byteranges");
        assert!(is_vulnerable);

        // 模拟正常响应（不受攻击）
        let resp_normal = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
        let first_line = resp_normal.lines().next().unwrap_or("");
        let is_vulnerable = first_line.contains("206") && resp_normal.to_lowercase().contains("multipart/byteranges");
        assert!(!is_vulnerable);
    }

    /// 验证畸形请求响应判定逻辑
    #[test]
    fn test_malformed_request_response_detection() {
        let resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        let first_line = resp.lines().next().unwrap_or("");
        assert!(first_line.contains("500"));

        let resp_normal = "HTTP/1.1 400 Bad Request\r\n\r\n";
        let first_line = resp_normal.lines().next().unwrap_or("");
        assert!(!first_line.contains("500"));
    }

    /// 验证所有插件类型都有非空的 as_str 和 risk_level
    #[test]
    fn test_all_plugins_have_metadata() {
        let plugins = vec![
            DosPluginType::SynFloodProbe,
            DosPluginType::ApacheKillerProbe,
            DosPluginType::MalformedRequestProbe,
            DosPluginType::SlowlorisProbe,
        ];
        for p in &plugins {
            assert!(!p.as_str().is_empty(), "{} as_str 不应为空", p.as_str());
            assert!(!p.risk_level().is_empty(), "{} risk_level 不应为空", p.as_str());
        }
    }
}
