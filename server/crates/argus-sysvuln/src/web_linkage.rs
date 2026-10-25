//! G4.6: 网站漏洞联动扫描
//!
//! 端口扫描发现 HTTP 服务时，自动创建应用扫描子任务
//! 流程:
//! 1. 从端口扫描结果中识别 HTTP/HTTPS 服务（Banner/端口匹配）
//! 2. 为每个发现的 Web 服务生成 WebScanTarget
//! 3. 返回子任务列表，由调度器创建 argus-webscan 任务

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Web 扫描目标（联动生成的子任务）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScanTarget {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub protocol: String, // "http" or "https"
    pub source_port: u16,
}

/// 端口扫描结果项（简化结构，从 JSON extra_params 注入）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResultItem {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// 从端口扫描结果中提取 Web 服务目标
///
/// 识别规则:
/// - 端口 80/8080/8000/8888/800/8081/8082 → HTTP
/// - 端口 443/8443/4443 → HTTPS
/// - Banner 包含 "HTTP" 或 "html" → HTTP
/// - 服务名包含 "http" 或 "https" → 对应协议
pub fn extract_web_targets(scan_results: &[PortScanResultItem]) -> Vec<WebScanTarget> {
    let http_ports: HashSet<u16> = [80, 8080, 8000, 8888, 800, 8081, 8082, 3000, 5000, 9000]
        .into_iter()
        .collect();
    let https_ports: HashSet<u16> = [443, 8443, 4443].into_iter().collect();

    let mut targets = Vec::new();
    let mut seen = HashSet::new(); // 去重 (host, port)

    for item in scan_results {
        if item.state != "open" {
            continue;
        }

        let key = (item.host.clone(), item.port);
        if seen.contains(&key) {
            continue;
        }

        let (is_web, protocol) = detect_web_service(item, &http_ports, &https_ports);
        if is_web {
            seen.insert(key);
            let url = format!("{}://{}:{}", protocol, item.host, item.port);
            targets.push(WebScanTarget {
                url,
                host: item.host.clone(),
                port: item.port,
                protocol: protocol.clone(),
                source_port: item.port,
            });
        }
    }

    targets
}

/// 检测端口/服务是否为 Web 服务
fn detect_web_service(
    item: &PortScanResultItem,
    http_ports: &HashSet<u16>,
    https_ports: &HashSet<u16>,
) -> (bool, String) {
    let banner_lower = item.banner.as_deref().unwrap_or("").to_lowercase();
    let service_lower = item.service.as_deref().unwrap_or("").to_lowercase();

    // HTTPS 端口
    if https_ports.contains(&item.port) {
        return (true, "https".to_string());
    }

    // HTTP 端口
    if http_ports.contains(&item.port) {
        // 如果 Banner 明确表示 HTTPS，则用 HTTPS
        if banner_lower.contains("https") || service_lower.contains("https") {
            return (true, "https".to_string());
        }
        return (true, "http".to_string());
    }

    // Banner 包含 HTTP 特征
    if banner_lower.contains("http/")
        || banner_lower.contains("server:")
        || banner_lower.contains("<html")
        || banner_lower.contains("content-type:")
    {
        if banner_lower.contains("https") || service_lower.contains("https") {
            return (true, "https".to_string());
        }
        return (true, "http".to_string());
    }

    // 服务名包含 http
    if service_lower.contains("http") {
        if service_lower.contains("https") || service_lower.contains("ssl") {
            return (true, "https".to_string());
        }
        return (true, "http".to_string());
    }

    (false, String::new())
}

/// 联动扫描配置参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebLinkageConfig {
    /// 是否启用网站漏洞联动扫描
    #[serde(default = "default_true")]
    pub enable_web_linkage: bool,
    /// 已知 Web 服务端口（覆盖默认列表）
    #[serde(default)]
    pub custom_http_ports: Vec<u16>,
    /// 自定义 HTTPS 端口
    #[serde(default)]
    pub custom_https_ports: Vec<u16>,
}

impl Default for WebLinkageConfig {
    fn default() -> Self {
        Self {
            enable_web_linkage: true,
            custom_http_ports: Vec::new(),
            custom_https_ports: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_web_targets_http_80() {
        let results = vec![PortScanResultItem {
            host: "192.168.1.1".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some("http".to_string()),
            banner: Some("HTTP/1.1 200 OK".to_string()),
        }];
        let targets = extract_web_targets(&results);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].protocol, "http");
        assert_eq!(targets[0].url, "http://192.168.1.1:80");
    }

    #[test]
    fn test_extract_web_targets_https_443() {
        let results = vec![PortScanResultItem {
            host: "10.0.0.1".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: None,
            banner: None,
        }];
        let targets = extract_web_targets(&results);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].protocol, "https");
        assert_eq!(targets[0].url, "https://10.0.0.1:443");
    }

    #[test]
    fn test_extract_web_targets_banner_detection() {
        // 非标准端口但 Banner 包含 HTTP 特征
        let results = vec![PortScanResultItem {
            host: "10.0.0.2".to_string(),
            port: 8080,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: None,
            banner: Some("Server: nginx/1.18.0".to_string()),
        }];
        let targets = extract_web_targets(&results);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].protocol, "http");
    }

    #[test]
    fn test_extract_web_targets_dedup() {
        // 重复的 host:port 应去重
        let results = vec![
            PortScanResultItem {
                host: "10.0.0.1".to_string(),
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("http".to_string()),
                banner: None,
            },
            PortScanResultItem {
                host: "10.0.0.1".to_string(),
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: Some("http".to_string()),
                banner: None,
            },
        ];
        let targets = extract_web_targets(&results);
        assert_eq!(targets.len(), 1, "重复目标应去重");
    }

    #[test]
    fn test_extract_web_targets_skip_closed() {
        let results = vec![PortScanResultItem {
            host: "10.0.0.1".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            state: "closed".to_string(),
            service: Some("http".to_string()),
            banner: None,
        }];
        let targets = extract_web_targets(&results);
        assert!(targets.is_empty(), "关闭的端口应跳过");
    }

    #[test]
    fn test_extract_web_targets_non_web_port() {
        let results = vec![PortScanResultItem {
            host: "10.0.0.1".to_string(),
            port: 22,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some("ssh".to_string()),
            banner: Some("SSH-2.0-OpenSSH_8.9".to_string()),
        }];
        let targets = extract_web_targets(&results);
        assert!(targets.is_empty(), "SSH 端口不应被识别为 Web");
    }

    #[test]
    fn test_extract_web_targets_multiple_ports() {
        let results = vec![
            PortScanResultItem {
                host: "10.0.0.1".to_string(),
                port: 80,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: None,
                banner: None,
            },
            PortScanResultItem {
                host: "10.0.0.1".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: None,
                banner: None,
            },
            PortScanResultItem {
                host: "10.0.0.1".to_string(),
                port: 8080,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: None,
                banner: None,
            },
        ];
        let targets = extract_web_targets(&results);
        assert_eq!(targets.len(), 3);
    }
}
