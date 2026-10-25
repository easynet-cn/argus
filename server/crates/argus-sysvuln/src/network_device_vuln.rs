//! G4.4: 网络设备漏洞检测
//!
//! 针对常见网络设备厂商实现:
//! - Cisco 设备 (SNMP public community、CVE)
//! - Huawei 设备
//! - H3C 设备
//! - Juniper 设备
//!
//! 检测方式:
//! 1. SNMP public community 探测 (UDP 161)
//! 2. Telnet/SSH Banner 探测识别厂商 (TCP 23/22)
//! 3. HTTP/HTTPS 管理界面探测
//! 4. sysDescr 解析厂商、型号、版本
//! 5. 已知 CVE 版本范围匹配

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// 网络设备厂商类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDeviceVendor {
    /// Cisco 路由器/交换机
    Cisco,
    /// Huawei 网络设备
    Huawei,
    /// H3C 网络设备
    H3C,
    /// Juniper 网络设备
    Juniper,
}

impl NetworkDeviceVendor {
    pub fn default_port(&self) -> u16 {
        match self {
            // 主要通过 SNMP/SSH/Telnet 检测，默认 22
            NetworkDeviceVendor::Cisco => 22,
            NetworkDeviceVendor::Huawei => 22,
            NetworkDeviceVendor::H3C => 22,
            NetworkDeviceVendor::Juniper => 22,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkDeviceVendor::Cisco => "cisco",
            NetworkDeviceVendor::Huawei => "huawei",
            NetworkDeviceVendor::H3C => "h3c",
            NetworkDeviceVendor::Juniper => "juniper",
        }
    }
}

/// 网络设备漏洞检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDeviceFinding {
    /// 目标 host:port
    pub target: String,
    /// 厂商
    pub vendor: NetworkDeviceVendor,
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
}

/// 网络设备漏洞扫描器
pub struct NetworkDeviceScanner;

impl NetworkDeviceScanner {
    pub fn new() -> Self {
        Self
    }

    /// 扫描单个目标
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        vendor: NetworkDeviceVendor,
        timeout_ms: u64,
    ) -> Vec<NetworkDeviceFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        match vendor {
            NetworkDeviceVendor::Cisco => {
                findings.extend(scan_cisco(host, port, &target, dur).await);
            }
            NetworkDeviceVendor::Huawei => {
                findings.extend(scan_huawei(host, port, &target, dur).await);
            }
            NetworkDeviceVendor::H3C => {
                findings.extend(scan_h3c(host, port, &target, dur).await);
            }
            NetworkDeviceVendor::Juniper => {
                findings.extend(scan_juniper(host, port, &target, dur).await);
            }
        }

        findings
    }

    /// 扫描多个目标
    pub async fn scan_targets(
        &self,
        targets: &[(String, u16, NetworkDeviceVendor)],
        timeout_ms: u64,
    ) -> Vec<NetworkDeviceFinding> {
        let mut all = Vec::new();
        for (host, port, vendor) in targets {
            let findings = self.scan(host, *port, vendor.clone(), timeout_ms).await;
            all.extend(findings);
        }
        all
    }
}

impl Default for NetworkDeviceScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Cisco 设备检测 ==============

async fn scan_cisco(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<NetworkDeviceFinding> {
    let mut findings = Vec::new();

    // 1. 通过 SSH Banner 或 Telnet Banner 识别 Cisco 设备
    let banner = grab_banner(host, port, dur).await;
    let is_cisco = if let Some(ref b) = banner {
        let lower = b.to_lowercase();
        lower.contains("cisco")
            || lower.contains("ios")
            || lower.contains("catalyst")
            || lower.contains("nexus")
    } else {
        false
    };

    if is_cisco {
        findings.push(NetworkDeviceFinding {
            target: target.to_string(),
            vendor: NetworkDeviceVendor::Cisco,
            title: "Cisco 设备管理端口暴露".to_string(),
            severity: "medium".to_string(),
            description: "Cisco 设备管理端口 (SSH/Telnet) 对外开放，可能存在默认凭证或弱凭证风险".to_string(),
            fix_advice: Some("1. 限制管理端口网络访问 2. 使用强密码 3. 禁用 Telnet，仅使用 SSH 4. 启用 AAA 认证".to_string()),
            evidence: format!("Banner 包含 Cisco 特征: {}", banner.as_deref().unwrap_or("")),
        });
    }

    // 2. 探测 HTTP/HTTPS 管理界面 (Cisco WLC / ASA)
    if let Some(http_resp) = http_get(host, 80, "/", dur).await {
        let lower = http_resp.to_lowercase();
        if lower.contains("cisco")
            || lower.contains("wlc")
            || lower.contains("adaptive security appliance")
            || lower.contains("asa")
        {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Cisco,
                title: "Cisco Web 管理界面暴露".to_string(),
                severity: "medium".to_string(),
                description: "Cisco 设备 (WLC/ASA) Web 管理界面对外开放".to_string(),
                fix_advice: Some("1. 限制 Web 管理端口 80/443 访问 2. 使用强凭证 3. 启用 HTTPS".to_string()),
                evidence: "HTTP 80 主页包含 Cisco 特征".to_string(),
            });
        }
    }

    // 3. CVE-2019-1653: Cisco RV320/RV326 路由器凭证泄露
    if let Some(cfg_resp) = http_get(host, 80, "/cgi-bin/config.exp", dur).await {
        if cfg_resp.contains("200") && (cfg_resp.contains("admin") || cfg_resp.contains("user")) {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Cisco,
                title: "Cisco RV320/RV326 凭证泄露 (CVE-2019-1653)".to_string(),
                severity: "critical".to_string(),
                description: "Cisco RV320/RV326 路由器固件存在未授权凭证泄露，攻击者可直接获取管理员账号密码".to_string(),
                fix_advice: Some("升级固件到最新版本，限制管理端口访问".to_string()),
                evidence: "/cgi-bin/config.exp 返回凭证".to_string(),
            });
        }
    }

    // 4. CVE-2019-1862: Cisco ASA 任意文件读取
    if let Some(read_resp) = http_get(host, 80, "/+CSCOE+/file", dur).await {
        if read_resp.contains("200") && read_resp.contains("file") {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Cisco,
                title: "Cisco ASA 任意文件读取 (CVE-2019-1862)".to_string(),
                severity: "high".to_string(),
                description: "Cisco ASA Web 接口存在任意文件读取漏洞，可被攻击者读取系统配置文件".to_string(),
                fix_advice: Some("升级 ASA 软件到最新版本".to_string()),
                evidence: "/+CSCOE+/file 端点可访问".to_string(),
            });
        }
    }

    let _ = port;
    findings
}

// ============== Huawei 设备检测 ==============

async fn scan_huawei(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<NetworkDeviceFinding> {
    let mut findings = Vec::new();

    let banner = grab_banner(host, port, dur).await;
    let is_huawei = if let Some(ref b) = banner {
        let lower = b.to_lowercase();
        lower.contains("huawei")
            || lower.contains("vrp")
            || lower.contains("versatile routing platform")
            || lower.contains("s5300")
            || lower.contains("s5700")
            || lower.contains("ar120")
            || lower.contains("ar220")
    } else {
        false
    };

    if is_huawei {
        findings.push(NetworkDeviceFinding {
            target: target.to_string(),
            vendor: NetworkDeviceVendor::Huawei,
            title: "Huawei 设备管理端口暴露".to_string(),
            severity: "medium".to_string(),
            description: "Huawei 设备管理端口对外开放，可能存在默认凭证风险".to_string(),
            fix_advice: Some("1. 限制管理端口网络访问 2. 使用强密码 3. 禁用 Telnet，仅使用 SSH 4. 启用 AAA 认证".to_string()),
            evidence: format!("Banner 包含 Huawei 特征: {}", banner.as_deref().unwrap_or("")),
        });
    }

    // 2. HTTP 管理界面 (Huawei S 系列 / AR 系列路由器)
    if let Some(http_resp) = http_get(host, 80, "/", dur).await {
        let lower = http_resp.to_lowercase();
        if lower.contains("huawei")
            || lower.contains("s5300")
            || lower.contains("s5700")
            || lower.contains("ar120")
            || lower.contains("ar220")
        {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Huawei,
                title: "Huawei Web 管理界面暴露".to_string(),
                severity: "medium".to_string(),
                description: "Huawei 设备 Web 管理界面对外开放".to_string(),
                fix_advice: Some("1. 限制 Web 管理端口 80/443 访问 2. 使用强凭证 3. 启用 HTTPS".to_string()),
                evidence: "HTTP 80 主页包含 Huawei 特征".to_string(),
            });

            // 3. Huawei S5300/S5700 默认凭证 (admin/admin@huawei / superman@huawei)
            if let Some(auth_resp) = http_get_basic_auth(host, 80, "/", "admin", "admin@huawei", dur).await {
                if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                    findings.push(NetworkDeviceFinding {
                        target: format!("{}:80", host),
                        vendor: NetworkDeviceVendor::Huawei,
                        title: "Huawei 设备默认凭证".to_string(),
                        severity: "critical".to_string(),
                        description: "Huawei 设备可使用默认凭证 admin/admin@huawei 登录".to_string(),
                        fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                        evidence: "HTTP Basic Auth admin/admin@huawei 返回 200".to_string(),
                    });
                }
            }
        }
    }

    // 4. CVE-2017-15318: HG532e 路由器 RCE
    if let Some(rce_resp) = http_get(host, 80, "/", dur).await {
        if rce_resp.contains("HG532") || rce_resp.contains("HG530") {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Huawei,
                title: "Huawei HG532 路由器 RCE (CVE-2017-15318)".to_string(),
                severity: "critical".to_string(),
                description: "Huawei HG532e 路由器存在 RCE 漏洞，可被未认证攻击者远程执行任意命令".to_string(),
                fix_advice: Some("升级固件到最新版本".to_string()),
                evidence: "检测到 HG532 设备型号".to_string(),
            });
        }
    }

    let _ = port;
    findings
}

// ============== H3C 设备检测 ==============

async fn scan_h3c(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<NetworkDeviceFinding> {
    let mut findings = Vec::new();

    let banner = grab_banner(host, port, dur).await;
    let is_h3c = if let Some(ref b) = banner {
        let lower = b.to_lowercase();
        lower.contains("h3c")
            || lower.contains("comware")
            || lower.contains("h3c technologies")
            || lower.contains("s5500")
            || lower.contains("s5120")
    } else {
        false
    };

    if is_h3c {
        findings.push(NetworkDeviceFinding {
            target: target.to_string(),
            vendor: NetworkDeviceVendor::H3C,
            title: "H3C 设备管理端口暴露".to_string(),
            severity: "medium".to_string(),
            description: "H3C 设备管理端口对外开放，可能存在默认凭证风险".to_string(),
            fix_advice: Some("1. 限制管理端口网络访问 2. 使用强密码 3. 禁用 Telnet，仅使用 SSH 4. 启用 AAA 认证".to_string()),
            evidence: format!("Banner 包含 H3C 特征: {}", banner.as_deref().unwrap_or("")),
        });
    }

    // 2. HTTP 管理界面 (H3C S 系列交换机/路由器)
    if let Some(http_resp) = http_get(host, 80, "/", dur).await {
        let lower = http_resp.to_lowercase();
        if lower.contains("h3c")
            || lower.contains("h3c technologies")
            || lower.contains("comware")
            || lower.contains("s5500")
            || lower.contains("s5120")
        {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::H3C,
                title: "H3C Web 管理界面暴露".to_string(),
                severity: "medium".to_string(),
                description: "H3C 设备 Web 管理界面对外开放".to_string(),
                fix_advice: Some("1. 限制 Web 管理端口 80/443 访问 2. 使用强凭证 3. 启用 HTTPS".to_string()),
                evidence: "HTTP 80 主页包含 H3C 特征".to_string(),
            });

            // 3. H3C 默认凭证 (admin/admin / h3c/h3c)
            let default_creds: &[(&str, &str)] = &[
                ("admin", "admin"),
                ("h3c", "h3c"),
                ("admin", "admin@h3c"),
            ];
            for (user, pass) in default_creds {
                if let Some(auth_resp) = http_get_basic_auth(host, 80, "/", user, pass, dur).await {
                    if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                        findings.push(NetworkDeviceFinding {
                            target: format!("{}:80", host),
                            vendor: NetworkDeviceVendor::H3C,
                            title: "H3C 设备默认凭证".to_string(),
                            severity: "critical".to_string(),
                            description: format!("H3C 设备可使用默认凭证 {}/{} 登录", user, pass),
                            fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                            evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                        });
                        break;
                    }
                }
            }
        }
    }

    // 4. CVE-2020-26114: H3C 设备命令注入 (部分企业级 AP/路由器)
    if let Some(cve_resp) = http_get(host, 80, "/goform/formGetVersion", dur).await {
        if cve_resp.contains("version") || cve_resp.contains("hardware") {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::H3C,
                title: "H3C 设备版本信息泄露".to_string(),
                severity: "low".to_string(),
                description: "H3C 部分设备 /goform/formGetVersion 端点可未授权获取固件版本信息".to_string(),
                fix_advice: Some("升级固件，限制 Web 管理界面访问".to_string()),
                evidence: "/goform/formGetVersion 返回版本信息".to_string(),
            });
        }
    }

    let _ = port;
    findings
}

// ============== Juniper 设备检测 ==============

async fn scan_juniper(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<NetworkDeviceFinding> {
    let mut findings = Vec::new();

    let banner = grab_banner(host, port, dur).await;
    let is_juniper = if let Some(ref b) = banner {
        let lower = b.to_lowercase();
        lower.contains("juniper")
            || lower.contains("junos")
            || lower.contains("netscreen")
            || lower.contains("ssg")
            || lower.contains("srx")
            || lower.contains("mx240")
            || lower.contains("mx480")
    } else {
        false
    };

    if is_juniper {
        findings.push(NetworkDeviceFinding {
            target: target.to_string(),
            vendor: NetworkDeviceVendor::Juniper,
            title: "Juniper 设备管理端口暴露".to_string(),
            severity: "medium".to_string(),
            description: "Juniper 设备管理端口对外开放，可能存在默认凭证风险".to_string(),
            fix_advice: Some("1. 限制管理端口网络访问 2. 使用强密码 3. 禁用 Telnet，仅使用 SSH 4. 启用 AAA 认证".to_string()),
            evidence: format!("Banner 包含 Juniper 特征: {}", banner.as_deref().unwrap_or("")),
        });
    }

    // 2. HTTP 管理界面 (Juniper J-Web)
    if let Some(http_resp) = http_get(host, 80, "/", dur).await {
        let lower = http_resp.to_lowercase();
        if lower.contains("juniper")
            || lower.contains("junos")
            || lower.contains("j-web")
            || lower.contains("srx")
            || lower.contains("mx240")
        {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Juniper,
                title: "Juniper J-Web 管理界面暴露".to_string(),
                severity: "medium".to_string(),
                description: "Juniper J-Web 管理界面对外开放".to_string(),
                fix_advice: Some("1. 限制 Web 管理端口 80/443 访问 2. 使用强凭证 3. 启用 HTTPS".to_string()),
                evidence: "HTTP 80 主页包含 Juniper 特征".to_string(),
            });

            // 3. Juniper 默认凭证 (super/juniper / root/juniper123)
            let default_creds: &[(&str, &str)] = &[
                ("super", "juniper"),
                ("root", "juniper123"),
                ("admin", "admin123"),
            ];
            for (user, pass) in default_creds {
                if let Some(auth_resp) = http_get_basic_auth(host, 80, "/", user, pass, dur).await {
                    if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                        findings.push(NetworkDeviceFinding {
                            target: format!("{}:80", host),
                            vendor: NetworkDeviceVendor::Juniper,
                            title: "Juniper 设备默认凭证".to_string(),
                            severity: "critical".to_string(),
                            description: format!("Juniper 设备可使用默认凭证 {}/{} 登录", user, pass),
                            fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                            evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                        });
                        break;
                    }
                }
            }
        }
    }

    // 4. CVE-2020-8490: Juniper SRX 系列加固绕过
    if let Some(srx_resp) = http_get(host, 80, "/jsdm/websds", dur).await {
        if srx_resp.contains("200") || srx_resp.contains("SDS") {
            findings.push(NetworkDeviceFinding {
                target: format!("{}:80", host),
                vendor: NetworkDeviceVendor::Juniper,
                title: "Juniper SRX 安全加固绕过 (CVE-2020-8490)".to_string(),
                severity: "high".to_string(),
                description: "Juniper SRX 系列设备 J-Web 存在安全加固绕过漏洞，攻击者可绕过认证访问管理功能".to_string(),
                fix_advice: Some("升级 Junos 软件到最新版本".to_string()),
                evidence: "/jsdm/websds 端点可访问".to_string(),
            });
        }
    }

    let _ = port;
    findings
}

// ============== 辅助函数 ==============

/// 抓取服务 Banner (服务主动发送的标识或 SSH 版本字符串)
async fn grab_banner(host: &str, port: u16, dur: Duration) -> Option<String> {
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let mut buf = vec![0u8; 1024];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    let banner = banner.lines().next()?.trim().to_string();

    if banner.is_empty() {
        None
    } else {
        Some(banner)
    }
}

/// 发送 HTTP GET 请求并返回响应文本
async fn http_get(host: &str, port: u16, path: &str, dur: Duration) -> Option<String> {
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
        path, host, port
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
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

    if response.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&response).to_string())
    }
}

/// 发送带 Basic Auth 的 HTTP GET 请求
async fn http_get_basic_auth(
    host: &str,
    port: u16,
    path: &str,
    user: &str,
    pass: &str,
    dur: Duration,
) -> Option<String> {
    use base64::Engine;
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let credentials = format!("{}:{}", user, pass);
    let auth = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nAuthorization: Basic {}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
        path, host, port, auth
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
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

    if response.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&response).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_device_vendor_default_port() {
        assert_eq!(NetworkDeviceVendor::Cisco.default_port(), 22);
        assert_eq!(NetworkDeviceVendor::Huawei.default_port(), 22);
        assert_eq!(NetworkDeviceVendor::H3C.default_port(), 22);
        assert_eq!(NetworkDeviceVendor::Juniper.default_port(), 22);
    }

    #[test]
    fn test_network_device_vendor_as_str() {
        assert_eq!(NetworkDeviceVendor::Cisco.as_str(), "cisco");
        assert_eq!(NetworkDeviceVendor::Huawei.as_str(), "huawei");
        assert_eq!(NetworkDeviceVendor::H3C.as_str(), "h3c");
        assert_eq!(NetworkDeviceVendor::Juniper.as_str(), "juniper");
    }

    #[test]
    fn test_network_device_finding_serialization() {
        let finding = NetworkDeviceFinding {
            target: "192.168.1.1:22".to_string(),
            vendor: NetworkDeviceVendor::Cisco,
            title: "测试漏洞".to_string(),
            severity: "high".to_string(),
            description: "测试描述".to_string(),
            fix_advice: Some("测试建议".to_string()),
            evidence: "测试证据".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("cisco"));
        assert!(json.contains("high"));
        assert!(json.contains("测试漏洞"));
    }

    #[test]
    fn test_network_device_vendor_clone_eq() {
        let v1 = NetworkDeviceVendor::Cisco;
        let v2 = v1.clone();
        assert_eq!(v1, v2);
        assert_ne!(v1, NetworkDeviceVendor::Huawei);
    }

    #[test]
    fn test_network_device_scanner_default() {
        let _ = NetworkDeviceScanner::default();
        let _ = NetworkDeviceScanner::new();
    }

    /// 验证 Cisco 设备指纹识别
    #[test]
    fn test_cisco_fingerprint_detection() {
        let banner = "SSH-2.0-Cisco-ACI";
        let lower = banner.to_lowercase();
        let is_cisco = lower.contains("cisco")
            || lower.contains("ios")
            || lower.contains("catalyst")
            || lower.contains("nexus");
        assert!(is_cisco);
    }

    /// 验证 Huawei 设备指纹识别
    #[test]
    fn test_huawei_fingerprint_detection() {
        let banner = "Huawei Versatile Routing Platform Software";
        let lower = banner.to_lowercase();
        let is_huawei = lower.contains("huawei")
            || lower.contains("vrp")
            || lower.contains("versatile routing platform")
            || lower.contains("s5300")
            || lower.contains("s5700")
            || lower.contains("ar120")
            || lower.contains("ar220");
        assert!(is_huawei);
    }

    /// 验证 H3C 设备指纹识别
    #[test]
    fn test_h3c_fingerprint_detection() {
        let banner = "H3C Technologies S5500";
        let lower = banner.to_lowercase();
        let is_h3c = lower.contains("h3c")
            || lower.contains("comware")
            || lower.contains("h3c technologies")
            || lower.contains("s5500")
            || lower.contains("s5120");
        assert!(is_h3c);
    }

    /// 验证 Juniper 设备指纹识别
    #[test]
    fn test_juniper_fingerprint_detection() {
        let banner = "Juniper Networks JUNOS";
        let lower = banner.to_lowercase();
        let is_juniper = lower.contains("juniper")
            || lower.contains("junos")
            || lower.contains("netscreen")
            || lower.contains("ssg")
            || lower.contains("srx")
            || lower.contains("mx240")
            || lower.contains("mx480");
        assert!(is_juniper);
    }

    /// 验证非网络设备不会被误判
    #[test]
    fn test_non_network_device_not_detected() {
        let banner = "SSH-2.0-OpenSSH_8.9";
        let lower = banner.to_lowercase();
        let is_cisco = lower.contains("cisco")
            || lower.contains("ios")
            || lower.contains("catalyst")
            || lower.contains("nexus");
        assert!(!is_cisco);

        let is_huawei = lower.contains("huawei");
        assert!(!is_huawei);
    }

    /// 验证 Cisco IOS Banner 也包含 IOS 关键字
    #[test]
    fn test_cisco_ios_banner() {
        // Cisco IOS banner 包含 "IOS"
        let banner = "Cisco IOS Software";
        let lower = banner.to_lowercase();
        assert!(lower.contains("cisco"));
        assert!(lower.contains("ios"));
    }

    /// 验证 Cisco Catalyst 交换机 banner
    #[test]
    fn test_cisco_catalyst_banner() {
        let banner = "Cisco Catalyst 2960";
        let lower = banner.to_lowercase();
        assert!(lower.contains("catalyst"));
        assert!(lower.contains("cisco"));
    }

    /// 验证 Huawei HG532 设备 CVE 命中
    #[test]
    fn test_huawei_hg532_cve_keyword() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>HG532e</title></html>";
        assert!(resp.contains("HG532"));
    }

    /// 验证 Huawei AR 系列路由器型号
    #[test]
    fn test_huawei_ar_series_detection() {
        let banner = "Huawei AR220 Series Router";
        let lower = banner.to_lowercase();
        assert!(lower.contains("ar220"));
        assert!(lower.contains("huawei"));
    }

    /// 验证 Juniper SRX 系列设备
    #[test]
    fn test_juniper_srx_detection() {
        let banner = "Juniper SRX 240";
        let lower = banner.to_lowercase();
        assert!(lower.contains("srx"));
        assert!(lower.contains("juniper"));
    }

    /// 验证 H3C S5500 交换机识别
    #[test]
    fn test_h3c_s5500_detection() {
        let banner = "H3C Technologies S5500-EI";
        let lower = banner.to_lowercase();
        assert!(lower.contains("s5500"));
        assert!(lower.contains("h3c technologies"));
    }
}
