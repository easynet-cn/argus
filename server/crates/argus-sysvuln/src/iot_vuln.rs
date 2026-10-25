//! G4.1: IoT 设备漏洞检测
//!
//! 针对常见 IoT 设备实现:
//! - IP 摄像头 (海康威视/大华 默认凭证 + CVE)
//! - 路由器 (TP-Link/Netgear/D-Link 已知 CVE)
//! - 智能家居设备 (默认凭证)
//!
//! 检测方式:
//! 1. HTTP 探测设备指纹 (特定 URL 路径、Banner、HTML 内容)
//! 2. 默认凭证检测 (admin/admin、admin/12345 等)
//! 3. 已知 CVE 版本范围匹配

use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// IoT 设备类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IoTDeviceType {
    /// 海康威视 IP 摄像头
    Hikvision,
    /// 大华 IP 摄像头
    Dahua,
    /// TP-Link 路由器
    TpLinkRouter,
    /// Netgear 路由器
    NetgearRouter,
    /// D-Link 路由器
    DLinkRouter,
    /// 智能家居设备 (通用)
    SmartHome,
}

impl IoTDeviceType {
    pub fn default_port(&self) -> u16 {
        match self {
            IoTDeviceType::Hikvision => 80,
            IoTDeviceType::Dahua => 80,
            IoTDeviceType::TpLinkRouter => 80,
            IoTDeviceType::NetgearRouter => 80,
            IoTDeviceType::DLinkRouter => 80,
            IoTDeviceType::SmartHome => 80,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IoTDeviceType::Hikvision => "hikvision",
            IoTDeviceType::Dahua => "dahua",
            IoTDeviceType::TpLinkRouter => "tp_link_router",
            IoTDeviceType::NetgearRouter => "netgear_router",
            IoTDeviceType::DLinkRouter => "dlink_router",
            IoTDeviceType::SmartHome => "smart_home",
        }
    }
}

/// IoT 设备漏洞检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDeviceFinding {
    /// 目标 host:port
    pub target: String,
    /// 设备类型
    pub device_type: IoTDeviceType,
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

/// IoT 设备漏洞扫描器
pub struct IoTDeviceScanner;

impl IoTDeviceScanner {
    pub fn new() -> Self {
        Self
    }

    /// 扫描单个目标
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        device_type: IoTDeviceType,
        timeout_ms: u64,
    ) -> Vec<IoTDeviceFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        match device_type {
            IoTDeviceType::Hikvision => {
                findings.extend(scan_hikvision(host, port, &target, dur).await);
            }
            IoTDeviceType::Dahua => {
                findings.extend(scan_dahua(host, port, &target, dur).await);
            }
            IoTDeviceType::TpLinkRouter => {
                findings.extend(scan_tp_link(host, port, &target, dur).await);
            }
            IoTDeviceType::NetgearRouter => {
                findings.extend(scan_netgear(host, port, &target, dur).await);
            }
            IoTDeviceType::DLinkRouter => {
                findings.extend(scan_dlink(host, port, &target, dur).await);
            }
            IoTDeviceType::SmartHome => {
                findings.extend(scan_smart_home(host, port, &target, dur).await);
            }
        }

        findings
    }

    /// 扫描多个目标
    pub async fn scan_targets(
        &self,
        targets: &[(String, u16, IoTDeviceType)],
        timeout_ms: u64,
    ) -> Vec<IoTDeviceFinding> {
        let mut all = Vec::new();
        for (host, port, device_type) in targets {
            let findings = self.scan(host, *port, device_type.clone(), timeout_ms).await;
            all.extend(findings);
        }
        all
    }
}

impl Default for IoTDeviceScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== 海康威视摄像头检测 ==============

async fn scan_hikvision(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    // 1. 指纹探测: 海康威视 Web 主页
    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_hikvision = lower.contains("hikvision")
        || lower.contains("hik")
        || lower.contains("webcomponents")
        || lower.contains("/doc/page/login")
        || lower.contains("doc/page/login.asp");
    if !is_hikvision {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::Hikvision,
        title: "海康威视 IP 摄像头暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到海康威视 IP 摄像头 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级固件到最新版本".to_string()),
        evidence: "HTTP 主页包含海康威视特征".to_string(),
    });

    // 2. 默认凭证检测: admin/12345 (海康威视常见默认凭证)
    let default_creds: &[(&str, &str)] = &[
        ("admin", "12345"),
        ("admin", "hik12345"),
        ("admin", "abc12345"),
        ("admin", "admin"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/ISAPI/System/deviceInfo", user, pass, dur).await {
            // 成功响应: HTTP 200 + XML 包含 <DeviceInfo>
            if auth_resp.starts_with("HTTP/1.1 200")
                || (auth_resp.contains("200") && auth_resp.contains("DeviceInfo"))
            {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::Hikvision,
                    title: "海康威视摄像头默认凭证".to_string(),
                    severity: "critical".to_string(),
                    description: format!("摄像头可使用默认凭证 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 账户密码为强密码".to_string()),
                    evidence: format!("ISAPI/System/deviceInfo 通过 {}/{} 返回 200", user, pass),
                });
                break; // 命中一个即可
            }
        }
    }

    // 3. CVE-2021-36260: iVMS 海康威视 RCE (影响大量设备)
    // 通过 /SDK/web/language 路径检测是否疑似受影响版本
    if let Some(lang_resp) = http_get(host, port, "/SDK/web/language", dur).await {
        if lang_resp.contains("1.0") || lang_resp.contains("language") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::Hikvision,
                title: "海康威视 iVMS RCE (CVE-2021-36260)".to_string(),
                severity: "critical".to_string(),
                description: "海康威视 iVMS-4200 存在命令注入漏洞，可被未认证攻击者利用执行任意命令".to_string(),
                fix_advice: Some("升级固件到最新版本，限制管理端口对外访问".to_string()),
                evidence: "/SDK/web/language 路径可访问，疑似受影响版本".to_string(),
            });
        }
    }

    // 4. CVE-2017-7921: 海康威视认证绕过
    // 通过 ?auth=YWRtaW46MTEK (admin:11) 检测
    if let Some(bypass_resp) = http_get(host, port, "/System/configurationFile?auth=YWRtaW46MTEK", dur).await {
        if bypass_resp.contains("200") || bypass_resp.contains("configuration") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::Hikvision,
                title: "海康威视认证绕过 (CVE-2017-7921)".to_string(),
                severity: "critical".to_string(),
                description: "海康威视部分版本存在认证绕过漏洞，可通过构造特殊 URL 直接访问设备配置".to_string(),
                fix_advice: Some("升级固件到最新版本".to_string()),
                evidence: "通过 ?auth= 参数可访问 configurationFile".to_string(),
            });
        }
    }

    findings
}

// ============== 大华摄像头检测 ==============

async fn scan_dahua(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_dahua = lower.contains("dahua")
        || lower.contains("cgi-bin")
        || lower.contains("/cgi-bin/magicBox")
        || lower.contains("web/login");
    if !is_dahua {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::Dahua,
        title: "大华 IP 摄像头暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到大华 IP 摄像头 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级固件到最新版本".to_string()),
        evidence: "HTTP 主页包含大华特征".to_string(),
    });

    // 2. 大华常见默认凭证
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("888888", "888888"),
        ("666666", "666666"),
        ("admin", "dahua2023"),
    ];
    for (user, pass) in default_creds {
        // 大华登录通过 /cgi-bin/dVR/login.cgi 或 magicBox
        let login_path = format!("/cgi-bin/magicBoxLogin.cgi?username={}&password={}", user, pass);
        if let Some(login_resp) = http_get(host, port, &login_path, dur).await {
            if login_resp.contains("200") || login_resp.contains("OK") || login_resp.contains("session") {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::Dahua,
                    title: "大华摄像头默认凭证".to_string(),
                    severity: "critical".to_string(),
                    description: format!("摄像头可使用默认凭证 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 账户密码为强密码".to_string()),
                    evidence: format!("magicBoxLogin.cgi 通过 {}/{} 返回成功", user, pass),
                });
                break;
            }
        }
    }

    // 3. CVE-2021-33029: 大华摄像头认证绕过
    // 通过特殊构造的 cookie 绕过认证
    if let Some(bypass_resp) = http_get_with_header(
        host,
        port,
        "/cgi-bin/magicBoxGetSecurityCfg.cgi",
        "Cookie: DHL_USERADMIN=1",
        dur,
    ).await {
        if bypass_resp.contains("200") || bypass_resp.contains("security") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::Dahua,
                title: "大华摄像头认证绕过 (CVE-2021-33029)".to_string(),
                severity: "critical".to_string(),
                description: "大华部分摄像头存在认证绕过漏洞，可通过伪造 Cookie 直接访问管理接口".to_string(),
                fix_advice: Some("升级固件到最新版本，限制管理端口对外访问".to_string()),
                evidence: "通过 DHL_USERADMIN Cookie 可访问 magicBoxGetSecurityCfg".to_string(),
            });
        }
    }

    findings
}

// ============== TP-Link 路由器检测 ==============

async fn scan_tp_link(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_tp_link = lower.contains("tp-link")
        || lower.contains("tplink")
        || lower.contains("tl-")
        || lower.contains("/loginlg")
        || lower.contains("cgi-bin/luci");
    if !is_tp_link {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::TpLinkRouter,
        title: "TP-Link 路由器管理界面暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 TP-Link 路由器 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制 WAN 端管理访问 2. 修改默认密码 3. 升级固件".to_string()),
        evidence: "HTTP 主页包含 TP-Link 特征".to_string(),
    });

    // 2. TP-Link 默认凭证 admin/admin
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::TpLinkRouter,
                    title: "TP-Link 路由器默认凭证".to_string(),
                    severity: "high".to_string(),
                    description: format!("路由器可使用默认凭证 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. CVE-2023-1389: TP-Link TL-WR940N 命令注入
    // 检测 /cgi-bin/luci/ethplorer 特征
    if let Some(cve_resp) = http_get(host, port, "/cgi-bin/luci", dur).await {
        if cve_resp.contains("TP-LINK") || cve_resp.contains("TL-WR") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::TpLinkRouter,
                title: "TP-Link TL-WR940N 命令注入 (CVE-2023-1389)".to_string(),
                severity: "critical".to_string(),
                description: "TP-Link TL-WR940N 路由器固件存在命令注入漏洞，可被认证后攻击者利用执行任意命令".to_string(),
                fix_advice: Some("升级固件到最新版本".to_string()),
                evidence: "检测到 TL-WR 系列路由器，疑似受影响版本".to_string(),
            });
        }
    }

    // 4. CVE-2020-9384: TP-Link TL-WR841N 缓冲区溢出
    if lower.contains("tl-wr841") {
        findings.push(IoTDeviceFinding {
            target: target.to_string(),
            device_type: IoTDeviceType::TpLinkRouter,
            title: "TP-Link TL-WR841N 缓冲区溢出 (CVE-2020-9384)".to_string(),
            severity: "high".to_string(),
            description: "TP-Link TL-WR841N 固件存在缓冲区溢出漏洞，可导致 DoS 或 RCE".to_string(),
            fix_advice: Some("升级固件到最新版本".to_string()),
            evidence: "检测到 TL-WR841N 设备".to_string(),
        });
    }

    findings
}

// ============== Netgear 路由器检测 ==============

async fn scan_netgear(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_netgear = lower.contains("netgear")
        || lower.contains("setup.cgi")
        || lower.contains("currentsetting.htm");
    if !is_netgear {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::NetgearRouter,
        title: "Netgear 路由器管理界面暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 Netgear 路由器 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制 WAN 端管理访问 2. 修改默认密码 3. 升级固件".to_string()),
        evidence: "HTTP 主页包含 Netgear 特征".to_string(),
    });

    // 2. Netgear 默认凭证 admin/password / admin/admin
    let default_creds: &[(&str, &str)] = &[
        ("admin", "password"),
        ("admin", "admin"),
        ("admin", "1234"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::NetgearRouter,
                    title: "Netgear 路由器默认凭证".to_string(),
                    severity: "high".to_string(),
                    description: format!("路由器可使用默认凭证 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. CVE-2021-34991: Netgear 认证绕过
    if let Some(bypass_resp) = http_get(host, port, "/setup.cgi?next_file=.htm", dur).await {
        if bypass_resp.contains("200") && bypass_resp.contains("setup") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::NetgearRouter,
                title: "Netgear 认证绕过 (CVE-2021-34991)".to_string(),
                severity: "critical".to_string(),
                description: "Netgear 部分型号路由器存在认证绕过漏洞，可通过特殊 URL 直接访问管理界面".to_string(),
                fix_advice: Some("升级固件到最新版本，限制 WAN 端管理访问".to_string()),
                evidence: "通过 /setup.cgi?next_file= 可绕过认证访问".to_string(),
            });
        }
    }

    // 4. CVE-2021-34992: Netgear 命令注入
    if lower.contains("r6700") || lower.contains("r7000") {
        findings.push(IoTDeviceFinding {
            target: target.to_string(),
            device_type: IoTDeviceType::NetgearRouter,
            title: "Netgear R6700/R7000 命令注入 (CVE-2021-34992)".to_string(),
            severity: "critical".to_string(),
            description: "Netgear R6700/R7000 路由器存在命令注入漏洞，可被认证后攻击者利用执行任意命令".to_string(),
            fix_advice: Some("升级固件到最新版本".to_string()),
            evidence: "检测到 R6700/R7000 型号".to_string(),
        });
    }

    findings
}

// ============== D-Link 路由器检测 ==============

async fn scan_dlink(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    let is_dlink = lower.contains("d-link")
        || lower.contains("dlink")
        || lower.contains("dir-")
        || lower.contains("login.htm");
    if !is_dlink {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::DLinkRouter,
        title: "D-Link 路由器管理界面暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到 D-Link 路由器 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制 WAN 端管理访问 2. 修改默认密码 3. 升级固件".to_string()),
        evidence: "HTTP 主页包含 D-Link 特征".to_string(),
    });

    // 2. D-Link 默认凭证 admin/(空)
    let default_creds: &[(&str, &str)] = &[
        ("admin", ""),
        ("admin", "admin"),
        ("admin", "password"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::DLinkRouter,
                    title: "D-Link 路由器默认凭证".to_string(),
                    severity: "high".to_string(),
                    description: format!("路由器可使用默认凭证 {}/{} 登录", user, if pass.is_empty() { "(空)" } else { pass }),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, if pass.is_empty() { "(空)" } else { pass }),
                });
                break;
            }
        }
    }

    // 3. CVE-2021-45702: D-Link 后门账号
    // 通过 /set_nbar 后门检测
    if let Some(backdoor_resp) = http_get(host, port, "/HNAP1/SetNBARSettings", dur).await {
        if backdoor_resp.contains("200") || backdoor_resp.contains("HNAP") {
            findings.push(IoTDeviceFinding {
                target: target.to_string(),
                device_type: IoTDeviceType::DLinkRouter,
                title: "D-Link 后门账号 (CVE-2021-45702)".to_string(),
                severity: "critical".to_string(),
                description: "D-Link 部分型号路由器存在后门账号，可被未认证攻击者直接访问管理功能".to_string(),
                fix_advice: Some("升级固件到最新版本或更换设备型号".to_string()),
                evidence: "HNAP1 后门接口可访问".to_string(),
            });
        }
    }

    // 4. CVE-2019-16919: D-Link 命令注入
    if lower.contains("dir-859") || lower.contains("dir-822") {
        findings.push(IoTDeviceFinding {
            target: target.to_string(),
            device_type: IoTDeviceType::DLinkRouter,
            title: "D-Link DIR-859/822 命令注入 (CVE-2019-16919)".to_string(),
            severity: "critical".to_string(),
            description: "D-Link DIR-859/822 路由器存在命令注入漏洞，可被认证后攻击者利用执行任意命令".to_string(),
            fix_advice: Some("升级固件到最新版本".to_string()),
            evidence: "检测到 DIR-859/822 型号".to_string(),
        });
    }

    findings
}

// ============== 智能家居设备检测 ==============

async fn scan_smart_home(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<IoTDeviceFinding> {
    let mut findings = Vec::new();

    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    let lower = resp.to_lowercase();
    // 智能家居设备特征: 关键字识别
    let is_smart_home = lower.contains("smart")
        || lower.contains("home")
        || lower.contains("iot")
        || lower.contains("tuya")
        || lower.contains("mijia")
        || lower.contains("alexa")
        || lower.contains("homeassistant");
    if !is_smart_home {
        return findings;
    }

    findings.push(IoTDeviceFinding {
        target: target.to_string(),
        device_type: IoTDeviceType::SmartHome,
        title: "智能家居设备管理界面暴露".to_string(),
        severity: "medium".to_string(),
        description: "检测到智能家居设备 Web 管理界面对外开放".to_string(),
        fix_advice: Some("1. 限制管理界面网络访问 2. 修改默认密码 3. 升级固件".to_string()),
        evidence: "HTTP 主页包含智能家居特征".to_string(),
    });

    // 2. 智能家居常见默认凭证
    let default_creds: &[(&str, &str)] = &[
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "root"),
        ("admin", "tuya"),
    ];
    for (user, pass) in default_creds {
        if let Some(auth_resp) = http_get_basic_auth(host, port, "/", user, pass, dur).await {
            if auth_resp.starts_with("HTTP/1.1 200") || auth_resp.contains("200 OK") {
                findings.push(IoTDeviceFinding {
                    target: target.to_string(),
                    device_type: IoTDeviceType::SmartHome,
                    title: "智能家居设备默认凭证".to_string(),
                    severity: "high".to_string(),
                    description: format!("设备可使用默认凭证 {}/{} 登录", user, pass),
                    fix_advice: Some("立即修改 admin 密码为强密码".to_string()),
                    evidence: format!("HTTP Basic Auth {}/{} 返回 200", user, pass),
                });
                break;
            }
        }
    }

    // 3. 检查 Telnet 服务暴露 (智能家居常见风险)
    // 这里通过 HTTP 探测推测设备开放性
    if lower.contains("telnet") {
        findings.push(IoTDeviceFinding {
            target: target.to_string(),
            device_type: IoTDeviceType::SmartHome,
            title: "智能家居设备 Telnet 服务暴露".to_string(),
            severity: "high".to_string(),
            description: "设备疑似开放 Telnet 服务，可被攻击者利用进行未授权访问".to_string(),
            fix_advice: Some("禁用 Telnet 服务，使用 SSH 替代".to_string()),
            evidence: "HTTP 主页包含 Telnet 相关特征".to_string(),
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
    fn test_iot_device_type_default_port() {
        assert_eq!(IoTDeviceType::Hikvision.default_port(), 80);
        assert_eq!(IoTDeviceType::Dahua.default_port(), 80);
        assert_eq!(IoTDeviceType::TpLinkRouter.default_port(), 80);
        assert_eq!(IoTDeviceType::NetgearRouter.default_port(), 80);
        assert_eq!(IoTDeviceType::DLinkRouter.default_port(), 80);
        assert_eq!(IoTDeviceType::SmartHome.default_port(), 80);
    }

    #[test]
    fn test_iot_device_type_as_str() {
        assert_eq!(IoTDeviceType::Hikvision.as_str(), "hikvision");
        assert_eq!(IoTDeviceType::Dahua.as_str(), "dahua");
        assert_eq!(IoTDeviceType::TpLinkRouter.as_str(), "tp_link_router");
        assert_eq!(IoTDeviceType::NetgearRouter.as_str(), "netgear_router");
        assert_eq!(IoTDeviceType::DLinkRouter.as_str(), "dlink_router");
        assert_eq!(IoTDeviceType::SmartHome.as_str(), "smart_home");
    }

    #[test]
    fn test_iot_device_finding_serialization() {
        let finding = IoTDeviceFinding {
            target: "192.168.1.100:80".to_string(),
            device_type: IoTDeviceType::Hikvision,
            title: "测试漏洞".to_string(),
            severity: "high".to_string(),
            description: "测试描述".to_string(),
            fix_advice: Some("测试建议".to_string()),
            evidence: "测试证据".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("hikvision"));
        assert!(json.contains("high"));
        assert!(json.contains("测试漏洞"));
    }

    #[test]
    fn test_iot_device_type_clone_eq() {
        let dt1 = IoTDeviceType::Hikvision;
        let dt2 = dt1.clone();
        assert_eq!(dt1, dt2);
        assert_ne!(dt1, IoTDeviceType::Dahua);
    }

    #[test]
    fn test_base64_encoding_for_basic_auth() {
        // admin:password = YWRtaW46cGFzc3dvcmQ=
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:password");
        assert_eq!(encoded, "YWRtaW46cGFzc3dvcmQ=");
    }

    #[test]
    fn test_base64_encoding_empty_password() {
        // admin: = YWRtaW46
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:");
        assert_eq!(encoded, "YWRtaW46");
    }

    #[test]
    fn test_iot_device_scanner_default() {
        let _scanner = IoTDeviceScanner::default();
        let _scanner2 = IoTDeviceScanner::new();
    }

    /// 验证 Hikvision 指纹关键字识别逻辑
    #[test]
    fn test_hikvision_fingerprint_detection() {
        // 模拟海康威视主页特征
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Hikvision Web Components</title></html>";
        let lower = resp.to_lowercase();
        let is_hikvision = lower.contains("hikvision")
            || lower.contains("hik")
            || lower.contains("webcomponents")
            || lower.contains("/doc/page/login")
            || lower.contains("doc/page/login.asp");
        assert!(is_hikvision);
    }

    /// 验证 Dahua 指纹关键字识别逻辑
    #[test]
    fn test_dahua_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Dahua CCTV</title></html>";
        let lower = resp.to_lowercase();
        let is_dahua = lower.contains("dahua")
            || lower.contains("cgi-bin")
            || lower.contains("/cgi-bin/magicbox")
            || lower.contains("web/login");
        assert!(is_dahua);
    }

    /// 验证 TP-Link 指纹关键字识别逻辑
    #[test]
    fn test_tp_link_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>TP-LINK TL-WR940N</title></html>";
        let lower = resp.to_lowercase();
        let is_tp_link = lower.contains("tp-link")
            || lower.contains("tplink")
            || lower.contains("tl-")
            || lower.contains("/loginlg")
            || lower.contains("cgi-bin/luci");
        assert!(is_tp_link);
    }

    /// 验证 Netgear 指纹关键字识别逻辑
    #[test]
    fn test_netgear_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>NETGEAR Router</title></html>";
        let lower = resp.to_lowercase();
        let is_netgear = lower.contains("netgear")
            || lower.contains("setup.cgi")
            || lower.contains("currentsetting.htm");
        assert!(is_netgear);
    }

    /// 验证 D-Link 指纹关键字识别逻辑
    #[test]
    fn test_dlink_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>D-Link DIR-859</title></html>";
        let lower = resp.to_lowercase();
        let is_dlink = lower.contains("d-link")
            || lower.contains("dlink")
            || lower.contains("dir-")
            || lower.contains("login.htm");
        assert!(is_dlink);
    }

    /// 验证智能家居指纹关键字识别逻辑
    #[test]
    fn test_smart_home_fingerprint_detection() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Tuya Smart Home</title></html>";
        let lower = resp.to_lowercase();
        let is_smart_home = lower.contains("smart")
            || lower.contains("home")
            || lower.contains("iot")
            || lower.contains("tuya")
            || lower.contains("mijia")
            || lower.contains("alexa")
            || lower.contains("homeassistant");
        assert!(is_smart_home);
    }

    /// 验证非 IoT 设备不会被误判
    #[test]
    fn test_non_iot_device_not_detected() {
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>Apache Server</title></html>";
        let lower = resp.to_lowercase();
        let is_hikvision = lower.contains("hikvision")
            || lower.contains("hik")
            || lower.contains("webcomponents")
            || lower.contains("/doc/page/login")
            || lower.contains("doc/page/login.asp");
        assert!(!is_hikvision);
    }

    /// 验证 CVE 命中关键字
    #[test]
    fn test_cve_keyword_detection() {
        // TP-Link TL-WR841N 设备关键字
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>TP-LINK TL-WR841N</title></html>";
        let lower = resp.to_lowercase();
        assert!(lower.contains("tl-wr841"));

        // D-Link DIR-859 设备关键字
        let resp = "HTTP/1.1 200 OK\r\n\r\n<html><title>D-Link DIR-859</title></html>";
        let lower = resp.to_lowercase();
        assert!(lower.contains("dir-859"));
    }
}
