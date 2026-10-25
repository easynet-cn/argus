//! 工控无损扫描策略
//!
//! 在指纹匹配后只执行只读探测，不修改设备状态:
//! - Modbus: 只读取保持寄存器/输入寄存器 (FC 3/4)，不写 (FC 5/6/15/16)
//! - S7: 只读取 SZL 系统状态，不写变量
//! - IEC 104: 只读 (_periodic_gen + 总召唤)，不发送控制命令
//! - Ethernet/IP: 只读 CIP 属性，不发送控制指令

use crate::types::*;
use crate::fingerprint::IcsFingerprintScanner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// 无损扫描结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NonIntrusiveScanResult {
    pub host: String,
    pub devices: Vec<IcsDevice>,
    pub findings: Vec<NonIntrusiveFinding>,
    pub warnings: Vec<String>,
}

impl NonIntrusiveScanResult {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            devices: vec![],
            findings: vec![],
            warnings: vec![],
        }
    }
}

/// 无损扫描发现
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NonIntrusiveFinding {
    pub target: String,
    pub protocol: String,
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
}

/// 工控无损扫描器
pub struct NonIntrusiveScanner {
    /// 是否允许写入操作（默认 false = 只读）
    allow_write: bool,
    /// 扫描超时
    timeout_ms: u64,
}

impl NonIntrusiveScanner {
    pub fn new() -> Self {
        Self {
            allow_write: false,
            timeout_ms: 3000,
        }
    }

    /// 设置超时
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// 启用写入模式（危险！仅用于授权测试）
    pub fn enable_write(mut self) -> Self {
        self.allow_write = true;
        self
    }

    /// 扫描单个主机
    pub async fn scan_host(&self, host: &str) -> NonIntrusiveScanResult {
        let mut result = NonIntrusiveScanResult::new(host);

        // 1. 指纹识别
        let fp_scanner = IcsFingerprintScanner::new();
        let devices = fp_scanner.scan_host(host, self.timeout_ms).await;
        result.devices = devices.clone();

        if devices.is_empty() {
            result.warnings.push("未发现工控设备".to_string());
            return result;
        }

        // 2. 对每个设备执行只读探测
        for device in &devices {
            let mut findings = Vec::new();

            match device.protocol {
                IcsProtocol::ModbusTcp => {
                    findings.extend(self.scan_modbus_readonly(device).await);
                }
                IcsProtocol::S7Comm => {
                    findings.extend(self.scan_s7_readonly(device).await);
                }
                IcsProtocol::Iec104 => {
                    findings.extend(self.scan_iec104_readonly(device).await);
                }
                IcsProtocol::ProfinetDcp => {
                    // PROFINET DCP 是以太网层协议，非侵入式扫描无需额外探测
                    // 设备发现已在 IcsScanner 中完成
                }
                IcsProtocol::Melsec => {
                    // G6.3: Mitsubishi MELSEC 已在 read_device_info 中完成只读探测
                }
                IcsProtocol::Fins => {
                    // G6.4: Omron FINS 已在 read_controller_info 中完成只读探测
                }
                IcsProtocol::HartIp => {
                    // G6.5: Emerson HART-IP 已在 read_hart_device_info 中完成只读探测
                }
                IcsProtocol::FieldbusHse => {
                    // G6.5: FF HSE 已在 read_ff_hse_device_info 中完成只读探测
                }
            }

            // 设备暴露 = 信息级别发现
            findings.push(NonIntrusiveFinding {
                target: format!("{}:{}", device.host, device.port),
                protocol: device.protocol.as_str().to_string(),
                finding_type: "device_exposure".to_string(),
                severity: "info".to_string(),
                description: format!("工控设备暴露: {} ({})", device.protocol.as_str(), device.device_type.as_deref().unwrap_or("未知")),
                evidence: format!("端口 {} 开放", device.port),
            });

            // 如果设备有 vendor 信息，也作为发现
            if let Some(vendor) = &device.vendor {
                findings.push(NonIntrusiveFinding {
                    target: format!("{}:{}", device.host, device.port),
                    protocol: device.protocol.as_str().to_string(),
                    finding_type: "vendor_identified".to_string(),
                    severity: "info".to_string(),
                    description: format!("设备厂商: {}", vendor),
                    evidence: format!("Modbus 设备标识: vendor={}", vendor),
                });
            }

            result.findings.extend(findings);
        }

        // 3. 安全告警
        if self.allow_write {
            result.warnings.push("⚠ 写入模式已启用，扫描可能修改设备状态".to_string());
        }

        result
    }

    /// Modbus 只读扫描
    async fn scan_modbus_readonly(&self, device: &IcsDevice) -> Vec<NonIntrusiveFinding> {
        let mut findings = Vec::new();
        let dur = Duration::from_millis(self.timeout_ms);

        // 只读: FC 03 (Read Holding Registers) - 读取前 10 个寄存器
        if let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect((device.host.as_str(), device.port))).await {
            let req = [
                0x00, 0x02, // Transaction ID
                0x00, 0x00, // Protocol ID
                0x00, 0x06, // Length
                0x01,       // Unit ID
                0x03,       // FC 03 (Read Holding Registers)
                0x00, 0x00, // Starting Address: 0
                0x00, 0x0A, // Quantity: 10
            ];

            if stream.write_all(&req).await.is_ok() {
                let mut buf = vec![0u8; 4096];
                if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                    if n > 9 {
                        let byte_count = buf.get(8).copied().unwrap_or(0) as usize;
                        findings.push(NonIntrusiveFinding {
                            target: format!("{}:{}", device.host, device.port),
                            protocol: "modbus".to_string(),
                            finding_type: "register_read".to_string(),
                            severity: "info".to_string(),
                            description: format!("读取到 {} 字节保持寄存器数据", byte_count),
                            evidence: format!("FC03 响应: {} bytes", n),
                        });

                        // 检查是否无认证（任何人都可读）
                        findings.push(NonIntrusiveFinding {
                            target: format!("{}:{}", device.host, device.port),
                            protocol: "modbus".to_string(),
                            finding_type: "no_auth".to_string(),
                            severity: "high".to_string(),
                            description: "Modbus TCP 无认证，可直接读取寄存器".to_string(),
                            evidence: "FC03 读取成功，无认证要求".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    /// S7 只读扫描（R6.3 修复：真实发送 SZL 请求）
    ///
    /// 发送 S7Comm SZL 读取请求（通过 TPKT + COTP + S7 协议栈），
    /// 如果成功读取到系统状态列表，说明设备无认证保护。
    async fn scan_s7_readonly(&self, device: &IcsDevice) -> Vec<NonIntrusiveFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", device.host, device.port);
        let dur = Duration::from_millis(self.timeout_ms);

        let mut stream = match timeout(dur, TcpStream::connect((device.host.as_str(), device.port))).await {
            Ok(Ok(s)) => s,
            _ => return findings,
        };

        // S7Comm SZL 请求 (TPKT + COTP DT + S7 Read SZL)
        // 读取 SZL 0x0011 (模块标识) — 与指纹识别相同的请求
        let s7_request = [
            0x03, 0x00, 0x00, 0x1F, // TPKT: version=3, reserved=0, length=31
            0x02, 0xF0, 0x80,       // COTP: DT, EOT
            0x32,                   // S7 header: protocol 0x32
            0x01, 0x00, 0x00, 0x08, // request, req_id=0, para_len=8
            0x00, 0x00, 0x08, 0x00, // data_len=0, function=8 (read_SZL)
            0x00, 0x12, 0x04, 0x11, // item header, variable spec
            0x00, 0x01,             // transport size: byte
            0x00, 0x0A,             // read length: 10
            0x00, 0x01, 0x11, 0x00, // szl_id=0x0011 (module identification)
            0xFF, 0x09,             // szl index=0xFF09
        ];

        if stream.write_all(&s7_request).await.is_err() {
            return findings;
        }

        let mut buf = vec![0u8; 4096];
        let n = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 4 => n,
            _ => return findings,
        };

        // 检查 TPKT 响应
        if buf[0] != 0x03 {
            return findings;
        }

        // 解析 S7 响应中的数据
        // S7 响应头从 TPKT(4) + COTP(3+) 之后开始
        let s7_offset = 7; // TPKT(4) + COTP DT(3)
        if n > s7_offset + 18 {
            // S7 响应: protocol(1) + header(10) + parameter + data
            let s7_func = buf[s7_offset + 5];
            let s7_error = u16::from_be_bytes([buf[s7_offset + 10], buf[s7_offset + 11]]);

            if s7_func == 0x08 && s7_error == 0 {
                // SZL 读取成功 → 无认证
                let resp_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                findings.push(NonIntrusiveFinding {
                    target: target.clone(),
                    protocol: "s7".to_string(),
                    finding_type: "no_auth".to_string(),
                    severity: "high".to_string(),
                    description: "S7Comm 无认证，可直接读取系统状态".to_string(),
                    evidence: format!(
                        "SZL 读取成功 (响应 {} 字节, TPKT len={}, S7 func=0x{:02X})",
                        n, resp_len, s7_func
                    ),
                });

                // 尝试提取设备信息作为 evidence
                let raw = String::from_utf8_lossy(&buf[s7_offset..n]);
                let device_info: String = raw
                    .split_whitespace()
                    .filter(|s| s.len() > 3 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" ");
                if !device_info.is_empty() {
                    findings.push(NonIntrusiveFinding {
                        target: target.clone(),
                        protocol: "s7".to_string(),
                        finding_type: "device_info_leak".to_string(),
                        severity: "medium".to_string(),
                        description: format!("S7 SZL 泄露设备信息: {}", device_info),
                        evidence: format!("SZL 0011 响应包含: {}", device_info),
                    });
                }
            } else if s7_error != 0 {
                // SZL 读取返回错误 → 可能需要认证
                findings.push(NonIntrusiveFinding {
                    target: target.clone(),
                    protocol: "s7".to_string(),
                    finding_type: "auth_required".to_string(),
                    severity: "info".to_string(),
                    description: "S7Comm 需要认证才能读取系统状态".to_string(),
                    evidence: format!("SZL 读取返回错误码: 0x{:04X}", s7_error),
                });
            }
        }

        findings
    }

    /// IEC 104 只读扫描（R6.3 修复：真实发送 STARTDT + 总召唤）
    ///
    /// 1. 发送 STARTDT act 激活数据传输
    /// 2. 发送总召唤请求 (C_IC_NA_1, Type=100)
    /// 3. 检查是否有遥测/遥信数据响应
    async fn scan_iec104_readonly(&self, device: &IcsDevice) -> Vec<NonIntrusiveFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", device.host, device.port);
        let dur = Duration::from_millis(self.timeout_ms);

        let mut stream = match timeout(dur, TcpStream::connect((device.host.as_str(), device.port))).await {
            Ok(Ok(s)) => s,
            _ => return findings,
        };

        // 1. STARTDT act (Type=0x07)
        let startdt = [
            0x68, 0x04, // Start byte + length
            0x07, 0x00, 0x00, 0x00, // Type=0x07 (STARTDT act)
        ];
        if stream.write_all(&startdt).await.is_err() {
            return findings;
        }

        let mut buf = vec![0u8; 4096];
        let n = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n >= 6 => n,
            _ => return findings,
        };

        // 检查 STARTDT con 响应 (Type=0x0B)
        let mut startdt_confirmed = false;
        if buf[2] == 0x0B {
            startdt_confirmed = true;
        }

        if !startdt_confirmed {
            return findings;
        }

        // 2. 总召唤请求 (C_IC_NA_1, Type=100)
        // IEC 104 APDU: Start(1) + APDU Length(1) + Type(1) + SQ(1) + COT(2) + OA(2) + CA(2) + IOA(3) + Value
        let interrogate = [
            0x68, 0x0E, // Start + length=14
            0x64,       // Type=100 (C_IC_NA_1 - Interrogation Command)
            0x01,       // SQ=1 (single), Num=1
            0x06, 0x00, // COT=6 (activation)
            0x00, 0x00, // Originator Address=0
            0x01, 0x00, // Common Address=1
            0x00, 0x00, 0x00, // IOA=0
            0x14,       // Value: 20 (general interrogation)
            0x00,       // QOI padding
        ];
        if stream.write_all(&interrogate).await.is_err() {
            // 即使总召唤失败，STARTDT 成功也说明无认证
            findings.push(NonIntrusiveFinding {
                target: target.clone(),
                protocol: "iec104".to_string(),
                finding_type: "no_auth".to_string(),
                severity: "high".to_string(),
                description: "IEC 104 无认证，STARTDT 激活成功".to_string(),
                evidence: format!("STARTDT con 确认 (Type=0x0B), 响应 {} 字节", n),
            });
            return findings;
        }

        // 3. 读取总召唤响应
        let n2 = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                // 总召唤无响应，但 STARTDT 成功
                findings.push(NonIntrusiveFinding {
                    target: target.clone(),
                    protocol: "iec104".to_string(),
                    finding_type: "no_auth".to_string(),
                    severity: "high".to_string(),
                    description: "IEC 104 无认证，STARTDT 激活成功但总召唤无响应".to_string(),
                    evidence: "STARTDT con 确认, 总召唤超时".to_string(),
                });
                return findings;
            }
        };

        // 分析响应：检查是否有数据帧
        let mut data_count = 0;
        let mut offset = 0;
        while offset + 2 < n2 {
            let apdu_len = buf[offset + 1] as usize;
            if offset + 2 + apdu_len > n2 || apdu_len == 0 {
                break;
            }
            let type_id = buf[offset + 2];
            // Type 1-40 是遥测/遥信数据类型
            if (1..=40).contains(&type_id) {
                data_count += 1;
            }
            // Type 70 = 1 号总召唤结束
            if type_id == 70 {
                break;
            }
            offset += 2 + apdu_len;
        }

        findings.push(NonIntrusiveFinding {
            target: target.clone(),
            protocol: "iec104".to_string(),
            finding_type: "no_auth".to_string(),
            severity: "high".to_string(),
            description: if data_count > 0 {
                "IEC 104 无认证，可直接读取遥测/遥信数据".to_string()
            } else {
                "IEC 104 无认证，STARTDT+总召唤响应成功".to_string()
            },
            evidence: format!(
                "STARTDT con 确认, 总召唤响应 {} 字节, {} 个数据帧",
                n2, data_count
            ),
        });

        findings
    }
}

impl Default for NonIntrusiveScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_intrusive_scanner_default() {
        let scanner = NonIntrusiveScanner::new();
        assert!(!scanner.allow_write);
        assert_eq!(scanner.timeout_ms, 3000);
    }

    #[test]
    fn test_with_timeout() {
        let scanner = NonIntrusiveScanner::new().with_timeout(5000);
        assert_eq!(scanner.timeout_ms, 5000);
    }

    #[test]
    fn test_enable_write() {
        let scanner = NonIntrusiveScanner::new().enable_write();
        assert!(scanner.allow_write);
    }

    #[test]
    fn test_non_intrusive_result_new() {
        let result = NonIntrusiveScanResult::new("127.0.0.1");
        assert_eq!(result.host, "127.0.0.1");
        assert!(result.devices.is_empty());
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn test_scan_host_unreachable() {
        let scanner = NonIntrusiveScanner::new().with_timeout(500);
        let result = scanner.scan_host("127.0.0.1").await;
        // 不应该 panic
        assert!(!result.warnings.is_empty() || !result.findings.is_empty());
    }
}
