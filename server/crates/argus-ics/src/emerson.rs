//! Emerson 工业协议设备指纹 (HART / FOUNDATION Fieldbus)
//!
//! G6.5: 实现艾默生系工业协议的设备探测与信息读取
//!
//! 覆盖协议:
//! - HART-IP (Highway Addressable Remote Transducer over IP):
//!   基于 UDP 5094 端口, 发送 HART Command 0 (Read Unique Identifier) 探测响应
//! - FOUNDATION Fieldbus HSE (High Speed Ethernet):
//!   基于 TCP 的 FF HSE 探测 (端口 1089) 以及 Web 接口 banner 识别 (端口 80)
//!
//! HART-IP 帧结构 (8 字节头 + HART 报文):
//! - Version (1 byte): 0x01
//! - Message Type (1 byte): 0x00 = PDU
//! - Message ID (1 byte)
//! - Status (1 byte)
//! - Sequence Number (1 byte)
//! - Reserved (1 byte)
//! - Data Length (2 bytes, BE)
//! - HART Payload (变长):
//!   - Delimiter (1 byte): 0x02 = 短帧主站请求, 0x01 = 短帧从站响应
//!   - Address (1 byte, 短帧) / 5 bytes (长帧)
//!   - Command (1 byte): 0x00 = Read Unique Identifier
//!   - Byte Count (1 byte)
//!   - Data (变长)
//!   - Checksum (1 byte): 从 Delimiter 到最后一个 Data 字节的 XOR
//!
//! Command 0 响应数据 (12 bytes):
//! - Device Vendor Code (1)
//! - Device Type Code (1)
//! - Required Preambles (1)
//! - Universal Command Revision (1)
//! - Device Revision (1)
//! - Software Revision (1)
//! - Hardware Revision (1)
//! - Device Flags (1)
//! - Device ID (3 bytes)
//!
//! 安全扫描内容:
//! - 检测 HART-IP 网关/设备 (UDP 5094)
//! - 检测 FF HSE 设备 (TCP 1089 / Web 端口)
//! - 读取设备厂商、型号、固件版本信息

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ==================== 协议常量 ====================

/// HART-IP 默认 UDP 端口
pub const HART_IP_DEFAULT_PORT: u16 = 5094;

/// FOUNDATION Fieldbus HSE 默认 TCP 端口
pub const FF_HSE_DEFAULT_PORT: u16 = 1089;

/// FF HSE Web 管理界面端口
pub const FF_HSE_WEB_PORT: u16 = 80;

// ---------- HART-IP 常量 ----------

/// HART-IP 协议版本
const HART_IP_VERSION: u8 = 0x01;

/// HART-IP 消息类型: PDU (携带 HART 协议报文)
const HART_IP_MSG_TYPE_PDU: u8 = 0x00;

/// HART-IP 消息类型: Keep-Alive
#[allow(dead_code)]
const HART_IP_MSG_TYPE_KEEPALIVE: u8 = 0x01;

/// HART-IP 消息 ID: 通用 HART 命令
const HART_IP_MSG_ID_GENERIC: u8 = 0x00;

/// HART-IP 头部长度 (8 bytes)
const HART_IP_HEADER_LEN: usize = 8;

/// HART 命令 0: Read Unique Identifier
const HART_CMD_READ_UID: u8 = 0x00;

/// HART 短帧主站请求 Delimiter
const HART_DELIM_SHORT_MASTER: u8 = 0x02;

/// HART 短帧从站响应 Delimiter
const HART_DELIM_SHORT_SLAVE: u8 = 0x01;

/// HART 长帧主站请求 Delimiter
#[allow(dead_code)]
const HART_DELIM_LONG_MASTER: u8 = 0x82;

/// HART 长帧从站响应 Delimiter
const HART_DELIM_LONG_SLAVE: u8 = 0x81;

/// HART 默认主站短地址 (polling address 0)
const HART_DEFAULT_MASTER_ADDR: u8 = 0x80;

/// HART Command 0 响应数据长度 (11 bytes)
/// 1 Vendor + 1 DeviceType + 1 Preambles + 1 UniversalRev +
/// 1 DeviceRev + 1 SoftwareRev + 1 HardwareRev + 1 Flags + 3 DeviceID
const HART_CMD0_RESP_DATA_LEN: usize = 11;

// ---------- FF HSE 常量 ----------

/// FF HSE 协议标识 (用于 banner 匹配)
const FF_HSE_BANNER_KEYWORDS: &[&str] = &[
    "fieldbus",
    "foundation fieldbus",
    "ff-hse",
    "ffhse",
    "hse",
    "emerson",
    "delta-v",
    "deltav",
];

// ==================== HART-IP 帧构造 ====================

/// 构造 HART-IP 帧头 (8 bytes)
///
/// 字段:
/// - Version (1)
/// - Message Type (1)
/// - Message ID (1)
/// - Status (1)
/// - Sequence Number (1)
/// - Reserved (1)
/// - Data Length (2, BE)
pub fn build_hart_ip_header(
    msg_type: u8,
    msg_id: u8,
    status: u8,
    sequence: u8,
    data_length: u16,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HART_IP_HEADER_LEN);
    header.push(HART_IP_VERSION);
    header.push(msg_type);
    header.push(msg_id);
    header.push(status);
    header.push(sequence);
    header.push(0x00); // reserved
    header.extend_from_slice(&data_length.to_be_bytes());
    header
}

/// 计算 HART 校验和 (XOR)
///
/// 从 Delimiter 开始, 到最后一个 Data 字节, 对所有字节做异或
pub fn hart_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// 构造 HART 短帧报文
///
/// 结构: Delimiter(1) + Address(1) + Command(1) + ByteCount(1) + Data(n) + Checksum(1)
pub fn build_hart_short_frame(
    delimiter: u8,
    address: u8,
    command: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.push(delimiter);
    frame.push(address);
    frame.push(command);
    frame.push(data.len() as u8); // byte count
    frame.extend_from_slice(data);
    let checksum = hart_checksum(&frame);
    frame.push(checksum);
    frame
}

/// 构造 HART Command 0 请求 (Read Unique Identifier)
///
/// 使用短帧格式, 无数据 (byte count = 0)
pub fn build_hart_cmd0_request() -> Vec<u8> {
    let hart_msg = build_hart_short_frame(
        HART_DELIM_SHORT_MASTER,
        HART_DEFAULT_MASTER_ADDR,
        HART_CMD_READ_UID,
        &[],
    );
    let data_length = hart_msg.len() as u16;
    let mut frame = build_hart_ip_header(
        HART_IP_MSG_TYPE_PDU,
        HART_IP_MSG_ID_GENERIC,
        0x00,
        0x00,
        data_length,
    );
    frame.extend_from_slice(&hart_msg);
    frame
}

// ==================== HART-IP 响应解析 ====================

/// HART Command 0 响应数据
#[derive(Debug, Clone, PartialEq)]
pub struct HartCmd0Response {
    pub vendor_code: u8,
    pub device_type: u8,
    pub required_preambles: u8,
    pub universal_revision: u8,
    pub device_revision: u8,
    pub software_revision: u8,
    pub hardware_revision: u8,
    pub device_flags: u8,
    pub device_id: [u8; 3],
}

impl HartCmd0Response {
    /// 将设备 ID 转换为十六进制字符串
    pub fn device_id_hex(&self) -> String {
        format!(
            "{:02X}{:02X}{:02X}",
            self.device_id[0], self.device_id[1], self.device_id[2]
        )
    }
}

/// 解析 HART-IP 响应帧头
///
/// 返回 (msg_type, msg_id, status, sequence, data_length, data_offset)
pub fn parse_hart_ip_header(response: &[u8]) -> Result<(u8, u8, u8, u8, u16, usize), String> {
    if response.len() < HART_IP_HEADER_LEN {
        return Err(format!(
            "HART-IP 响应过短: {} (期望 >= {})",
            response.len(),
            HART_IP_HEADER_LEN
        ));
    }
    let version = response[0];
    if version != HART_IP_VERSION {
        return Err(format!(
            "无效的 HART-IP 版本: 0x{:02X} (期望 0x{:02X})",
            version, HART_IP_VERSION
        ));
    }
    let msg_type = response[1];
    let msg_id = response[2];
    let status = response[3];
    let sequence = response[4];
    let data_length = u16::from_be_bytes([response[6], response[7]]) as usize;
    Ok((
        msg_type,
        msg_id,
        status,
        sequence,
        data_length as u16,
        HART_IP_HEADER_LEN,
    ))
}

/// 从 HART-IP 响应中提取 HART 报文并校验 checksum
///
/// 返回 HART 报文切片 (含 delimiter 到 checksum)
pub fn extract_hart_message(response: &[u8]) -> Result<&[u8], String> {
    let (_, _, _, _, data_length, data_offset) = parse_hart_ip_header(response)?;
    let data_len = data_length as usize;
    if response.len() < data_offset + data_len {
        return Err(format!(
            "HART-IP 数据长度不匹配: 声明 {} bytes, 实际 {} bytes",
            data_len,
            response.len() - data_offset
        ));
    }
    let hart_msg = &response[data_offset..data_offset + data_len];
    // 最小 HART 报文: delimiter(1) + address(1) + command(1) + byte_count(1) + checksum(1) = 5
    if hart_msg.len() < 5 {
        return Err(format!("HART 报文过短: {} bytes", hart_msg.len()));
    }
    // 校验 checksum: XOR 所有字节 (含 checksum) 应为 0
    let calc_checksum = hart_checksum(hart_msg);
    if calc_checksum != 0 {
        return Err(format!(
            "HART 校验和错误: XOR=0x{:02X} (期望 0x00)",
            calc_checksum
        ));
    }
    Ok(hart_msg)
}

/// 解析 HART Command 0 响应数据
///
/// 输入: HART 报文数据区 (不含 delimiter/address/command/byte_count/checksum)
pub fn parse_hart_cmd0_response(data: &[u8]) -> Option<HartCmd0Response> {
    if data.len() < HART_CMD0_RESP_DATA_LEN {
        return None;
    }
    Some(HartCmd0Response {
        vendor_code: data[0],
        device_type: data[1],
        required_preambles: data[2],
        universal_revision: data[3],
        device_revision: data[4],
        software_revision: data[5],
        hardware_revision: data[6],
        device_flags: data[7],
        device_id: [data[8], data[9], data[10]],
    })
}

/// 从 HART 报文中解析 Command 0 响应
///
/// 输入: 完整 HART 报文 (delimiter ... checksum)
pub fn parse_hart_cmd0_from_message(hart_msg: &[u8]) -> Option<HartCmd0Response> {
    if hart_msg.len() < 5 {
        return None;
    }
    let delimiter = hart_msg[0];
    // 必须是从站响应
    if delimiter != HART_DELIM_SHORT_SLAVE && delimiter != HART_DELIM_LONG_SLAVE {
        return None;
    }
    let command = hart_msg[2];
    if command != HART_CMD_READ_UID {
        return None;
    }
    let byte_count = hart_msg[3] as usize;
    // 短帧: delimiter(1) + address(1) + command(1) + byte_count(1) + data + checksum(1)
    let data = &hart_msg[4..4 + byte_count];
    parse_hart_cmd0_response(data)
}

/// 根据 HART vendor code 映射厂商名称
pub fn hart_vendor_to_string(vendor_code: u8) -> String {
    match vendor_code {
        0x01 => "Rosemount".to_string(),
        0x02 => "Fisher Controls".to_string(),
        0x03 => "Micro Motion".to_string(),
        0x06 => "Honeywell".to_string(),
        0x0E => "Yokogawa".to_string(),
        0x10 => "Endress+Hauser".to_string(),
        0x1B => "Smar".to_string(),
        0x1E => "Flowserve".to_string(),
        0x27 => "ABB".to_string(),
        0x37 => "Siemens".to_string(),
        0x42 => "Schneider Electric".to_string(),
        0x82 => "Emerson Process Management".to_string(),
        _ => format!("Unknown HART Vendor (0x{:02X})", vendor_code),
    }
}

// ==================== HART-IP 网络请求 ====================

/// 通过 UDP 发送 HART-IP 请求并读取响应
async fn send_hart_ip_request(
    host: &str,
    port: u16,
    request: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);

    // 绑定本地 UDP socket (绑定到任意端口)
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("创建 UDP socket 失败: {e}"))?;

    // 连接到目标 (限定只接收来自目标的响应)
    socket
        .connect(&addr)
        .await
        .map_err(|e| format!("UDP 连接失败: {addr}: {e}"))?;

    socket
        .send(request)
        .await
        .map_err(|e| format!("UDP 发送失败: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| "HART-IP 响应超时".to_string())?
        .map_err(|e| format!("UDP 接收失败: {e}"))?;

    if n < HART_IP_HEADER_LEN {
        return Err(format!("HART-IP 响应过短: {n} bytes"));
    }

    buf.truncate(n);
    Ok(buf)
}

// ==================== HART-IP 公共接口 ====================

/// 探测 HART-IP 设备信息 (厂商、设备类型、固件版本、设备 ID)
///
/// 发送 HART Command 0 (Read Unique Identifier) 并解析响应
pub async fn read_hart_device_info(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::HartIp);
    device.vendor = Some("Emerson".to_string());
    device.device_type = Some("HART Field Instrument".to_string());

    let request = build_hart_cmd0_request();
    match send_hart_ip_request(host, port, &request, timeout_ms).await {
        Ok(response) => match extract_hart_message(&response) {
            Ok(hart_msg) => {
                if let Some(cmd0) = parse_hart_cmd0_from_message(hart_msg) {
                    device.vendor = Some(hart_vendor_to_string(cmd0.vendor_code));
                    device.model = Some(format!(
                        "DeviceType=0x{:02X}, HWRev={}",
                        cmd0.device_type, cmd0.hardware_revision
                    ));
                    device.firmware = Some(format!(
                        "SWRev={}, DevRev={}, UniversalRev={}",
                        cmd0.software_revision, cmd0.device_revision, cmd0.universal_revision
                    ));
                    device.raw_response = Some(serde_json::json!({
                        "vendor_code": format!("0x{:02X}", cmd0.vendor_code),
                        "device_type": format!("0x{:02X}", cmd0.device_type),
                        "device_id": cmd0.device_id_hex(),
                        "software_revision": cmd0.software_revision,
                        "hardware_revision": cmd0.hardware_revision,
                        "device_flags": format!("0x{:02X}", cmd0.device_flags),
                        "identified": true,
                    }));
                } else {
                    device.raw_response = Some(serde_json::json!({
                        "error": "无法解析 Command 0 响应",
                        "response_length": response.len(),
                        "identified_by_protocol": true,
                    }));
                }
            }
            Err(e) => {
                device.raw_response = Some(serde_json::json!({
                    "error": e,
                    "response_length": response.len(),
                    "identified_by_protocol": true,
                }));
            }
        },
        Err(e) => {
            device.raw_response = Some(serde_json::json!({
                "error": e,
                "identified_by_port": true,
            }));
        }
    }

    Ok(device)
}

/// 探测 HART-IP 端口是否可达 (UDP)
pub async fn probe_hart(host: &str, port: u16, timeout_ms: u64) -> bool {
    let request = build_hart_cmd0_request();
    // 发送一个探测包, 能收到任意响应即认为端口可达
    send_hart_ip_request(host, port, &request, timeout_ms)
        .await
        .is_ok()
}

// ==================== FOUNDATION Fieldbus HSE ====================

/// 构造 FF HSE 探测请求 (简单 HTTP GET / 用于获取 banner)
///
/// 许多 FF HSE 设备提供 Web 管理界面, 通过 HTTP banner 识别
pub fn build_ff_hse_http_probe(host: &str) -> Vec<u8> {
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Argus-ICS-Scanner\r\nConnection: close\r\n\r\n",
        host
    );
    request.into_bytes()
}

/// 通过 TCP 发送 FF HSE 探测并读取响应 banner
async fn send_ff_hse_probe(
    host: &str,
    port: u16,
    request: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("连接超时: {addr}"))?
        .map_err(|e| format!("连接失败: {addr}: {e}"))?;

    if !request.is_empty() {
        stream
            .write_all(request)
            .await
            .map_err(|e| format!("发送失败: {e}"))?;
    }

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "读取响应超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    buf.truncate(n);
    Ok(buf)
}

/// 从 HTTP banner 中提取 FF HSE / Emerson 相关信息
///
/// 返回 (vendor, model, firmware) 的可选值
pub fn parse_ff_hse_banner(banner: &str) -> (Option<String>, Option<String>, Option<String>) {
    let banner_lower = banner.to_lowercase();
    let mut vendor: Option<String> = None;
    let mut model: Option<String> = None;
    let mut firmware: Option<String> = None;

    // 厂商识别
    for keyword in FF_HSE_BANNER_KEYWORDS {
        if banner_lower.contains(keyword) {
            vendor = Some(match *keyword {
                "emerson" | "delta-v" | "deltav" => "Emerson".to_string(),
                "fieldbus" | "foundation fieldbus" | "ff-hse" | "ffhse" => {
                    "Fieldbus Foundation".to_string()
                }
                _ => "Emerson".to_string(),
            });
            break;
        }
    }

    // 尝试从 Server 头提取型号
    if let Some(server_line) = banner
        .lines()
        .find(|l| l.to_lowercase().starts_with("server:"))
    {
        let server_val = server_line
            .splitn(2, ':')
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string();
        if !server_val.is_empty() {
            model = Some(server_val.clone());
            // 尝试从 server 头提取版本号
            if let Some(ver) = extract_version(&server_val) {
                firmware = Some(ver);
            }
        }
    }

    // 尝试从 banner 文本中提取版本号
    if firmware.is_none() {
        if let Some(ver) = extract_version(banner) {
            firmware = Some(ver);
        }
    }

    (vendor, model, firmware)
}

/// 从文本中提取版本号 (如 v1.2.3, Version 2.5, 1.0.0)
fn extract_version(text: &str) -> Option<String> {
    // 匹配 "v" 或 "version" 后跟数字版本号
    let patterns = [
        r"[vV](\d+\.\d+\.\d+)",
        r"[vV](\d+\.\d+)",
        r"[Vv]ersion[:\s]+(\d+\.\d+\.\d+)",
        r"[Vv]ersion[:\s]+(\d+\.\d+)",
    ];
    for pat in patterns {
        // 简单实现: 不用 regex crate, 手动查找
        if let Some(found) = find_version_pattern(text, pat) {
            return Some(found);
        }
    }
    None
}

/// 简单的版本号模式匹配 (不依赖 regex crate)
fn find_version_pattern(text: &str, _pattern: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        // 查找 "v" 或 "V" 后跟数字
        if (bytes[i] == b'v' || bytes[i] == b'V')
            && i + 1 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
        {
            // 提取 vX.Y.Z 或 vX.Y
            let start = i + 1;
            let mut end = start;
            let mut dots = 0;
            while end < bytes.len()
                && (bytes[end].is_ascii_digit() || (bytes[end] == b'.' && dots < 2))
            {
                if bytes[end] == b'.' {
                    dots += 1;
                }
                end += 1;
            }
            if end > start && bytes[end - 1].is_ascii_digit() {
                return Some(String::from_utf8_lossy(&bytes[start..end]).to_string());
            }
        }
        // 查找 "Version" / "version" 后跟数字
        if i + 7 <= bytes.len() {
            let prefix = &text[i..i + 7].to_lowercase();
            if prefix == "version" {
                // 跳过 "version" 和可能的冒号/空格
                let mut j = i + 7;
                while j < bytes.len() && (bytes[j] == b':' || bytes[j] == b' ') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j].is_ascii_digit() {
                    let start = j;
                    let mut end = start;
                    let mut dots = 0;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_digit() || (bytes[end] == b'.' && dots < 2))
                    {
                        if bytes[end] == b'.' {
                            dots += 1;
                        }
                        end += 1;
                    }
                    if end > start && bytes[end - 1].is_ascii_digit() {
                        return Some(String::from_utf8_lossy(&bytes[start..end]).to_string());
                    }
                }
            }
        }
    }
    None
}

// ==================== FF HSE 公共接口 ====================

/// 读取 FF HSE 设备信息
///
/// 优先尝试 TCP 1089 端口探测, 然后尝试 Web 端口 (80) 获取 banner
pub async fn read_ff_hse_device_info(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::FieldbusHse);
    device.vendor = Some("Emerson".to_string());
    device.device_type = Some("FF HSE Device".to_string());

    // 尝试发送 HTTP 探测 (适用于 Web 管理界面端口)
    let request = build_ff_hse_http_probe(host);
    match send_ff_hse_probe(host, port, &request, timeout_ms).await {
        Ok(response) => {
            let banner = String::from_utf8_lossy(&response);
            let (vendor, model, firmware) = parse_ff_hse_banner(&banner);
            if let Some(ref v) = vendor {
                device.vendor = Some(v.clone());
            }
            if let Some(ref m) = model {
                device.model = Some(m.clone());
            }
            if let Some(ref f) = firmware {
                device.firmware = Some(f.clone());
            }
            // 截取 banner 前 256 字节作为证据
            let banner_preview: String = banner.chars().take(256).collect();
            device.raw_response = Some(serde_json::json!({
                "port": port,
                "response_length": response.len(),
                "banner_preview": banner_preview,
                "identified_by_banner": vendor.is_some(),
            }));
        }
        Err(e) => {
            // 端口开放但探测失败, 仍记录
            device.raw_response = Some(serde_json::json!({
                "error": e,
                "port": port,
                "identified_by_port": true,
            }));
        }
    }

    Ok(device)
}

/// 探测 FF HSE TCP 端口是否开放
pub async fn probe_ff_hse(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);
    tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- HART-IP 帧构造测试 ----------

    #[test]
    fn test_hart_ip_header_structure() {
        let header = build_hart_ip_header(
            HART_IP_MSG_TYPE_PDU,
            HART_IP_MSG_ID_GENERIC,
            0x00,
            0x00,
            5,
        );
        assert_eq!(header.len(), HART_IP_HEADER_LEN);
        // Version = 0x01
        assert_eq!(header[0], HART_IP_VERSION);
        // Message Type = 0x00 (PDU)
        assert_eq!(header[1], HART_IP_MSG_TYPE_PDU);
        // Message ID = 0x00
        assert_eq!(header[2], HART_IP_MSG_ID_GENERIC);
        // Status = 0x00
        assert_eq!(header[3], 0x00);
        // Sequence = 0x00
        assert_eq!(header[4], 0x00);
        // Reserved = 0x00
        assert_eq!(header[5], 0x00);
        // Data Length = 5 (BE)
        assert_eq!(header[6], 0x00);
        assert_eq!(header[7], 0x05);
    }

    #[test]
    fn test_hart_checksum() {
        // 单字节: checksum = 该字节
        assert_eq!(hart_checksum(&[0x42]), 0x42);
        // 空: 0
        assert_eq!(hart_checksum(&[]), 0);
        // 多字节异或
        assert_eq!(hart_checksum(&[0xFF, 0xFF]), 0x00);
        assert_eq!(hart_checksum(&[0x01, 0x02, 0x03]), 0x00); // 01^02=03, 03^03=00
    }

    #[test]
    fn test_hart_short_frame_structure() {
        let frame = build_hart_short_frame(
            HART_DELIM_SHORT_MASTER,
            HART_DEFAULT_MASTER_ADDR,
            HART_CMD_READ_UID,
            &[],
        );
        // delimiter(1) + address(1) + command(1) + byte_count(1) + checksum(1) = 5
        assert_eq!(frame.len(), 5);
        assert_eq!(frame[0], HART_DELIM_SHORT_MASTER);
        assert_eq!(frame[1], HART_DEFAULT_MASTER_ADDR);
        assert_eq!(frame[2], HART_CMD_READ_UID);
        assert_eq!(frame[3], 0x00); // byte count = 0
        // checksum = delimiter ^ address ^ command ^ byte_count
        let expected = HART_DELIM_SHORT_MASTER
            ^ HART_DEFAULT_MASTER_ADDR
            ^ HART_CMD_READ_UID
            ^ 0x00;
        assert_eq!(frame[4], expected);
    }

    #[test]
    fn test_hart_short_frame_with_data() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let frame = build_hart_short_frame(0x02, 0x80, 0x01, &data);
        // 5 + 3 = 8
        assert_eq!(frame.len(), 8);
        assert_eq!(frame[3], 0x03); // byte count = 3
        // 数据区
        assert_eq!(&frame[4..7], &[0xAA, 0xBB, 0xCC]);
        // 包含 checksum 的完整帧 XOR 应为 0
        let full_xor = hart_checksum(&frame);
        assert_eq!(full_xor, 0x00);
    }

    #[test]
    fn test_build_hart_cmd0_request() {
        let req = build_hart_cmd0_request();
        // HART-IP 头(8) + HART 报文(5) = 13
        assert_eq!(req.len(), 13);
        // 头字段
        assert_eq!(req[0], HART_IP_VERSION);
        assert_eq!(req[1], HART_IP_MSG_TYPE_PDU);
        // Data Length = 5 (BE)
        assert_eq!(u16::from_be_bytes([req[6], req[7]]), 5);
        // HART 报文: delimiter = 0x02
        assert_eq!(req[8], HART_DELIM_SHORT_MASTER);
        // command = 0x00
        assert_eq!(req[10], HART_CMD_READ_UID);
    }

    // ---------- HART-IP 响应解析测试 ----------

    #[test]
    fn test_parse_hart_ip_header_ok() {
        let response = build_hart_cmd0_request(); // 复用构造的帧
        let (msg_type, msg_id, status, seq, data_len, offset) =
            parse_hart_ip_header(&response).unwrap();
        assert_eq!(msg_type, HART_IP_MSG_TYPE_PDU);
        assert_eq!(msg_id, HART_IP_MSG_ID_GENERIC);
        assert_eq!(status, 0x00);
        assert_eq!(seq, 0x00);
        assert_eq!(data_len, 5);
        assert_eq!(offset, HART_IP_HEADER_LEN);
    }

    #[test]
    fn test_parse_hart_ip_header_short() {
        let response = vec![0x01, 0x00, 0x00];
        let result = parse_hart_ip_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hart_ip_header_invalid_version() {
        let mut response = build_hart_cmd0_request();
        response[0] = 0x99; // 无效版本
        let result = parse_hart_ip_header(&response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("无效的 HART-IP 版本"));
    }

    #[test]
    fn test_extract_hart_message_ok() {
        // 构造一个合法的 HART-IP 响应 (Command 0 响应)
        let response_data = [
            0x01, // vendor code
            0x02, // device type
            0x05, // required preambles
            0x07, // universal revision
            0x03, // device revision
            0x04, // software revision
            0x01, // hardware revision
            0x00, // device flags
            0xAA, 0xBB, 0xCC, // device id
        ];
        let hart_msg = build_hart_short_frame(
            HART_DELIM_SHORT_SLAVE,
            HART_DEFAULT_MASTER_ADDR,
            HART_CMD_READ_UID,
            &response_data,
        );
        let mut response = build_hart_ip_header(
            HART_IP_MSG_TYPE_PDU,
            HART_IP_MSG_ID_GENERIC,
            0x00,
            0x00,
            hart_msg.len() as u16,
        );
        response.extend_from_slice(&hart_msg);

        let extracted = extract_hart_message(&response).unwrap();
        assert_eq!(extracted.len(), hart_msg.len());
        // 完整帧 XOR 校验通过
        assert_eq!(hart_checksum(extracted), 0x00);
    }

    #[test]
    fn test_extract_hart_message_bad_checksum() {
        // 构造响应但破坏 checksum
        let response_data = [0x01u8; 12];
        let mut hart_msg = build_hart_short_frame(
            HART_DELIM_SHORT_SLAVE,
            0x80,
            HART_CMD_READ_UID,
            &response_data,
        );
        // 翻转 checksum
        let last_idx = hart_msg.len() - 1;
        hart_msg[last_idx] ^= 0xFF;

        let mut response = build_hart_ip_header(
            HART_IP_MSG_TYPE_PDU,
            0x00,
            0x00,
            0x00,
            hart_msg.len() as u16,
        );
        response.extend_from_slice(&hart_msg);

        let result = extract_hart_message(&response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("校验和错误"));
    }

    #[test]
    fn test_parse_hart_cmd0_response() {
        let data = [
            0x01, // vendor code
            0x0A, // device type
            0x05, // required preambles
            0x07, // universal revision
            0x03, // device revision
            0x04, // software revision
            0x01, // hardware revision
            0x80, // device flags
            0x12, 0x34, 0x56, // device id
        ];
        let cmd0 = parse_hart_cmd0_response(&data).unwrap();
        assert_eq!(cmd0.vendor_code, 0x01);
        assert_eq!(cmd0.device_type, 0x0A);
        assert_eq!(cmd0.required_preambles, 0x05);
        assert_eq!(cmd0.universal_revision, 0x07);
        assert_eq!(cmd0.device_revision, 0x03);
        assert_eq!(cmd0.software_revision, 0x04);
        assert_eq!(cmd0.hardware_revision, 0x01);
        assert_eq!(cmd0.device_flags, 0x80);
        assert_eq!(cmd0.device_id, [0x12, 0x34, 0x56]);
        assert_eq!(cmd0.device_id_hex(), "123456");
    }

    #[test]
    fn test_parse_hart_cmd0_response_short() {
        let data = [0x01u8; 10]; // 不足 12 字节
        let result = parse_hart_cmd0_response(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_hart_cmd0_from_message() {
        let response_data = [
            0x01, 0x02, 0x05, 0x07, 0x03, 0x04, 0x01, 0x00, 0xAA, 0xBB, 0xCC,
        ];
        let hart_msg = build_hart_short_frame(
            HART_DELIM_SHORT_SLAVE,
            0x80,
            HART_CMD_READ_UID,
            &response_data,
        );
        let cmd0 = parse_hart_cmd0_from_message(&hart_msg).unwrap();
        assert_eq!(cmd0.vendor_code, 0x01);
        assert_eq!(cmd0.device_id, [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_parse_hart_cmd0_from_message_wrong_delimiter() {
        // 使用主站请求 delimiter (非响应)
        let hart_msg = build_hart_short_frame(
            HART_DELIM_SHORT_MASTER,
            0x80,
            HART_CMD_READ_UID,
            &[0x00; 12],
        );
        let result = parse_hart_cmd0_from_message(&hart_msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_hart_cmd0_from_message_wrong_command() {
        let hart_msg = build_hart_short_frame(
            HART_DELIM_SHORT_SLAVE,
            0x80,
            0x01, // 非 Command 0
            &[0x00; 12],
        );
        let result = parse_hart_cmd0_from_message(&hart_msg);
        assert!(result.is_none());
    }

    #[test]
    fn test_hart_vendor_to_string() {
        assert_eq!(hart_vendor_to_string(0x01), "Rosemount");
        assert_eq!(hart_vendor_to_string(0x82), "Emerson Process Management");
        assert_eq!(hart_vendor_to_string(0x10), "Endress+Hauser");
        assert_eq!(hart_vendor_to_string(0xFF), "Unknown HART Vendor (0xFF)");
    }

    // ---------- FF HSE 测试 ----------

    #[test]
    fn test_build_ff_hse_http_probe() {
        let req = build_ff_hse_http_probe("192.168.1.100");
        let text = String::from_utf8_lossy(&req);
        assert!(text.starts_with("GET / HTTP/1.1"));
        assert!(text.contains("Host: 192.168.1.100"));
        assert!(text.contains("User-Agent: Argus-ICS-Scanner"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_parse_ff_hse_banner_emerson() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Emerson DeltaV HSE Gateway v2.5.1\r\nContent-Type: text/html\r\n\r\n";
        let (vendor, model, firmware) = parse_ff_hse_banner(banner);
        assert_eq!(vendor.as_deref(), Some("Emerson"));
        assert!(model.is_some());
        assert_eq!(firmware.as_deref(), Some("2.5.1"));
    }

    #[test]
    fn test_parse_ff_hse_banner_fieldbus() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Foundation Fieldbus HSE Device\r\n\r\n";
        let (vendor, _model, _firmware) = parse_ff_hse_banner(banner);
        assert_eq!(vendor.as_deref(), Some("Fieldbus Foundation"));
    }

    #[test]
    fn test_parse_ff_hse_banner_no_keyword() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n";
        let (vendor, model, _firmware) = parse_ff_hse_banner(banner);
        // 无 FF HSE 关键字, vendor 为 None
        assert!(vendor.is_none());
        // 但仍可能提取 model (Server 头)
        assert!(model.is_some());
    }

    #[test]
    fn test_extract_version_v_prefix() {
        assert_eq!(extract_version("Software v1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(extract_version("Firmware V2.5"), Some("2.5".to_string()));
    }

    #[test]
    fn test_extract_version_word() {
        assert_eq!(
            extract_version("Version: 3.0.1"),
            Some("3.0.1".to_string())
        );
        assert_eq!(
            extract_version("version 1.2"),
            Some("1.2".to_string())
        );
    }

    #[test]
    fn test_extract_version_none() {
        assert_eq!(extract_version("no version here"), None);
    }

    // ---------- 协议端口测试 ----------

    #[test]
    fn test_protocol_ports() {
        assert_eq!(IcsProtocol::HartIp.port(), HART_IP_DEFAULT_PORT);
        assert_eq!(IcsProtocol::HartIp.port(), 5094);
        assert_eq!(IcsProtocol::HartIp.as_str(), "hart-ip");

        assert_eq!(IcsProtocol::FieldbusHse.port(), FF_HSE_DEFAULT_PORT);
        assert_eq!(IcsProtocol::FieldbusHse.port(), 1089);
        assert_eq!(IcsProtocol::FieldbusHse.as_str(), "fieldbus-hse");
    }

    // ---------- HART-IP 端到端帧往返测试 ----------

    #[test]
    fn test_hart_cmd0_round_trip() {
        // 模拟设备对 Command 0 的响应
        let device_data = [
            0x82, // vendor: Emerson Process Management
            0x10, // device type
            0x05, // preambles
            0x07, // universal rev
            0x01, // device rev
            0x02, // software rev
            0x03, // hardware rev
            0x00, // flags
            0xDE, 0xAD, 0xBE, // device id
        ];
        let hart_resp = build_hart_short_frame(
            HART_DELIM_SHORT_SLAVE,
            0x80,
            HART_CMD_READ_UID,
            &device_data,
        );
        let mut ip_resp = build_hart_ip_header(
            HART_IP_MSG_TYPE_PDU,
            0x00,
            0x00,
            0x01,
            hart_resp.len() as u16,
        );
        ip_resp.extend_from_slice(&hart_resp);

        // 解析
        let extracted = extract_hart_message(&ip_resp).unwrap();
        let cmd0 = parse_hart_cmd0_from_message(extracted).unwrap();

        assert_eq!(cmd0.vendor_code, 0x82);
        assert_eq!(hart_vendor_to_string(cmd0.vendor_code), "Emerson Process Management");
        assert_eq!(cmd0.device_id_hex(), "DEADBE");
        assert_eq!(cmd0.software_revision, 0x02);
        assert_eq!(cmd0.hardware_revision, 0x03);
    }
}
