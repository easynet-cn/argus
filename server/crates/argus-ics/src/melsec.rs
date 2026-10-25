//! Mitsubishi MELSEC MC Protocol (端口 1281)
//!
//! G6.3: 实现 MC Protocol over TCP 的设备探测与信息读取
//!
//! MC Protocol (MELSEC Communication Protocol) 是三菱 PLC 使用的二进制协议。
//! 本模块基于 3E 帧格式实现:
//! - 子头 (1 byte): 0x50 (监视方向)
//! - 网络号 (1 byte): 0x00
//! - PC 号 (1 byte): 0xFF (本地站)
//! - 请求目标模块 I/O 号 (2 bytes, LE): 0x03FF (CPU 模块)
//! - 请求目标模块站号 (1 byte): 0x00
//! - 监视定时器 (2 bytes, LE): 0x0010 (1000ms)
//! - 命令 (2 bytes, LE)
//! - 子命令 (2 bytes, LE)
//! - 数据 (变长)
//!
//! 安全扫描内容:
//! - 检测 PLC (TCP 端口开放)
//! - 读 CPU 类型 (命令 0x0101) 获取型号
//! - 检查是否需要认证 (结束码判断)

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ==================== 协议常量 ====================

/// MELSEC MC Protocol 默认端口
pub const MELSEC_DEFAULT_PORT: u16 = 1281;

/// 3E 帧子头标识 (监视方向)
const MELSEC_SUBHEADER: u8 = 0x50;

/// 默认网络号
const DEFAULT_NETWORK_NUMBER: u8 = 0x00;

/// 默认 PC 号 (0xFF = 本地站)
const DEFAULT_PC_NUMBER: u8 = 0xFF;

/// 默认目标模块 I/O 号 (CPU 模块 = 0x03FF)
const DEFAULT_DEST_MODULE_IO: u16 = 0x03FF;

/// 默认目标模块站号
const DEFAULT_DEST_MODULE_STATION: u8 = 0x00;

/// 监视定时器 (1000ms = 0x0010)
const MONITORING_TIMER: u16 = 0x0010;

/// 命令: 读 CPU 类型 (PLC 型号)
const CMD_READ_CPU_TYPE: u16 = 0x0101;

/// 命令: 读设备批量 (随机)
pub const CMD_READ_DEVICE_BATCH: u16 = 0x0401;

/// 命令: 写设备批量 (随机)
pub const CMD_WRITE_DEVICE_BATCH: u16 = 0x1401;

/// 子命令: 0x0000 (标准二进制模式)
const SUBCMD_DEFAULT: u16 = 0x0000;

/// 成功结束码
const END_CODE_OK: u16 = 0x0000;

/// 结束码: 需要认证 (访问被拒绝)
const END_CODE_ACCESS_DENIED: u16 = 0xC000;

/// 结束码: 命令错误 (可能因权限不足)
const END_CODE_COMMAND_ERROR: u16 = 0xC001;

// ==================== 帧构造 ====================

/// 构造 3E 帧格式的请求
///
/// 3E 帧结构 (二进制格式):
/// - 子头 (1 byte): 0x50
/// - 网络号 (1 byte): 0x00
/// - PC 号 (1 byte): 0xFF
/// - 请求目标模块 I/O 号 (2 bytes, LE)
/// - 请求目标模块站号 (1 byte): 0x00
/// - 监视定时器 (2 bytes, LE)
/// - 命令 (2 bytes, LE)
/// - 子命令 (2 bytes, LE)
/// - 数据 (变长)
pub fn build_3e_frame(command: u16, subcommand: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + data.len());
    // 子头 + 路由信息
    frame.push(MELSEC_SUBHEADER);
    frame.push(DEFAULT_NETWORK_NUMBER);
    frame.push(DEFAULT_PC_NUMBER);
    // 目标模块 I/O 号 (LE)
    frame.extend_from_slice(&DEFAULT_DEST_MODULE_IO.to_le_bytes());
    // 目标模块站号
    frame.push(DEFAULT_DEST_MODULE_STATION);
    // 监视定时器 (LE)
    frame.extend_from_slice(&MONITORING_TIMER.to_le_bytes());
    // 命令 (LE)
    frame.extend_from_slice(&command.to_le_bytes());
    // 子命令 (LE)
    frame.extend_from_slice(&subcommand.to_le_bytes());
    // 数据
    frame.extend_from_slice(data);
    frame
}

/// 构造读设备批量请求 (命令 0x0401)
///
/// 请求参数:
/// - 设备代号 (3 bytes, ASCII 编码如 "D" + 编号)
/// - 设备编号 (3 bytes, ASCII 数字)
/// - 设备点数 (2 bytes, LE)
pub fn build_read_device_batch(
    device_code: &str,
    device_number: u32,
    count: u16,
) -> Result<Vec<u8>, String> {
    // 设备代号: 1 字母 + 2 数字 (ASCII)
    if device_code.is_empty() {
        return Err("设备代号不能为空".to_string());
    }
    let mut data = Vec::with_capacity(8);
    // 设备代号 (3 bytes ASCII): 如 "D*" 表示 D 寄存器
    let code_bytes = device_code.as_bytes();
    if code_bytes.len() == 1 {
        data.push(code_bytes[0]);
        data.push(b'*');
        data.push(b'*');
    } else if code_bytes.len() == 3 {
        data.extend_from_slice(code_bytes);
    } else {
        return Err("设备代号应为 1 字母或 3 ASCII 字符".to_string());
    }
    // 设备编号 (6 位 ASCII 数字, 前导补零)
    let num_str = format!("{:06}", device_number);
    data.extend_from_slice(num_str.as_bytes());
    // 设备点数 (2 bytes, LE)
    data.extend_from_slice(&count.to_le_bytes());
    // 构造完整帧
    Ok(build_3e_frame(CMD_READ_DEVICE_BATCH, SUBCMD_DEFAULT, &data))
}

// ==================== 请求发送 ====================

/// 发送 MELSEC 请求并读取响应
///
/// MELSEC 响应帧没有显式长度字段, 使用监视定时器超时来界定帧边界。
/// 响应最小长度: 子头(1) + 网络(1) + PC(1) + I/O(2) + 站号(1)
///              + 命令(2) + 子命令(2) + 结束码(2) = 12 bytes
async fn send_melsec_request(
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

    stream
        .write_all(request)
        .await
        .map_err(|e| format!("发送失败: {e}"))?;

    // 读取响应 (MELSEC 帧无显式长度, 使用一次性读取)
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "读取响应超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    if n < 12 {
        return Err(format!("响应数据过短: {n} bytes (期望 >= 12)"));
    }

    buf.truncate(n);
    Ok(buf)
}

// ==================== 响应解析 ====================

/// 解析 MELSEC 响应帧头部 (子头 + 路由信息 + 命令 + 子命令 + 结束码)
///
/// 返回 (end_code, data_offset):
/// - end_code: 结束码 (0x0000 = 成功)
/// - data_offset: 数据区在响应中的起始偏移
pub fn parse_response_header(response: &[u8]) -> Result<(u16, usize), String> {
    // 最小响应长度: 子头(1) + 网络(1) + PC(1) + I/O(2) + 站号(1) + 命令(2) + 子命令(2) + 结束码(2) = 12
    if response.len() < 12 {
        return Err(format!("响应数据过短: {}", response.len()));
    }
    // 检查子头
    if response[0] != MELSEC_SUBHEADER {
        return Err(format!("无效的子头: 0x{:02X} (期望 0x{:02X})", response[0], MELSEC_SUBHEADER));
    }
    // 结束码在偏移 10 处
    // 偏移: 0=子头 1=网络 2=PC 3-4=I/O 5=站号 6-7=命令 8-9=子命令 10-11=结束码
    let end_code = u16::from_le_bytes([response[10], response[11]]);
    Ok((end_code, 12))
}

/// 解析 CPU 类型响应数据 (命令 0x0101 的数据区)
///
/// 数据结构 (在结束码之后):
/// - PLC 类型代码 (2 bytes, LE): 区分 Q/L/FX/iQ-R/iQ-F 系列
/// - PLC 型号代码 (2 bytes, LE): 区分同系列内具体型号
/// - 保留区域 (变长, 通常 0xFF 填充)
pub fn parse_cpu_type_response(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 4 {
        return None;
    }
    let plc_type = u16::from_le_bytes([data[0], data[1]]);
    let plc_model = u16::from_le_bytes([data[2], data[3]]);
    Some((plc_type, plc_model))
}

/// 将 PLC 类型代码转换为型号字符串
///
/// 基于 MELSEC CPU 类型代码表
pub fn plc_type_to_string(plc_type: u16) -> String {
    match plc_type {
        // Q 系列
        0x0011 => "Q02/Q06H CPU".to_string(),
        0x0012 => "Q00UJCPU".to_string(),
        0x0021 => "Q02/Q06CPU".to_string(),
        0x0022 => "Q00UJCPU".to_string(),
        0x0031 => "Q02CH CPU".to_string(),
        0x0032 => "Q12PH CPU".to_string(),
        // L 系列
        0x0041 => "L02/L06CPU".to_string(),
        0x0042 => "L02CPU".to_string(),
        0x0043 => "L26CPU".to_string(),
        // FX 系列
        0x0081 => "FX3U/FX3UC CPU".to_string(),
        0x0082 => "FX3U CPU".to_string(),
        0x0084 => "FX3G CPU".to_string(),
        // iQ-R 系列
        0x0091 => "iQ-R Series CPU".to_string(),
        0x0092 => "iQ-R R08CPU".to_string(),
        0x0093 => "iQ-R R16CPU".to_string(),
        // iQ-F 系列
        0x00A1 => "iQ-F Series CPU".to_string(),
        0x00A2 => "iQ-F FX5U CPU".to_string(),
        _ => format!("Unknown MELSEC CPU (0x{:04X})", plc_type),
    }
}

/// 根据结束码判断是否需要认证
///
/// 返回 true 表示访问被拒绝 (可能需要认证)
pub fn is_auth_required(end_code: u16) -> bool {
    matches!(end_code, END_CODE_ACCESS_DENIED | END_CODE_COMMAND_ERROR)
}

// ==================== 公共接口 ====================

/// 读取 MELSEC 设备信息 (PLC 类型、型号)
///
/// 通过命令 0x0101 (读 CPU 类型) 获取设备型号, 并判断是否需要认证。
pub async fn read_device_info(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::Melsec);
    device.vendor = Some("Mitsubishi".to_string());
    device.device_type = Some("PLC".to_string());

    // 构造读 CPU 类型请求 (命令 0x0101, 子命令 0x0000, 无数据)
    let request = build_3e_frame(CMD_READ_CPU_TYPE, SUBCMD_DEFAULT, &[]);
    match send_melsec_request(host, port, &request, timeout_ms).await {
        Ok(response) => {
            match parse_response_header(&response) {
                Ok((end_code, data_offset)) => {
                    if end_code == END_CODE_OK {
                        // 成功: 提取 PLC 类型
                        let data = &response[data_offset..];
                        if let Some((plc_type, plc_model)) = parse_cpu_type_response(data) {
                            device.model = Some(plc_type_to_string(plc_type));
                            device.firmware = Some(format!("model_code=0x{:04X}", plc_model));
                        }
                        device.raw_response = Some(serde_json::json!({
                            "end_code": format!("0x{:04X}", end_code),
                            "response_length": response.len(),
                            "auth_required": false,
                            "identified": true,
                        }));
                    } else {
                        // 非零结束码: 可能需要认证或命令错误
                        device.raw_response = Some(serde_json::json!({
                            "end_code": format!("0x{:04X}", end_code),
                            "response_length": response.len(),
                            "auth_required": is_auth_required(end_code),
                        }));
                    }
                }
                Err(e) => {
                    // 响应头解析失败, 但端口开放, 可能是 MELSEC
                    device.raw_response = Some(serde_json::json!({
                        "error": e,
                        "response_length": response.len(),
                        "identified_by_port": true,
                    }));
                }
            }
        }
        Err(e) => {
            // 请求失败: 端口开放但协议不匹配, 或需要认证
            device.raw_response = Some(serde_json::json!({
                "error": e,
                "identified_by_port": true,
            }));
        }
    }

    Ok(device)
}

/// 探测 MELSEC 端口是否开放
pub async fn probe(host: &str, port: u16, timeout_ms: u64) -> bool {
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

    #[test]
    fn test_build_3e_frame_structure() {
        let frame = build_3e_frame(CMD_READ_CPU_TYPE, SUBCMD_DEFAULT, &[]);
        // 3E 帧头: 子头(1) + 网络(1) + PC(1) + I/O(2) + 站号(1) + 定时器(2) + 命令(2) + 子命令(2) = 12 bytes
        assert_eq!(frame.len(), 12);
        // 子头 = 0x50
        assert_eq!(frame[0], MELSEC_SUBHEADER);
        // 网络 = 0x00
        assert_eq!(frame[1], DEFAULT_NETWORK_NUMBER);
        // PC = 0xFF
        assert_eq!(frame[2], DEFAULT_PC_NUMBER);
        // I/O = 0x03FF (LE: FF 03)
        assert_eq!(frame[3], 0xFF);
        assert_eq!(frame[4], 0x03);
        // 站号 = 0x00
        assert_eq!(frame[5], DEFAULT_DEST_MODULE_STATION);
        // 监视定时器 = 0x0010 (LE: 10 00)
        assert_eq!(frame[6], 0x10);
        assert_eq!(frame[7], 0x00);
        // 命令 = 0x0101 (LE: 01 01)
        assert_eq!(frame[8], 0x01);
        assert_eq!(frame[9], 0x01);
        // 子命令 = 0x0000 (LE: 00 00)
        assert_eq!(frame[10], 0x00);
        assert_eq!(frame[11], 0x00);
    }

    #[test]
    fn test_build_3e_frame_with_data() {
        let data = vec![0xAB, 0xCD];
        let frame = build_3e_frame(CMD_READ_DEVICE_BATCH, SUBCMD_DEFAULT, &data);
        // 帧头(12) + 数据(2) = 14
        assert_eq!(frame.len(), 14);
        // 数据在末尾
        assert_eq!(&frame[12..], &data[..]);
    }

    #[test]
    fn test_build_read_device_batch_d_register() {
        let frame = build_read_device_batch("D", 100, 1).unwrap();
        // 12 (header) + 3 (device code "D**") + 6 (device number "000100") + 2 (count) = 23
        assert_eq!(frame.len(), 23);
        // 命令 = 0x0401 (LE: 01 04)
        assert_eq!(frame[8], 0x01);
        assert_eq!(frame[9], 0x04);
        // 设备代号 "D**" 从偏移 12 开始
        assert_eq!(&frame[12..15], b"D**");
        // 设备编号 "000100" 从偏移 15 开始
        assert_eq!(&frame[15..21], b"000100");
        // 设备点数 = 1 (LE: 01 00)
        assert_eq!(frame[21], 0x01);
        assert_eq!(frame[22], 0x00);
    }

    #[test]
    fn test_build_read_device_batch_invalid_code() {
        // 空设备代号
        assert!(build_read_device_batch("", 0, 1).is_err());
        // 设备代号长度错误
        assert!(build_read_device_batch("AB", 0, 1).is_err());
    }

    #[test]
    fn test_parse_response_header_ok() {
        // 构造一个成功响应
        let response: Vec<u8> = vec![
            0x50, 0x00, 0xFF, 0xFF, 0x03, 0x00, // 子头 + 路由信息
            0x01, 0x01, 0x00, 0x00, // 命令 + 子命令
            0x00, 0x00, // 结束码 = 0 (成功)
            0x11, 0x00, 0x21, 0x00, // PLC 类型 + 型号代码
        ];
        let (end_code, offset) = parse_response_header(&response).unwrap();
        assert_eq!(end_code, END_CODE_OK);
        assert_eq!(offset, 12);
    }

    #[test]
    fn test_parse_response_header_error_code() {
        // 构造一个错误响应 (访问被拒绝)
        let response: Vec<u8> = vec![
            0x50, 0x00, 0xFF, 0xFF, 0x03, 0x00,
            0x01, 0x01, 0x00, 0x00,
            0x00, 0xC0, // 结束码 = 0xC000 (LE: 00 C0)
        ];
        let (end_code, _) = parse_response_header(&response).unwrap();
        assert_eq!(end_code, END_CODE_ACCESS_DENIED);
        assert!(is_auth_required(end_code));
    }

    #[test]
    fn test_parse_response_header_invalid_subheader() {
        let response: Vec<u8> = vec![
            0x51, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_response_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_header_short() {
        let response: Vec<u8> = vec![0x50, 0x00, 0xFF];
        let result = parse_response_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cpu_type_response() {
        let data: &[u8] = &[0x11, 0x00, 0x21, 0x00];
        let result = parse_cpu_type_response(data);
        assert!(result.is_some());
        let (plc_type, plc_model) = result.unwrap();
        assert_eq!(plc_type, 0x0011);
        assert_eq!(plc_model, 0x0021);
    }

    #[test]
    fn test_parse_cpu_type_response_short() {
        let data: &[u8] = &[0x11, 0x00];
        let result = parse_cpu_type_response(data);
        assert!(result.is_none());
    }

    #[test]
    fn test_plc_type_to_string() {
        assert_eq!(plc_type_to_string(0x0011), "Q02/Q06H CPU");
        assert_eq!(plc_type_to_string(0x0041), "L02/L06CPU");
        assert_eq!(plc_type_to_string(0x0081), "FX3U/FX3UC CPU");
        assert_eq!(plc_type_to_string(0x0091), "iQ-R Series CPU");
        assert_eq!(plc_type_to_string(0x00A1), "iQ-F Series CPU");
        assert_eq!(plc_type_to_string(0x9999), "Unknown MELSEC CPU (0x9999)");
    }

    #[test]
    fn test_is_auth_required() {
        assert!(!is_auth_required(END_CODE_OK));
        assert!(is_auth_required(END_CODE_ACCESS_DENIED));
        assert!(is_auth_required(END_CODE_COMMAND_ERROR));
        assert!(!is_auth_required(0x0001)); // 其他错误码不视为需要认证
    }

    #[test]
    fn test_protocol_port() {
        assert_eq!(IcsProtocol::Melsec.port(), MELSEC_DEFAULT_PORT);
        assert_eq!(IcsProtocol::Melsec.port(), 1281);
        assert_eq!(IcsProtocol::Melsec.as_str(), "melsec");
    }

    #[test]
    fn test_read_device_batch_high_number() {
        // 测试较大的设备编号 (需要 6 位 ASCII)
        let frame = build_read_device_batch("D", 123456, 10).unwrap();
        // 设备编号 "123456"
        assert_eq!(&frame[15..21], b"123456");
        // 设备点数 = 10 (LE: 0A 00)
        assert_eq!(frame[21], 0x0A);
        assert_eq!(frame[22], 0x00);
    }
}
