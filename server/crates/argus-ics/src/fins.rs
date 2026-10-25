//! Omron FINS TCP Protocol (端口 9600)
//!
//! G6.4: 实现 FINS (Factory Interface Network System) over TCP 的设备探测
//!
//! FINS/TCP 帧结构:
//! - FINS/TCP 头 (8 bytes): Magic "FINS" (4) + Command (2, BE) + Length (2, BE)
//! - FINS 数据 (变长):
//!   - 节点连接数据 (Command 0x0000/0x0001): 初始握手, 交换节点地址
//!   - FINS 信息头 (9 bytes) + PDU (Command 0x0200/0x0300): 发送 FINS 命令
//!
//! FINS 信息头 (9 bytes):
//! - Source Network/Node/Unit (3 bytes)
//! - Dest Network/Node/Unit (3 bytes)
//! - SID (1 byte): Service ID (用于匹配请求/响应)
//! - Response Code (2 bytes, BE): MRC + SRC, 0x0000 = 成功
//!
//! FINS PDU:
//! - Command Code (2 bytes, BE)
//! - Subcommand (2 bytes, BE)
//! - Data (variable)
//!
//! 安全扫描内容:
//! - TCP 连接 + FINS/TCP 节点握手
//! - 命令 0x0501: Controller Read (读取 PLC 型号)
//! - 检查是否需要认证 (响应码判断)

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ==================== 协议常量 ====================

/// FINS/TCP 默认端口
pub const FINS_DEFAULT_PORT: u16 = 9600;

/// FINS/TCP Magic: "FINS" (0x46 0x49 0x4E 0x53)
const FINS_MAGIC: [u8; 4] = [0x46, 0x49, 0x4E, 0x53];

/// FINS/TCP 命令码: 节点连接请求 (Client → Server)
const FINS_TCP_CMD_NODE_REQUEST: u16 = 0x0000;

/// FINS/TCP 命令码: 节点连接响应 (Server → Client)
const FINS_TCP_CMD_NODE_RESPONSE: u16 = 0x0001;

/// FINS/TCP 命令码: FINS 数据发送 (Client → Server)
const FINS_TCP_CMD_SEND_DATA: u16 = 0x0200;

/// FINS/TCP 命令码: FINS 数据发送响应 (Server → Client)
const FINS_TCP_CMD_SEND_DATA_RESPONSE: u16 = 0x0300;

/// FINS/TCP 命令码: 错误 (Server → Client)
const FINS_TCP_CMD_ERROR: u16 = 0x0002;

/// FINS 命令码 (PDU): Controller Read (读取控制器型号)
const FINS_CMD_CONTROLLER_READ: u16 = 0x0501;

/// FINS 子命令: 0x0000 (标准)
const FINS_SUBCMD_DEFAULT: u16 = 0x0000;

/// FINS 响应码: 成功
const FINS_RESPONSE_CODE_OK: u16 = 0x0000;

/// 默认客户端节点地址
const DEFAULT_CLIENT_NODE: u8 = 0x01;

/// 默认客户端单元地址 (CPU = 0x00)
const DEFAULT_CLIENT_UNIT: u8 = 0x00;

/// 默认服务器节点地址 (初始值, 实际从握手响应获取)
const DEFAULT_SERVER_NODE: u8 = 0x00;

/// 默认服务器单元地址 (CPU = 0x00)
const DEFAULT_SERVER_UNIT: u8 = 0x00;

/// 本地网络号
const LOCAL_NETWORK: u8 = 0x00;

// ==================== 帧构造 ====================

/// 构造 FINS/TCP 帧 (Magic + Command + Length + Data)
pub fn build_fins_tcp_frame(command: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + data.len());
    // FINS Magic "FINS"
    frame.extend_from_slice(&FINS_MAGIC);
    // Command (2 bytes, BE)
    frame.extend_from_slice(&command.to_be_bytes());
    // Length (2 bytes, BE) - 数据部分长度
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    // 数据
    frame.extend_from_slice(data);
    frame
}

/// 构造节点连接请求 (FINS/TCP 握手第一步)
///
/// 数据结构 (4 bytes):
/// - Client FINS node address (1 byte)
/// - Reserved (1 byte, 0x00)
/// - Client FINS unit address (1 byte)
/// - Reserved (1 byte, 0x00)
pub fn build_node_connection_request(client_node: u8, client_unit: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(4);
    data.push(client_node);
    data.push(0x00); // reserved
    data.push(client_unit);
    data.push(0x00); // reserved
    build_fins_tcp_frame(FINS_TCP_CMD_NODE_REQUEST, &data)
}

/// 构造 FINS 信息头 (9 bytes)
///
/// 信息头结构:
/// - Source Network/Node/Unit (3 bytes)
/// - Dest Network/Node/Unit (3 bytes)
/// - SID (1 byte)
/// - Response Code (2 bytes, BE): 0x0000 for request
pub fn build_fins_info_header(
    src_network: u8,
    src_node: u8,
    src_unit: u8,
    dst_network: u8,
    dst_node: u8,
    dst_unit: u8,
    sid: u8,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(9);
    // Source Info
    header.push(src_network);
    header.push(src_node);
    header.push(src_unit);
    // Dest Info
    header.push(dst_network);
    header.push(dst_node);
    header.push(dst_unit);
    // SID
    header.push(sid);
    // Response Code (0x0000 for request)
    header.extend_from_slice(&FINS_RESPONSE_CODE_OK.to_be_bytes());
    header
}

/// 构造 Controller Read 请求 (命令 0x0501)
///
/// 完整帧 = FINS/TCP 头 + 信息头 + PDU (命令 + 子命令, 无数据)
pub fn build_controller_read_request(
    src_network: u8,
    src_node: u8,
    src_unit: u8,
    dst_network: u8,
    dst_node: u8,
    dst_unit: u8,
    sid: u8,
) -> Vec<u8> {
    // FINS 信息头
    let info_header = build_fins_info_header(
        src_network,
        src_node,
        src_unit,
        dst_network,
        dst_node,
        dst_unit,
        sid,
    );
    // FINS PDU: 命令 (2 bytes BE) + 子命令 (2 bytes BE), 无额外数据
    let mut pdu = Vec::with_capacity(4);
    pdu.extend_from_slice(&FINS_CMD_CONTROLLER_READ.to_be_bytes());
    pdu.extend_from_slice(&FINS_SUBCMD_DEFAULT.to_be_bytes());
    // 组合: 信息头 + PDU
    let mut data = info_header;
    data.extend_from_slice(&pdu);
    // 构造 FINS/TCP 帧
    build_fins_tcp_frame(FINS_TCP_CMD_SEND_DATA, &data)
}

// ==================== 请求发送 ====================

/// 发送 FINS/TCP 帧并读取响应
///
/// 响应帧格式: FINS/TCP 头 (8 bytes) + 数据 (变长)
async fn send_fins_request(
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

    // 读取 FINS/TCP 响应头 (8 bytes)
    let mut header = [0u8; 8];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| "读取响应头超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    // 检查 FINS Magic
    if header[0..4] != FINS_MAGIC {
        return Err(format!(
            "无效的 FINS Magic: {:02X?} (期望 {:02X?})",
            &header[0..4], FINS_MAGIC
        ));
    }

    // 解析数据长度
    let length = u16::from_be_bytes([header[6], header[7]]) as usize;

    // 读取数据部分
    let mut data = vec![0u8; length];
    if !data.is_empty() {
        tokio::time::timeout(timeout, stream.read_exact(&mut data))
            .await
            .map_err(|_| "读取数据超时".to_string())?
            .map_err(|e| format!("读取数据失败: {e}"))?;
    }

    let mut response = Vec::with_capacity(8 + length);
    response.extend_from_slice(&header);
    response.extend_from_slice(&data);
    Ok(response)
}

// ==================== 响应解析 ====================

/// 解析 FINS/TCP 响应头
///
/// 返回 (fins_tcp_command, data_length)
pub fn parse_fins_tcp_header(response: &[u8]) -> Result<(u16, u16), String> {
    if response.len() < 8 {
        return Err(format!("响应数据过短: {} (期望 >= 8)", response.len()));
    }
    if response[0..4] != FINS_MAGIC {
        return Err(format!(
            "无效的 FINS Magic: {:02X?} (期望 {:02X?})",
            &response[0..4], FINS_MAGIC
        ));
    }
    let command = u16::from_be_bytes([response[4], response[5]]);
    let length = u16::from_be_bytes([response[6], response[7]]);
    // 检查是否为 FINS/TCP 错误响应
    if command == FINS_TCP_CMD_ERROR {
        let error_code = if response.len() >= 10 {
            u16::from_be_bytes([response[8], response[9]])
        } else {
            0
        };
        return Err(format!(
            "FINS/TCP 错误响应: error_code=0x{:04X}",
            error_code
        ));
    }
    Ok((command, length))
}

/// 解析节点连接响应, 获取服务器节点地址和单元地址
///
/// 响应数据 (4 bytes):
/// - Server FINS node address (1 byte)
/// - Reserved (1 byte)
/// - Server FINS unit address (1 byte)
/// - Reserved (1 byte)
pub fn parse_node_connection_response(response: &[u8]) -> Option<(u8, u8)> {
    // FINS/TCP 头 (8) + 数据 (4) = 12 bytes 最小
    if response.len() < 12 {
        return None;
    }
    let command = u16::from_be_bytes([response[4], response[5]]);
    if command != FINS_TCP_CMD_NODE_RESPONSE {
        return None;
    }
    // 数据: server_node (offset 8) + reserved (9) + server_unit (10) + reserved (11)
    Some((response[8], response[10]))
}

/// 解析 FINS 数据响应的信息头
///
/// 返回 (response_code, pdu_offset):
/// - response_code: MRC + SRC (0x0000 = 成功)
/// - pdu_offset: PDU 在响应中的起始偏移 (命令码 + 子命令 + 数据)
pub fn parse_fins_info_header(response: &[u8]) -> Result<(u16, usize), String> {
    // FINS/TCP 头 (8) + FINS 信息头 (9) = 17 bytes 最小
    if response.len() < 17 {
        return Err(format!("响应数据过短: {} (期望 >= 17)", response.len()));
    }
    // 检查 FINS/TCP 命令是否为 0x0300 (数据响应)
    let command = u16::from_be_bytes([response[4], response[5]]);
    if command != FINS_TCP_CMD_SEND_DATA_RESPONSE {
        return Err(format!(
            "无效的 FINS/TCP 命令: 0x{:04X} (期望 0x{:04X})",
            command, FINS_TCP_CMD_SEND_DATA_RESPONSE
        ));
    }
    // 响应码 (MRC + SRC) 在偏移 15-16
    // 偏移: 8-10=Source 11-13=Dest 14=SID 15-16=Response Code
    let response_code = u16::from_be_bytes([response[15], response[16]]);
    // PDU 从偏移 17 开始: 命令(2) + 子命令(2) + 数据
    Ok((response_code, 17))
}

/// 解析 Controller Read 响应数据
///
/// 提取控制器型号和版本信息。
///
/// 响应数据结构 (命令 0x0501):
/// - Controller Model (20 bytes, ASCII, 空格补齐)
/// - Controller Version (20 bytes, ASCII)
/// - 其他字段 (变长)
pub fn parse_controller_read_response(data: &[u8]) -> Option<(String, String)> {
    // 至少需要 20 字节读取控制器型号
    if data.len() < 20 {
        return None;
    }
    let model = String::from_utf8_lossy(&data[0..20])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    let version = if data.len() >= 40 {
        String::from_utf8_lossy(&data[20..40])
            .trim_end_matches('\0')
            .trim()
            .to_string()
    } else {
        String::new()
    };
    Some((model, version))
}

/// 根据响应码判断是否需要认证
///
/// 返回 true 表示访问被拒绝 (可能需要认证)
pub fn is_auth_required(response_code: u16) -> bool {
    // 0x0001: Service unavailable (可能需要认证)
    // 0x0002: Undefined command (可能因权限不足)
    // 0x0201: No access (access denied)
    // 0x0202: No access write (write denied)
    matches!(
        response_code,
        0x0001 | 0x0002 | 0x0201 | 0x0202
    )
}

// ==================== 公共接口 ====================

/// 读取 FINS 设备信息 (控制器型号、版本)
///
/// 执行流程:
/// 1. TCP 连接到目标
/// 2. 发送 FINS/TCP 节点连接请求 (握手)
/// 3. 发送 Controller Read 命令 (0x0501) 获取 PLC 型号
/// 4. 检查是否需要认证 (响应码判断)
pub async fn read_controller_info(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::Fins);
    device.vendor = Some("Omron".to_string());
    device.device_type = Some("PLC".to_string());

    // 1. 节点连接握手
    let node_request = build_node_connection_request(DEFAULT_CLIENT_NODE, DEFAULT_CLIENT_UNIT);
    match send_fins_request(host, port, &node_request, timeout_ms).await {
        Ok(node_response) => {
            // 从握手响应获取服务器节点地址
            let server_node = parse_node_connection_response(&node_response)
                .map(|(n, _)| n)
                .unwrap_or(DEFAULT_SERVER_NODE);

            // 2. 发送 Controller Read 命令
            let read_request = build_controller_read_request(
                LOCAL_NETWORK,
                DEFAULT_CLIENT_NODE,
                DEFAULT_CLIENT_UNIT,
                LOCAL_NETWORK,
                server_node,
                DEFAULT_SERVER_UNIT,
                0x01, // SID
            );

            match send_fins_request(host, port, &read_request, timeout_ms).await {
                Ok(response) => {
                    match parse_fins_info_header(&response) {
                        Ok((response_code, pdu_offset)) => {
                            if response_code == FINS_RESPONSE_CODE_OK {
                                // 成功: 提取控制器型号
                                // PDU: 命令(2) + 子命令(2) + 数据
                                let pdu = &response[pdu_offset..];
                                // 跳过命令码和子命令 (4 bytes) 获取响应数据
                                if pdu.len() >= 4 {
                                    let controller_data = &pdu[4..];
                                    if let Some((model, version)) =
                                        parse_controller_read_response(controller_data)
                                    {
                                        if !model.is_empty() {
                                            device.model = Some(model);
                                        }
                                        if !version.is_empty() {
                                            device.firmware = Some(version);
                                        }
                                    }
                                }
                                device.raw_response = Some(serde_json::json!({
                                    "response_code": format!("0x{:04X}", response_code),
                                    "auth_required": false,
                                    "identified": true,
                                }));
                            } else {
                                // 非零响应码: 可能需要认证或命令错误
                                device.raw_response = Some(serde_json::json!({
                                    "response_code": format!("0x{:04X}", response_code),
                                    "auth_required": is_auth_required(response_code),
                                }));
                            }
                        }
                        Err(e) => {
                            // 信息头解析失败, 但端口开放且握手成功, 可能是 FINS 设备
                            device.raw_response = Some(serde_json::json!({
                                "error": e,
                                "response_length": response.len(),
                                "identified_by_port": true,
                            }));
                        }
                    }
                }
                Err(e) => {
                    // Controller Read 请求失败, 但握手成功, 可能是 FINS 设备
                    device.raw_response = Some(serde_json::json!({
                        "error": format!("Controller Read 失败: {e}"),
                        "handshake_ok": true,
                        "identified_by_port": true,
                    }));
                }
            }
        }
        Err(e) => {
            // 节点连接握手失败, 但端口开放, 可能是 FINS 设备或需要认证
            device.raw_response = Some(serde_json::json!({
                "error": format!("节点连接握手失败: {e}"),
                "identified_by_port": true,
            }));
        }
    }

    Ok(device)
}

/// 探测 FINS 端口是否开放
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
    fn test_fins_magic() {
        // FINS Magic = "FINS" = 0x46 0x49 0x4E 0x53
        assert_eq!(&FINS_MAGIC, b"FINS");
    }

    #[test]
    fn test_build_fins_tcp_frame() {
        let data = vec![0x01, 0x02, 0x03];
        let frame = build_fins_tcp_frame(FINS_TCP_CMD_NODE_REQUEST, &data);
        // FINS/TCP 头 (8) + 数据 (3) = 11
        assert_eq!(frame.len(), 11);
        // Magic "FINS"
        assert_eq!(&frame[0..4], b"FINS");
        // Command = 0x0000 (BE)
        assert_eq!(frame[4], 0x00);
        assert_eq!(frame[5], 0x00);
        // Length = 3 (BE)
        assert_eq!(frame[6], 0x00);
        assert_eq!(frame[7], 0x03);
        // 数据
        assert_eq!(&frame[8..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_build_node_connection_request() {
        let frame = build_node_connection_request(0x01, 0x00);
        // FINS/TCP 头 (8) + 数据 (4) = 12
        assert_eq!(frame.len(), 12);
        // Command = 0x0000
        assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), FINS_TCP_CMD_NODE_REQUEST);
        // Length = 4
        assert_eq!(u16::from_be_bytes([frame[6], frame[7]]), 4);
        // 数据: client_node=0x01, reserved=0x00, client_unit=0x00, reserved=0x00
        assert_eq!(frame[8], 0x01); // client_node
        assert_eq!(frame[9], 0x00); // reserved
        assert_eq!(frame[10], 0x00); // client_unit
        assert_eq!(frame[11], 0x00); // reserved
    }

    #[test]
    fn test_build_fins_info_header() {
        let header = build_fins_info_header(
            0x00, 0x01, 0x00, // src
            0x00, 0x02, 0x00, // dst
            0x01, // SID
        );
        // 信息头 = 9 bytes
        assert_eq!(header.len(), 9);
        // Source: network=0, node=1, unit=0
        assert_eq!(header[0], 0x00);
        assert_eq!(header[1], 0x01);
        assert_eq!(header[2], 0x00);
        // Dest: network=0, node=2, unit=0
        assert_eq!(header[3], 0x00);
        assert_eq!(header[4], 0x02);
        assert_eq!(header[5], 0x00);
        // SID
        assert_eq!(header[6], 0x01);
        // Response Code = 0x0000 (BE)
        assert_eq!(header[7], 0x00);
        assert_eq!(header[8], 0x00);
    }

    #[test]
    fn test_build_controller_read_request() {
        let frame = build_controller_read_request(
            0x00, 0x01, 0x00, // src
            0x00, 0x02, 0x00, // dst
            0x01, // SID
        );
        // FINS/TCP 头 (8) + 信息头 (9) + PDU 命令(2) + 子命令(2) = 21
        assert_eq!(frame.len(), 21);
        // FINS/TCP Command = 0x0200 (数据发送)
        assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), FINS_TCP_CMD_SEND_DATA);
        // Length = 13 (信息头 9 + PDU 4)
        assert_eq!(u16::from_be_bytes([frame[6], frame[7]]), 13);
        // FINS Command Code = 0x0501 (Controller Read, BE)
        assert_eq!(frame[17], 0x05);
        assert_eq!(frame[18], 0x01);
        // FINS Subcommand = 0x0000 (BE)
        assert_eq!(frame[19], 0x00);
        assert_eq!(frame[20], 0x00);
    }

    #[test]
    fn test_parse_fins_tcp_header_ok() {
        let response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53, // "FINS"
            0x03, 0x00, // Command = 0x0300 (数据响应)
            0x00, 0x09, // Length = 9
            0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, // 数据 (9 bytes)
        ];
        let (command, length) = parse_fins_tcp_header(&response).unwrap();
        assert_eq!(command, FINS_TCP_CMD_SEND_DATA_RESPONSE);
        assert_eq!(length, 9);
    }

    #[test]
    fn test_parse_fins_tcp_header_invalid_magic() {
        let response: Vec<u8> = vec![
            0x58, 0x59, 0x5A, 0x5B, // 无效 Magic
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = parse_fins_tcp_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fins_tcp_header_short() {
        let response: Vec<u8> = vec![0x46, 0x49, 0x4E];
        let result = parse_fins_tcp_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fins_tcp_header_error_response() {
        // FINS/TCP 错误响应 (Command = 0x0002)
        let response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53, // "FINS"
            0x00, 0x02, // Command = 0x0002 (ERROR)
            0x00, 0x02, // Length = 2
            0x00, 0x01, // Error code = 0x0001
        ];
        let result = parse_fins_tcp_header(&response);
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("FINS/TCP 错误响应"));
        assert!(err_msg.contains("0x0001"));
    }

    #[test]
    fn test_parse_node_connection_response() {
        // 构造节点连接响应
        let response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53, // "FINS"
            0x00, 0x01, // Command = 0x0001 (节点连接响应)
            0x00, 0x04, // Length = 4
            0x0A, 0x00, 0x00, 0x00, // server_node=0x0A, reserved, server_unit=0x00, reserved
        ];
        let result = parse_node_connection_response(&response);
        assert!(result.is_some());
        let (node, unit) = result.unwrap();
        assert_eq!(node, 0x0A);
        assert_eq!(unit, 0x00);
    }

    #[test]
    fn test_parse_node_connection_response_wrong_command() {
        let response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53,
            0x02, 0x00, // Command = 0x0200 (错误)
            0x00, 0x04,
            0x0A, 0x00, 0x00, 0x00,
        ];
        let result = parse_node_connection_response(&response);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_fins_info_header_ok() {
        // 构造 FINS 数据响应
        let mut response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53, // "FINS"
            0x03, 0x00, // Command = 0x0300 (数据响应)
            0x00, 0x00, // Length (placeholder)
            // FINS 信息头 (9 bytes)
            0x00, 0x02, 0x00, // Source: network=0, node=2, unit=0
            0x00, 0x01, 0x00, // Dest: network=0, node=1, unit=0
            0x01, // SID
            0x00, 0x00, // Response Code = 0x0000 (成功)
        ];
        // 设置长度
        let data_len = response.len() - 8;
        response[6] = (data_len >> 8) as u8;
        response[7] = (data_len & 0xFF) as u8;

        let (response_code, pdu_offset) = parse_fins_info_header(&response).unwrap();
        assert_eq!(response_code, FINS_RESPONSE_CODE_OK);
        assert_eq!(pdu_offset, 17);
    }

    #[test]
    fn test_parse_fins_info_header_error_code() {
        let mut response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53,
            0x03, 0x00,
            0x00, 0x00,
            0x00, 0x02, 0x00,
            0x00, 0x01, 0x00,
            0x01,
            0x02, 0x01, // Response Code = 0x0201 (访问拒绝)
        ];
        let data_len = response.len() - 8;
        response[6] = (data_len >> 8) as u8;
        response[7] = (data_len & 0xFF) as u8;

        let (response_code, _) = parse_fins_info_header(&response).unwrap();
        assert_eq!(response_code, 0x0201);
        assert!(is_auth_required(response_code));
    }

    #[test]
    fn test_parse_fins_info_header_wrong_command() {
        let response: Vec<u8> = vec![
            0x46, 0x49, 0x4E, 0x53,
            0x02, 0x00, // Command = 0x0200 (错误)
            0x00, 0x09,
            0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        ];
        let result = parse_fins_info_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fins_info_header_short() {
        let response: Vec<u8> = vec![0x46, 0x49, 0x4E, 0x53, 0x03, 0x00, 0x00, 0x01, 0x00];
        let result = parse_fins_info_header(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_controller_read_response() {
        // 构造 Controller Read 响应数据
        let model = "CJ2M-CPU15          "; // 20 bytes, 空格补齐
        let version = "Ver1.0              "; // 20 bytes, 空格补齐
        let mut data = Vec::new();
        data.extend_from_slice(model.as_bytes());
        data.extend_from_slice(version.as_bytes());

        let result = parse_controller_read_response(&data);
        assert!(result.is_some());
        let (m, v) = result.unwrap();
        assert_eq!(m, "CJ2M-CPU15");
        assert_eq!(v, "Ver1.0");
    }

    #[test]
    fn test_parse_controller_read_response_short() {
        let data: &[u8] = &[0x01, 0x02, 0x03];
        let result = parse_controller_read_response(data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_controller_read_response_model_only() {
        // 只有型号, 没有版本
        let model = "CP1H                "; // 20 bytes
        let data = model.as_bytes();
        let result = parse_controller_read_response(data);
        assert!(result.is_some());
        let (m, v) = result.unwrap();
        assert_eq!(m, "CP1H");
        assert_eq!(v, ""); // 版本为空
    }

    #[test]
    fn test_parse_controller_read_response_null_terminated() {
        // null 结尾的字符串
        let mut data = vec![0u8; 40];
        let model = b"CJ1G-CPU44";
        data[..model.len()].copy_from_slice(model);
        // 后面填充 null
        let result = parse_controller_read_response(&data);
        assert!(result.is_some());
        let (m, _) = result.unwrap();
        assert_eq!(m, "CJ1G-CPU44");
    }

    #[test]
    fn test_is_auth_required() {
        assert!(!is_auth_required(FINS_RESPONSE_CODE_OK));
        assert!(is_auth_required(0x0001)); // Service unavailable
        assert!(is_auth_required(0x0201)); // No access
        assert!(is_auth_required(0x0202)); // No access write
        assert!(!is_auth_required(0x0003)); // 其他错误码
    }

    #[test]
    fn test_protocol_port() {
        assert_eq!(IcsProtocol::Fins.port(), FINS_DEFAULT_PORT);
        assert_eq!(IcsProtocol::Fins.port(), 9600);
        assert_eq!(IcsProtocol::Fins.as_str(), "fins");
    }

    #[test]
    fn test_controller_read_request_structure() {
        // 验证完整帧结构
        let frame = build_controller_read_request(
            0x00, 0x01, 0x00,
            0x00, 0x0A, 0x00,
            0x05, // SID = 5
        );
        // 总长度: 8 (TCP头) + 9 (信息头) + 4 (PDU) = 21
        assert_eq!(frame.len(), 21);
        // FINS/TCP Command = 0x0200
        assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), FINS_TCP_CMD_SEND_DATA);
        // SID at offset 14
        assert_eq!(frame[14], 0x05);
        // FINS Command = 0x0501 at offset 17-18
        assert_eq!(u16::from_be_bytes([frame[17], frame[18]]), FINS_CMD_CONTROLLER_READ);
        // FINS Subcommand = 0x0000 at offset 19-20
        assert_eq!(u16::from_be_bytes([frame[19], frame[20]]), FINS_SUBCMD_DEFAULT);
    }
}
