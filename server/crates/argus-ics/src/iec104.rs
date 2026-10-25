//! IEC 104 协议（端口 2404）
//!
//! 帧结构: start_byte(0x68) + APDU_length(1) + APDU
//! APDU = APCI(4) + ASDU(variable)
//! APCI: I-format / S-format / U-format

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 构建 I 格式 APCI
fn build_i_format(asdu: &[u8]) -> Vec<u8> {
    let total_len = 1 + 1 + 4 + asdu.len(); // start + length + APCI + ASDU
    let mut buf = Vec::with_capacity(total_len);
    buf.push(0x68); // Start byte
    buf.push((4 + asdu.len()) as u8); // APDU length
    // APCI (I format): 4 bytes, first 2 bytes = send sequence + I format flag
    buf.extend_from_slice(&[0x01, 0x00]); // I format, send seq = 0
    buf.extend_from_slice(&[0x00, 0x00]); // receive seq = 0
    buf.extend_from_slice(asdu);
    buf
}

/// 构建 U 格式（STARTDT_ACT = 启动数据传输）
fn build_startdt_act() -> Vec<u8> {
    vec![
        0x68, 0x04, // Start byte + length
        0x07, 0x00, 0x00, 0x00, // U format: STARTDT_ACT
    ]
}

/// 构建 U 格式（STOPDT_ACT = 停止数据传输）
fn build_stopdt_act() -> Vec<u8> {
    vec![
        0x68,
        0x04,
        0x13,
        0x00,
        0x00,
        0x00, // U format: STOPDT_ACT
    ]
}

/// 发送 IEC 104 帧
async fn send_iec104_frame(
    host: &str,
    port: u16,
    frame: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("连接超时: {addr}"))?
        .map_err(|e| format!("连接失败: {addr}: {e}"))?;

    stream
        .write_all(frame)
        .await
        .map_err(|e| format!("发送失败: {e}"))?;

    // 读取响应帧: start(1) + length(1) + APDU
    let mut header = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| "读取响应头超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    if header[0] != 0x68 {
        return Err(format!("无效的起始字节: 0x{:02X}", header[0]));
    }

    let apdu_len = header[1] as usize;
    let mut apdu = vec![0u8; apdu_len];
    if apdu_len > 0 {
        tokio::time::timeout(timeout, stream.read_exact(&mut apdu))
            .await
            .map_err(|_| "读取 APDU 超时".to_string())?
            .map_err(|e| format!("读取 APDU 失败: {e}"))?;
    }

    let mut response = Vec::with_capacity(2 + apdu_len);
    response.extend_from_slice(&header);
    response.extend_from_slice(&apdu);
    Ok(response)
}

/// 发送总召唤（General Interrogation, Type ID 0x64 = C_IC_NA_1）
pub async fn send_general_interrogation(
    host: &str,
    port: u16,
    common_addr: u16,
    timeout_ms: u64,
) -> Result<Vec<Iec104Asdu>, String> {
    // 先发送 STARTDT_ACT
    let _ = send_iec104_frame(host, port, &build_startdt_act(), timeout_ms).await;

    // 构建总召唤 ASDU
    let mut asdu = Vec::with_capacity(12);
    // ASDU: type_id(1) + variable_struct_qualifier(1) + cause_of_transmission(1) + originator_addr(1) + common_addr(2) + IOA
    asdu.push(0x64); // Type ID: C_IC_NA_1
    asdu.push(0x01); // Variable struct qualifier: 1 = single
    asdu.push(0x06); // Cause of transmission: 6 = activation
    asdu.push(0x00); // Originator address
    asdu.extend_from_slice(&common_addr.to_le_bytes()); // Common address (little-endian)
    // Information object: IOA(3) + COT(1)
    asdu.extend_from_slice(&[0x00, 0x00, 0x00]); // IOA = 0
    asdu.push(0x01); // QOI: 1 = station interrogation

    let frame = build_i_format(&asdu);
    let response = send_iec104_frame(host, port, &frame, timeout_ms).await?;

    // 解析响应中的 ASDU
    let mut asdus = vec![];
    if response.len() > 6 {
        let apdu = &response[2..];
        if apdu.len() > 4 {
            // 跳过 APCI (4 bytes)
            let asdu_data = &apdu[4..];
            if let Ok(parsed) = parse_asdu(asdu_data) {
                asdus.push(parsed);
            }
        }
    }

    Ok(asdus)
}

/// 解析 ASDU
pub fn parse_asdu(data: &[u8]) -> Result<Iec104Asdu, String> {
    if data.len() < 6 {
        return Err("ASDU 数据过短".to_string());
    }

    let type_id = data[0];
    let var_struct = data[1];
    let cause_of_transmission = data[2];
    // originator_addr = data[3]
    let common_addr = u16::from_le_bytes([data[4], data[5]]);

    // 解析信息对象
    let mut info_objects = vec![];
    let mut offset = 6;
    let io_count = if var_struct & 0x80 != 0 {
        // 连续
        (var_struct & 0x7F) as usize
    } else {
        1
    };

    for _ in 0..io_count {
        if offset + 3 > data.len() {
            break;
        }
        let address = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]);
        offset += 3;
        // 信息对象值长度取决于 type_id，简化处理
        let value = serde_json::json!({
            "type_id": type_id,
            "raw_bytes": data.get(offset..offset + 5.min(data.len() - offset))
                .map(|b| b.iter().map(|v| format!("{:02X}", v)).collect::<Vec<_>>())
                .unwrap_or_default()
        });
        info_objects.push(InformationObject { address, value });
        offset += 5; // 简化: 每个对象 5 字节值
    }

    Ok(Iec104Asdu {
        type_id,
        cause_of_transmission,
        common_addr,
        information_objects: info_objects,
    })
}

/// 探测 IEC 104 端口
pub async fn probe(host: &str, port: u16, timeout_ms: u64) -> bool {
    // 发送 STARTDT_ACT，检查是否有响应
    match send_iec104_frame(host, port, &build_startdt_act(), timeout_ms).await {
        Ok(resp) => {
            // 响应应包含 STARTDT_CON (0x0B)
            if resp.len() >= 4 {
                let apdu = &resp[2..];
                apdu.first().map_or(false, |&b| b == 0x0B || b == 0x07 || b == 0x01)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_byte() {
        // IEC 104 帧以 0x68 开头
        let frame = build_startdt_act();
        assert_eq!(frame[0], 0x68);
    }

    #[test]
    fn test_startdt_act() {
        let frame = build_startdt_act();
        assert_eq!(frame.len(), 6); // start(1) + length(1) + APCI(4)
        assert_eq!(frame[1], 0x04); // length = 4
        assert_eq!(frame[2], 0x07); // STARTDT_ACT
    }

    #[test]
    fn test_i_format() {
        let asdu = vec![0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        let frame = build_i_format(&asdu);
        assert_eq!(frame[0], 0x68); // Start byte
        assert_eq!(frame[1], 4 + asdu.len() as u8); // APDU length
    }

    #[test]
    fn test_parse_asdu() {
        // 构造一个简单的 ASDU
        let data: &[u8] = &[
            0x01, // Type ID: M_SP_NA_1 (single point)
            0x01, // Variable struct: 1 single
            0x03, // COT: 3 = spontaneous
            0x00, // Originator address
            0x01, 0x00, // Common address = 1 (LE)
            0x01, 0x00, 0x00, // IOA = 1 (LE)
            0x01, // Value: ON
            0x00, 0x00, 0x00, 0x00, // padding
        ];
        let asdu = parse_asdu(data).unwrap();
        assert_eq!(asdu.type_id, 0x01);
        assert_eq!(asdu.cause_of_transmission, 0x03);
        assert_eq!(asdu.common_addr, 1);
        assert_eq!(asdu.information_objects.len(), 1);
        assert_eq!(asdu.information_objects[0].address, 1);
    }

    #[test]
    fn test_parse_asdu_short_data() {
        assert!(parse_asdu(&[0x01, 0x01]).is_err()); // 数据过短
    }
}
