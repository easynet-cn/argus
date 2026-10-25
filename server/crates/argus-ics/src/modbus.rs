//! Modbus TCP 协议（端口 502）
//!
//! MBAP 头: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
//! PDU: function_code(1) + data

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 构建 Modbus MBAP 请求
fn build_mbap_request(
    transaction_id: u16,
    unit_id: u8,
    function_code: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + 1 + data.len());
    // MBAP 头
    buf.extend_from_slice(&transaction_id.to_be_bytes()); // transaction_id
    buf.extend_from_slice(&0u16.to_be_bytes()); // protocol_id = 0 (Modbus)
    let length = (1 + 1 + data.len()) as u16; // unit_id + fn_code + data
    buf.extend_from_slice(&length.to_be_bytes());
    buf.push(unit_id);
    // PDU
    buf.push(function_code);
    buf.extend_from_slice(data);
    buf
}

/// 发送 Modbus 请求并读取响应
async fn send_modbus_request(
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

    // 读取 MBAP 头 (7 bytes)
    let mut header = [0u8; 7];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| "读取响应超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    // 解析长度
    let length = u16::from_be_bytes([header[4], header[5]]) as usize;
    if length < 2 {
        return Err(format!("无效的响应长度: {length}"));
    }

    // 读取剩余数据
    let mut pdu = vec![0u8; length - 1]; // 减去 unit_id
    tokio::time::timeout(timeout, stream.read_exact(&mut pdu))
        .await
        .map_err(|_| "读取 PDU 超时".to_string())?
        .map_err(|e| format!("读取 PDU 失败: {e}"))?;

    let mut response = Vec::with_capacity(header.len() + pdu.len());
    response.extend_from_slice(&header);
    response.extend_from_slice(&pdu);
    Ok(response)
}

/// 读线圈 (Function Code 0x01)
pub async fn read_coils(
    host: &str,
    port: u16,
    unit_id: u8,
    start_addr: u16,
    count: u16,
    timeout_ms: u64,
) -> Result<Vec<bool>, String> {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&start_addr.to_be_bytes());
    data.extend_from_slice(&count.to_be_bytes());

    let request = build_mbap_request(1, unit_id, 0x01, &data);
    let response = send_modbus_request(host, port, &request, timeout_ms).await?;

    // 响应: MBAP(7) + fn_code(1) + byte_count(1) + coil_data(n)
    if response.len() < 9 {
        return Err("响应数据过短".to_string());
    }

    let byte_count = response[8] as usize;
    let coil_bytes = &response[9..9 + byte_count.min(response.len() - 9)];

    let mut coils = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < coil_bytes.len() {
            coils.push((coil_bytes[byte_idx] >> bit_idx) & 1 == 1);
        } else {
            coils.push(false);
        }
    }
    Ok(coils)
}

/// 读保持寄存器 (Function Code 0x03)
pub async fn read_holding_registers(
    host: &str,
    port: u16,
    unit_id: u8,
    start_addr: u16,
    count: u16,
    timeout_ms: u64,
) -> Result<Vec<u16>, String> {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&start_addr.to_be_bytes());
    data.extend_from_slice(&count.to_be_bytes());

    let request = build_mbap_request(1, unit_id, 0x03, &data);
    let response = send_modbus_request(host, port, &request, timeout_ms).await?;

    // 响应: MBAP(7) + fn_code(1) + byte_count(1) + reg_data(n*2)
    if response.len() < 9 {
        return Err("响应数据过短".to_string());
    }

    let byte_count = response[8] as usize;
    let reg_data = &response[9..9 + byte_count.min(response.len() - 9)];

    let mut registers = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let offset = i * 2;
        if offset + 1 < reg_data.len() {
            registers.push(u16::from_be_bytes([reg_data[offset], reg_data[offset + 1]]));
        } else {
            registers.push(0);
        }
    }
    Ok(registers)
}

/// 读设备识别 (Function Code 0x2B/0x0E)
/// 读 VendorName(0x00), ProductName(0x01), Version(0x02)
pub async fn identify_device(
    host: &str,
    port: u16,
    unit_id: u8,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::ModbusTcp);

    // 读取设备识别: 0x2B (MEI) + 0x0E (Read Device Identification) + 0x01 (Basic) + 0x00 (Object ID)
    let data = &[0x0E, 0x01, 0x00];
    let request = build_mbap_request(1, unit_id, 0x2B, data);

    match send_modbus_request(host, port, &request, timeout_ms).await {
        Ok(response) => {
            // 响应: MBAP(7) + fn(1) + MEI_type(1) + read_dev_id(1) + conformity_level(1) + more_follows(1) + next_obj_id(1) + num_objects(1) + objects...
            if response.len() > 14 {
                let num_objects = response[14] as usize;
                let mut offset = 15;
                for _ in 0..num_objects {
                    if offset + 2 < response.len() {
                        let obj_id = response[offset];
                        let obj_len = response[offset + 1] as usize;
                        offset += 2;
                        if offset + obj_len <= response.len() {
                            let value =
                                String::from_utf8_lossy(&response[offset..offset + obj_len])
                                    .to_string();
                            match obj_id {
                                0x00 => device.vendor = Some(value),       // VendorName
                                0x01 => device.model = Some(value),         // ProductName
                                0x02 => device.firmware = Some(value),      // Version
                                _ => {}
                            }
                            offset += obj_len;
                        }
                    }
                }
            }
            device.raw_response = Some(serde_json::json!({
                "function_code": 0x2B,
                "response_length": response.len(),
            }));
        }
        Err(e) => {
            // 设备识别不支持时，仍标记为 Modbus 设备
            device.raw_response = Some(serde_json::json!({
                "error": e,
                "identified_by_port": true,
            }));
        }
    }

    device.device_type = Some("PLC/RTU".to_string());
    Ok(device)
}

/// 探测 Modbus 端口是否开放
pub async fn probe(host: &str, port: u16, timeout_ms: u64) -> bool {
    // 尝试读取 0 个线圈，如果响应正确则确认是 Modbus
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&0u16.to_be_bytes()); // start_addr = 0
    data.extend_from_slice(&1u16.to_be_bytes()); // count = 1

    let request = build_mbap_request(1, 1, 0x01, &data);
    send_modbus_request(host, port, &request, timeout_ms)
        .await
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mbap_request() {
        let req = build_mbap_request(1, 1, 0x03, &[0x00, 0x00, 0x00, 0x0A]);
        // MBAP: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1) = 7
        // PDU: fn_code(1) + data(4) = 5
        assert_eq!(req.len(), 12);
        // transaction_id = 1
        assert_eq!(&req[0..2], &1u16.to_be_bytes());
        // protocol_id = 0
        assert_eq!(&req[2..4], &0u16.to_be_bytes());
        // length = 6 (unit_id + fn_code + data = 1+1+4)
        assert_eq!(&req[4..6], &6u16.to_be_bytes());
        // unit_id = 1
        assert_eq!(req[6], 1);
        // fn_code = 0x03
        assert_eq!(req[7], 0x03);
    }

    #[test]
    fn test_modbus_read_coils_response_parse() {
        // 模拟响应: MBAP(7) + fn(1) + byte_count(1) + data(1)
        let response: Vec<u8> = vec![
            0x00, 0x01, // transaction_id
            0x00, 0x00, // protocol_id
            0x00, 0x04, // length
            0x01, // unit_id
            0x01, // function_code
            0x01, // byte_count
            0x05, // coil data: 00000101 (coils 0,2 = true)
        ];

        let byte_count = response[8] as usize;
        assert_eq!(byte_count, 1);
        let coil_data = &response[9..10];

        let mut coils = vec![false; 4];
        for i in 0..4 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            coils[i] = (coil_data[byte_idx] >> bit_idx) & 1 == 1;
        }
        assert!(coils[0]); // bit 0 = 1
        assert!(!coils[1]); // bit 1 = 0
        assert!(coils[2]); // bit 2 = 1
        assert!(!coils[3]); // bit 3 = 0
    }

    #[test]
    fn test_protocol_port() {
        assert_eq!(IcsProtocol::ModbusTcp.port(), 502);
        assert_eq!(IcsProtocol::S7Comm.port(), 102);
        assert_eq!(IcsProtocol::Iec104.port(), 2404);
    }
}
