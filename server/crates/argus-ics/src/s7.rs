//! S7 Comm 协议（端口 102）
//!
//! TPKT (RFC 1006): version(1) + reserved(1) + length(2)
//! COTP: length(1) + PDU_type(1) + ...
//! S7: header + parameter + data

use crate::types::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 构建 TPKT+COTP 请求
fn build_tpkt_cotp(cotp_pdu: &[u8]) -> Vec<u8> {
    let total_len = 4 + 1 + cotp_pdu.len(); // TPKT(4) + COTP length(1) + PDU
    let mut buf = Vec::with_capacity(total_len);
    // TPKT 头
    buf.push(0x03); // version
    buf.push(0x00); // reserved
    buf.extend_from_slice(&(total_len as u16).to_be_bytes());
    // COTP 头
    buf.push(cotp_pdu.len() as u8); // COTP length (不含自身)
    buf.extend_from_slice(cotp_pdu);
    buf
}

/// 发送 S7 请求并读取响应
async fn send_s7_request(
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

    // 读取 TPKT 头 (4 bytes)
    let mut tpkt_header = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut tpkt_header))
        .await
        .map_err(|_| "读取 TPKT 头超时".to_string())?
        .map_err(|e| format!("读取 TPKT 头失败: {e}"))?;

    let total_len = u16::from_be_bytes([tpkt_header[2], tpkt_header[3]]) as usize;
    if total_len < 4 {
        return Err(format!("无效的 TPKT 长度: {total_len}"));
    }

    // 读取剩余数据
    let mut data = vec![0u8; total_len - 4];
    if !data.is_empty() {
        tokio::time::timeout(timeout, stream.read_exact(&mut data))
            .await
            .map_err(|_| "读取数据超时".to_string())?
            .map_err(|e| format!("读取数据失败: {e}"))?;
    }

    let mut response = Vec::with_capacity(total_len);
    response.extend_from_slice(&tpkt_header);
    response.extend_from_slice(&data);
    Ok(response)
}

/// 建立 S7 通信连接 (Communication Setup)
pub async fn setup_connection(host: &str, port: u16, timeout_ms: u64) -> Result<(), String> {
    // COTP Connect Request: CR TPDU
    // COTP: length(1) + PDU_type(1=CR) + dst_ref(2) + src_ref(2) + class(1) + params
    let cotp_pdu = vec![
        0x11, 0x00, 0x00, 0x00, 0x01, 0x00, // CR TPDU header
        0x00, 0x0F, 0x00, 0x01, // TPDU Size parameter: 0xF0 = 1024 bytes
        0x00, 0x08, 0x00, 0x00, // TSAP parameters
        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];
    let request = build_tpkt_cotp(&cotp_pdu);
    let _response = send_s7_request(host, port, &request, timeout_ms).await?;
    Ok(())
}

/// 读取设备信息（通过 SZL 0x011C）
pub async fn read_device_info(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<IcsDevice, String> {
    let mut device = IcsDevice::new(host, port, IcsProtocol::S7Comm);

    // 先建立连接
    if let Err(e) = setup_connection(host, port, timeout_ms).await {
        device.raw_response = Some(serde_json::json!({"error": format!("连接失败: {e}")}));
        device.device_type = Some("Unknown".to_string());
        return Ok(device);
    }

    // 构建读 SZL 请求
    // S7 头: 0x32 + header_type(1) + reserved(2) + pdu_ref(2) + param_len(2) + data_len(2)
    // 读请求参数: 0x04 + item_count(1) + item_header(4) + item_data(4)
    let s7_request = vec![
        // TPKT
        0x03, 0x00, 0x00, 0x1F, // TPKT: version=3, length=31
        // COTP DT
        0x02, 0xF0, 0x80, // DT TPDU: length=2, EOT=1
        // S7 Header
        0x32, // Protocol ID
        0x01, // ROSCTR: Job (1)
        0x00, 0x00, // Reserved
        0x00, 0x01, // PDU Reference
        0x00, 0x08, // Parameter length
        0x00, 0x00, // Data length
        // Parameter
        0x04, // Function: Read
        0x01, // Item count
        // Item header
        0x12, // Variable spec
        0x0A, // Length of spec: 10
        0x10, // Syntax ID: S7ANY
        0x00, // Transport size: BYTE
        0x00, 0x06, // Data length: 6
        0x00, 0x01, // DB number
        0x00, 0x1C, // SZL ID: 0x011C (Module identification)
        0x00, 0x01, // Address: 1
    ];

    match send_s7_request_raw(host, port, &s7_request, timeout_ms).await {
        Ok(response) => {
            device.vendor = Some("Siemens".to_string());
            device.device_type = Some("PLC".to_string());
            device.raw_response = Some(serde_json::json!({
                "response_length": response.len(),
                "identified": true,
            }));
        }
        Err(e) => {
            device.raw_response = Some(serde_json::json!({
                "error": e,
                "identified_by_port": true,
            }));
            device.vendor = Some("Siemens".to_string()); // 端口 102 开放基本可确认是 Siemens
            device.device_type = Some("PLC".to_string());
        }
    }

    Ok(device)
}

/// 发送原始 S7 请求
async fn send_s7_request_raw(
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

    // 读取 TPKT 头
    let mut tpkt_header = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut tpkt_header))
        .await
        .map_err(|_| "读取 TPKT 超时".to_string())?
        .map_err(|e| format!("读取失败: {e}"))?;

    let total_len = u16::from_be_bytes([tpkt_header[2], tpkt_header[3]]) as usize;
    let mut data = vec![0u8; total_len.saturating_sub(4)];
    if !data.is_empty() {
        let _ = tokio::time::timeout(timeout, stream.read_exact(&mut data)).await;
    }

    let mut response = Vec::with_capacity(total_len);
    response.extend_from_slice(&tpkt_header);
    response.extend_from_slice(&data);
    Ok(response)
}

/// 探测 S7 端口
pub async fn probe(host: &str, port: u16, timeout_ms: u64) -> bool {
    // 尝试建立连接
    let addr = format!("{host}:{port}");
    let timeout = Duration::from_millis(timeout_ms);
    tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpkt_cotp_construction() {
        let cotp_pdu = vec![0x02, 0xF0, 0x80];
        let buf = build_tpkt_cotp(&cotp_pdu);
        // TPKT(4) + COTP length(1) + COTP PDU(3) = 8
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[0], 0x03); // version
        // length = 8
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 8);
    }

    #[test]
    fn test_s7_protocol_id() {
        // S7 请求以 0x32 作为协议标识
        let s7_request = vec![
            0x03, 0x00, 0x00, 0x1F, 0x02, 0xF0, 0x80, 0x32, // 0x32 = S7 Protocol ID
        ];
        assert_eq!(s7_request[7], 0x32);
    }
}
