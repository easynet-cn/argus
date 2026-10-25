//! PROFINET DCP (Discovery and Configuration Protocol) 协议实现
//!
//! 真实实现 PROFINET 设备发现（基于以太网层多播，IEC 61158 / PN-DCP）：
//! 1. 构造 DCP Identify Broadcast 请求帧（Ethertype 0x8892，多播 MAC 01:0E:CF:00:00:00）
//! 2. 通过 pnet_datalink 在指定网络接口发送原始以太网帧
//! 3. 接收并解析 DCP Identify 响应
//! 4. 提取设备名称、厂商、IP 地址、MAC 地址、设备角色等信息
//!
//! 限制：需要 root/raw socket 权限；macOS 上需要 sudo 执行

use std::time::{Duration, Instant};

use pnet_datalink::interfaces;

use crate::types::{IcsDevice, IcsProtocol};

// ==================== 协议常量 ====================

/// PROFINET Ethertype
const PN_ETHERTYPE: u16 = 0x8892;

/// DCP 多播目标 MAC (01:0E:CF:00:00:00)
const DCP_MULTICAST_MAC: [u8; 6] = [0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00];

/// DCP Identify Broadcast 请求 Frame ID
const FRAME_ID_DCP_IDENTIFY_BCAST_REQ: u16 = 0xFEFD;

/// DCP Identify Response Frame ID
const FRAME_ID_DCP_IDENTIFY_RSP: u16 = 0xFEFE;

/// DCP Service: Identify
const DCP_SERVICE_IDENTIFY: u8 = 0x05;

/// DCP Service Type: Request
const DCP_SERVICE_TYPE_REQUEST: u8 = 0x00;

/// DCP Service Type: Response
const DCP_SERVICE_TYPE_RESPONSE: u8 = 0x01;

/// DCP Option: Device Properties
const DCP_OPTION_DEVICE_PROPERTIES: u8 = 0x05;

/// DCP Suboption: Device Vendor (0x01)
const DCP_SUBOPTION_VENDOR: u8 = 0x01;

/// DCP Suboption: Device Name (0x02)
const DCP_SUBOPTION_DEVICE_NAME: u8 = 0x02;

/// DCP Suboption: Device Role (0x04)
const DCP_SUBOPTION_DEVICE_ROLE: u8 = 0x04;

/// DCP Suboption: Device ID (0x05)
const DCP_SUBOPTION_DEVICE_ID: u8 = 0x05;

/// DCP Suboption: IP (0x03)
const DCP_SUBOPTION_IP: u8 = 0x03;

/// DCP Option: All (0xFF)
const DCP_OPTION_ALL: u8 = 0xFF;

/// DCP Suboption: All (0xFF)
const DCP_SUBOPTION_ALL: u8 = 0xFF;

// ==================== DCP 设备发现结果 ====================

/// PROFINET DCP 发现的设备信息
#[derive(Debug, Clone)]
pub struct ProfinetDevice {
    pub mac_address: String,
    pub device_name: Option<String>,
    pub vendor_name: Option<String>,
    pub device_id: Option<String>,
    pub device_role: Option<u8>,
    pub ip_address: Option<String>,
    pub netmask: Option<String>,
    pub gateway: Option<String>,
    pub raw_response: Vec<u8>,
}

impl ProfinetDevice {
    pub fn to_ics_device(&self, interface_name: &str) -> IcsDevice {
        let mut device = IcsDevice::new(interface_name, 0, IcsProtocol::ProfinetDcp);
        device.vendor = self.vendor_name.clone();
        device.model = self.device_id.clone();
        device.device_type = self.device_role.map(|r| match r {
            0 => "IO Controller".to_string(),
            1 => "IO Device".to_string(),
            2 => "IO Supervisor".to_string(),
            _ => format!("Unknown Role ({r})"),
        });
        device.raw_response = Some(serde_json::json!({
            "mac": self.mac_address,
            "name": self.device_name,
            "ip": self.ip_address,
            "device_id": self.device_id,
            "vendor": self.vendor_name,
        }));
        device
    }
}

// ==================== 以太网帧构造 ====================

/// 构造 DCP Identify Broadcast 请求帧
///
/// 帧结构：
/// - Ethernet Header (14 bytes): Dst MAC(6) + Src MAC(6) + Ethertype(2)
/// - PN Frame: FrameID(2) + DCP Header(10) + DCP Data
pub fn build_dcp_identify_request(src_mac: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);

    // === Ethernet Header ===
    // Dst MAC: DCP 多播地址
    frame.extend_from_slice(&DCP_MULTICAST_MAC);
    // Src MAC: 本机接口 MAC
    frame.extend_from_slice(&src_mac);
    // Ethertype: PROFINET (0x8892)
    frame.extend_from_slice(&PN_ETHERTYPE.to_be_bytes());

    // === PN Frame Header ===
    // Frame ID: DCP Identify Broadcast Request (0xFEFD)
    frame.extend_from_slice(&FRAME_ID_DCP_IDENTIFY_BCAST_REQ.to_be_bytes());

    // === DCP Header (10 bytes) ===
    // Service ID: Identify (0x05)
    frame.push(DCP_SERVICE_IDENTIFY);
    // Service Type: Request (0x00)
    frame.push(DCP_SERVICE_TYPE_REQUEST);
    // XID: 事务标识（4 bytes，使用固定值 0x00000001）
    frame.extend_from_slice(&1u32.to_be_bytes());
    // Response Delay Indicator (2 bytes): 0 for request
    frame.extend_from_slice(&0u16.to_be_bytes());
    // DCP Data Length (2 bytes): will fill later
    let data_len_pos = frame.len();
    frame.extend_from_slice(&0u16.to_be_bytes()); // placeholder

    // === DCP Data ===
    // Option: All (0xFF) — query all properties
    frame.push(DCP_OPTION_ALL);
    // Suboption: All (0xFF)
    frame.push(DCP_SUBOPTION_ALL);
    // Suboption Data Length: 0 (we want all properties)
    frame.extend_from_slice(&0u16.to_be_bytes());
    // Suboption Data: none

    // Fill in DCP Data Length
    let dcp_data_len = frame.len() - (data_len_pos + 2);
    let data_len_bytes = (dcp_data_len as u16).to_be_bytes();
    frame[data_len_pos] = data_len_bytes[0];
    frame[data_len_pos + 1] = data_len_bytes[1];

    // Pad to minimum Ethernet frame size (60 bytes without FCS)
    while frame.len() < 60 {
        frame.push(0x00);
    }

    frame
}

// ==================== DCP 响应解析 ====================

/// 解析 DCP Identify 响应帧
///
/// 从完整的以太网帧中提取 DCP 设备信息
pub fn parse_dcp_identify_response(frame: &[u8]) -> Option<ProfinetDevice> {
    // 最小帧长度: Ethernet(14) + FrameID(2) + DCP Header(10) = 26
    if frame.len() < 26 {
        return None;
    }

    // 检查 Ethertype
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != PN_ETHERTYPE {
        return None;
    }

    // 提取源 MAC（响应设备的 MAC）
    let src_mac = &frame[6..12];

    // 检查 Frame ID
    let frame_id = u16::from_be_bytes([frame[14], frame[15]]);
    if frame_id != FRAME_ID_DCP_IDENTIFY_RSP {
        return None;
    }

    // DCP Header 从 offset 16 开始
    let dcp_start = 16;
    if frame.len() < dcp_start + 10 {
        return None;
    }

    let service_id = frame[dcp_start];
    let service_type = frame[dcp_start + 1];

    // 只处理 Identify Response
    if service_id != DCP_SERVICE_IDENTIFY || service_type != DCP_SERVICE_TYPE_RESPONSE {
        return None;
    }

    // XID (4 bytes)
    // Response Delay (2 bytes)
    // DCP Data Length (2 bytes)
    let dcp_data_len = u16::from_be_bytes([frame[dcp_start + 8], frame[dcp_start + 9]]) as usize;

    // DCP Data 从 offset dcp_start + 10 开始
    let dcp_data_start = dcp_start + 10;
    if frame.len() < dcp_data_start + dcp_data_len {
        return None;
    }

    let dcp_data = &frame[dcp_data_start..dcp_data_start + dcp_data_len];

    let mut device = ProfinetDevice {
        mac_address: format_mac_address(src_mac),
        device_name: None,
        vendor_name: None,
        device_id: None,
        device_role: None,
        ip_address: None,
        netmask: None,
        gateway: None,
        raw_response: frame[..frame.len().min(256)].to_vec(),
    };

    // 解析 DCP Data 中的 TLV 块
    let mut pos = 0;
    while pos + 4 <= dcp_data.len() {
        let option = dcp_data[pos];
        let suboption = dcp_data[pos + 1];
        let block_len = u16::from_be_bytes([dcp_data[pos + 2], dcp_data[pos + 3]]) as usize;
        pos += 4;

        if pos + block_len > dcp_data.len() {
            break;
        }

        let block_data = &dcp_data[pos..pos + block_len];

        match (option, suboption) {
            (DCP_OPTION_DEVICE_PROPERTIES, DCP_SUBOPTION_DEVICE_NAME) => {
                device.device_name = String::from_utf8(block_data.to_vec()).ok();
            }
            (DCP_OPTION_DEVICE_PROPERTIES, DCP_SUBOPTION_VENDOR) => {
                device.vendor_name = String::from_utf8(block_data.to_vec()).ok();
            }
            (DCP_OPTION_DEVICE_PROPERTIES, DCP_SUBOPTION_DEVICE_ID) => {
                // Device ID: vendor_id(2) + device_id(2)
                if block_data.len() >= 4 {
                    let vendor_id = u16::from_be_bytes([block_data[0], block_data[1]]);
                    let dev_id = u16::from_be_bytes([block_data[2], block_data[3]]);
                    device.device_id = Some(format!("0x{vendor_id:04X}/0x{dev_id:04X}"));
                }
            }
            (DCP_OPTION_DEVICE_PROPERTIES, DCP_SUBOPTION_DEVICE_ROLE) => {
                if !block_data.is_empty() {
                    device.device_role = Some(block_data[0]);
                }
            }
            (DCP_OPTION_DEVICE_PROPERTIES, DCP_SUBOPTION_IP) => {
                // IP: IP(4) + Netmask(4) + Gateway(4) + DNS(4+4)
                if block_data.len() >= 12 {
                    device.ip_address = Some(format_ip(&block_data[0..4]));
                    device.netmask = Some(format_ip(&block_data[4..8]));
                    device.gateway = Some(format_ip(&block_data[8..12]));
                }
            }
            _ => {}
        }

        pos += block_len;
        // 对齐到 4 字节边界（padding）
        let padding = (4 - (block_len % 4)) % 4;
        pos += padding;
    }

    Some(device)
}

// ==================== DCP 发现执行 ====================

/// 在指定网络接口上执行 PROFINET DCP 设备发现
///
/// 发送 DCP Identify Broadcast 请求，收集响应并返回设备列表。
///
/// 参数：
/// - `interface_name`: 网络接口名（如 "eth0"、"en0"）
/// - `timeout`: 等待响应的超时时间
/// - `max_devices`: 最多收集多少个设备响应
///
/// 注意：需要 root 权限才能发送/接收原始以太网帧
pub fn discover_devices(
    interface_name: &str,
    timeout: Duration,
    max_devices: usize,
) -> Result<Vec<ProfinetDevice>, String> {
    // 获取网络接口
    let interfaces = interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| format!("网络接口 '{interface_name}' 不存在"))?;

    // 获取接口 MAC
    let src_mac = interface
        .mac
        .ok_or_else(|| format!("接口 '{interface_name}' 无 MAC 地址"))?
        .octets();

    // 打开数据链路层通道
    let config = pnet_datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(timeout),
        write_timeout: Some(timeout),
        channel_type: pnet_datalink::ChannelType::Layer2,
        ..Default::default()
    };

    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, config) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("不支持的链路层类型".to_string()),
        Err(e) => return Err(format!("打开接口 '{interface_name}' 失败: {e}")),
    };

    // 构造并发送 DCP Identify 请求
    let request = build_dcp_identify_request(src_mac);
    match tx.send_to(&request, None) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(format!("DCP 请求发送失败: {e}")),
        None => return Err("DCP 请求发送失败: 缓冲区不足".to_string()),
    }

    // 接收响应
    let start = Instant::now();
    let mut devices = Vec::new();

    while start.elapsed() < timeout && devices.len() < max_devices {
        match rx.next() {
            Ok(packet) => {
                if let Some(device) = parse_dcp_identify_response(packet) {
                    // 去重：同一个 MAC 只记录一次
                    if !devices.iter().any(|d: &ProfinetDevice| d.mac_address == device.mac_address) {
                        devices.push(device);
                    }
                }
            }
            Err(_) => break, // 超时或错误
        }
    }

    tracing::info!(
        "PROFINET DCP 发现在接口 {} 上发现 {} 台设备",
        interface_name,
        devices.len()
    );

    Ok(devices)
}

/// 列出所有可用的网络接口
pub fn list_interfaces() -> Vec<String> {
    interfaces()
        .into_iter()
        .filter(|i| i.mac.is_some() && !i.is_loopback())
        .map(|i| i.name)
        .collect()
}

// ==================== 工具函数 ====================

fn format_mac_address(mac: &[u8]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_ip(ip: &[u8]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dcp_identify_request_structure() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = build_dcp_identify_request(src_mac);

        // 最小以太网帧长度 60 bytes
        assert!(frame.len() >= 60);

        // 目标 MAC = DCP 多播地址
        assert_eq!(&frame[0..6], &DCP_MULTICAST_MAC);
        // 源 MAC
        assert_eq!(&frame[6..12], &src_mac);
        // Ethertype = 0x8892
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), PN_ETHERTYPE);
        // Frame ID = 0xFEFD
        assert_eq!(u16::from_be_bytes([frame[14], frame[15]]), FRAME_ID_DCP_IDENTIFY_BCAST_REQ);
        // Service ID = Identify
        assert_eq!(frame[16], DCP_SERVICE_IDENTIFY);
        // Service Type = Request
        assert_eq!(frame[17], DCP_SERVICE_TYPE_REQUEST);
    }

    #[test]
    fn test_parse_dcp_response_with_device_name() {
        // 构造模拟 DCP Identify Response
        let mut frame = vec![0u8; 0];

        // Ethernet Header
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC (不检查)
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Src MAC (设备 MAC)
        frame.extend_from_slice(&PN_ETHERTYPE.to_be_bytes());

        // Frame ID = Identify Response
        frame.extend_from_slice(&FRAME_ID_DCP_IDENTIFY_RSP.to_be_bytes());

        // DCP Header
        frame.push(DCP_SERVICE_IDENTIFY);       // Service ID
        frame.push(DCP_SERVICE_TYPE_RESPONSE);  // Service Type
        frame.extend_from_slice(&1u32.to_be_bytes()); // XID
        frame.extend_from_slice(&0u16.to_be_bytes()); // Response Delay
        let data_len_pos = frame.len();
        frame.extend_from_slice(&0u16.to_be_bytes()); // DCP Data Length (placeholder)

        // DCP Data: Device Name
        let name = "my-profinet-device";
        frame.push(DCP_OPTION_DEVICE_PROPERTIES); // Option
        frame.push(DCP_SUBOPTION_DEVICE_NAME);     // Suboption
        frame.extend_from_slice(&(name.len() as u16).to_be_bytes());
        frame.extend_from_slice(name.as_bytes());
        // Padding to 4-byte boundary
        let pad = (4 - (name.len() % 4)) % 4;
        frame.extend(vec![0u8; pad]);

        // Fill DCP Data Length
        let dcp_data_len = frame.len() - (data_len_pos + 2);
        let len_bytes = (dcp_data_len as u16).to_be_bytes();
        frame[data_len_pos] = len_bytes[0];
        frame[data_len_pos + 1] = len_bytes[1];

        // 解析
        let device = parse_dcp_identify_response(&frame);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.mac_address, "AA:BB:CC:DD:EE:FF");
        assert_eq!(device.device_name, Some("my-profinet-device".to_string()));
    }

    #[test]
    fn test_parse_dcp_response_with_ip() {
        let mut frame = vec![0u8; 0];

        // Ethernet Header
        frame.extend_from_slice(&[0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        frame.extend_from_slice(&PN_ETHERTYPE.to_be_bytes());

        // Frame ID
        frame.extend_from_slice(&FRAME_ID_DCP_IDENTIFY_RSP.to_be_bytes());

        // DCP Header
        frame.push(DCP_SERVICE_IDENTIFY);
        frame.push(DCP_SERVICE_TYPE_RESPONSE);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        let data_len_pos = frame.len();
        frame.extend_from_slice(&0u16.to_be_bytes());

        // DCP Data: IP
        frame.push(DCP_OPTION_DEVICE_PROPERTIES);
        frame.push(DCP_SUBOPTION_IP);
        frame.extend_from_slice(&12u16.to_be_bytes()); // block length = 12
        frame.extend_from_slice(&[192, 168, 1, 10]);   // IP
        frame.extend_from_slice(&[255, 255, 255, 0]);  // Netmask
        frame.extend_from_slice(&[192, 168, 1, 1]);     // Gateway

        // Fill DCP Data Length
        let dcp_data_len = frame.len() - (data_len_pos + 2);
        let len_bytes = (dcp_data_len as u16).to_be_bytes();
        frame[data_len_pos] = len_bytes[0];
        frame[data_len_pos + 1] = len_bytes[1];

        let device = parse_dcp_identify_response(&frame);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.ip_address, Some("192.168.1.10".to_string()));
        assert_eq!(device.netmask, Some("255.255.255.0".to_string()));
        assert_eq!(device.gateway, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_parse_dcp_response_wrong_ethertype() {
        let frame = vec![0u8; 64]; // 全零帧
        assert!(parse_dcp_identify_response(&frame).is_none());
    }

    #[test]
    fn test_parse_dcp_response_too_short() {
        let frame = vec![0u8; 10]; // 过短
        assert!(parse_dcp_identify_response(&frame).is_none());
    }

    #[test]
    fn test_parse_dcp_response_device_role() {
        let mut frame = vec![0u8; 0];

        // Ethernet Header
        frame.extend_from_slice(&[0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        frame.extend_from_slice(&PN_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&FRAME_ID_DCP_IDENTIFY_RSP.to_be_bytes());

        // DCP Header
        frame.push(DCP_SERVICE_IDENTIFY);
        frame.push(DCP_SERVICE_TYPE_RESPONSE);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        let data_len_pos = frame.len();
        frame.extend_from_slice(&0u16.to_be_bytes());

        // DCP Data: Device Role = IO Controller (0)
        frame.push(DCP_OPTION_DEVICE_PROPERTIES);
        frame.push(DCP_SUBOPTION_DEVICE_ROLE);
        frame.extend_from_slice(&1u16.to_be_bytes()); // block length
        frame.push(0x00); // IO Controller
        frame.extend_from_slice(&[0u8; 3]); // padding

        // Fill DCP Data Length
        let dcp_data_len = frame.len() - (data_len_pos + 2);
        let len_bytes = (dcp_data_len as u16).to_be_bytes();
        frame[data_len_pos] = len_bytes[0];
        frame[data_len_pos + 1] = len_bytes[1];

        let device = parse_dcp_identify_response(&frame);
        assert!(device.is_some());
        let device = device.unwrap();
        assert_eq!(device.device_role, Some(0));
    }

    #[test]
    fn test_format_mac_address() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac_address(&mac), "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn test_format_ip() {
        let ip = [192, 168, 1, 100];
        assert_eq!(format_ip(&ip), "192.168.1.100");
    }

    #[test]
    fn test_to_ics_device() {
        let device = ProfinetDevice {
            mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
            device_name: Some("test-device".to_string()),
            vendor_name: Some("Siemens".to_string()),
            device_id: Some("0x0001/0x0002".to_string()),
            device_role: Some(1),
            ip_address: Some("192.168.1.10".to_string()),
            netmask: None,
            gateway: None,
            raw_response: vec![],
        };

        let ics_device = device.to_ics_device("eth0");
        assert_eq!(ics_device.protocol, IcsProtocol::ProfinetDcp);
        assert_eq!(ics_device.vendor, Some("Siemens".to_string()));
        assert_eq!(ics_device.device_type, Some("IO Device".to_string()));
    }

    #[test]
    fn test_list_interfaces() {
        // 仅验证函数可调用，不检查具体接口
        let _ = list_interfaces();
    }
}
