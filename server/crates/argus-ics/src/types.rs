//! 工控协议类型定义

use serde::{Deserialize, Serialize};

/// 工控协议
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IcsProtocol {
    ModbusTcp,
    S7Comm,
    Iec104,
    /// PROFINET DCP (以太网层多播探测，非 TCP 端口)
    ProfinetDcp,
    /// Mitsubishi MELSEC MC Protocol (端口 1281)
    Melsec,
    /// Omron FINS TCP (端口 9600)
    Fins,
    /// Emerson HART-IP (UDP 端口 5094)
    HartIp,
    /// FOUNDATION Fieldbus HSE (TCP 端口 1089)
    FieldbusHse,
}

impl IcsProtocol {
    pub fn port(&self) -> u16 {
        match self {
            IcsProtocol::ModbusTcp => 502,
            IcsProtocol::S7Comm => 102,
            IcsProtocol::Iec104 => 2404,
            // PROFINET DCP 工作在以太网层（Ethertype 0x8892），无 TCP/UDP 端口
            IcsProtocol::ProfinetDcp => 0,
            // G6.3: Mitsubishi MELSEC 默认端口 1281
            IcsProtocol::Melsec => 1281,
            // G6.4: Omron FINS TCP 默认端口 9600
            IcsProtocol::Fins => 9600,
            // G6.5: Emerson HART-IP 默认 UDP 端口 5094
            IcsProtocol::HartIp => 5094,
            // G6.5: FOUNDATION Fieldbus HSE 默认 TCP 端口 1089
            IcsProtocol::FieldbusHse => 1089,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IcsProtocol::ModbusTcp => "modbus",
            IcsProtocol::S7Comm => "s7",
            IcsProtocol::Iec104 => "iec104",
            IcsProtocol::ProfinetDcp => "profinet-dcp",
            IcsProtocol::Melsec => "melsec",
            IcsProtocol::Fins => "fins",
            IcsProtocol::HartIp => "hart-ip",
            IcsProtocol::FieldbusHse => "fieldbus-hse",
        }
    }
}

/// 工控设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsDevice {
    pub host: String,
    pub port: u16,
    pub protocol: IcsProtocol,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub device_type: Option<String>,
    pub raw_response: Option<serde_json::Value>,
}

impl IcsDevice {
    pub fn new(host: impl Into<String>, port: u16, protocol: IcsProtocol) -> Self {
        Self {
            host: host.into(),
            port,
            protocol,
            vendor: None,
            model: None,
            firmware: None,
            device_type: None,
            raw_response: None,
        }
    }
}

/// IEC 104 ASDU
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iec104Asdu {
    pub type_id: u8,
    pub cause_of_transmission: u8,
    pub common_addr: u16,
    pub information_objects: Vec<InformationObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformationObject {
    pub address: u32,
    pub value: serde_json::Value,
}

/// 工控扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsScanResult {
    pub host: String,
    pub devices: Vec<IcsDevice>,
    pub errors: Vec<String>,
}

impl IcsScanResult {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            devices: vec![],
            errors: vec![],
        }
    }
}
