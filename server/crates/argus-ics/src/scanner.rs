//! IcsScanner 实现 Scanner trait

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use async_trait::async_trait;
use argus_scanner::{Scanner, ScanConfig, ScanResult, ScannerError};
use argus_engine::PluginResult;
use argus_core::entity::task::TaskStatus;
use crate::types::*;
use crate::{modbus, s7, iec104, profinet_dcp, melsec, fins, emerson};

pub struct IcsScanner {
    progress: Arc<RwLock<HashMap<String, f32>>>,
}

impl IcsScanner {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for IcsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for IcsScanner {
    fn name(&self) -> &str {
        "ics_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();
        let total = config.targets.len();

        let mut all_devices = Vec::new();
        let mut all_vulns = Vec::new();

        for (i, target) in config.targets.iter().enumerate() {
            let mut scan_result = IcsScanResult::new(&target.host);
            let timeout_ms = (config.timeout_secs * 1000) as u64;

            // Modbus 探测 (端口 502)
            let modbus_port = IcsProtocol::ModbusTcp.port();
            if modbus::probe(&target.host, modbus_port, timeout_ms).await {
                match modbus::identify_device(&target.host, modbus_port, 1, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        // 工控设备暴露 = info 级别
                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, modbus_port),
                            "工控设备暴露: Modbus TCP".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(modbus_port);
                        pr.service = Some("modbus".to_string());
                        pr.evidence = format!("Modbus TCP 端口 {} 开放", modbus_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            // S7 探测 (端口 102)
            let s7_port = IcsProtocol::S7Comm.port();
            if s7::probe(&target.host, s7_port, timeout_ms).await {
                match s7::read_device_info(&target.host, s7_port, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, s7_port),
                            "工控设备暴露: S7 Comm".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(s7_port);
                        pr.service = Some("s7".to_string());
                        pr.evidence = format!("S7 Comm 端口 {} 开放", s7_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            // IEC 104 探测 (端口 2404)
            let iec_port = IcsProtocol::Iec104.port();
            if iec104::probe(&target.host, iec_port, timeout_ms).await {
                let device = IcsDevice {
                    host: target.host.clone(),
                    port: iec_port,
                    protocol: IcsProtocol::Iec104,
                    vendor: None,
                    model: None,
                    firmware: None,
                    device_type: Some("RTU/Server".to_string()),
                    raw_response: Some(serde_json::json!({"identified_by_port": true})),
                };
                scan_result.devices.push(device.clone());

                let mut pr = PluginResult::new(
                    format!("{}:{}", target.host, iec_port),
                    "工控设备暴露: IEC 104".to_string(),
                    "info".to_string(),
                );
                pr.port = Some(iec_port);
                pr.service = Some("iec104".to_string());
                pr.evidence = format!("IEC 104 端口 {} 开放", iec_port);
                all_vulns.push(pr);
            }

            // PROFINET DCP 发现（以太网层多播探测）
            // 在所有网络接口上尝试 DCP Identify 请求
            for iface_name in profinet_dcp::list_interfaces() {
                match profinet_dcp::discover_devices(
                    &iface_name,
                    std::time::Duration::from_millis(timeout_ms),
                    50,
                ) {
                    Ok(pn_devices) => {
                        for pn_dev in pn_devices {
                            let mut pr = PluginResult::new(
                                format!("{}:{}", pn_dev.mac_address, iface_name),
                                "工控设备暴露: PROFINET DCP".to_string(),
                                "info".to_string(),
                            );
                            pr.service = Some("profinet-dcp".to_string());
                            pr.evidence = format!(
                                "PROFINET 设备 MAC={} name={:?} vendor={:?} ip={:?}",
                                pn_dev.mac_address,
                                pn_dev.device_name,
                                pn_dev.vendor_name,
                                pn_dev.ip_address
                            );
                            all_vulns.push(pr);

                            let ics_dev = pn_dev.to_ics_device(&iface_name);
                            scan_result.devices.push(ics_dev);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("PROFINET DCP 发现失败 (接口 {}): {}", iface_name, e);
                    }
                }
            }

            // G6.3: Mitsubishi MELSEC 探测 (端口 1281)
            let melsec_port = IcsProtocol::Melsec.port();
            if melsec::probe(&target.host, melsec_port, timeout_ms).await {
                match melsec::read_device_info(&target.host, melsec_port, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, melsec_port),
                            "工控设备暴露: Mitsubishi MELSEC".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(melsec_port);
                        pr.service = Some("melsec".to_string());
                        pr.evidence = format!("MELSEC MC Protocol 端口 {} 开放", melsec_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            // G6.4: Omron FINS TCP 探测 (端口 9600)
            let fins_port = IcsProtocol::Fins.port();
            if fins::probe(&target.host, fins_port, timeout_ms).await {
                match fins::read_controller_info(&target.host, fins_port, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, fins_port),
                            "工控设备暴露: Omron FINS".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(fins_port);
                        pr.service = Some("fins".to_string());
                        pr.evidence = format!("Omron FINS TCP 端口 {} 开放", fins_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            // G6.5: Emerson HART-IP 探测 (UDP 端口 5094)
            let hart_port = IcsProtocol::HartIp.port();
            if emerson::probe_hart(&target.host, hart_port, timeout_ms).await {
                match emerson::read_hart_device_info(&target.host, hart_port, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, hart_port),
                            "工控设备暴露: Emerson HART-IP".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(hart_port);
                        pr.service = Some("hart-ip".to_string());
                        pr.evidence = format!("HART-IP UDP 端口 {} 可达", hart_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            // G6.5: FOUNDATION Fieldbus HSE 探测 (TCP 端口 1089)
            let ff_port = IcsProtocol::FieldbusHse.port();
            if emerson::probe_ff_hse(&target.host, ff_port, timeout_ms).await {
                match emerson::read_ff_hse_device_info(&target.host, ff_port, timeout_ms).await {
                    Ok(device) => {
                        scan_result.devices.push(device);

                        let mut pr = PluginResult::new(
                            format!("{}:{}", target.host, ff_port),
                            "工控设备暴露: FOUNDATION Fieldbus HSE".to_string(),
                            "info".to_string(),
                        );
                        pr.port = Some(ff_port);
                        pr.service = Some("fieldbus-hse".to_string());
                        pr.evidence = format!("FF HSE TCP 端口 {} 开放", ff_port);
                        all_vulns.push(pr);
                    }
                    Err(e) => scan_result.errors.push(e),
                }
            }

            all_devices.push(scan_result);

            // 更新进度
            let progress = ((i + 1) as f32) / total as f32;
            if let Ok(mut map) = self.progress.write() {
                map.insert(task_id.clone(), progress);
            }
        }

        let duration = start.elapsed().as_secs_f64();

        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: TaskStatus::Completed,
            hosts_scanned: total,
            vulnerabilities: all_vulns,
            duration_secs: duration,
            raw_data: Some(
                serde_json::to_value(&all_devices).unwrap_or(serde_json::Value::Null),
            ),
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        if let Ok(map) = self.progress.read() {
            Ok(map.get(task_id).copied().unwrap_or(0.0))
        } else {
            Ok(0.0)
        }
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.to_string(), -1.0);
        }
        Ok(())
    }
}
