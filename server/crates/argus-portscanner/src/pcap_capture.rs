//! G1.4: 网络抓包模块
//!
//! 在扫描任务期间捕获网络流量，任务结束后保存为 pcap 文件（支持下载）。
//! 使用 pcap crate 进行抓包（支持 BPF 过滤规则），手动实现 libpcap 文件格式写入。
//!
//! libpcap 文件格式：
//! - Global Header (24 字节)
//! - Packet Record (16 字节头部 + 包数据)

use std::fs::File;
use std::io::{Error as IoError, Write};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::{LittleEndian, WriteBytesExt};
use thiserror::Error;

/// libpcap 魔数（小端序）
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// libpcap 主版本号
const PCAP_VERSION_MAJOR: u16 = 2;
/// libpcap 次版本号
const PCAP_VERSION_MINOR: u16 = 4;
/// 默认抓包长度（snaplen）
const DEFAULT_SNAPLEN: u32 = 65535;
/// 抓包循环超时（毫秒），用于定期检查停止标志
const CAPTURE_TIMEOUT_MS: i32 = 500;
/// LINKTYPE_ETHERNET = 1（默认数据链路类型）
const LINKTYPE_ETHERNET: u32 = 1;

/// 抓包错误
#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("抓包设备未找到: {0}")]
    DeviceNotFound(String),
    #[error("打开抓包设备失败: {0}")]
    OpenFailed(String),
    #[error("设置 BPF 过滤失败: {0}")]
    FilterFailed(String),
    #[error("抓包已在运行中")]
    AlreadyRunning,
    #[error("抓包未启动")]
    NotRunning,
    #[error("IO 错误: {0}")]
    Io(#[from] IoError),
}

/// 捕获的数据包
#[derive(Clone, Debug)]
pub struct CapturedPacket {
    /// 时间戳（秒）
    pub ts_sec: u32,
    /// 时间戳（微秒）
    pub ts_usec: u32,
    /// 原始包数据（以太网帧）
    pub data: Vec<u8>,
}

/// 抓包配置
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// 网络接口名（如 "en0"、"eth0"）
    pub interface: String,
    /// BPF 过滤规则（如 "tcp port 80"、"host 1.2.3.4"）
    pub filter: Option<String>,
    /// 最大抓包数，None 表示不限
    pub max_packets: Option<usize>,
    /// 最大抓包时长，None 表示不限
    pub max_duration: Option<Duration>,
    /// 抓包长度（snaplen）
    pub snaplen: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: None,
            max_packets: None,
            max_duration: None,
            snaplen: DEFAULT_SNAPLEN,
        }
    }
}

/// Pcap 抓包器
///
/// 在扫描期间捕获网络流量，支持 BPF 过滤，结束后保存为 libpcap 格式文件。
pub struct PcapCapture {
    config: CaptureConfig,
    packets: Arc<Mutex<Vec<CapturedPacket>>>,
    stop_flag: Arc<Mutex<bool>>,
    datalink: Arc<Mutex<Option<u32>>>,
    handle: Option<JoinHandle<()>>,
}

impl PcapCapture {
    /// 创建抓包器
    ///
    /// # Arguments
    /// * `interface` - 网络接口名
    /// * `filter` - BPF 过滤规则（None 表示不过滤）
    pub fn new(interface: &str, filter: Option<&str>) -> Self {
        Self {
            config: CaptureConfig {
                interface: interface.to_string(),
                filter: filter.map(|s| s.to_string()),
                ..Default::default()
            },
            packets: Arc::new(Mutex::new(Vec::new())),
            stop_flag: Arc::new(Mutex::new(false)),
            datalink: Arc::new(Mutex::new(None)),
            handle: None,
        }
    }

    /// 使用完整配置创建抓包器
    pub fn with_config(config: CaptureConfig) -> Self {
        Self {
            config,
            packets: Arc::new(Mutex::new(Vec::new())),
            stop_flag: Arc::new(Mutex::new(false)),
            datalink: Arc::new(Mutex::new(None)),
            handle: None,
        }
    }

    /// 设置最大抓包数（链式调用）
    pub fn max_packets(mut self, max: usize) -> Self {
        self.config.max_packets = Some(max);
        self
    }

    /// 设置最大抓包时长（链式调用）
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.config.max_duration = Some(duration);
        self
    }

    /// 开始抓包（非阻塞，后台线程运行）
    pub fn start(&mut self) -> Result<(), CaptureError> {
        if self.handle.is_some() {
            return Err(CaptureError::AlreadyRunning);
        }
        if self.config.interface.is_empty() {
            return Err(CaptureError::DeviceNotFound(
                "接口名不能为空".to_string(),
            ));
        }

        // 重置状态
        *self.stop_flag.lock().unwrap() = false;
        self.packets.lock().unwrap().clear();
        *self.datalink.lock().unwrap() = None;

        let config = self.config.clone();
        let packets = Arc::clone(&self.packets);
        let stop_flag = Arc::clone(&self.stop_flag);
        let datalink = Arc::clone(&self.datalink);

        let handle = thread::spawn(move || {
            capture_loop(config, packets, stop_flag, datalink);
        });
        self.handle = Some(handle);
        Ok(())
    }

    /// 停止抓包（阻塞直到抓包线程退出）
    pub fn stop(&mut self) {
        *self.stop_flag.lock().unwrap() = true;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// 获取已捕获的数据包
    pub fn get_packets(&self) -> Vec<CapturedPacket> {
        self.packets.lock().unwrap().clone()
    }

    /// 获取已捕获数据包数量
    pub fn packet_count(&self) -> usize {
        self.packets.lock().unwrap().len()
    }

    /// 保存为 pcap 文件（libpcap 格式）
    ///
    /// 写入 Global Header (24 字节) + Packet Records。
    pub fn save(&self, path: &str) -> Result<(), CaptureError> {
        let packets = self.packets.lock().unwrap();
        let datalink = self.datalink.lock().unwrap().unwrap_or(LINKTYPE_ETHERNET);

        let mut file = File::create(path)?;

        // ===== Global Header (24 字节) =====
        // magic_number (4 bytes): 0xa1b2c3d4（小端序）
        file.write_u32::<LittleEndian>(PCAP_MAGIC)?;
        // version_major (2 bytes)
        file.write_u16::<LittleEndian>(PCAP_VERSION_MAJOR)?;
        // version_minor (2 bytes)
        file.write_u16::<LittleEndian>(PCAP_VERSION_MINOR)?;
        // thiszone (4 bytes): GMT 偏移（0）
        file.write_i32::<LittleEndian>(0)?;
        // sigfigs (4 bytes): 时间戳精度（0）
        file.write_u32::<LittleEndian>(0)?;
        // snaplen (4 bytes): 最大包长
        file.write_u32::<LittleEndian>(self.config.snaplen)?;
        // network (4 bytes): 数据链路类型
        file.write_u32::<LittleEndian>(datalink)?;

        // ===== Packet Records =====
        for pkt in packets.iter() {
            // ts_sec (4 bytes): 时间戳秒数
            file.write_u32::<LittleEndian>(pkt.ts_sec)?;
            // ts_usec (4 bytes): 时间戳微秒数
            file.write_u32::<LittleEndian>(pkt.ts_usec)?;
            // incl_len (4 bytes): 文件中保存的包长度
            let incl_len = pkt.data.len() as u32;
            file.write_u32::<LittleEndian>(incl_len)?;
            // orig_len (4 bytes): 原始包长度（假设未截断）
            file.write_u32::<LittleEndian>(incl_len)?;
            // packet data
            file.write_all(&pkt.data)?;
        }

        file.flush()?;
        tracing::info!(
            "pcap 文件已保存: {} ({} 个包, {} 字节)",
            path,
            packets.len(),
            24 + packets
                .iter()
                .map(|p| 16 + p.data.len() as u64)
                .sum::<u64>()
        );
        Ok(())
    }
}

impl Drop for PcapCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 抓包主循环（在后台线程中运行）
fn capture_loop(
    config: CaptureConfig,
    packets: Arc<Mutex<Vec<CapturedPacket>>>,
    stop_flag: Arc<Mutex<bool>>,
    datalink: Arc<Mutex<Option<u32>>>,
) {
    // 创建抓包设备（从接口名构造）
    let cap = match pcap::Capture::from_device(config.interface.as_str()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("创建抓包设备失败 ({}): {}", config.interface, e);
            return;
        }
    };

    let mut cap = match cap
        .promisc(true)
        .snaplen(config.snaplen as i32)
        .timeout(CAPTURE_TIMEOUT_MS)
        .open()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("打开抓包设备失败 ({}): {}", config.interface, e);
            return;
        }
    };

    // 保存数据链路类型
    let linktype = cap.get_datalink().0 as u32;
    *datalink.lock().unwrap() = Some(linktype);

    // 设置 BPF 过滤规则
    if let Some(filter) = &config.filter {
        if !filter.is_empty() {
            if let Err(e) = cap.filter(filter, true) {
                tracing::warn!("设置 BPF 过滤规则失败 ({}): {}", filter, e);
            }
        }
    }

    tracing::info!(
        "开始抓包: 接口={}, 过滤={:?}, snaplen={}, linktype={}",
        config.interface,
        config.filter,
        config.snaplen,
        linktype
    );

    let start_time = SystemTime::now();

    loop {
        // 检查停止标志
        if *stop_flag.lock().unwrap() {
            break;
        }

        // 检查包数限制
        if let Some(max) = config.max_packets {
            if packets.lock().unwrap().len() >= max {
                tracing::info!("达到最大抓包数限制: {}", max);
                break;
            }
        }

        // 检查时长限制
        if let Some(max_dur) = config.max_duration {
            if start_time.elapsed().unwrap_or_default() >= max_dur {
                tracing::info!("达到最大抓包时长限制: {:?}", max_dur);
                break;
            }
        }

        match cap.next_packet() {
            Ok(packet) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let captured = CapturedPacket {
                    ts_sec: now.as_secs() as u32,
                    ts_usec: now.subsec_micros(),
                    data: packet.data.to_vec(),
                };
                packets.lock().unwrap().push(captured);
            }
            Err(pcap::Error::TimeoutExpired) => {
                // 超时，继续循环检查停止标志
                continue;
            }
            Err(e) => {
                tracing::debug!("抓包循环结束: {}", e);
                break;
            }
        }
    }

    tracing::info!("抓包结束，共捕获 {} 个包", packets.lock().unwrap().len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// 构造一个假的以太网帧（最小 64 字节）
    fn fake_ethernet_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        // 目的 MAC (6 bytes)
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // 源 MAC (6 bytes)
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // EtherType: IPv4 (0x0800)
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // payload
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert!(config.interface.is_empty());
        assert!(config.filter.is_none());
        assert!(config.max_packets.is_none());
        assert!(config.max_duration.is_none());
        assert_eq!(config.snaplen, DEFAULT_SNAPLEN);
    }

    #[test]
    fn test_pcap_capture_new() {
        let capture = PcapCapture::new("eth0", Some("tcp port 80"));
        assert_eq!(capture.config.interface, "eth0");
        assert_eq!(capture.config.filter.as_deref(), Some("tcp port 80"));
        assert_eq!(capture.packet_count(), 0);
    }

    #[test]
    fn test_pcap_capture_with_config() {
        let config = CaptureConfig {
            interface: "en0".to_string(),
            filter: Some("host 1.2.3.4".to_string()),
            max_packets: Some(100),
            max_duration: Some(Duration::from_secs(30)),
            snaplen: 9000,
        };
        let capture = PcapCapture::with_config(config);
        assert_eq!(capture.config.interface, "en0");
        assert_eq!(capture.config.max_packets, Some(100));
        assert_eq!(capture.config.max_duration, Some(Duration::from_secs(30)));
        assert_eq!(capture.config.snaplen, 9000);
    }

    #[test]
    fn test_builder_methods() {
        let capture = PcapCapture::new("eth0", None)
            .max_packets(50)
            .max_duration(Duration::from_secs(10));
        assert_eq!(capture.config.max_packets, Some(50));
        assert_eq!(capture.config.max_duration, Some(Duration::from_secs(10)));
    }

    #[test]
    fn test_start_empty_interface_fails() {
        let mut capture = PcapCapture::new("", None);
        let result = capture.start();
        assert!(result.is_err());
        assert!(matches!(result, Err(CaptureError::DeviceNotFound(_))));
    }

    #[test]
    fn test_stop_without_start() {
        // stop 在未 start 时不应 panic
        let mut capture = PcapCapture::new("eth0", None);
        capture.stop();
        assert_eq!(capture.packet_count(), 0);
    }

    /// 测试 pcap 文件格式：Global Header (24 字节) 结构正确
    #[test]
    fn test_pcap_global_header_format() {
        // 直接构造 capture 并注入假数据包
        let capture = PcapCapture::new("eth0", None);

        // 注入假数据包
        let frame = fake_ethernet_frame(&[0xde, 0xad, 0xbe, 0xef]);
        capture.packets.lock().unwrap().push(CapturedPacket {
            ts_sec: 1700000000,
            ts_usec: 123456,
            data: frame.clone(),
        });

        let path = "/tmp/argus_test_global_header.pcap";
        capture.save(path).unwrap();

        // 读取并验证文件
        let mut file = File::open(path).unwrap();
        let mut header = [0u8; 24];
        file.read_exact(&mut header).unwrap();

        // 验证 magic number (小端序 0xa1b2c3d4)
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        assert_eq!(magic, 0xa1b2c3d4, "pcap magic number 错误");

        // 验证版本号
        let version_major = u16::from_le_bytes([header[4], header[5]]);
        let version_minor = u16::from_le_bytes([header[6], header[7]]);
        assert_eq!(version_major, 2, "pcap 主版本号错误");
        assert_eq!(version_minor, 4, "pcap 次版本号错误");

        // 验证 thiszone (字节 8-11) = 0
        let thiszone = i32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        assert_eq!(thiszone, 0, "thiszone 应为 0");

        // 验证 sigfigs (字节 12-15) = 0
        let sigfigs = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        assert_eq!(sigfigs, 0, "sigfigs 应为 0");

        // 验证 snaplen (字节 16-19)
        let snaplen = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        assert_eq!(snaplen, DEFAULT_SNAPLEN, "snaplen 错误");

        // 验证 network (字节 20-23) = LINKTYPE_ETHERNET (1)
        let network = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
        assert_eq!(network, LINKTYPE_ETHERNET, "network 应为 Ethernet (1)");

        let _ = std::fs::remove_file(path);
    }

    /// 测试 pcap 文件格式：Packet Record 结构正确
    #[test]
    fn test_pcap_packet_record_format() {
        let capture = PcapCapture::new("eth0", None);

        let frame = fake_ethernet_frame(&[0x01, 0x02, 0x03, 0x04]);
        let frame_len = frame.len() as u32;
        capture.packets.lock().unwrap().push(CapturedPacket {
            ts_sec: 1700000000,
            ts_usec: 123456,
            data: frame.clone(),
        });

        let path = "/tmp/argus_test_packet_record.pcap";
        capture.save(path).unwrap();

        let mut file = File::open(path).unwrap();
        // 跳过 Global Header (24 字节)
        let mut header = [0u8; 24];
        file.read_exact(&mut header).unwrap();

        // 读取 Packet Record Header (16 字节)
        let mut rec_header = [0u8; 16];
        file.read_exact(&mut rec_header).unwrap();

        let ts_sec = u32::from_le_bytes([rec_header[0], rec_header[1], rec_header[2], rec_header[3]]);
        let ts_usec = u32::from_le_bytes([rec_header[4], rec_header[5], rec_header[6], rec_header[7]]);
        let incl_len = u32::from_le_bytes([rec_header[8], rec_header[9], rec_header[10], rec_header[11]]);
        let orig_len = u32::from_le_bytes([rec_header[12], rec_header[13], rec_header[14], rec_header[15]]);

        assert_eq!(ts_sec, 1700000000, "ts_sec 错误");
        assert_eq!(ts_usec, 123456, "ts_usec 错误");
        assert_eq!(incl_len, frame_len, "incl_len 错误");
        assert_eq!(orig_len, frame_len, "orig_len 错误");

        // 读取包数据
        let mut data = vec![0u8; frame_len as usize];
        file.read_exact(&mut data).unwrap();
        assert_eq!(data, frame, "包数据不匹配");

        let _ = std::fs::remove_file(path);
    }

    /// 测试多包 pcap 文件
    #[test]
    fn test_pcap_multiple_packets() {
        let capture = PcapCapture::new("eth0", None);

        for i in 0..5 {
            let frame = fake_ethernet_frame(&[i]);
            capture.packets.lock().unwrap().push(CapturedPacket {
                ts_sec: 1700000000 + i as u32,
            ts_usec: (i as u32) * 1000,
                data: frame,
            });
        }

        let path = "/tmp/argus_test_multi_packets.pcap";
        capture.save(path).unwrap();

        // 验证文件大小 = 24 (global header) + 5 * (16 + 包长)
        let metadata = std::fs::metadata(path).unwrap();
        let frame_len = fake_ethernet_frame(&[0]).len() as u64;
        let expected_size = 24 + 5 * (16 + frame_len);
        assert_eq!(metadata.len(), expected_size, "pcap 文件大小错误");

        let _ = std::fs::remove_file(path);
    }

    /// 测试空抓包保存（仅 Global Header）
    #[test]
    fn test_pcap_empty_save() {
        let capture = PcapCapture::new("eth0", None);
        let path = "/tmp/argus_test_empty.pcap";
        capture.save(path).unwrap();

        // 空 pcap 文件只有 Global Header (24 字节)
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.len(), 24, "空 pcap 应为 24 字节");

        let _ = std::fs::remove_file(path);
    }

    /// 测试 get_packets 返回正确数量
    #[test]
    fn test_get_packets() {
        let capture = PcapCapture::new("eth0", None);
        for i in 0..3 {
            capture.packets.lock().unwrap().push(CapturedPacket {
                ts_sec: i,
                ts_usec: 0,
                data: vec![i as u8],
            });
        }
        let packets = capture.get_packets();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].data, vec![0]);
        assert_eq!(packets[2].data, vec![2]);
    }

    /// 测试用 pcap crate 反向解析我们生成的 pcap 文件，验证格式兼容性
    #[test]
    fn test_pcap_file_compatible_with_pcap_crate() {
        let capture = PcapCapture::new("eth0", None);

        // 构造一个真实的以太网帧（IPv4 + TCP）
        let mut frame = fake_ethernet_frame(&[]);
        // 简化的 IP + TCP 头部（仅用于格式验证）
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28, // IP: version=4, IHL=5, total_len=40
            0x00, 0x00, 0x40, 0x00, // id, flags+frag
            0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP, checksum
            0x7f, 0x00, 0x00, 0x01, // src 127.0.0.1
            0x7f, 0x00, 0x00, 0x01, // dst 127.0.0.1
            0x12, 0x34, 0x00, 0x50, // TCP: sport=4660, dport=80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x20, 0x00, // data_offset, flags=SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ]);

        capture.packets.lock().unwrap().push(CapturedPacket {
            ts_sec: 1700000000,
            ts_usec: 0,
            data: frame.clone(),
        });

        let path = "/tmp/argus_test_compat.pcap";
        capture.save(path).unwrap();

        // 用 pcap crate 打开我们生成的文件
        let mut cap = pcap::Capture::from_file(path).expect("pcap crate 应能打开我们生成的文件");

        // 读取一个包
        let packet = cap.next_packet().expect("应能读到一个包");
        assert_eq!(packet.data, frame.as_slice(), "pcap crate 读取的包数据应匹配");

        let _ = std::fs::remove_file(path);
    }
}
