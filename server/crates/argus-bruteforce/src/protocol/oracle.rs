//! Oracle (TNS 协议) 连接器
//!
//! 实现 TNS Connect 探测 + 认证阶段探测：
//! 1. 发送 TNS Connect 数据包（携带 service name + username）
//! 2. 检查 ACCEPT/REFUSE 响应，解析版本和能力信息
//! 3. 发送 NS Data (TTC OSSESS) 探测认证阶段
//! 4. 根据响应判断认证是否成功
//!
//! **限制说明**: Oracle 完整认证（O5L/O5LNPw）需要：
//! - 从 ACCEPT 响应提取 session key
//! - 使用 DES 变种加密密码（O5L）或 SHA1 密钥派生（O5LNPw）
//! - 构造完整的 TTC OSSESS 消息
//! - 处理多轮 TNS NS Data 交换
//!
//! 当前实现发送 TNS Connect + NS Data 探测包，能检测：
//! - 端口是否为 Oracle TNS 监听
//! - 服务名/SID 是否有效
//! - TNS 版本和监听器能力
//! - 认证是否被拒绝（REFUSE）或需要进一步交互（DATA）

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct OracleConnector {
    service_name: String,
}

impl OracleConnector {
    pub fn new() -> Self {
        Self {
            service_name: "ORCL".to_string(),
        }
    }

    /// 指定 Oracle service name（默认 ORCL）
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service_name: service.into(),
        }
    }
}

impl Default for OracleConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolConnector for OracleConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Oracle
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        let mut stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("连接超时: {e}"))?
            .map_err(|e| format!("连接失败: {e}"))?;

        // 1. 发送 TNS Connect 数据包
        let connect_pkt = build_tns_connect(&self.service_name, &credential.username);
        timeout(dur, stream.write_all(&connect_pkt))
            .await
            .map_err(|e| format!("发送 TNS Connect 超时: {e}"))?
            .map_err(|e| format!("发送 TNS Connect 失败: {e}"))?;

        // 2. 读取 TNS 响应
        let mut tns_header = [0u8; 8];
        timeout(dur, stream.read_exact(&mut tns_header))
            .await
            .map_err(|e| format!("读取 TNS header 超时: {e}"))?
            .map_err(|e| format!("读取 TNS header 失败: {e}"))?;

        let pkt_len = u16::from_be_bytes(tns_header[0..2].try_into().unwrap()) as usize;
        if pkt_len < 8 || pkt_len > 65536 {
            return Err(format!("TNS 响应长度异常: {}", pkt_len));
        }

        let pkt_type = tns_header[4];

        // 读取剩余 body
        let remaining = pkt_len - 8;
        let mut tns_body = vec![0u8; remaining];
        if remaining > 0 {
            timeout(dur, stream.read_exact(&mut tns_body))
                .await
                .map_err(|e| format!("读取 TNS body 超时: {e}"))?
                .map_err(|e| format!("读取 TNS body 失败: {e}"))?;
        }

        // TNS packet types:
        // 1 = CONNECT, 2 = ACCEPT, 4 = REFUSE, 5 = REDIRECT, 6 = DATA, 12 = RESUME
        match pkt_type {
            2 | 12 => {
                // ACCEPT / RESUME —— TNS 连接建立成功
                // 解析 ACCEPT 响应中的版本和 session 信息
                let version = if tns_body.len() >= 4 {
                    u16::from_le_bytes([tns_body[0], tns_body[1]])
                } else {
                    0
                };
                tracing::debug!(
                    "Oracle TNS ACCEPT: {}:{} {} (version={}, body_len={})",
                    host, port, self.service_name, version, tns_body.len()
                );

                // 3. 发送 NS Data (TTC OSSESS) 探测认证
                // 构造一个 NS Data 包，包含简化的 TTC 认证请求
                let ns_data = build_tns_ns_data(&credential.username, &credential.password);
                if timeout(dur, stream.write_all(&ns_data))
                    .await
                    .is_err()
                {
                    // NS Data 发送失败，但 TNS Connect 成功
                    // 返回 false — 认证未通过
                    return Ok(false);
                }

                // 4. 读取认证响应
                let mut resp_header = [0u8; 8];
                if timeout(dur, stream.read_exact(&mut resp_header))
                    .await
                    .is_err()
                {
                    return Ok(false);
                }

                let resp_type = resp_header[4];
                let resp_len = u16::from_be_bytes([resp_header[0], resp_header[1]]) as usize;

                let mut resp_body = vec![0u8; resp_len.saturating_sub(8)];
                if resp_len > 8 && !resp_body.is_empty() {
                    let _ = timeout(dur, stream.read_exact(&mut resp_body)).await;
                }

                // 分析响应类型
                match resp_type {
                    6 => {
                        // DATA — 服务器返回了 TTC 数据
                        // 检查 TTC 消息中的错误码
                        // TTC 响应通常包含一个消息类型字节 + 错误码
                        if resp_body.len() > 10 {
                            // TTC 错误码在响应中的偏移因版本而异
                            // 如果响应中包含 ORA- 错误前缀（通常为 0x65 或 "ORA" 字符串），
                            // 说明认证失败
                            let resp_str = String::from_utf8_lossy(&resp_body);
                            if resp_str.contains("ORA-01017") || resp_str.contains("ORA-01005") {
                                // ORA-01017: invalid username/password
                                // ORA-01005: null password
                                tracing::debug!("Oracle 认证失败: {}@{}", credential.username, self.service_name);
                                return Ok(false);
                            }
                            // 如果没有错误码且收到了 DATA 响应，
                            // 可能是认证成功或需要进一步交互
                            // 由于无法确定 O5L 认证的完整状态，
                            // 返回 false 以避免误报
                            return Ok(false);
                        }
                        Ok(false)
                    }
                    4 => {
                        // REFUSE — 认证被拒绝
                        Ok(false)
                    }
                    _ => {
                        // 其他响应类型（REDIRECT 等）
                        Ok(false)
                    }
                }
            }
            4 => {
                // REFUSE — TNS Connect 被拒（服务名无效或监听器不接受连接）
                Ok(false)
            }
            _ => {
                Err(format!("未知的 TNS 响应类型: {}", pkt_type))
            }
        }
    }
}

/// 构造 TNS Connect 数据包
fn build_tns_connect(service_name: &str, username: &str) -> Vec<u8> {
    let connect_str = format!(
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={})(CID=(PROGRAM=argus)(HOST=argus)(USER={})))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))",
        service_name, username
    );

    let connect_bytes = connect_str.as_bytes();
    let connect_len = connect_bytes.len();
    let header_len = 28usize;
    let total_len = header_len + connect_len;

    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.push(0x01); // Type: CONNECT
    pkt.push(0x00); // Reserved
    pkt.extend_from_slice(&318u16.to_le_bytes()); // Version (Oracle 10g)
    pkt.extend_from_slice(&318u16.to_le_bytes()); // Version compat
    pkt.extend_from_slice(&0x0C41u16.to_le_bytes()); // Service options
    pkt.extend_from_slice(&0x0800u16.to_le_bytes()); // SDU length
    pkt.extend_from_slice(&0x7FFFu16.to_le_bytes()); // TDU length
    pkt.extend_from_slice(&0x7F08u16.to_le_bytes()); // NT proto chars
    pkt.extend_from_slice(&0x0001u16.to_le_bytes()); // Line turnaround
    pkt.extend_from_slice(&(header_len as u16).to_le_bytes()); // Connect data offset
    pkt.extend_from_slice(&0x0800u32.to_le_bytes()); // Max recv connect data
    pkt.push(0x41); // Connect data flags
    pkt.push(0x00); // Reserved
    pkt.extend_from_slice(connect_bytes);

    assert_eq!(pkt.len() - connect_len, header_len, "TNS header length mismatch");
    pkt
}

/// 构造 TNS NS Data 包（包含简化的 TTC 认证请求）
///
/// TNS NS Data packet:
/// - Length (2 bytes, big-endian)
/// - Packet checksum (2 bytes)
/// - Type (1 byte): 6 = DATA
/// - Reserved (1 byte): 0
/// - NS data: flags(1) + ...
/// - TTC message: 包含用户名和密码的简化编码
fn build_tns_ns_data(username: &str, password: &str) -> Vec<u8> {
    // 构造 TTC OSSESS (Open Session) 消息
    // 这是一个简化的 TTC 消息，包含：
    // - TTC 消息类型 (0x01 = request)
    // - 用户名和密码（以 null 结尾的 UTF-8）

    let username_bytes = username.as_bytes();
    let password_bytes = password.as_bytes();

    // TTC body: type(1) + username_len(4) + username + password_len(4) + password
    let ttc_body_len = 1 + 4 + username_bytes.len() + 4 + password_bytes.len();
    let mut ttc = Vec::with_capacity(ttc_body_len);
    ttc.push(0x01); // TTC message type: OSSESS request
    ttc.extend_from_slice(&(username_bytes.len() as u32).to_le_bytes());
    ttc.extend_from_slice(username_bytes);
    ttc.extend_from_slice(&(password_bytes.len() as u32).to_le_bytes());
    ttc.extend_from_slice(password_bytes);

    // TNS NS Data header: length(2) + checksum(2) + type(1=DATA) + reserved(1) + ns_flags(1) + ns_reserved(1) = 8 bytes
    // 之后跟随 TTC body
    let total_len = 8 + ttc.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.push(0x06); // Type: DATA
    pkt.push(0x00); // Reserved
    pkt.push(0x00); // NS flags: data
    pkt.push(0x00); // NS reserved
    pkt.extend_from_slice(&ttc);

    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tns_connect_structure() {
        let pkt = build_tns_connect("ORCL", "sa");
        let len = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());
        assert_eq!(pkt[4], 0x01); // CONNECT
        let body_str = String::from_utf8_lossy(&pkt);
        assert!(body_str.contains("ORCL"));
        assert!(body_str.contains("sa"));
    }

    #[test]
    fn test_tns_ns_data_structure() {
        let pkt = build_tns_ns_data("admin", "password123");
        let len = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());
        assert_eq!(pkt[4], 0x06); // DATA
        // TNS header 之后紧接 NS flags + reserved (pkt[6..8])
        assert_eq!(pkt[6], 0x00); // NS flags
        assert_eq!(pkt[7], 0x00); // NS reserved
        // TTC body 第一字节为消息类型 (pkt[8])
        assert_eq!(pkt[8], 0x01); // OSSESS request
    }

    #[test]
    fn test_connector_default() {
        let c = OracleConnector::new();
        assert_eq!(c.service_name, "ORCL");
    }

    #[test]
    fn test_connector_with_service() {
        let c = OracleConnector::with_service("XE");
        assert_eq!(c.service_name, "XE");
    }

    #[test]
    fn test_tns_connect_with_long_service_name() {
        let pkt = build_tns_connect("VERY_LONG_SERVICE_NAME_XYZ", "admin");
        let len = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());
    }

    #[test]
    fn test_ns_data_contains_credentials() {
        let pkt = build_tns_ns_data("scott", "tiger");
        let body_str = String::from_utf8_lossy(&pkt);
        // 用户名和密码应出现在 NS Data 包中
        assert!(body_str.contains("scott"));
        assert!(body_str.contains("tiger"));
    }
}
