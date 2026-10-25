//! SNMP 协议连接器
//!
//! 真实实现 SNMP community 字符串爆破（SNMPv2c, RFC 3416）：
//! SNMP 爆破是爆破 community 字符串（非用户名/密码），此处将 password 字段作为 community
//! 1. 构造 BER 编码的 SNMP GetRequest 数据包
//! 2. 通过 UDP 发送到目标端口（默认 161）
//! 3. 接收响应
//! 4. 有效响应 = community 正确，超时/错误 = community 错误

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct SnmpConnector;

#[async_trait]
impl ProtocolConnector for SnmpConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Snmp
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let dur = Duration::from_millis(timeout_ms);
        let addr = format!("{host}:{port}");

        // SNMP 是 UDP 协议，使用 password 字段作为 community
        let community = &credential.password;

        // 构造 SNMPv2c GetRequest 数据包
        let packet = build_snmp_getrequest(community);

        // 绑定本地 UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("SNMP UDP 绑定失败: {e}"))?;

        // 发送数据包
        socket
            .send_to(&packet, &addr)
            .await
            .map_err(|e| format!("SNMP UDP 发送失败: {e}"))?;

        // 接收响应
        let mut buf = vec![0u8; 65535];
        match timeout(dur, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                // 验证响应是否为有效 SNMP 响应
                // 最小有效响应：SEQUENCE + INTEGER(version) + OCTET STRING(community) + PDU
                if is_valid_snmp_response(&buf[..n], community) {
                    Ok(true) // community 字符串正确
                } else {
                    // 收到响应但 community 可能不对（某些设备返回错误包）
                    // 如果响应包含我们发送的 community，可能是正确的
                    Ok(buf[..n].iter().any(|&b| b == community.len() as u8)
                        && buf[..n]
                            .windows(community.len())
                            .any(|w| w == community.as_bytes()))
                }
            }
            Ok(Ok(_)) => Ok(false),
            Ok(Err(e)) => Err(format!("SNMP UDP 接收失败: {e}")),
            Err(_) => {
                // 超时 = community 不正确（服务器未响应）
                Ok(false)
            }
        }
    }
}

/// 构造 SNMPv2c GetRequest 数据包
///
/// 包结构（BER 编码）：
/// SEQUENCE {
///   INTEGER 1 (version = v2c)
///   OCTET STRING community
///   GetRequestPDU [0] {
///     INTEGER 1 (request-id)
///     INTEGER 0 (error-status)
///     INTEGER 0 (error-index)
///     SEQUENCE {
///       SEQUENCE {
///         OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
///         NULL
///       }
///     }
///   }
/// }
fn build_snmp_getrequest(community: &str) -> Vec<u8> {
    // 版本 = 1 (SNMPv2c)
    let version = ber_integer(1);

    // community
    let community_encoded = ber_octet_string(community.as_bytes());

    // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    let oid = ber_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);

    // NULL value
    let null_value = vec![0x05, 0x00];

    // VarBind: SEQUENCE { OID, NULL }
    let varbind_content: Vec<u8> = vec![oid, null_value]
        .into_iter()
        .flatten()
        .collect();
    let varbind = ber_sequence(varbind_content);

    // VarBindList: SEQUENCE { VarBind }
    let varbind_list = ber_sequence(varbind.clone());

    // GetRequestPDU: [0] (context tag 0, constructed) { request-id, error-status, error-index, varbind_list }
    let request_id = ber_integer(1); // request-id = 1
    let error_status = ber_integer(0); // no error
    let error_index = ber_integer(0); // no error

    let pdu_content = vec![request_id, error_status, error_index, varbind_list];
    let pdu_content_flat: Vec<u8> = pdu_content.into_iter().flatten().collect();
    let pdu = ber_context_tag(0, true, pdu_content_flat);

    // 完整 SNMP 消息
    let message_content = vec![version, community_encoded, pdu];
    let message_content_flat: Vec<u8> = message_content.into_iter().flatten().collect();
    ber_sequence(message_content_flat)
}

/// 验证 SNMP 响应是否有效
fn is_valid_snmp_response(data: &[u8], _community: &str) -> bool {
    // 最小有效响应长度
    if data.len() < 10 {
        return false;
    }
    // 第一个字节应为 SEQUENCE (0x30)
    if data[0] != 0x30 {
        return false;
    }
    // 应包含版本号 (INTEGER 1)
    // 应包含 community (OCTET STRING)
    // 应包含 PDU
    // 简化检查：解析 BER 结构
    let mut pos = 1;
    let (_seq_len, seq_len_bytes) = match parse_ber_length(&data[pos..]) {
        Ok(r) => r,
        Err(_) => return false,
    };
    pos += seq_len_bytes;

    // 版本号
    if pos >= data.len() || data[pos] != 0x02 {
        return false;
    }
    pos += 1;
    let (ver_len, ver_len_bytes) = match parse_ber_length(&data[pos..]) {
        Ok(r) => r,
        Err(_) => return false,
    };
    pos += ver_len_bytes + ver_len;

    // Community
    if pos >= data.len() || data[pos] != 0x04 {
        return false;
    }
    pos += 1;
    let (comm_len, comm_len_bytes) = match parse_ber_length(&data[pos..]) {
        Ok(r) => r,
        Err(_) => return false,
    };
    pos += comm_len_bytes + comm_len;

    // PDU (context tag [0] to [4])
    if pos >= data.len() {
        return false;
    }
    // Response PDU = [2] (GetResponse) = 0xA2
    // GetRequest = [0] = 0xA0
    let pdu_tag = data[pos];
    // 上下文标签 (0x80 | constructed | tag_number)
    // GetResponse = tag 2 = 0xA2
    // Report = tag 4 = 0xA4
    if pdu_tag == 0xA2 || pdu_tag == 0xA4 || pdu_tag == 0xA0 {
        return true; // 有效 SNMP 响应
    }

    false
}

// ==================== BER 编码工具 ====================

fn ber_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn ber_integer(val: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    if val == 0 {
        bytes.push(0);
    } else {
        let mut v = val;
        while v > 0 {
            bytes.insert(0, (v & 0xFF) as u8);
            v >>= 8;
        }
    }
    let mut result = vec![0x02, bytes.len() as u8];
    result.extend(bytes);
    result
}

fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04];
    result.extend(ber_length(data.len()));
    result.extend_from_slice(data);
    result
}

fn ber_sequence(contents: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x30];
    result.extend(ber_length(contents.len()));
    result.extend(contents);
    result
}

/// 编码 OID（BER）
fn ber_oid(components: &[u32]) -> Vec<u8> {
    let mut encoded = Vec::new();
    // 第一个字节 = 40 * first + second
    if components.len() >= 2 {
        encoded.push((40 * components[0] + components[1]) as u8);
    } else if components.len() == 1 {
        encoded.push((40 * components[0]) as u8);
    } else {
        encoded.push(0);
    }

    // 其余组件使用 base-128 编码
    for &c in components.iter().skip(2) {
        if c < 128 {
            encoded.push(c as u8);
        } else {
            // base-128 编码
            let mut tmp = Vec::new();
            let mut v = c;
            tmp.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                tmp.push(((v & 0x7F) as u8) | 0x80);
                v >>= 7;
            }
            tmp.reverse();
            // 最后一个字节的最高位为 0
            if let Some(last) = tmp.last_mut() {
                *last &= 0x7F;
            }
            // 第一个字节需要设置续位
            if tmp.len() > 1 {
                for i in 0..tmp.len() - 1 {
                    tmp[i] |= 0x80;
                }
            }
            encoded.extend(tmp);
        }
    }

    let mut result = vec![0x06, encoded.len() as u8]; // OBJECT IDENTIFIER tag
    result.extend(encoded);
    result
}

/// 编码上下文标签（用于 PDU 类型）
fn ber_context_tag(tag: u8, constructed: bool, contents: Vec<u8>) -> Vec<u8> {
    let tag_byte = 0x80 | (if constructed { 0x20 } else { 0x00 }) | (tag & 0x1F);
    let mut result = vec![tag_byte];
    result.extend(ber_length(contents.len()));
    result.extend(contents);
    result
}

fn parse_ber_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("BER 长度为空".to_string());
    }
    let first = data[0];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err("BER 长度无效".to_string());
        }
        let mut len = 0;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_protocol() {
        assert_eq!(SnmpConnector.protocol(), Protocol::Snmp);
    }

    #[test]
    fn test_build_snmp_getrequest() {
        let packet = build_snmp_getrequest("public");
        // 第一个字节应为 SEQUENCE (0x30)
        assert_eq!(packet[0], 0x30);
        // 包含 "public" community
        assert!(packet.windows(6).any(|w| w == b"public"));
        // 包含 version 1
        assert!(packet.windows(3).any(|w| w == &[0x02, 0x01, 0x01]));
    }

    #[test]
    fn test_build_snmp_getrequest_empty_community() {
        let packet = build_snmp_getrequest("");
        assert_eq!(packet[0], 0x30);
        // 仍应有效
        assert!(packet.len() > 20);
    }

    #[test]
    fn test_ber_oid() {
        // OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        let oid = ber_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid[0], 0x06); // OBJECT IDENTIFIER tag
        assert_eq!(oid[2], 0x2b); // 40*1 + 3 = 43 = 0x2b
    }

    #[test]
    fn test_is_valid_snmp_response() {
        // 构造一个简化的有效响应
        let mut response = Vec::new();
        // SEQUENCE
        response.push(0x30);
        response.push(0x15); // length = 21
        // version = 1
        response.extend_from_slice(&[0x02, 0x01, 0x01]);
        // community = "public"
        response.extend_from_slice(&[0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c']);
        // GetResponse PDU [2]
        response.push(0xA2); // context tag 2, constructed
        response.push(0x08); // length
        // request-id = 1
        response.extend_from_slice(&[0x02, 0x01, 0x01]);
        // error-status = 0
        response.extend_from_slice(&[0x02, 0x01, 0x00]);

        assert!(is_valid_snmp_response(&response, "public"));
    }

    #[test]
    fn test_is_valid_snmp_response_invalid() {
        // 无效数据
        assert!(!is_valid_snmp_response(&[0x00, 0x01, 0x02], "public"));
        // 空数据
        assert!(!is_valid_snmp_response(&[], "public"));
    }
}
