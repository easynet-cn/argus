//! LDAP 协议连接器
//!
//! G2.6: 实现 LDAPv3 Simple Bind 爆破
//! 1. TCP 连接到目标端口（默认 389，LDAPS 636）
//! 2. 发送 BER 编码的 BindRequest（Simple 认证模式）
//! 3. 解析 BindResponse，resultCode=0 表示认证成功
//!
//! LDAPMessage ::= SEQUENCE {
//!     messageID  INTEGER,
//!     protocolOp [APPLICATION 0] BindRequest
//! }
//! BindRequest ::= SEQUENCE {
//!     version  INTEGER (3),
//!     name     LDAPDN,
//!     authentication [0] OCTET STRING  -- 简单认证密码
//! }

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct LdapConnector;

#[async_trait]
impl ProtocolConnector for LdapConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Ldap
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

        // 1. TCP 连接
        let mut stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("LDAP 连接超时: {e}"))?
            .map_err(|e| format!("LDAP 连接失败: {e}"))?;

        // 2. 构造并发送 BindRequest
        // 用户名可以是 DN 格式（uid=user,ou=people,dc=example,dc=com）
        // 或直接用户名，由服务端决定
        let bind_request = encode_bind_request(&credential.username, &credential.password);
        stream
            .write_all(&bind_request)
            .await
            .map_err(|e| format!("发送 LDAP Bind 失败: {e}"))?;

        // 3. 读取 BindResponse
        let mut buf = vec![0u8; 4096];
        let n = timeout(dur, stream.read(&mut buf))
            .await
            .map_err(|e| format!("读取 LDAP 响应超时: {e}"))?
            .map_err(|e| format!("读取 LDAP 响应失败: {e}"))?;

        if n == 0 {
            return Err("LDAP 连接已关闭".to_string());
        }

        // 解析 BindResponse 中的 resultCode
        // resultCode == 0 表示认证成功
        let result_code = parse_bind_response_result_code(&buf[..n]);
        match result_code {
            Some(0) => Ok(true),
            Some(code) => {
                // 49 = invalidCredentials, 7 = authMethodNotSupported, etc.
                tracing::debug!(
                    "LDAP Bind 失败: resultCode={} ({})",
                    code,
                    ldap_error_string(code)
                );
                Ok(false)
            }
            None => Err(format!("无法解析 LDAP BindResponse: {:02x?}", &buf[..n])),
        }
    }
}

/// 编码 LDAP BindRequest（Simple 认证）
///
/// LDAPMessage = SEQUENCE { messageID=1, [APPLICATION 0] BindRequest }
/// BindRequest = SEQUENCE { version=3, name=DN, [0] password }
fn encode_bind_request(username: &str, password: &str) -> Vec<u8> {
    // 构造 BindRequest SEQUENCE 内部
    let mut bind_inner = Vec::new();
    // version: INTEGER 3
    bind_inner.extend(ber_integer(3));
    // name: LDAPDN (OCTET STRING)
    bind_inner.extend(ber_octet_string(username.as_bytes()));
    // authentication: [0] context-specific, constructed OCTET STRING (simple password)
    bind_inner.extend(ber_context_octet_string(0, password.as_bytes()));

    // BindRequest = [APPLICATION 0] (constructed)
    let bind_app = ber_application_constructed(0, &bind_inner);

    // LDAPMessage = SEQUENCE { messageID, protocolOp }
    let mut msg_inner = Vec::new();
    msg_inner.extend(ber_integer(1)); // messageID = 1
    msg_inner.extend(&bind_app);
    ber_sequence(&msg_inner)
}

// ====== BER 编码辅助函数 ======

/// BER INTEGER 编码
fn ber_integer(val: i32) -> Vec<u8> {
    let mut buf = vec![0x02]; // INTEGER tag
    let content = if val >= 0 && val <= 127 {
        vec![val as u8]
    } else {
        // 简化处理：支持 1~4 字节
        let bytes = val.to_be_bytes();
        // 去除前导零字节
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        bytes[start..].to_vec()
    };
    buf.push(content.len() as u8);
    buf.extend(content);
    buf
}

/// BER OCTET STRING 编码
fn ber_octet_string(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x04]; // OCTET STRING tag
    buf.extend(ber_length(data.len()));
    buf.extend(data);
    buf
}

/// BER context-specific [n] OCTET STRING（primitive）
fn ber_context_octet_string(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x80 | tag]; // context-specific, primitive
    buf.extend(ber_length(data.len()));
    buf.extend(data);
    buf
}

/// BER APPLICATION constructed [n]
fn ber_application_constructed(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x40 | 0x20 | tag]; // application, constructed
    buf.extend(ber_length(data.len()));
    buf.extend(data);
    buf
}

/// BER SEQUENCE
fn ber_sequence(data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x30]; // SEQUENCE, constructed
    buf.extend(ber_length(data.len()));
    buf.extend(data);
    buf
}

/// BER 长度编码（支持短格式和长格式）
fn ber_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let content = &bytes[start..];
        let mut buf = vec![0x80 | content.len() as u8];
        buf.extend(content);
        buf
    }
}

/// 解析 BindResponse 中的 resultCode
///
/// BindResponse ::= SEQUENCE {
///     resultCode  ENUMERATED,
///     matchedDN   LDAPDN,
///     diagnosticMessage  LDAPString
/// }
///
/// 在 LDAPMessage 中位置: SEQUENCE > messageID > [APPLICATION 1] > SEQUENCE > resultCode
fn parse_bind_response_result_code(data: &[u8]) -> Option<i32> {
    let mut pos = 0;
    // 外层 SEQUENCE
    if data.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    pos += skip_length(data, pos)?;
    // messageID (INTEGER)
    if data.get(pos)? != &0x02 {
        return None;
    }
    pos += 1;
    let id_len = read_length(data, pos)? as usize;
    pos += length_bytes_count(data, pos);
    pos += id_len;
    // [APPLICATION 1] BindResponse (constructed)
    if data.get(pos)? != &(0x40 | 0x20 | 1) {
        return None;
    }
    pos += 1;
    pos += skip_length(data, pos)?;
    // BindResponse SEQUENCE
    if data.get(pos)? != &0x30 {
        return None;
    }
    pos += 1;
    pos += skip_length(data, pos)?;
    // resultCode (ENUMERATED, tag 0x0A)
    if data.get(pos)? != &0x0A {
        return None;
    }
    pos += 1;
    let code_len = read_length(data, pos)? as usize;
    pos += length_bytes_count(data, pos);
    let mut code_bytes = Vec::new();
    for _ in 0..code_len {
        code_bytes.push(*data.get(pos)?);
        pos += 1;
    }
    let mut result = 0i32;
    for &b in &code_bytes {
        result = (result << 8) | (b as i32);
    }
    Some(result)
}

/// 读取 BER 长度值
fn read_length(data: &[u8], pos: usize) -> Option<u64> {
    let first = *data.get(pos)?;
    if first < 0x80 {
        Some(first as u64)
    } else {
        let n = (first & 0x7F) as usize;
        let mut len = 0u64;
        for i in 0..n {
            len = (len << 8) | (*data.get(pos + 1 + i)? as u64);
        }
        Some(len)
    }
}

/// 返回 BER 长度字段占用的字节数
fn length_bytes_count(data: &[u8], pos: usize) -> usize {
    let first = data.get(pos).copied().unwrap_or(0);
    if first < 0x80 {
        1
    } else {
        1 + (first & 0x7F) as usize
    }
}

/// 跳过 BER 长度字段，返回跳过的字节数
fn skip_length(data: &[u8], pos: usize) -> Option<usize> {
    let first = *data.get(pos)?;
    if first < 0x80 {
        Some(1)
    } else {
        Some(1 + (first & 0x7F) as usize)
    }
}

/// LDAP resultCode 错误描述
fn ldap_error_string(code: i32) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        14 => "saslBindInProgress",
        49 => "invalidCredentials",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_protocol() {
        assert_eq!(LdapConnector.protocol(), Protocol::Ldap);
    }

    #[test]
    fn test_ldap_default_port() {
        assert_eq!(Protocol::Ldap.default_port(), 389);
    }

    #[test]
    fn test_ldap_from_str() {
        assert_eq!(Protocol::from_str("ldap"), Some(Protocol::Ldap));
    }

    #[test]
    fn test_encode_bind_request_structure() {
        let buf = encode_bind_request("cn=admin,dc=example,dc=com", "password");
        // 必须以 SEQUENCE tag 开头
        assert_eq!(buf[0], 0x30);
        // 必须包含 messageID (INTEGER, tag 0x02)
        assert!(buf.windows(2).any(|w| w[0] == 0x02 && w[1] == 1));
        // 必须包含 [APPLICATION 0] BindRequest tag (0x60)
        assert!(buf.contains(&0x60));
        // 必须包含密码 "password" 的字节
        assert!(buf.windows(8).any(|w| w == b"password"));
    }

    #[test]
    fn test_ber_integer_encoding() {
        // INTEGER 3 = 02 01 03
        let buf = ber_integer(3);
        assert_eq!(buf, vec![0x02, 0x01, 0x03]);
    }

    #[test]
    fn test_ber_octet_string_encoding() {
        let buf = ber_octet_string(b"hello");
        assert_eq!(buf, vec![0x04, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_parse_bind_response_success() {
        // 构造一个 resultCode=0 的 BindResponse
        let bind_resp_inner = vec![0x0A, 0x01, 0x00]; // ENUMERATED 0 (success)
        let bind_resp_seq = ber_sequence(&bind_resp_inner);
        let bind_resp_app = ber_application_constructed(1, &bind_resp_seq);
        let msg_inner = {
            let mut v = Vec::new();
            v.extend(ber_integer(1));
            v.extend(&bind_resp_app);
            v
        };
        let msg = ber_sequence(&msg_inner);
        assert_eq!(parse_bind_response_result_code(&msg), Some(0));
    }

    #[test]
    fn test_parse_bind_response_invalid_credentials() {
        // resultCode=49 (invalidCredentials)
        let bind_resp_inner = vec![0x0A, 0x01, 0x31]; // ENUMERATED 49
        let bind_resp_seq = ber_sequence(&bind_resp_inner);
        let bind_resp_app = ber_application_constructed(1, &bind_resp_seq);
        let msg_inner = {
            let mut v = Vec::new();
            v.extend(ber_integer(1));
            v.extend(&bind_resp_app);
            v
        };
        let msg = ber_sequence(&msg_inner);
        assert_eq!(parse_bind_response_result_code(&msg), Some(49));
    }

    #[test]
    fn test_ldap_error_string_known_codes() {
        assert_eq!(ldap_error_string(49), "invalidCredentials");
        assert_eq!(ldap_error_string(0), "success");
        assert_eq!(ldap_error_string(999), "other");
    }
}
