//! MySQL 协议连接器（纯 TCP 实现）
//!
//! 支持：
//! - mysql_native_password (default)
//! - caching_sha2_password (MySQL 8 默认)

use async_trait::async_trait;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct MysqlConnector;

#[async_trait]
impl ProtocolConnector for MysqlConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Mysql
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

        // 1. 读取握手包
        let handshake = read_packet(&mut stream, dur).await?;
        if handshake.is_empty() {
            return Err("握手包为空".to_string());
        }
        if handshake[0] == 0xff {
            let err_msg = String::from_utf8_lossy(&handshake[3..]).to_string();
            return Err(format!("MySQL 错误: {err_msg}"));
        }

        let parsed = parse_handshake(&handshake)?;
        tracing::debug!(
            "MySQL 服务器: {} 协议={}, auth_plugin={:?}",
            parsed.server_version, parsed.protocol_version, parsed.auth_plugin_name
        );

        // 2. 构造 HandshakeResponse41
        let auth_plugin = parsed
            .auth_plugin_name
            .as_deref()
            .unwrap_or("mysql_native_password");

        let auth_response = match auth_plugin {
            "mysql_native_password" => mysql_native_password(&credential.password, &parsed.salt),
            "caching_sha2_password" => {
                caching_sha2_fast_auth(&credential.password, &parsed.salt)?
            }
            other => {
                return Err(format!("不支持的认证插件: {other}"));
            }
        };

        let login_packet = build_login_packet(
            &credential.username,
            &auth_response,
            auth_plugin,
            parsed.server_capabilities,
        );

        write_packet(&mut stream, &login_packet, 1, dur).await?;

        // 3. 读取响应
        let resp = read_packet(&mut stream, dur).await?;

        match resp.first() {
            Some(&0x00) => Ok(true),  // OK packet
            Some(&0xff) => Ok(false), // Error packet (认证失败)
            Some(&0xfe) => {
                // AuthSwitchRequest - 服务器要求切换插件
                // payload[1..] 是新插件名 (null-terminated)
                // 中间可能有新 salt
                if resp.len() < 2 {
                    return Ok(false);
                }
                let new_plugin = resp[1..]
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect::<String>();
                let new_salt: Vec<u8> = resp[1 + new_plugin.len() + 1..]
                    .iter()
                    .take_while(|&&b| b != 0)
                    .copied()
                    .collect();

                let new_response = match new_plugin.as_str() {
                    "mysql_native_password" => mysql_native_password(&credential.password, &new_salt),
                    "caching_sha2_password" => {
                        caching_sha2_fast_auth(&credential.password, &new_salt)?
                    }
                    other => return Err(format!("切换到不支持的插件: {other}")),
                };

                write_packet(&mut stream, &new_response, 3, dur).await?;

                let resp2 = read_packet(&mut stream, dur).await?;
                match resp2.first() {
                    Some(&0x00) => Ok(true),
                    Some(&0xff) => Ok(false),
                    _ => {
                        // 可能是 caching_sha2_password 的中间状态
                        handle_caching_intermediate(&mut stream, &credential.password, &new_salt, &resp2, dur).await
                    }
                }
            }
            Some(_) => {
                // 可能是 caching_sha2_password 中间状态 0x01
                handle_caching_intermediate(&mut stream, &credential.password, &parsed.salt, &resp, dur).await
            }
            None => Err("响应为空".to_string()),
        }
    }
}

/// 处理 caching_sha2_password 中间状态
/// - 0x01 0x03: full auth needed (需要 RSA 加密)
/// - 0x01 0x04: fast auth success
async fn handle_caching_intermediate(
    stream: &mut TcpStream,
    password: &str,
    salt: &[u8],
    resp: &[u8],
    dur: Duration,
) -> Result<bool, String> {
    if resp.len() < 2 || resp[0] != 0x01 {
        return Ok(false);
    }
    match resp[1] {
        0x03 => {
            // 需要 full auth：请求 RSA 公钥
            // 发送单字节 0x02
            write_packet(stream, &[0x02], 2, dur).await?;

            // 读取 RSA 公钥（PEM 格式）
            let pubkey_pkt = read_packet(stream, dur).await?;
            let pem = String::from_utf8_lossy(&pubkey_pkt).to_string();
            let pubkey = rsa_public_key_from_pem(&pem)?;

            // 重新计算 caching_sha2_password 响应（带 salt）
            let fast_response = caching_sha2_fast_auth(password, salt)?;

            // 用 RSA-OAEP-SHA256 加密响应
            let encrypted = rsa_oaep_encrypt(&pubkey, &fast_response)?;

            // 发送加密后的密码（长度 = 密钥字节数）
            write_packet(stream, &encrypted, 3, dur).await?;

            // 读取最终响应
            let final_resp = read_packet(stream, dur).await?;
            match final_resp.first() {
                Some(&0x00) => Ok(true),
                Some(&0xff) => Ok(false),
                _ => Ok(false),
            }
        }
        0x04 => Ok(true), // fast auth success
        other => Err(format!("未知的 caching_sha2 中间状态: {other}")),
    }
}

/// MySQL 握手包解析结果
struct HandshakeInfo {
    protocol_version: u8,
    server_version: String,
    server_capabilities: u32,
    salt: Vec<u8>,
    auth_plugin_name: Option<String>,
}

/// 解析 MySQL 服务器握手包（Protocol::HandshakeV10）
fn parse_handshake(payload: &[u8]) -> Result<HandshakeInfo, String> {
    if payload.is_empty() {
        return Err("握手包为空".to_string());
    }
    let protocol_version = payload[0];

    // 服务器版本（null-terminated）
    let end = payload[1..]
        .iter()
        .position(|&b| b == 0)
        .ok_or("握手包: 缺少服务器版本结束符")?;
    let server_version = String::from_utf8_lossy(&payload[1..1 + end]).to_string();
    let mut pos = 1 + end + 1; // 跳过 null

    if pos + 4 > payload.len() {
        return Err("握手包: 缺少连接 ID".to_string());
    }
    // connection_id (4 bytes, 低 3 字节实际，但通常读 4)
    pos += 4;

    // auth-plugin-data-part-1 (8 bytes)
    if pos + 8 > payload.len() {
        return Err("握手包: 缺少 salt1".to_string());
    }
    let mut salt = Vec::with_capacity(20);
    salt.extend_from_slice(&payload[pos..pos + 8]);
    pos += 8;

    // filler (1 byte)
    if pos >= payload.len() {
        return Err("握手包: 缺少 filler".to_string());
    }
    pos += 1;

    // capability flags lower 2 bytes
    if pos + 2 > payload.len() {
        return Err("握手包: 缺少 capability lower".to_string());
    }
    let cap_lower = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as u32;
    pos += 2;

    // 如果还有更多数据，说明是新版握手包
    let mut capabilities = cap_lower;
    let mut auth_plugin_name = None;

    if pos < payload.len() {
        // character set (1 byte)
        if pos + 1 > payload.len() {
            return Err("握手包: 缺少 charset".to_string());
        }
        pos += 1;
        // status flags (2 bytes)
        if pos + 2 > payload.len() {
            return Err("握手包: 缺少 status".to_string());
        }
        pos += 2;
        // capability flags upper 2 bytes
        if pos + 2 > payload.len() {
            return Err("握手包: 缺少 capability upper".to_string());
        }
        let cap_upper = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as u32;
        capabilities |= cap_upper << 16;
        pos += 2;

        // auth-plugin-data length (1 byte) - 仅当 PLUGIN_AUTH flag 设置
        let has_plugin_auth = (capabilities & 0x00080000) != 0;
        if has_plugin_auth {
            if pos >= payload.len() {
                return Err("握手包: 缺少 auth-plugin-data length".to_string());
            }
            pos += 1;
        } else {
            pos += 1; // reserved
        }

        // reserved (10 bytes)
        if pos + 10 > payload.len() {
            return Err("握手包: 缺少 reserved".to_string());
        }
        pos += 10;

        // auth-plugin-data-part-2 (12 bytes + null) - 仅当 SECURE_CONNECTION flag 设置
        let has_secure_conn = (capabilities & 0x8000) != 0;
        if has_secure_conn {
            // MySQL 协议规定：part-2 长度 = max(13, auth_plugin_data_len - 8)
            // 通常取 13 字节（含末尾 null），我们取前 12 字节
            if pos + 12 > payload.len() {
                return Err("握手包: 缺少 salt2".to_string());
            }
            salt.extend_from_slice(&payload[pos..pos + 12]);
            pos += 13; // 跳过 12 字节 + 1 byte null
        }

        // auth-plugin-name (null-terminated)
        if has_plugin_auth && pos < payload.len() {
            let end = payload[pos..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(payload.len() - pos);
            auth_plugin_name = Some(
                String::from_utf8_lossy(&payload[pos..pos + end]).to_string(),
            );
        }
    }

    Ok(HandshakeInfo {
        protocol_version,
        server_version,
        server_capabilities: capabilities,
        salt,
        auth_plugin_name,
    })
}

/// 构造 HandshakeResponse41 登录包
fn build_login_packet(
    username: &str,
    auth_response: &[u8],
    auth_plugin: &str,
    _server_caps: u32,
) -> Vec<u8> {
    let mut packet = Vec::new();
    // capability flags (4 bytes) - CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    let caps: u32 = 0x000fa685;
    packet.extend_from_slice(&caps.to_le_bytes());
    // max packet size
    packet.extend_from_slice(&0x00ffffffu32.to_le_bytes());
    // character set (utf8mb4 = 255, 但 0x21=utf8 也常用)
    packet.push(0x21);
    // reserved (23 bytes)
    packet.extend_from_slice(&[0u8; 23]);
    // username (null-terminated)
    packet.extend_from_slice(username.as_bytes());
    packet.push(0);
    // auth response length (lenenc) + response
    packet.push(auth_response.len() as u8);
    packet.extend_from_slice(auth_response);
    // database (null-terminated) - 空（用默认）
    packet.push(0);
    // auth plugin name (null-terminated)
    packet.extend_from_slice(auth_plugin.as_bytes());
    packet.push(0);
    packet
}

/// 计算 mysql_native_password 认证响应
/// response = SHA1(password) XOR SHA1(sha256(sha1(password)) || salt)
/// 实际公式：SHA1(password) XOR SHA1(SHA1(SHA1(password)) + salt)
fn mysql_native_password(password: &str, salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let mut h1 = Sha1::new();
    h1.update(password.as_bytes());
    let hash1 = h1.finalize();

    let mut h2 = Sha1::new();
    h2.update(&hash1);
    let hash2 = h2.finalize();

    let mut h3 = Sha1::new();
    h3.update(salt);
    h3.update(&hash2);
    let hash3 = h3.finalize();

    hash1.iter().zip(hash3.iter()).map(|(a, b)| a ^ b).collect()
}

/// 计算 caching_sha2_password 的 fast auth 响应
/// 1. stage1 = SHA256(password)
/// 2. stage2 = SHA256(stage1 || salt)  (concatenate stage1 and salt)
/// 3. response = stage1 XOR stage2
fn caching_sha2_fast_auth(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Ok(Vec::new());
    }
    // stage1 = SHA256(password)
    let mut h1 = Sha256::new();
    h1.update(password.as_bytes());
    let stage1 = h1.finalize();

    // stage2 = SHA256(stage1 || salt)
    let mut h2 = Sha256::new();
    h2.update(&stage1);
    h2.update(salt);
    let stage2 = h2.finalize();

    // response = stage1 XOR stage2
    Ok(stage1.iter().zip(stage2.iter()).map(|(a, b)| a ^ b).collect())
}

/// 从 PEM 解析 RSA 公钥（PKCS#1 或 PKCS#8）
fn rsa_public_key_from_pem(pem: &str) -> Result<rsa::RsaPublicKey, String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;

    // 移除 PEM header/footer 和换行
    let body = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("base64 解码失败: {e}"))?;

    rsa::RsaPublicKey::from_pkcs1_der(&der)
        .or_else(|_| rsa::RsaPublicKey::from_public_key_der(&der))
        .map_err(|e| format!("RSA 公钥解析失败: {e}"))
}

/// RSA-OAEP-SHA256 加密
fn rsa_oaep_encrypt(
    pub_key: &rsa::RsaPublicKey,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    use rsa::Oaep;
    use sha2::Sha256;
    let padding = Oaep::<Sha256>::new();
    let mut rng = rand::rng();
    pub_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| format!("RSA 加密失败: {e}"))
}

// 引入 base64
use base64::Engine;

/// 读取一个 MySQL 数据包
async fn read_packet(stream: &mut TcpStream, dur: Duration) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    timeout(dur, stream.read_exact(&mut header))
        .await
        .map_err(|e| format!("读取超时: {e}"))?
        .map_err(|e| format!("读取失败: {e}"))?;
    let pkt_len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    let mut payload = vec![0u8; pkt_len];
    if pkt_len > 0 {
        timeout(dur, stream.read_exact(&mut payload))
            .await
            .map_err(|e| format!("读取超时: {e}"))?
            .map_err(|e| format!("读取失败: {e}"))?;
    }
    Ok(payload)
}

/// 写入一个 MySQL 数据包（含 sequence id）
async fn write_packet(
    stream: &mut TcpStream,
    payload: &[u8],
    seq: u8,
    dur: Duration,
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(payload.len() + 4);
    let len = payload.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes()[..3]);
    buf.push(seq);
    buf.extend_from_slice(payload);
    timeout(dur, stream.write_all(&buf))
        .await
        .map_err(|e| format!("发送超时: {e}"))?
        .map_err(|e| format!("发送失败: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_native_password_format() {
        let r = mysql_native_password("password", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        assert_eq!(r.len(), 20); // SHA1 输出 20 字节
    }

    #[test]
    fn test_caching_sha2_response_format() {
        let r = caching_sha2_fast_auth("password", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]).unwrap();
        assert_eq!(r.len(), 32); // SHA256 输出 32 字节
    }

    #[test]
    fn test_empty_password() {
        assert!(mysql_native_password("", &[1, 2]).is_empty());
        assert!(caching_sha2_fast_auth("", &[1, 2]).unwrap().is_empty());
    }
}
