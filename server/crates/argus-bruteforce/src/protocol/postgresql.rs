//! PostgreSQL 协议连接器
//!
//! 支持：
//! - AuthenticationCleartextPassword (auth_type=3)
//! - AuthenticationMD5Password (auth_type=5)
//! - AuthenticationSASL / SCRAM-SHA-256 (auth_type=10/11/12)

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use hex;
use md5::Md5;

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct PostgresqlConnector;

#[async_trait]
impl ProtocolConnector for PostgresqlConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Postgresql
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

        // 1. 发送 StartupMessage
        let startup = build_startup_message(&credential.username);
        write_message(&mut stream, None, &startup, dur).await?;

        // 2. 读取认证请求，循环处理直到 Ok 或 Error
        loop {
            let (msg_type, body) = read_message(&mut stream, dur).await?;

            match msg_type {
                'R' => {
                    if body.len() < 4 {
                        return Err("认证响应体过短".to_string());
                    }
                    let auth_type = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);

                    match auth_type {
                        0 => return Ok(true), // AuthenticationOk
                        3 => {
                            // AuthenticationCleartextPassword
                            let pwd_msg = format!("{}\0", credential.password);
                            write_message(&mut stream, Some(b'p'), pwd_msg.as_bytes(), dur).await?;
                        }
                        5 => {
                            // AuthenticationMD5Password
                            let salt = &body[4..8];
                            let hash = md5_hash(&credential.password, &credential.username, salt);
                            let pwd_msg = format!("md5{}\0", hash);
                            write_message(&mut stream, Some(b'p'), pwd_msg.as_bytes(), dur).await?;
                        }
                        10 => {
                            // AuthenticationSASL - 机制列表（null 分隔，以 \xFF\xFF\xFF\xFF 结束）
                            let mechanisms = parse_sasl_mechanisms(&body[4..])?;
                            if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                                return Err(format!(
                                    "服务器不支持 SCRAM-SHA-256，机制: {:?}",
                                    mechanisms
                                ));
                            }
                            let client_first = build_client_first_message(&credential.username);
                            let client_nonce = extract_nonce(&client_first);

                            // SASLInitialResponse: 机制名(null) + 长度(4 BE) + 客户端首条消息
                            let mut payload = Vec::new();
                            payload.extend_from_slice(b"SCRAM-SHA-256\0");
                            let cf_len = client_first.len() as i32;
                            payload.extend_from_slice(&cf_len.to_be_bytes());
                            payload.extend_from_slice(client_first.as_bytes());

                            write_message(&mut stream, Some(b'p'), &payload, dur).await?;

                            // 3. 读取 SASLContinue (Server First Message)
                            let (sftype, sbody) = read_message(&mut stream, dur).await?;
                            if sftype != 'R' || sbody.len() < 4 {
                                return Err(format!("期望 SASLContinue，收到: {sftype}"));
                            }
                            let sauth = i32::from_be_bytes([sbody[0], sbody[1], sbody[2], sbody[3]]);
                            if sauth != 11 {
                                return Err(format!("期望 auth_type=11，收到 {sauth}"));
                            }
                            let server_first =
                                String::from_utf8_lossy(&sbody[4..]).to_string();

                            // 4. 计算并发送 Client Final Message
                            let client_final = build_client_final_message(
                                &credential.password,
                                &client_first,
                                &server_first,
                                &client_nonce,
                            )?;

                            // SASLResponse: 仅 Client Final Message 字节
                            write_message(
                                &mut stream,
                                Some(b'p'),
                                client_final.as_bytes(),
                                dur,
                            )
                            .await?;

                            // 5. 读取 SASLFinal (Server Final Message) + AuthenticationOk
                            // 循环处理后续消息
                            // 下一次外层循环会处理
                        }
                        12 => {
                            // AuthenticationSASLFinal - 服务器最终消息，验证即可（这里不强制校验 server signature）
                            // 直接等待下一帧 AuthenticationOk
                        }
                        other => {
                            return Err(format!("不支持的认证类型: {other}"));
                        }
                    }
                }
                'E' => return Ok(false), // ErrorResponse -> 认证失败
                other => {
                    return Err(format!("意外的响应类型: {other}"));
                }
            }
        }
    }
}

/// 构造 StartupMessage（协议版本 3.0）
fn build_startup_message(username: &str) -> Vec<u8> {
    let mut startup = Vec::new();
    startup.extend_from_slice(&196608u32.to_be_bytes()); // 3.0
    startup.extend_from_slice(b"user\0");
    startup.extend_from_slice(username.as_bytes());
    startup.push(0);
    startup.extend_from_slice(b"database\0postgres\0");
    startup.push(0); // 结束
    // 注意：返回 payload（不含 length prefix），由 write_message 统一添加
    startup
}

/// 写一帧消息到流
/// - 对于 StartupMessage，type_byte 为 None（无类型字节）
/// - 其他消息传 Some(type_byte)，会在 length 前写入 type_byte
async fn write_message(
    stream: &mut TcpStream,
    type_byte: Option<u8>,
    payload: &[u8],
    dur: Duration,
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(payload.len() + 5);
    if let Some(t) = type_byte {
        buf.push(t);
    }
    let len = (payload.len() + 4) as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);

    timeout(dur, stream.write_all(&buf))
        .await
        .map_err(|e| format!("发送超时: {e}"))?
        .map_err(|e| format!("发送失败: {e}"))?;
    Ok(())
}

/// 读取一帧消息，返回 (type_byte, body)
/// 对于 StartupMessage 响应，type_byte 是第一个字节
async fn read_message(stream: &mut TcpStream, dur: Duration) -> Result<(char, Vec<u8>), String> {
    let mut header = [0u8; 5];
    match timeout(dur, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err("读取失败: early eof".to_string());
        }
        Ok(Err(e)) => return Err(format!("读取失败: {e}")),
        Err(e) => return Err(format!("读取超时: {e}")),
    }

    let msg_type = header[0] as char;
    let msg_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if msg_len < 4 {
        return Err(format!("消息长度字段无效: {msg_len}"));
    }
    let body_len = msg_len - 4;
    let mut body = vec![0u8; body_len];
    if !body.is_empty() {
        match timeout(dur, stream.read_exact(&mut body)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err("读取失败: early eof (body)".to_string());
            }
            Ok(Err(e)) => return Err(format!("读取失败 (body): {e}")),
            Err(e) => return Err(format!("读取超时 (body): {e}")),
        }
    }
    Ok((msg_type, body))
}

/// 解析 SASL 机制列表（body 部分，每项以 null 分隔，以 -1 (0xFFFFFFFF) 终止）
fn parse_sasl_mechanisms(data: &[u8]) -> Result<Vec<String>, String> {
    let mut mechs = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            if i > start {
                mechs.push(String::from_utf8_lossy(&data[start..i]).to_string());
            }
            start = i + 1;
        }
    }
    Ok(mechs)
}

/// 构造 Client First Message: `n,,n=<user>,r=<nonce>`
fn build_client_first_message(username: &str) -> String {
    let nonce = generate_nonce();
    // SASLprep 简化处理：直接用 username（PostgreSQL 不允许 SASLprep 后含 = 等字符）
    let safe_user = username.replace('=', "=3D").replace(',', "=2C");
    format!("n,,n={safe_user},r={nonce}")
}

/// 从 Client First Message 中提取 nonce
fn extract_nonce(client_first: &str) -> String {
    if let Some(idx) = client_first.rfind("r=") {
        client_first[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// 生成 base64 随机 nonce（18 字节 -> 24 字符）
fn generate_nonce() -> String {
    let bytes: [u8; 18] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 构造 Client Final Message 并计算 ClientProof
/// Client Final Message: `c=biws,r=<combined_nonce>,p=<base64_client_proof>`
fn build_client_final_message(
    password: &str,
    client_first: &str,
    server_first: &str,
    client_nonce: &str,
) -> Result<String, String> {
    // 解析 Server First Message: r=<nonce>,s=<salt_b64>,i=<iter>
    let mut combined_nonce = String::new();
    let mut salt_b64 = String::new();
    let mut iterations: u32 = 0;

    for part in server_first.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            combined_nonce = v.to_string();
        } else if let Some(v) = part.strip_prefix("s=") {
            salt_b64 = v.to_string();
        } else if let Some(v) = part.strip_prefix("i=") {
            iterations = v.parse::<u32>().map_err(|e| format!("iterations 解析失败: {e}"))?;
        }
    }

    if combined_nonce.is_empty() || salt_b64.is_empty() || iterations == 0 {
        return Err(format!("Server First 解析失败: {server_first}"));
    }
    if !combined_nonce.starts_with(client_nonce) {
        return Err("服务器 nonce 不以客户端 nonce 开头".to_string());
    }

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&salt_b64)
        .map_err(|e| format!("salt base64 解码失败: {e}"))?;

    // SaltedPassword = PBKDF2(password, salt, iter, 32)
    let mut salted_password = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iterations, &mut salted_password);

    // ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(&salted_password)
        .map_err(|e| format!("HMAC 初始化失败: {e}"))?;
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // StoredKey = SHA256(ClientKey)
    let mut hasher = Sha256::new();
    hasher.update(&client_key);
    let stored_key = hasher.finalize();

    // AuthMessage = client_first_bare + "," + server_first + "," + client_final_without_proof
    // client_first_bare = "n=<user>,r=<nonce>" (去掉 GS2 header "n,,")
    let client_first_bare = client_first
        .strip_prefix("n,,")
        .ok_or("Client First 缺少 GS2 header")?;
    let client_final_without_proof = format!("c=biws,r={combined_nonce}");
    let auth_message = format!(
        "{client_first_bare},{server_first},{client_final_without_proof}"
    );

    // ClientSignature = HMAC-SHA256(StoredKey, AuthMessage)
    let mut sig_mac = HmacSha256::new_from_slice(&stored_key)
        .map_err(|e| format!("HMAC 初始化失败: {e}"))?;
    sig_mac.update(auth_message.as_bytes());
    let client_signature = sig_mac.finalize().into_bytes();

    // ClientProof = ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&client_proof);

    Ok(format!("{client_final_without_proof},p={proof_b64}"))
}

/// PostgreSQL MD5 密码哈希
/// md5(md5(password + username) + salt)
fn md5_hash(password: &str, username: &str, salt: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(password.as_bytes());
    hasher.update(username.as_bytes());
    let inner = hex::encode(hasher.finalize());

    let mut hasher2 = Md5::new();
    hasher2.update(inner.as_bytes());
    hasher2.update(salt);
    hex::encode(hasher2.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_hash_format() {
        let h = md5_hash("password", "user", &[1, 2, 3, 4]);
        assert_eq!(h.len(), 32); // 16 bytes hex
    }

    #[test]
    fn test_nonce_is_base64() {
        let n = generate_nonce();
        assert_eq!(n.len(), 24);
    }

    #[test]
    fn test_extract_nonce() {
        let cf = "n,,n=user,r=abc123";
        assert_eq!(extract_nonce(cf), "abc123");
    }

    #[test]
    fn test_parse_sasl_mechanisms() {
        let data = b"SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0";
        let mechs = parse_sasl_mechanisms(data).unwrap();
        assert!(mechs.contains(&"SCRAM-SHA-256".to_string()));
    }

    #[test]
    fn test_client_final_computes_proof() {
        let password = "password";
        let client_first = "n,,n=user,r=clientnonce123";
        // 模拟 Server First
        let salt = base64::engine::general_purpose::STANDARD.encode(b"saltsalt");
        let server_first = format!("r=clientnonce123sernonce456,s={salt},i=4096");
        let result = build_client_final_message(password, client_first, &server_first, "clientnonce123");
        assert!(result.is_ok());
        let cf = result.unwrap();
        assert!(cf.starts_with("c=biws,r=clientnonce123sernonce456,p="));
    }
}
