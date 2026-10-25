//! MongoDB 协议连接器
//!
//! 通过 OP_MSG (MongoDB 3.6+ wire protocol) 实现 SCRAM-SHA-1 认证。
//! 纯 Rust 实现，不依赖官方 MongoDB driver，避免引入重量级依赖。
//!
//! 认证流程:
//! 1. 发送 `hello` / `isMaster` 命令探测是否需要认证
//! 2. 若需要认证，执行 SCRAM-SHA-1:
//!    - saslStart: 发送 client-first-message
//!    - saslContinue: 发送 client-final-message，校验 server-signature

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use base64::Engine;

type HmacSha1 = Hmac<Sha1>;

pub struct MongodbConnector;

#[async_trait]
impl ProtocolConnector for MongodbConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Mongodb
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

        // 1. 探测认证需求
        let hello_doc = bson_doc(vec![
            ("isMaster", bson_i32(1)),
            ("helloOk", bson_i32(1)),
        ]);
        let response = send_op_msg(&mut stream, "admin.$cmd", hello_doc, dur).await?;

        // 如果 ok=1 且无 saslSupportedMechs，则无需认证（开放访问）
        if let Some(ok) = bson_get_f64(&response, "ok") {
            if ok >= 1.0 && bson_get_str(&response, "saslSupportedMechs").is_none() {
                return Ok(true); // 无认证即可访问
            }
        }

        // 2. SCRAM-SHA-1 认证
        scram_sha1_auth(&mut stream, &credential.username, &credential.password, dur).await
    }
}

/// 执行 SCRAM-SHA-1 认证
async fn scram_sha1_auth(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    dur: Duration,
) -> Result<bool, String> {
    let nonce = generate_nonce();
    let client_first_bare = format!("n=,r={}", nonce);
    let client_first = format!("n,,{}", client_first_bare);

    // saslStart
    let sasl_start_doc = bson_doc(vec![
        ("saslStart", bson_i32(1)),
        ("mechanism", bson_str("SCRAM-SHA-1")),
        ("payload", bson_bin(client_first.as_bytes().to_vec())),
        ("autoStart", bson_i32(0)),
    ]);
    let resp1 = send_op_msg(stream, "admin.$cmd", sasl_start_doc, dur).await?;

    // 检查 saslStart 响应
    let conv_id = bson_get_i32(&resp1, "conversationId").unwrap_or(1);
    let payload1 = bson_get_bin(&resp1, "payload");
    let done1 = bson_get_i32(&resp1, "done").unwrap_or(0);

    if done1 == 1 {
        // 认证立即成功（空密码或已认证）
        return Ok(true);
    }

    let server_first = match payload1 {
        Some(p) => String::from_utf8_lossy(&p).to_string(),
        None => return Err("saslStart 未返回 payload".to_string()),
    };

    // 解析 server-first-message: r=<server-nonce>,s=<salt>,i=<iterations>
    let server_nonce = extract_scram_field(&server_first, 'r')?;
    let salt_b64 = extract_scram_field(&server_first, 's')?;
    let iterations: u32 = extract_scram_field(&server_first, 'i')?
        .parse()
        .map_err(|_| "iterations 解析失败".to_string())?;

    // 验证 server-nonce 以 client-nonce 开头
    if !server_nonce.starts_with(&nonce) {
        return Err("server nonce 不匹配".to_string());
    }

    // 计算 SaltedPassword = PBKDF2(password, salt, iterations, 20)
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&salt_b64)
        .map_err(|e| format!("salt base64 解码失败: {e}"))?;
    let mut salted_password = [0u8; 20];
    pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt, iterations, &mut salted_password);

    // ClientKey = HMAC(SaltedPassword, "Client Key")
    let mut mac = HmacSha1::new_from_slice(&salted_password[..])
        .map_err(|e| format!("HMAC key 失败: {e}"))?;
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();

    // StoredKey = SHA1(ClientKey)
    let stored_key = {
        use sha1::Digest;
        let mut hasher = Sha1::new();
        hasher.update(client_key);
        hasher.finalize()
    };

    // AuthMessage
    let client_final_wo_proof = format!("c=biws,r={}", server_nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_wo_proof
    );

    // ClientSignature = HMAC(StoredKey, AuthMessage)
    let mut sig_mac = HmacSha1::new_from_slice(&stored_key)
        .map_err(|e| format!("HMAC sig 失败: {e}"))?;
    sig_mac.update(auth_message.as_bytes());
    let client_signature = sig_mac.finalize().into_bytes();

    // ClientProof = ClientKey XOR ClientSignature
    let client_proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(&client_proof);

    let client_final = format!("{},p={}", client_final_wo_proof, proof_b64);

    // saslContinue
    let sasl_cont_doc = bson_doc(vec![
        ("saslContinue", bson_i32(1)),
        ("conversationId", bson_i32(conv_id)),
        ("payload", bson_bin(client_final.as_bytes().to_vec())),
    ]);
    let resp2 = send_op_msg(stream, "admin.$cmd", sasl_cont_doc, dur).await?;

    let done2 = bson_get_i32(&resp2, "done").unwrap_or(0);
    let ok2 = bson_get_f64(&resp2, "ok").unwrap_or(0.0);

    if done2 == 1 && ok2 >= 1.0 {
        // 校验 server-signature (可选，增强安全性)
        if let Some(payload2) = bson_get_bin(&resp2, "payload") {
            let server_final = String::from_utf8_lossy(&payload2).to_string();
            if let Ok(server_sig_b64) = extract_scram_field(&server_final, 'v') {
                // ServerKey = HMAC(SaltedPassword, "Server Key")
                let mut srv_mac = HmacSha1::new_from_slice(&salted_password[..])
                    .map_err(|e| format!("HMAC srv 失败: {e}"))?;
                srv_mac.update(b"Server Key");
                let server_key = srv_mac.finalize().into_bytes();
                // ServerSignature = HMAC(ServerKey, AuthMessage)
                let mut srv_sig_mac = HmacSha1::new_from_slice(&server_key)
                    .map_err(|e| format!("HMAC srv sig 失败: {e}"))?;
                srv_sig_mac.update(auth_message.as_bytes());
                let expected_sig = srv_sig_mac.finalize().into_bytes();
                let expected_b64 = base64::engine::general_purpose::STANDARD
                    .encode(&expected_sig);
                if server_sig_b64 != expected_b64 {
                    return Ok(false); // 签名不匹配
                }
            }
        }
        return Ok(true);
    }

    Ok(false)
}

/// 生成 16 字节随机 nonce (base64)
fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    base64::engine::general_purpose::STANDARD.encode(&bytes)
}

/// 从 SCRAM 消息中提取字段值 (格式: r=xxx,s=yyy,i=zzz)
fn extract_scram_field(msg: &str, field: char) -> Result<String, String> {
    for part in msg.split(',') {
        if let Some(rest) = part.strip_prefix(&format!("{}=", field)) {
            return Ok(rest.to_string());
        }
    }
    Err(format!("SCRAM 字段 '{}' 未找到", field))
}

// ============== BSON 最小编码/解码 ==============
// 只实现 auth 所需的类型: int32, string, binary, double

const BSON_INT32: u8 = 0x10;
const BSON_STRING: u8 = 0x02;
const BSON_BINARY: u8 = 0x05;
const BSON_DOUBLE: u8 = 0x01;

/// BSON 文档构造辅助
struct BsonDoc {
    fields: Vec<(&'static str, Vec<u8>)>,
}

fn bson_doc(fields: Vec<(&'static str, Vec<u8>)>) -> BsonDoc {
    BsonDoc { fields }
}

fn bson_i32(v: i32) -> Vec<u8> {
    let mut buf = vec![BSON_INT32];
    buf.extend_from_slice(&v.to_le_bytes());
    buf
}

fn bson_str(s: &str) -> Vec<u8> {
    let mut buf = vec![BSON_STRING];
    let s_len = (s.len() + 1) as i32;
    buf.extend_from_slice(&s_len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0); // null terminator
    buf
}

fn bson_bin(data: Vec<u8>) -> Vec<u8> {
    let mut buf = vec![BSON_BINARY];
    let len = data.len() as i32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(0x00); // subtype: generic
    buf.extend_from_slice(&data);
    buf
}

fn bson_f64(v: f64) -> Vec<u8> {
    let mut buf = vec![BSON_DOUBLE];
    buf.extend_from_slice(&v.to_le_bytes());
    buf
}

/// 序列化 BSON 文档为字节
impl BsonDoc {
    fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, val) in &self.fields {
            // BSON field: [type:1][key:cstring][value]
            // val = [type_byte, value_bytes...]
            let type_byte = val[0];
            let value_bytes = &val[1..];
            body.push(type_byte);
            body.extend_from_slice(key.as_bytes());
            body.push(0); // key null terminator
            body.extend_from_slice(value_bytes);
        }
        body.push(0); // document null terminator

        let total_len = (body.len() + 4) as i32;
        let mut out = total_len.to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }
}

/// 解析 BSON 文档，返回所有键值对的扁平 map
fn parse_bson(data: &[u8]) -> BsonValue {
    if data.len() < 4 {
        return BsonValue::Null;
    }
    let doc_len = i32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < doc_len {
        return BsonValue::Null;
    }
    // 跳过长度前缀和末尾的 null，解析字段
    let fields_data = &data[4..doc_len - 1];
    let mut map = std::collections::BTreeMap::new();
    let mut pos = 0;
    while pos < fields_data.len() {
        let type_tag = fields_data[pos];
        pos += 1;
        // 读取 key (cstring)
        let key_end = fields_data[pos..].iter().position(|&b| b == 0).unwrap_or(0);
        let key = String::from_utf8_lossy(&fields_data[pos..pos + key_end]).to_string();
        pos += key_end + 1;

        let val = match type_tag {
            BSON_DOUBLE => {
                let v = f64::from_le_bytes(fields_data[pos..pos + 8].try_into().unwrap_or([0; 8]));
                pos += 8;
                BsonValue::F64(v)
            }
            BSON_STRING => {
                let s_len = i32::from_le_bytes(
                    fields_data[pos..pos + 4].try_into().unwrap_or([0; 4]),
                ) as usize;
                pos += 4;
                let s = String::from_utf8_lossy(
                    &fields_data[pos..pos + s_len.saturating_sub(1)],
                )
                .to_string();
                pos += s_len;
                BsonValue::Str(s)
            }
            BSON_INT32 => {
                let v = i32::from_le_bytes(
                    fields_data[pos..pos + 4].try_into().unwrap_or([0; 4]),
                );
                pos += 4;
                BsonValue::I32(v)
            }
            BSON_BINARY => {
                let b_len = i32::from_le_bytes(
                    fields_data[pos..pos + 4].try_into().unwrap_or([0; 4]),
                ) as usize;
                pos += 4;
                let _subtype = fields_data[pos];
                pos += 1;
                let data = fields_data[pos..pos + b_len].to_vec();
                pos += b_len;
                BsonValue::Bin(data)
            }
            0x08 => {
                // boolean
                let v = fields_data[pos] != 0;
                pos += 1;
                BsonValue::Bool(v)
            }
            0x0A => BsonValue::Null, // null
            _ => {
                // 未知类型，无法安全跳过；停止解析
                break;
            }
        };
        map.insert(key, val);
    }
    BsonValue::Doc(map)
}

#[derive(Debug, Clone)]
enum BsonValue {
    Doc(std::collections::BTreeMap<String, BsonValue>),
    F64(f64),
    I32(i32),
    Str(String),
    Bin(Vec<u8>),
    Bool(bool),
    Null,
}

fn bson_get_f64(doc: &BsonValue, key: &str) -> Option<f64> {
    match doc {
        BsonValue::Doc(m) => match m.get(key) {
            Some(BsonValue::F64(v)) => Some(*v),
            Some(BsonValue::I32(v)) => Some(*v as f64),
            _ => None,
        },
        _ => None,
    }
}

fn bson_get_i32(doc: &BsonValue, key: &str) -> Option<i32> {
    match doc {
        BsonValue::Doc(m) => match m.get(key) {
            Some(BsonValue::I32(v)) => Some(*v),
            Some(BsonValue::F64(v)) => Some(*v as i32),
            _ => None,
        },
        _ => None,
    }
}

fn bson_get_str(doc: &BsonValue, key: &str) -> Option<String> {
    match doc {
        BsonValue::Doc(m) => match m.get(key) {
            Some(BsonValue::Str(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn bson_get_bin(doc: &BsonValue, key: &str) -> Option<Vec<u8>> {
    match doc {
        BsonValue::Doc(m) => match m.get(key) {
            Some(BsonValue::Bin(b)) => Some(b.clone()),
            _ => None,
        },
        _ => None,
    }
}

// ============== OP_MSG wire protocol ==============
// OP_MSG = 2013
// 格式: int32 messageLength | int32 requestID | int32 responseTo | int32 opCode(2013)
//        | uint32 flag | Section 0: kind(0) + body document

const OP_MSG: i32 = 2013;

/// 发送 OP_MSG 命令并读取响应
async fn send_op_msg(
    stream: &mut TcpStream,
    collection: &str,
    doc: BsonDoc,
    dur: Duration,
) -> Result<BsonValue, String> {
    // 构造 OP_MSG body
    let mut body = Vec::new();
    // Section 0: kind = 0 (body document)
    body.push(0u8);
    // body document
    let doc_bytes = doc.to_bytes();
    body.extend_from_slice(&doc_bytes);

    // flagBits (uint32, 0 = no special flags)
    let mut msg = Vec::new();
    msg.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    msg.extend_from_slice(&body);

    let total_len = (msg.len() + 16) as i32; // 16 = header
    let request_id: i32 = 1;
    let response_to: i32 = 0;

    // 写 header + msg
    let mut packet = Vec::new();
    packet.extend_from_slice(&total_len.to_le_bytes());
    packet.extend_from_slice(&request_id.to_le_bytes());
    packet.extend_from_slice(&response_to.to_le_bytes());
    packet.extend_from_slice(&OP_MSG.to_le_bytes());
    packet.extend_from_slice(&msg);

    // 发送
    timeout(dur, stream.write_all(&packet))
        .await
        .map_err(|e| format!("发送超时: {e}"))?
        .map_err(|e| format!("发送失败: {e}"))?;

    // 读取响应 header (16 bytes)
    let mut header = [0u8; 16];
    timeout(dur, stream.read_exact(&mut header))
        .await
        .map_err(|e| format!("读取 header 超时: {e}"))?
        .map_err(|e| format!("读取 header 失败: {e}"))?;

    let resp_len = i32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    if resp_len < 16 || resp_len > 64 * 1024 * 1024 {
        return Err(format!("响应长度异常: {}", resp_len));
    }

    // 读取剩余
    let remaining = resp_len - 16;
    let mut resp_body = vec![0u8; remaining];
    timeout(dur, stream.read_exact(&mut resp_body))
        .await
        .map_err(|e| format!("读取 body 超时: {e}"))?
        .map_err(|e| format!("读取 body 失败: {e}"))?;

    // 解析 OP_MSG: flagBits(4) + section
    if resp_body.len() < 5 {
        return Err("响应体过短".to_string());
    }
    // flagBits = &resp_body[0..4]
    let kind = resp_body[4];
    if kind != 0 {
        return Err(format!("不支持的 section kind: {}", kind));
    }
    // body document 从 offset 5 开始
    let doc_data = &resp_body[5..];
    let parsed = parse_bson(doc_data);
    // collection 参数保留用于未来扩展（如 $cmd aggregate）
    let _ = collection;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bson_doc_serialization() {
        let doc = bson_doc(vec![
            ("isMaster", bson_i32(1)),
            ("helloOk", bson_i32(1)),
        ]);
        let bytes = doc.to_bytes();
        assert!(bytes.len() > 4);
        // 第一个字段应该是 int32 type tag (0x10)
        assert_eq!(bytes[4], BSON_INT32);
    }

    #[test]
    fn test_bson_string_serialization() {
        let s = bson_str("SCRAM-SHA-1");
        assert_eq!(s[0], BSON_STRING);
        // 长度前缀 + null terminator
        let len = i32::from_le_bytes(s[1..5].try_into().unwrap());
        assert_eq!(len as usize, "SCRAM-SHA-1".len() + 1);
    }

    #[test]
    fn test_bson_binary_serialization() {
        let b = bson_bin(vec![1, 2, 3]);
        assert_eq!(b[0], BSON_BINARY);
        let len = i32::from_le_bytes(b[1..5].try_into().unwrap());
        assert_eq!(len, 3);
        assert_eq!(b[5], 0x00); // subtype generic
    }

    #[test]
    fn test_bson_doc_round_trip() {
        let doc = bson_doc(vec![
            ("ok", bson_f64(1.0)),
            ("name", bson_str("test")),
        ]);
        let bytes = doc.to_bytes();
        let parsed = parse_bson(&bytes);
        assert_eq!(bson_get_f64(&parsed, "ok"), Some(1.0));
        assert_eq!(bson_get_str(&parsed, "name"), Some("test".to_string()));
    }

    #[test]
    fn test_extract_scram_field() {
        let msg = "r=fyko+d5lbb2sbrr6afbmsg,s=QSXCR+Q6sek8f5Ls,g=4096";
        assert_eq!(extract_scram_field(msg, 'r').unwrap(), "fyko+d5lbb2sbrr6afbmsg");
        assert_eq!(extract_scram_field(msg, 's').unwrap(), "QSXCR+Q6sek8f5Ls");
        assert_eq!(extract_scram_field(msg, 'g').unwrap(), "4096");
        assert!(extract_scram_field(msg, 'x').is_err());
    }

    #[test]
    fn test_generate_nonce() {
        let n = generate_nonce();
        assert!(!n.is_empty());
        // base64 编码 16 字节 = 24 字符
        assert_eq!(n.len(), 24);
    }

    #[test]
    fn test_bson_parse_empty_doc() {
        // 空 BSON 文档: 长度=5 (4字节长度 + 1字节null)
        let empty = vec![5, 0, 0, 0, 0];
        let parsed = parse_bson(&empty);
        match parsed {
            BsonValue::Doc(m) => assert!(m.is_empty()),
            _ => panic!("应为 Doc"),
        }
    }

    #[test]
    fn test_bson_parse_int32() {
        // 构造一个包含 int32 字段的文档
        let doc = bson_doc(vec![("count", bson_i32(42))]);
        let bytes = doc.to_bytes();
        let parsed = parse_bson(&bytes);
        assert_eq!(bson_get_i32(&parsed, "count"), Some(42));
    }

    #[test]
    fn test_bson_parse_binary() {
        let doc = bson_doc(vec![("payload", bson_bin(vec![0xDE, 0xAD]))]);
        let bytes = doc.to_bytes();
        let parsed = parse_bson(&bytes);
        let bin = bson_get_bin(&parsed, "payload").unwrap();
        assert_eq!(bin, vec![0xDE, 0xAD]);
    }
}
