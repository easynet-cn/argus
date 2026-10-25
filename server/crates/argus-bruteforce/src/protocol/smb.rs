//! SMB2 协议连接器
//!
//! 真实实现 SMB2 登录爆破（NTLM 认证）：
//! 1. TCP 连接到目标端口（默认 445）
//! 2. 发送 SMB2 Negotiate 请求
//! 3. 读取 Negotiate 响应
//! 4. 发送 SMB2 Session Setup（含 NTLM Negotiate）
//! 5. 读取 Session Setup 响应（含 NTLM Challenge）
//! 6. 计算 NTLMv2 响应（MD4 NT Hash + HMAC-MD5）
//! 7. 发送 SMB2 Session Setup（含 NTLM Auth）
//! 8. 检查状态码判断是否成功

use async_trait::async_trait;
use md4::Md4;
use md4::Digest as Md4Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct SmbConnector;

// SMB2 常量
const SMB2_MAGIC: u32 = 0x424D53FE; // 0xFE "SMB"
const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;

// NTLM 标识
const NTLMSSP_SIGNATURE: &[u8] = b"NTLMSSP\0";

#[async_trait]
impl ProtocolConnector for SmbConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Smb
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
            .map_err(|e| format!("SMB 连接超时: {e}"))?
            .map_err(|e| format!("SMB 连接失败: {e}"))?;

        // 2. 发送 SMB2 Negotiate 请求
        let negotiate_req = build_smb2_negotiate();
        stream
            .write_all(&negotiate_req)
            .await
            .map_err(|e| format!("发送 SMB2 Negotiate 失败: {e}"))?;

        // 3. 读取 Negotiate 响应
        let negotiate_resp =
            read_smb2_response(&mut stream, dur).await?;

        // 验证 SMB2 响应
        if negotiate_resp.len() < 68 {
            return Err("SMB2 Negotiate 响应过短".to_string());
        }
        if u32::from_le_bytes(negotiate_resp[4..8].try_into().unwrap_or([0; 4])) != SMB2_MAGIC {
            return Err("SMB2 响应魔术字不匹配".to_string());
        }

        // 4. 发送 SMB2 Session Setup（NTLM Negotiate）
        let ntlm_negotiate = build_ntlm_negotiate();
        let session_setup1 = build_smb2_session_setup(&ntlm_negotiate, 0);
        stream
            .write_all(&session_setup1)
            .await
            .map_err(|e| format!("发送 SMB2 Session Setup 失败: {e}"))?;

        // 5. 读取 Session Setup 响应（NTLM Challenge）
        let session_resp1 = read_smb2_response(&mut stream, dur).await?;

        // 解析 NTLM Challenge
        let ntlm_challenge = extract_ntlm_challenge(&session_resp1)?;
        let server_challenge = &ntlm_challenge[24..32]; // 8 字节 server challenge

        // 提取 target_info（用于 NTLMv2 计算）
        let target_info = extract_target_info(&ntlm_challenge);

        // 6. 计算 NTLMv2 响应
        let nt_hash = compute_nt_hash(&credential.password);
        let ntlm_response =
            compute_ntlmv2_response(&nt_hash, server_challenge, &target_info, &credential.username);

        // 构造 NTLM Auth 消息
        let ntlm_auth = build_ntlm_auth(&ntlm_response, &credential.username);

        // 7. 发送 SMB2 Session Setup（NTLM Auth）
        let session_id = u64::from_le_bytes(
            session_resp1[40..48].try_into().unwrap_or([0; 8]),
        );
        let session_setup2 = build_smb2_session_setup(&ntlm_auth, session_id);
        stream
            .write_all(&session_setup2)
            .await
            .map_err(|e| format!("发送 NTLM Auth 失败: {e}"))?;

        // 8. 读取 Session Setup 响应
        let session_resp2 = read_smb2_response(&mut stream, dur).await?;

        // 检查状态码（offset 8-12，LE u32）
        // 0x00000000 = STATUS_SUCCESS（登录成功）
        if session_resp2.len() >= 12 {
            let status = u32::from_le_bytes(
                session_resp2[8..12].try_into().unwrap_or([0; 4]),
            );
            Ok(status == 0)
        } else {
            Ok(false)
        }
    }
}

/// 构造 SMB2 Negotiate 请求
fn build_smb2_negotiate() -> Vec<u8> {
    // SMB2 dialects: 2.0.2, 2.1, 3.0
    let dialects: Vec<u16> = vec![0x0202, 0x0210, 0x0300];

    // Negotiate body (36 bytes + dialects)
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // DialectCount
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode (SIGNING_ENABLED)
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0x7Fu32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&[0u8; 16]); // ClientGuid
    body.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    body.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for d in &dialects {
        body.extend_from_slice(&d.to_le_bytes());
    }

    // SMB2 Header (64 bytes)
    let mut packet = Vec::with_capacity(64 + body.len());
    packet.extend_from_slice(&SMB2_MAGIC.to_le_bytes()); // ProtocolId
    packet.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    packet.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    packet.extend_from_slice(&0u32.to_le_bytes()); // Status
    packet.extend_from_slice(&SMB2_NEGOTIATE.to_le_bytes()); // Command
    packet.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    packet.extend_from_slice(&0u32.to_le_bytes()); // Flags
    packet.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    packet.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    packet.extend_from_slice(&0u32.to_le_bytes()); // Reserved (was: ProcessId)
    packet.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    packet.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    packet.extend_from_slice(&[0u8; 16]); // Signature
    packet.extend_from_slice(&body);

    // 前置 NetBIOS 头 (4 bytes: length as u32 LE, but only lower 3 bytes used)
    let netbios_len = packet.len() as u32;
    let mut full_packet = Vec::with_capacity(4 + packet.len());
    full_packet.extend_from_slice(&netbios_len.to_le_bytes());
    full_packet.extend_from_slice(&packet);

    full_packet
}

/// 构造 SMB2 Session Setup 请求
fn build_smb2_session_setup(security_buffer: &[u8], session_id: u64) -> Vec<u8> {
    // Session Setup body (24 bytes + security buffer)
    let mut body = Vec::new();
    body.extend_from_slice(&24u16.to_le_bytes()); // StructureSize
    body.push(0u8); // Flags
    body.push(0u8); // SecurityMode
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    // SecurityBufferOffset: offset from start of SMB2 header (64 + 24 = 88, but actually it's from start of body)
    // Actually, SecurityBufferOffset is from the beginning of the SMB2 header
    let sec_buf_offset = 64u32 + 24; // header + body fixed part
    body.extend_from_slice(&sec_buf_offset.to_le_bytes()); // SecurityBufferOffset (from SMB2 header start)
    body.extend_from_slice(&(security_buffer.len() as u16).to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&0u32.to_le_bytes()); // PreviousSessionId
    body.extend_from_slice(security_buffer);

    // SMB2 Header
    let mut packet = Vec::with_capacity(64 + body.len());
    packet.extend_from_slice(&SMB2_MAGIC.to_le_bytes());
    packet.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    packet.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    packet.extend_from_slice(&0u32.to_le_bytes()); // Status
    packet.extend_from_slice(&SMB2_SESSION_SETUP.to_le_bytes()); // Command
    packet.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    packet.extend_from_slice(&0u32.to_le_bytes()); // Flags
    packet.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    packet.extend_from_slice(&1u64.to_le_bytes()); // MessageId
    packet.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    packet.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    packet.extend_from_slice(&session_id.to_le_bytes()); // SessionId
    packet.extend_from_slice(&[0u8; 16]); // Signature
    packet.extend_from_slice(&body);

    // NetBIOS 头
    let netbios_len = packet.len() as u32;
    let mut full_packet = Vec::with_capacity(4 + packet.len());
    full_packet.extend_from_slice(&netbios_len.to_le_bytes());
    full_packet.extend_from_slice(&packet);

    full_packet
}

/// 构造 NTLM Negotiate (Type 1) 消息
fn build_ntlm_negotiate() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // Signature
    msg.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1 (Negotiate)
    // Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM
    let flags: u32 = 0x60000002; // 0x00000001 (Unicode) | 0x00000002 (NTLM) | 0x60000000
    msg.extend_from_slice(&flags.to_le_bytes());
    // DomainNameFields (offset=0, length=0)
    msg.extend_from_slice(&0u16.to_le_bytes()); // length
    msg.extend_from_slice(&0u16.to_le_bytes()); // max length
    msg.extend_from_slice(&0u32.to_le_bytes()); // offset
    // WorkstationFields (offset=0, length=0)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg
}

/// 从 SMB2 Session Setup 响应中提取 NTLM Challenge
fn extract_ntlm_challenge(resp: &[u8]) -> Result<Vec<u8>, String> {
    // SMB2 header = 64 bytes
    // Session Setup response body starts at offset 64
    // SecurityBufferOffset (u16 at body+8) and SecurityBufferLength (u16 at body+10)
    // SecurityBufferOffset is from the start of the SMB2 header

    if resp.len() < 68 {
        return Err("Session Setup 响应过短".to_string());
    }

    // 读取 NetBIOS 头 (4 bytes) -> actual SMB2 starts at offset 4
    // SMB2 header starts at offset 4
    let smb2_start = 4;

    // SecurityBufferOffset at body offset 8 (from SMB2 header)
    let sec_buf_offset = u16::from_le_bytes([
        resp[smb2_start + 64 + 8],
        resp[smb2_start + 64 + 9],
    ]) as usize;
    let sec_buf_len = u16::from_le_bytes([
        resp[smb2_start + 64 + 10],
        resp[smb2_start + 64 + 11],
    ]) as usize;

    let abs_offset = smb2_start + sec_buf_offset;
    if abs_offset + sec_buf_len > resp.len() {
        return Err(format!(
            "NTLM Challenge 超出范围: offset={abs_offset}, len={sec_buf_len}, resp={}",
            resp.len()
        ));
    }

    let challenge = resp[abs_offset..abs_offset + sec_buf_len].to_vec();

    // 验证 NTLM 签名
    if challenge.len() < 40 || &challenge[..8] != NTLMSSP_SIGNATURE {
        return Err("NTLM Challenge 签名不匹配".to_string());
    }

    Ok(challenge)
}

/// 从 NTLM Challenge 中提取 target_info
fn extract_target_info(challenge: &[u8]) -> Vec<u8> {
    if challenge.len() < 56 {
        return Vec::new();
    }

    // TargetInfoFields: offset at 48-50 (u16 LE length), 52-54 (u16 LE maxlen), 56-59 (u32 LE offset)
    // Wait, the NTLM Challenge structure:
    // 0-7: Signature (8 bytes)
    // 8-11: MessageType (4 bytes)
    // 12-19: TargetNameFields (8 bytes: length 2 + maxlen 2 + offset 4)
    // 20-23: NegotiateFlags (4 bytes)
    // 24-31: ServerChallenge (8 bytes)
    // 32-39: Reserved (8 bytes)
    // 40-47: TargetInfoFields (8 bytes: length 2 + maxlen 2 + offset 4)

    let ti_length = u16::from_le_bytes([
        challenge[40],
        challenge[41],
    ]) as usize;
    let ti_offset = u32::from_le_bytes([
        challenge[44],
        challenge[45],
        challenge[46],
        challenge[47],
    ]) as usize;

    if ti_offset + ti_length <= challenge.len() {
        challenge[ti_offset..ti_offset + ti_length].to_vec()
    } else {
        Vec::new()
    }
}

/// 计算 NT Hash: MD4(UTF-16LE(password))
fn compute_nt_hash(password: &str) -> [u8; 16] {
    let utf16_pass: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16_pass);
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// 计算 NTLMv2 响应
///
/// NTLMv2_Response = HMAC-MD5(NTLMv2_Hash, server_challenge + client_blob)
/// NTLMv2_Hash = HMAC-MD5(NT_Hash, "USERNAME\0DOMAIN" in UTF-16LE)
/// client_blob = timestamp(8) + client_nonce(8) + target_info + 0x00_00_00_00 terminator
fn compute_ntlmv2_response(
    nt_hash: &[u8; 16],
    server_challenge: &[u8],
    target_info: &[u8],
    username: &str,
) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use md5::Md5;

    // NTLMv2 Hash = HMAC-MD5(NT_Hash, USERNAME_UPPERCASE\0DOMAIN\0 in UTF-16LE)
    let mut user_domain = String::new();
    user_domain.push_str(&username.to_uppercase());
    user_domain.push('\0'); // domain (empty)
    let user_domain_utf16: Vec<u8> = user_domain
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hmac = Hmac::<Md5>::new_from_slice(nt_hash).unwrap();
    hmac.update(&user_domain_utf16);
    let ntlmv2_hash = hmac.finalize().into_bytes();

    // client_blob (NTLMv2 client challenge structure):
    // ResponseVersion(1) + HiVersion(1) + Z6(6) + TimeStamp(8) + ClientChallenge(8) + Reserved(4) + TargetInfo + Reserved(4)
    let timestamp = 0u64; // 简化时间戳
    let client_nonce: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    let mut blob = Vec::new();
    blob.push(0x01); // ResponseVersion
    blob.push(0x01); // HiVersion
    blob.extend_from_slice(&[0u8; 6]); // Z6
    blob.extend_from_slice(&timestamp.to_le_bytes()); // TimeStamp
    blob.extend_from_slice(&client_nonce); // ClientChallenge
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    blob.extend_from_slice(target_info); // TargetInfo
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved (end of list)

    // NTLMv2 Response = HMAC-MD5(NTLMv2_Hash, server_challenge + blob)
    let mut hmac2 = Hmac::<Md5>::new_from_slice(&ntlmv2_hash).unwrap();
    hmac2.update(server_challenge);
    hmac2.update(&blob);
    let nt_proof = hmac2.finalize().into_bytes();

    // Full NTLMv2 response = NTProofStr (16 bytes) + blob
    let mut response = Vec::with_capacity(16 + blob.len());
    response.extend_from_slice(&nt_proof);
    response.extend_from_slice(&blob);
    response
}

/// 构造 NTLM Auth (Type 3) 消息
fn build_ntlm_auth(ntlm_response: &[u8], username: &str) -> Vec<u8> {
    // UTF-16LE 编码用户名
    let username_utf16: Vec<u8> = username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // 偏移量: header(64) + username + response
    let header_len = 64usize;
    let username_offset = header_len;
    let response_offset = username_offset + username_utf16.len();

    let mut msg = Vec::new();
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // Signature
    msg.extend_from_slice(&3u32.to_le_bytes()); // MessageType = 3 (Auth)

    // LmChallengeResponseFields (length=0, offset=0)
    msg.extend_from_slice(&0u16.to_le_bytes()); // LmLen
    msg.extend_from_slice(&0u16.to_le_bytes()); // LmMaxLen
    msg.extend_from_slice(&(header_len as u32).to_le_bytes()); // LmOffset

    // NtChallengeResponseFields
    msg.extend_from_slice(&(ntlm_response.len() as u16).to_le_bytes()); // NtLen
    msg.extend_from_slice(&(ntlm_response.len() as u16).to_le_bytes()); // NtMaxLen
    msg.extend_from_slice(&(response_offset as u32).to_le_bytes()); // NtOffset

    // DomainNameFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&(header_len as u32).to_le_bytes());

    // UserNameFields
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());
    msg.extend_from_slice(&(username_offset as u32).to_le_bytes());

    // WorkstationFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&(header_len as u32).to_le_bytes());

    // EncryptedRandomSessionKeyFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&(header_len as u32).to_le_bytes());

    // NegotiateFlags
    let flags: u32 = 0x60000002;
    msg.extend_from_slice(&flags.to_le_bytes());

    // 变长数据
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(ntlm_response);

    msg
}

/// 读取 SMB2 响应
async fn read_smb2_response(
    stream: &mut TcpStream,
    dur: Duration,
) -> Result<Vec<u8>, String> {
    // 先读 4 字节 NetBIOS 头
    let mut header = [0u8; 4];
    match timeout(dur, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("读取 SMB2 头失败: {e}")),
        Err(_) => return Err("读取 SMB2 头超时".to_string()),
    }

    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > 65536 {
        return Err(format!("SMB2 响应长度异常: {length}"));
    }

    let mut buf = vec![0u8; length];
    match timeout(dur, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(format!("读取 SMB2 体失败: {e}")),
        Err(_) => return Err("读取 SMB2 体超时".to_string()),
    }

    // 合并 NetBIOS 头 + SMB2 数据
    let mut full = Vec::with_capacity(4 + length);
    full.extend_from_slice(&header);
    full.extend_from_slice(&buf);
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_protocol() {
        assert_eq!(SmbConnector.protocol(), Protocol::Smb);
    }

    #[test]
    fn test_build_smb2_negotiate() {
        let pkt = build_smb2_negotiate();
        // NetBIOS 头 (4) + SMB2 头 (64) + body (36 + 6) = 110
        assert!(pkt.len() >= 110);
        // 验证 SMB2 魔术字 (offset 4-8, LE)
        let magic = u32::from_le_bytes(pkt[4..8].try_into().unwrap());
        assert_eq!(magic, SMB2_MAGIC);
        // Command = NEGOTIATE (offset 16-18, LE)
        let cmd = u16::from_le_bytes(pkt[16..18].try_into().unwrap());
        assert_eq!(cmd, SMB2_NEGOTIATE);
    }

    #[test]
    fn test_compute_nt_hash() {
        // NT Hash of "password" = MD4(UTF-16LE("password")) = 8846F7EAEE8FB117AD06BDD830B7586C
        let hash = compute_nt_hash("password");
        let expected: [u8; 16] = [
            0x88, 0x46, 0xF7, 0xEA, 0xEE, 0x8F, 0xB1, 0x17,
            0xAD, 0x06, 0xBD, 0xD8, 0x30, 0xB7, 0x58, 0x6C,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_build_ntlm_negotiate() {
        let msg = build_ntlm_negotiate();
        // 签名
        assert_eq!(&msg[..8], NTLMSSP_SIGNATURE);
        // MessageType = 1
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, 1);
    }

    #[test]
    fn test_build_ntlm_auth() {
        let response = vec![0u8; 16]; // 模拟 NTLMv2 响应
        let msg = build_ntlm_auth(&response, "admin");
        // 签名
        assert_eq!(&msg[..8], NTLMSSP_SIGNATURE);
        // MessageType = 3
        let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(msg_type, 3);
    }
}
