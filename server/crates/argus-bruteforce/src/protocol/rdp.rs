//! RDP 协议连接器
//!
//! 真实实现 RDP 认证爆破（X.224 + Standard Security 路径）：
//! 1. TPKT + X.224 Connection Request → 协商认证方式
//! 2. 如果服务器仅支持 NLA (CredSSP) → 报错（NLA 需 NTLM+TLS+SPNEGO，暂不支持）
//! 3. 如果支持 Standard Security → MCS Connect-Initial → 获取服务器证书/随机数
//! 4. Security Exchange: RSA 加密 client random 发送给服务器
//! 5. 派生 RC4 密钥
//! 6. 加密 Client Info PDU（含用户名/密码）发送给服务器
//! 7. 检查响应：成功 = 正确凭证，失败 = 错误凭证
//!
//! 限制：完整 NLA (CredSSP) 爆破需后续实现（需 NTLM/Kerberos over TLS + SPNEGO）

use async_trait::async_trait;
use rsa::pkcs1::DecodeRsaPublicKey;  // 提供 from_pkcs1_der 方法
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

// RDP 协议常量
const PROTOCOL_STD: u32 = 0x00000001; // Standard Security
const PROTOCOL_HYBRID: u32 = 0x00000002; // NLA (CredSSP)
const PROTOCOL_HYBRID_EX: u32 = 0x00000008; // CredSSP + Early User Auth

// X.224 类型
const X224_CR: u8 = 0xE0; // Connection Request
const X224_CC: u8 = 0xD0; // Connection Confirm

// RDP Negotiate 类型
const TYPE_RDP_NEG_REQ: u8 = 0x01;
const TYPE_RDP_NEG_RSP: u8 = 0x02;
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

// 安全标志
const SEC_EXCHANGE_PKT: u32 = 0x00000001;
const SEC_INFO_PKT: u32 = 0x00000040;

pub struct RdpConnector;

#[async_trait]
impl ProtocolConnector for RdpConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Rdp
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
            .map_err(|e| format!("RDP 连接超时: {e}"))?
            .map_err(|e| format!("RDP 连接失败: {e}"))?;

        // 2. X.224 Connection Request（请求所有协议以探测服务器支持）
        let cr = build_x224_cr(PROTOCOL_STD | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX);
        stream
            .write_all(&cr)
            .await
            .map_err(|e| format!("RDP 发送 CR 失败: {e}"))?;

        // 3. 接收 Connection Confirm
        let cc = read_tpkt_response(&mut stream, dur).await?;
        let selected_proto = parse_x224_cc(&cc)?;

        // 4. 检查选中的协议
        // 如果服务器仅支持 NLA（无 Standard Security bit）→ 不支持
        if selected_proto != 0xFFFFFFFF
            && (selected_proto & PROTOCOL_HYBRID != 0 || selected_proto & PROTOCOL_HYBRID_EX != 0)
            && selected_proto & PROTOCOL_STD == 0
        {
            return Err(
                "RDP 服务器仅支持 NLA (CredSSP)，当前实现不支持 NLA 爆破".to_string(),
            );
        }

        // 5. MCS Connect-Initial
        let mci = build_mcs_connect_initial();
        let mci_pkt = build_tpkt_pdu(&mci);
        stream
            .write_all(&mci_pkt)
            .await
            .map_err(|e| format!("RDP 发送 MCS Connect-Initial 失败: {e}"))?;

        // 6. 接收 MCS Connect-Response
        let mcr = read_tpkt_response(&mut stream, dur).await?;

        // 7. 解析 Connect-Response 获取服务器安全数据
        let server_sec = parse_mcs_connect_response(&mcr)?;

        // 8. erectDomainRequest
        let erect = build_erect_domain_request();
        stream
            .write_all(&build_tpkt_pdu(&erect))
            .await
            .map_err(|e| format!("RDP 发送 erectDomain 失败: {e}"))?;

        // 9. attachUserRequest
        let attach = build_attach_user_request();
        stream
            .write_all(&build_tpkt_pdu(&attach))
            .await
            .map_err(|e| format!("RDP 发送 attachUser 失败: {e}"))?;

        // 接收 attachUserConfirm
        let _ = read_tpkt_response(&mut stream, dur).await;

        // 10. Security Exchange: RSA 加密 client random
        let client_random = generate_random(32);
        let encrypted_random = encrypt_with_server_key(&client_random, &server_sec.server_cert)
            .map_err(|e| format!("RDP RSA 加密失败: {e}"))?;

        let sec_exchange = build_security_exchange(&encrypted_random);
        let sec_data = build_mcs_send_data_request(1003, &sec_exchange);
        stream
            .write_all(&build_tpkt_pdu(&sec_data))
            .await
            .map_err(|e| format!("RDP 发送 Security Exchange 失败: {e}"))?;

        // 11. 派生 RC4 密钥
        let rc4_key = derive_rc4_key(&client_random, &server_sec.server_random);

        // 12. 构造并发送加密的 Client Info PDU
        let client_info = build_client_info_pdu(credential);
        let encrypted_info = rc4_encrypt(&rc4_key, &client_info);
        let info_pdu = build_secure_data_pdu(&encrypted_info, SEC_INFO_PKT);
        let info_data = build_mcs_send_data_request(1003, &info_pdu);
        stream
            .write_all(&build_tpkt_pdu(&info_data))
            .await
            .map_err(|e| format!("RDP 发送 Client Info 失败: {e}"))?;

        // 13. 接收响应并检查登录结果
        match read_tpkt_response(&mut stream, dur).await {
            Ok(data) => {
                // 检查 MCS Disconnect 包含 reason code
                // 0x0005 = Access denied（用户名/密码错误）
                // 0x0000 = 正常
                if data.contains(&0xA1) {
                    // MCS Disconnect
                    if data.len() >= 6 {
                        let reason = u16::from_le_bytes([data[4], data[5]]);
                        if reason == 0x0005 {
                            return Ok(false); // Access denied
                        }
                        if reason == 0x0000 {
                            return Ok(true); // Success
                        }
                    }
                    return Ok(false);
                }
                // 收到正常数据 → 可能成功
                Ok(true)
            }
            Err(_) => {
                // 连接关闭 → 登录失败
                Ok(false)
            }
        }
    }
}

// ==================== 服务器安全数据 ====================

struct ServerSecData {
    server_random: Vec<u8>,
    server_cert: Vec<u8>,
}

// ==================== X.224 CR/CC ====================

fn build_x224_cr(requested_protocols: u32) -> Vec<u8> {
    let mut neg_req = Vec::with_capacity(8);
    neg_req.push(TYPE_RDP_NEG_REQ);
    neg_req.push(0x00);
    neg_req.extend_from_slice(&8u16.to_le_bytes());
    neg_req.extend_from_slice(&requested_protocols.to_le_bytes());

    let li = neg_req.len() as u8 + 6;
    let mut x224 = Vec::new();
    x224.push(li);
    x224.push(X224_CR);
    x224.extend_from_slice(&0u16.to_be_bytes());
    x224.extend_from_slice(&0u16.to_be_bytes());
    x224.push(0x00);
    x224.extend(neg_req);

    let total_len = 4 + x224.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend(x224);
    pkt
}

fn parse_x224_cc(data: &[u8]) -> Result<u32, String> {
    if data.len() < 11 {
        return Err("RDP CC 数据过短".to_string());
    }

    let x224_type = data[5];
    if x224_type != X224_CC {
        return Err(format!("RDP 预期 CC (0xD0)，得到 0x{x224_type:02X}"));
    }

    // RDP 协商数据位于 X.224 固定头之后：
    // TPKT(4) + LI(1) + Type(1) + DstRef(2) + SrcRef(2) + Class(1) = 11
    let neg_offset = 11;

    if data.len() > neg_offset {
        let neg_type = data[neg_offset];
        match neg_type {
            TYPE_RDP_NEG_RSP => {
                if data.len() >= neg_offset + 8 {
                    return Ok(u32::from_le_bytes([
                        data[neg_offset + 4],
                        data[neg_offset + 5],
                        data[neg_offset + 6],
                        data[neg_offset + 7],
                    ]));
                }
            }
            TYPE_RDP_NEG_FAILURE => return Ok(0xFFFFFFFF),
            _ => {}
        }
    }

    Ok(PROTOCOL_STD)
}

// ==================== MCS ====================

fn build_mcs_connect_initial() -> Vec<u8> {
    let client_data = build_client_set_data();

    // GCC Conference Create Request
    let mut gcc = Vec::new();
    gcc.extend_from_slice(&[0x00, 0x05, 0x00, 0x03, 0x01, 0x00]); // GCC header
    gcc.push(0x04); // userData tag
    gcc.extend(ber_length(client_data.len()));
    gcc.extend(client_data);

    // MCS parameters
    let params = || -> Vec<u8> {
        let mut p = Vec::new();
        p.extend(ber_integer(34));
        p.extend(ber_integer(2));
        p.extend(ber_integer(0));
        p.extend(ber_integer(1));
        p.extend(ber_integer(0));
        p.extend(ber_integer(0));
        p.extend(ber_integer(0));
        p.extend(ber_integer(0xFFFF));
        p.extend(ber_integer(2));
        p
    };

    let mut content = Vec::new();
    content.extend(ber_octet_string(vec![0x01]));
    content.extend(ber_octet_string(vec![0x01]));
    content.extend(ber_boolean(true));
    content.extend(ber_sequence(params()));
    content.extend(ber_sequence(params()));
    content.extend(ber_sequence(params()));
    content.extend(ber_octet_string(gcc));

    let mut result = vec![0x7F, 0x65];
    result.extend(ber_length(content.len()));
    result.extend(content);
    result
}

fn build_client_set_data() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(build_client_core_info());
    data.extend(build_client_security_info());
    // Client Network Info (0 channels)
    data.extend_from_slice(&[
        0x03, 0x00, // type = 0x0003
        0x08, 0x00, // length = 8
        0x00, 0x00, 0x00, 0x00, // channelCount = 0
    ]);
    data
}

fn build_client_core_info() -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&0x0001u16.to_le_bytes()); // type
    info.extend_from_slice(&0x00D8u16.to_le_bytes()); // length = 216 (data after header)
    info.extend_from_slice(&0x00080001u32.to_le_bytes()); // version
    info.extend_from_slice(&1024u16.to_le_bytes()); // desktopWidth
    info.extend_from_slice(&768u16.to_le_bytes()); // desktopHeight
    info.extend_from_slice(&0x0010u16.to_le_bytes()); // colorDepth
    info.extend_from_slice(&0x0001u16.to_le_bytes()); // sasSequence
    info.extend_from_slice(&0x0409u32.to_le_bytes()); // keyboardLayout
    // clientName = "Argus" (32 bytes, UTF-16LE)
    let client_name: Vec<u8> = "Argus\0"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut name_buf = vec![0u8; 32];
    name_buf[..client_name.len()].copy_from_slice(&client_name);
    info.extend(name_buf);
    info.extend_from_slice(&4u32.to_le_bytes()); // keyboardType
    info.extend_from_slice(&0u32.to_le_bytes()); // keyboardSubtype
    info.extend_from_slice(&12u32.to_le_bytes()); // keyboardFunctionKey
    info.extend(vec![0u8; 64]); // imeFileName
    info.extend_from_slice(&0x0010u16.to_le_bytes()); // postBeta2ColorDepth
    info.extend_from_slice(&0u16.to_le_bytes()); // clientProductId
    info.extend_from_slice(&0u32.to_le_bytes()); // serialNumber
    info.extend_from_slice(&0x0018u16.to_le_bytes()); // highColorDepth
    info.push(0x01); // connectionType = LAN
    info.push(0x00); // pad1octet
    // Pad to 220 total (4 header + 216 data, matching length field)
    while info.len() < 220 {
        info.push(0x00);
    }
    info
}

fn build_client_security_info() -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&0x0002u16.to_le_bytes()); // type
    info.extend_from_slice(&0x000Cu16.to_le_bytes()); // length = 12
    info.extend_from_slice(&0x00000007u32.to_le_bytes()); // encryptionMethods
    info.extend_from_slice(&0u32.to_le_bytes()); // extEncryptionMethods
    info
}

fn parse_mcs_connect_response(data: &[u8]) -> Result<ServerSecData, String> {
    if data.len() < 7 {
        return Err("MCS Connect-Response 数据过短".to_string());
    }

    // 查找 userData OctetString (0x04)
    let mut pos = 4;
    while pos < data.len() {
        if data[pos] == 0x04 {
            pos += 1;
            let (len, len_bytes) = parse_ber_length(&data[pos..])?;
            pos += len_bytes;
            if pos + len <= data.len() {
                return parse_gcc_response(&data[pos..pos + len]);
            }
        }
        pos += 1;
    }
    Err("MCS Connect-Response 中未找到 userData".to_string())
}

fn parse_gcc_response(data: &[u8]) -> Result<ServerSecData, String> {
    let mut pos = 0;
    while pos < data.len() {
        if data[pos] == 0x04 {
            pos += 1;
            let (len, len_bytes) = parse_ber_length(&data[pos..])?;
            pos += len_bytes;
            if pos + len <= data.len() {
                return parse_server_set_data(&data[pos..pos + len]);
            }
        }
        pos += 1;
    }
    Err("GCC Response 中未找到 userData".to_string())
}

fn parse_server_set_data(data: &[u8]) -> Result<ServerSecData, String> {
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let block_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let block_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + block_len > data.len() {
            break;
        }
        if block_type == 0x0005 {
            // TS_UD_SC_SEC: Server Security Info
            return parse_server_security_info(&data[pos..pos + block_len]);
        }
        pos += block_len;
    }
    Err("Server Set Data 中未找到 Security Info".to_string())
}

fn parse_server_security_info(data: &[u8]) -> Result<ServerSecData, String> {
    if data.len() < 32 {
        return Err("Server Security Info 数据过短".to_string());
    }
    Ok(ServerSecData {
        server_random: data[..32].to_vec(),
        server_cert: data[32..].to_vec(),
    })
}

// ==================== Security Exchange ====================

fn encrypt_with_server_key(client_random: &[u8], server_cert: &[u8]) -> Result<Vec<u8>, String> {
    let pub_key = parse_server_cert_pubkey(server_cert)?;
    let mut rng = rand::rng();
    let encrypted = pub_key
        .encrypt(&mut rng, rsa::pkcs1v15::Pkcs1v15Encrypt, client_random)
        .map_err(|e| format!("RSA 加密失败: {e}"))?;
    Ok(encrypted)
}

fn parse_server_cert_pubkey(cert: &[u8]) -> Result<rsa::RsaPublicKey, String> {
    if cert.len() < 16 {
        return Err("服务器证书数据过短".to_string());
    }

    // dwVersion(4) + dwSigAlgId(4) + dwKeyAlgId(4) + wPublicKeyBlobType(2) + wPublicKeyBlobLen(2)
    let blob_type = u16::from_le_bytes([cert[12], cert[13]]);
    let blob_len = u16::from_le_bytes([cert[14], cert[15]]) as usize;
    let blob_data = &cert[16..16 + blob_len.min(cert.len() - 16)];

    if blob_type == 0x0006 {
        // RSA1 公钥 blob
        if blob_data.len() < 20 {
            return Err("RSA1 blob 数据过短".to_string());
        }
        if &blob_data[..4] != b"RSA1" {
            return Err("非 RSA1 公钥 blob".to_string());
        }
        let keylen = u32::from_le_bytes([
            blob_data[4],
            blob_data[5],
            blob_data[6],
            blob_data[7],
        ]) as usize;
        let pubexp = u32::from_le_bytes([
            blob_data[16],
            blob_data[17],
            blob_data[18],
            blob_data[19],
        ]);
        if blob_data.len() < 20 + keylen {
            return Err("RSA1 blob modulus 数据不足".to_string());
        }
        let modulus_bytes = &blob_data[20..20 + keylen];
        // 构造 DER 编码的 RSAPublicKey 并解析
        let der = build_rsa_pubkey_der(modulus_bytes, pubexp);
        rsa::RsaPublicKey::from_pkcs1_der(&der)
            .map_err(|e| format!("RSA 公钥 DER 解析失败: {e}"))
    } else if blob_type == 0x0001 || blob_type == 0x0003 {
        parse_x509_pubkey(blob_data)
    } else {
        Err(format!("不支持的证书类型: 0x{blob_type:04X}"))
    }
}

/// 构造 DER 编码的 RSAPublicKey (PKCS#1 格式)
/// SEQUENCE { INTEGER modulus, INTEGER publicExponent }
fn build_rsa_pubkey_der(modulus_bytes: &[u8], exponent: u32) -> Vec<u8> {
    let mut mod_bytes = modulus_bytes.to_vec();
    // 去除前导零
    while mod_bytes.len() > 1 && mod_bytes[0] == 0 {
        mod_bytes.remove(0);
    }
    // 添加前导 0x00 如果最高位为 1（确保为正数）
    if mod_bytes[0] & 0x80 != 0 {
        mod_bytes.insert(0, 0x00);
    }

    // exponent: 大端序
    let exp_bytes = exponent.to_be_bytes().to_vec();
    let mut exp_trimmed = exp_bytes;
    while exp_trimmed.len() > 1 && exp_trimmed[0] == 0 {
        exp_trimmed.remove(0);
    }

    let modulus_tlv = build_der_integer(&mod_bytes);
    let exponent_tlv = build_der_integer(&exp_trimmed);

    let mut content = Vec::new();
    content.extend(modulus_tlv);
    content.extend(exponent_tlv);
    let mut result = vec![0x30];
    result.extend(ber_length(content.len()));
    result.extend(content);
    result
}

fn build_der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02];
    result.extend(ber_length(bytes.len()));
    result.extend_from_slice(bytes);
    result
}

fn parse_x509_pubkey(cert_data: &[u8]) -> Result<rsa::RsaPublicKey, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_data)
        .map_err(|e| format!("X.509 解析失败: {e}"))?;
    let spki = cert.public_key();
    let key_bytes = spki.subject_public_key.data.as_ref();
    rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
        .map_err(|e| format!("RSA 公钥 DER 解析失败: {e}"))
}

// ==================== RC4 + Key Derivation ====================

fn derive_rc4_key(client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.finalize().to_vec()
}

fn rc4_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = [0; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut result = Vec::with_capacity(data.len());
    let mut i: u16 = 0;
    let mut jj: u8 = 0;
    for &byte in data {
        i = i.wrapping_add(1);
        jj = jj.wrapping_add(s[(i & 0xFF) as usize]);
        s.swap((i & 0xFF) as usize, jj as usize);
        let k = s[(s[(i & 0xFF) as usize].wrapping_add(s[jj as usize])) as usize];
        result.push(byte ^ k);
    }
    result
}

// ==================== PDU 构建 ====================

fn build_tpkt_pdu(payload: &[u8]) -> Vec<u8> {
    let total_len = 4 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn build_erect_domain_request() -> Vec<u8> {
    vec![0x71, 0x01, 0x01, 0x01]
}

fn build_attach_user_request() -> Vec<u8> {
    vec![0x76]
}

fn build_security_exchange(encrypted_random: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&SEC_EXCHANGE_PKT.to_le_bytes());
    pkt.extend_from_slice(&(encrypted_random.len() as u32).to_le_bytes());
    pkt.extend_from_slice(encrypted_random);
    let pad = (8 - (pkt.len() % 8)) % 8;
    pkt.extend(vec![0u8; pad]);
    pkt
}

fn build_secure_data_pdu(encrypted_data: &[u8], flags: u32) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&flags.to_le_bytes());
    pkt.extend_from_slice(&((flags >> 16) as u16).to_le_bytes());
    let share_start = pkt.len();
    pkt.extend_from_slice(&0u16.to_le_bytes());
    pkt.extend_from_slice(&0x0011u16.to_le_bytes());
    pkt.push(0x00);
    pkt.push(0x00);
    pkt.extend_from_slice(&0u32.to_le_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&(encrypted_data.len() as u16).to_le_bytes());
    pkt.push(0x00); // pduType2
    pkt.push(0x00);
    pkt.extend_from_slice(&0u16.to_le_bytes());
    pkt.extend_from_slice(encrypted_data);
    let total_len = pkt.len() as u16;
    pkt[share_start..share_start + 2].copy_from_slice(&total_len.to_le_bytes());
    pkt
}

fn build_mcs_send_data_request(channel_id: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.push(0x64 | 0x60); // MCS_SEND_DATA_REQUEST
    pkt.extend_from_slice(&channel_id.to_be_bytes());
    pkt.extend_from_slice(&1003u16.to_be_bytes());
    pkt.push(0x70);
    pkt.extend(ber_length(data.len()));
    pkt.extend_from_slice(data);
    pkt
}

fn build_client_info_pdu(credential: &Credential) -> Vec<u8> {
    let user_utf16: Vec<u8> = credential
        .username
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let pass_utf16: Vec<u8> = credential
        .password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut info = Vec::new();
    info.extend_from_slice(&0u32.to_le_bytes()); // CodePage
    info.extend_from_slice(&0x00000010u32.to_le_bytes()); // flag = INFO_UNICODE
    info.extend_from_slice(&0u16.to_le_bytes()); // cbDomain
    info.extend_from_slice(&(user_utf16.len() as u16).to_le_bytes()); // cbUserName
    info.extend_from_slice(&(pass_utf16.len() as u16).to_le_bytes()); // cbPassword
    info.extend_from_slice(&0u16.to_le_bytes()); // cbAlternateShell
    info.extend_from_slice(&0u16.to_le_bytes()); // cbWorkingDir
    info.extend_from_slice(&0u16.to_le_bytes()); // padding
    info.extend(&user_utf16); // UserName
    info.extend(&pass_utf16); // Password
    // Pad to 8-byte boundary
    let pad = (8 - (info.len() % 8)) % 8;
    info.extend(vec![0u8; pad]);
    info
}

// ==================== 工具函数 ====================

fn generate_random(len: usize) -> Vec<u8> {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..len).map(|_| rng.random()).collect()
}

async fn read_tpkt_response(stream: &mut TcpStream, dur: Duration) -> Result<Vec<u8>, String> {
    // 读取 TPKT 头 (4 bytes)
    let mut header = [0u8; 4];
    timeout(dur, stream.read_exact(&mut header))
        .await
        .map_err(|e| format!("RDP 读取 TPKT 头超时: {e}"))?
        .map_err(|e| format!("RDP 读取 TPKT 头失败: {e}"))?;

    if header[0] != 0x03 {
        // 可能是 X.224 Class 0 消息（无 TPKT）
        // 尝试读取剩余数据
        let mut data = header.to_vec();
        let mut buf = [0u8; 4096];
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&buf[..n]),
            _ => {}
        }
        return Ok(data);
    }

    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_len < 4 {
        return Err(format!("RDP TPKT 长度无效: {total_len}"));
    }

    let body_len = total_len - 4;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        timeout(dur, stream.read_exact(&mut body))
            .await
            .map_err(|e| format!("RDP 读取 TPKT body 超时: {e}"))?
            .map_err(|e| format!("RDP 读取 TPKT body 失败: {e}"))?;
    }

    let mut result = header.to_vec();
    result.extend(body);
    Ok(result)
}

// ==================== BER 编码 ====================

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

fn ber_sequence(contents: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x30];
    result.extend(ber_length(contents.len()));
    result.extend(contents);
    result
}

fn ber_octet_string(contents: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x04];
    result.extend(ber_length(contents.len()));
    result.extend(contents);
    result
}

fn ber_boolean(val: bool) -> Vec<u8> {
    vec![0x01, 0x01, if val { 0xFF } else { 0x00 }]
}

fn parse_ber_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("BER 长度数据为空".to_string());
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
    fn test_rdp_protocol() {
        assert_eq!(RdpConnector.protocol(), Protocol::Rdp);
    }

    #[test]
    fn test_build_x224_cr() {
        let cr = build_x224_cr(PROTOCOL_STD);
        assert_eq!(cr[0], 0x03); // TPKT version
        assert_eq!(cr[2], 0x00); // TPKT length high byte
        // Total length should be 19 (4 TPKT + 15 X.224)
        assert_eq!(cr[3], 19); // TPKT length low byte
    }

    #[test]
    fn test_parse_x224_cc_success() {
        // 模拟 X.224 CC + Negotiate Response
        let mut data = vec![0x03, 0x00, 0x00, 0x00]; // TPKT (length filled later)
        let x224_li = 14; // LI
        data.push(x224_li);
        data.push(X224_CC); // type
        data.extend_from_slice(&[0, 0]); // dst-ref
        data.extend_from_slice(&[0, 0]); // src-ref
        data.push(0x00); // class
        // Negotiate Response
        data.push(TYPE_RDP_NEG_RSP); // type
        data.push(0x00); // flags
        data.extend_from_slice(&8u16.to_le_bytes()); // length
        data.extend_from_slice(&PROTOCOL_STD.to_le_bytes()); // selectedProtocols
        // Fix TPKT length
        let total = data.len() as u16;
        data[2] = (total >> 8) as u8;
        data[3] = total as u8;

        let result = parse_x224_cc(&data).unwrap();
        assert_eq!(result, PROTOCOL_STD);
    }

    #[test]
    fn test_parse_x224_cc_nla_only() {
        let mut data = vec![0x03, 0x00, 0x00, 0x00];
        let x224_li = 14;
        data.push(x224_li);
        data.push(X224_CC);
        data.extend_from_slice(&[0, 0, 0, 0, 0x00]);
        data.push(TYPE_RDP_NEG_RSP);
        data.push(0x00);
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&PROTOCOL_HYBRID.to_le_bytes()); // NLA only
        let total = data.len() as u16;
        data[2] = (total >> 8) as u8;
        data[3] = total as u8;

        let result = parse_x224_cc(&data).unwrap();
        assert_eq!(result, PROTOCOL_HYBRID);
    }

    #[test]
    fn test_rc4_encrypt() {
        let key = b"testkey";
        let data = b"hello world";
        let encrypted = rc4_encrypt(key, data);
        assert_eq!(encrypted.len(), data.len());
        // 解密应得到原始数据
        let decrypted = rc4_encrypt(key, &encrypted);
        assert_eq!(&decrypted, data);
    }

    #[test]
    fn test_derive_rc4_key() {
        let client_random = vec![0u8; 32];
        let server_random = vec![0u8; 32];
        let key = derive_rc4_key(&client_random, &server_random);
        assert_eq!(key.len(), 16); // MD5 = 16 bytes
    }

    #[test]
    fn test_build_client_info_pdu() {
        let cred = Credential::new("admin", "password");
        let info = build_client_info_pdu(&cred);
        // Should contain Unicode flag
        assert!(info.len() > 20);
    }

    #[test]
    fn test_ber_length() {
        assert_eq!(ber_length(0), vec![0x00]);
        assert_eq!(ber_length(127), vec![0x7F]);
        assert_eq!(ber_length(128), vec![0x81, 0x80]);
        assert_eq!(ber_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_parse_ber_length() {
        assert_eq!(parse_ber_length(&[0x05]).unwrap(), (5, 1));
        assert_eq!(parse_ber_length(&[0x81, 0x80]).unwrap(), (128, 2));
        assert_eq!(parse_ber_length(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
    }
}
