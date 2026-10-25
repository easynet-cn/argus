//! VNC 协议连接器
//!
//! 真实实现 VNC 认证爆破（RFB 3.8 + VNC Authentication）：
//! 1. TCP 连接到目标端口（默认 5900）
//! 2. 接收 ProtocolVersion (RFB 003.008\n)
//! 3. 发送 ProtocolVersion
//! 4. 接收安全类型列表
//! 5. 选择 VNC Authentication (type 2)
//! 6. 接收 16 字节 challenge
//! 7. 用密码生成 DES 密钥（每字节 bit 顺序反转）
//! 8. DES-ECB 加密 16 字节 challenge（2 个 8 字节块）
//! 9. 发送 16 字节 response
//! 10. 接收 4 字节 SecurityResult（0=成功，1=失败）

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

// VNC 安全类型
const SECURITY_VNC_AUTH: u8 = 2;
const SECURITY_INVALID: u8 = 1;

pub struct VncConnector;

#[async_trait]
impl ProtocolConnector for VncConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Vnc
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
            .map_err(|e| format!("VNC 连接超时: {e}"))?
            .map_err(|e| format!("VNC 连接失败: {e}"))?;

        // 2. 接收 ProtocolVersion (12 bytes: "RFB 003.008\n")
        let mut version_buf = [0u8; 12];
        timeout(dur, stream.read_exact(&mut version_buf))
            .await
            .map_err(|e| format!("VNC 读取版本超时: {e}"))?
            .map_err(|e| format!("VNC 读取版本失败: {e}"))?;

        let version_str = String::from_utf8_lossy(&version_buf);
        if !version_str.starts_with("RFB ") {
            return Err(format!("VNC 非法版本: {version_str}"));
        }

        // 3. 发送 ProtocolVersion
        let client_version = b"RFB 003.008\n";
        stream
            .write_all(client_version)
            .await
            .map_err(|e| format!("VNC 发送版本失败: {e}"))?;

        // 4. 接收安全类型
        // RFB 3.8: 1 byte count + count bytes of types
        let mut count_buf = [0u8; 1];
        timeout(dur, stream.read_exact(&mut count_buf))
            .await
            .map_err(|e| format!("VNC 读取安全类型数超时: {e}"))?
            .map_err(|e| format!("VNC 读取安全类型数失败: {e}"))?;

        let count = count_buf[0];
        if count == 0 {
            // 服务器拒绝连接，读取失败原因
            let mut reason_len = [0u8; 4];
            let _ = stream.read_exact(&mut reason_len).await;
            let len = u32::from_be_bytes(reason_len) as usize;
            if len > 0 && len < 1024 {
                let mut reason = vec![0u8; len];
                let _ = stream.read_exact(&mut reason).await;
                return Err(format!("VNC 连接被拒绝: {}", String::from_utf8_lossy(&reason)));
            }
            return Err("VNC 连接被拒绝".to_string());
        }

        let mut types = vec![0u8; count as usize];
        timeout(dur, stream.read_exact(&mut types))
            .await
            .map_err(|e| format!("VNC 读取安全类型超时: {e}"))?
            .map_err(|e| format!("VNC 读取安全类型失败: {e}"))?;

        // 5. 检查是否支持 VNC Authentication
        if !types.contains(&SECURITY_VNC_AUTH) {
            // 如果支持 None (0) 则无需认证
            if types.contains(&0) {
                // 选择 None 安全类型
                stream
                    .write_all(&[0u8])
                    .await
                    .map_err(|e| format!("VNC 选择安全类型失败: {e}"))?;
                // 接收 SecurityResult
                let mut result = [0u8; 4];
                let _ = stream.read_exact(&mut result).await;
                return Ok(u32::from_be_bytes(result) == 0);
            }
            return Err("VNC 服务器不支持 VNC Authentication".to_string());
        }

        // 选择 VNC Authentication
        stream
            .write_all(&[SECURITY_VNC_AUTH])
            .await
            .map_err(|e| format!("VNC 选择认证类型失败: {e}"))?;

        // 6. 接收 16 字节 challenge
        let mut challenge = [0u8; 16];
        timeout(dur, stream.read_exact(&mut challenge))
            .await
            .map_err(|e| format!("VNC 读取 challenge 超时: {e}"))?
            .map_err(|e| format!("VNC 读取 challenge 失败: {e}"))?;

        // 7-8. 用密码生成 DES 密钥并加密 challenge
        let response = vnc_encrypt_challenge(&challenge, &credential.password);

        // 9. 发送 16 字节 response
        stream
            .write_all(&response)
            .await
            .map_err(|e| format!("VNC 发送 response 失败: {e}"))?;

        // 10. 接收 4 字节 SecurityResult (big-endian)
        let mut result_buf = [0u8; 4];
        timeout(dur, stream.read_exact(&mut result_buf))
            .await
            .map_err(|e| format!("VNC 读取结果超时: {e}"))?
            .map_err(|e| format!("VNC 读取结果失败: {e}"))?;

        let result = u32::from_be_bytes(result_buf);
        // 0 = 成功，1 = 失败
        Ok(result == 0)
    }
}

/// VNC Authentication: 用密码生成 DES 密钥并加密 challenge
///
/// 密钥生成：取密码的前 8 字节（不足补 0），每字节 bit 顺序反转
/// 加密：DES-ECB，16 字节 challenge 分成 2 个 8 字节块分别加密
fn vnc_encrypt_challenge(challenge: &[u8; 16], password: &str) -> [u8; 16] {
    use des::cipher::generic_array::GenericArray;

    // 生成 DES 密钥（8 字节）
    let mut key = [0u8; 8];
    let password_bytes = password.as_bytes();
    for i in 0..8.min(password_bytes.len()) {
        key[i] = password_bytes[i];
    }
    // 反转每字节的 bit 顺序
    for i in 0..8 {
        key[i] = reverse_bits(key[i]);
    }

    // DES-ECB 加密
    let cipher = Des::new_from_slice(&key).expect("DES 密钥生成失败");
    let mut response = [0u8; 16];

    // 第一个 8 字节块
    let mut block1 = GenericArray::clone_from_slice(&challenge[..8]);
    cipher.encrypt_block(&mut block1);
    response[..8].copy_from_slice(&block1);

    // 第二个 8 字节块
    let mut block2 = GenericArray::clone_from_slice(&challenge[8..]);
    cipher.encrypt_block(&mut block2);
    response[8..].copy_from_slice(&block2);

    response
}

/// 反转一个字节的 bit 顺序
fn reverse_bits(b: u8) -> u8 {
    let mut r = 0u8;
    let mut v = b;
    for _ in 0..8 {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    r
}

// 引入 DES 加密
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vnc_protocol() {
        assert_eq!(VncConnector.protocol(), Protocol::Vnc);
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b00000000), 0b00000000);
        assert_eq!(reverse_bits(0b11111111), 0b11111111);
        assert_eq!(reverse_bits(0b10000000), 0b00000001);
        assert_eq!(reverse_bits(0b00000001), 0b10000000);
        assert_eq!(reverse_bits(0b10101010), 0b01010101);
    }

    #[test]
    fn test_vnc_encrypt_challenge() {
        let challenge = [0u8; 16];
        let response = vnc_encrypt_challenge(&challenge, "secret");
        // 响应应该是 16 字节
        assert_eq!(response.len(), 16);
        // 相同输入应得到相同输出
        let response2 = vnc_encrypt_challenge(&challenge, "secret");
        assert_eq!(response, response2);
    }

    #[test]
    fn test_vnc_encrypt_different_passwords() {
        let challenge = [0xAA; 16];
        let r1 = vnc_encrypt_challenge(&challenge, "pass1");
        let r2 = vnc_encrypt_challenge(&challenge, "pass2");
        // 不同密码应产生不同结果
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_vnc_encrypt_short_password() {
        let challenge = [0xFF; 16];
        // 短密码应正常工作（不足 8 字节补 0）
        let response = vnc_encrypt_challenge(&challenge, "ab");
        assert_eq!(response.len(), 16);
    }

    #[test]
    fn test_vnc_encrypt_long_password() {
        let challenge = [0x55; 16];
        // 长密码只取前 8 字节
        let response = vnc_encrypt_challenge(&challenge, "verylongpassword");
        assert_eq!(response.len(), 16);
    }
}
