//! 敏感数据加密工具（AES-256-GCM）
//!
//! 用于密码、API Key 等敏感字段的加密存储。
//! 加密后的字符串格式为 `enc::<base64(nonce || ciphertext)>`，
//! 便于与历史明文数据区分并平滑迁移。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use sha2::Digest;
use std::env;

/// 加密前缀，用于标识已加密的密文
const ENC_PREFIX: &str = "enc::";

/// 从环境变量获取 32 字节加密密钥
/// 未设置 ARGUS_ENCRYPTION_KEY 时使用开发默认值（生产环境必须设置）
fn encryption_key() -> [u8; 32] {
    let key_str = env::var("ARGUS_ENCRYPTION_KEY").unwrap_or_else(|_| {
        // 开发环境默认密钥，生产环境请通过 ARGUS_ENCRYPTION_KEY 覆盖
        "argus-default-encryption-key-32bytes!".to_string()
    });
    // 使用 SHA-256 对任意长度的密钥字符串派生 32 字节密钥
    let hash = sha2::Sha256::digest(key_str.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// 加密明文，返回 `enc::<base64>` 格式的密文
pub fn encrypt(plaintext: &str) -> Result<String, String> {
    let key = encryption_key();
    let cipher = Aes256Gcm::new(&key.into());
    // 生成 96-bit (12 字节) 随机 nonce
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("生成 nonce 失败: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("加密失败: {e}"))?;
    // 拼接 nonce + ciphertext 后 base64 编码
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    let encoded = base64::engine::general_purpose::STANDARD.encode(combined);
    Ok(format!("{ENC_PREFIX}{encoded}"))
}

/// 解密密文。如果输入不是加密格式（历史明文），则原样返回。
pub fn decrypt(ciphertext: &str) -> Result<String, String> {
    if !ciphertext.starts_with(ENC_PREFIX) {
        // 历史明文数据，直接返回
        return Ok(ciphertext.to_string());
    }
    let encoded = &ciphertext[ENC_PREFIX.len()..];
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64 解码失败: {e}"))?;
    if combined.len() < 12 {
        return Err("密文格式错误: 长度不足".to_string());
    }
    let (nonce_bytes, ciphertext_bytes) = combined.split_at(12);
    let key = encryption_key();
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_bytes)
        .map_err(|e| format!("解密失败: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 解码失败: {e}"))
}

/// 判断字符串是否为已加密格式
pub fn is_encrypted(s: &str) -> bool {
    s.starts_with(ENC_PREFIX)
}

/// 加密 Option<String>，None 保持 None
pub fn encrypt_opt(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        if v.is_empty() {
            Some(v)
        } else {
            encrypt(&v).ok()
        }
    })
}

/// 解密 Option<String>，None 保持 None
pub fn decrypt_opt(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        if v.is_empty() {
            Some(v)
        } else {
            decrypt(&v).ok()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = "MyP@ssw0rd!123";
        let encrypted = encrypt(plaintext).unwrap();
        assert!(encrypted.starts_with(ENC_PREFIX));
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_plaintext_passthrough() {
        // 历史明文数据应原样返回
        let plaintext = "old_plain_password";
        assert_eq!(decrypt(plaintext).unwrap(), plaintext);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(is_encrypted("enc::abc123"));
        assert!(!is_encrypted("plain_text"));
    }

    #[test]
    fn test_encrypt_opt() {
        assert_eq!(encrypt_opt(None), None);
        assert_eq!(encrypt_opt(Some(String::new())), Some(String::new()));
        let enc = encrypt_opt(Some("secret".to_string())).unwrap();
        assert!(enc.starts_with(ENC_PREFIX));
    }

    #[test]
    fn test_different_nonce_produces_different_ciphertext() {
        let plaintext = "same_password";
        let e1 = encrypt(plaintext).unwrap();
        let e2 = encrypt(plaintext).unwrap();
        assert_ne!(e1, e2); // 随机 nonce 保证密文不同
        assert_eq!(decrypt(&e1).unwrap(), plaintext);
        assert_eq!(decrypt(&e2).unwrap(), plaintext);
    }
}
