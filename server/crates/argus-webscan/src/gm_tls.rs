//! 国密密码学支持 (G5.12)
//!
//! 基于 RustCrypto 的 sm2 / sm3 / sm4 crate 实现国密基础密码学原语：
//! - SM3 哈希（用于证书指纹、消息摘要）
//! - SM2 密钥对生成 / 签名 / 验签
//! - SM4 对称加解密（ECB / CBC 模式）
//!
//! 注意：完整的国密 TLS 栈（TLCP / GMSSL）实现非常复杂，
//! 本模块仅提供基础密码学原语和证书指纹计算，TLS 集成留作后续工作。

use sm2::dsa::{signature::{Signer, Verifier}, Signature, SigningKey, VerifyingKey};
use sm2::SecretKey;
use sm3::{Digest, Sm3};
use sm4::cipher::{block::{BlockCipherDecrypt, BlockCipherEncrypt}, Block, KeyInit};
use sm4::Sm4;

/// SM3 哈希输出长度（32 字节）
pub const SM3_DIGEST_LEN: usize = 32;
/// SM4 密钥长度（16 字节）
pub const SM4_KEY_LEN: usize = 16;
/// SM4 分组长度（16 字节）
pub const SM4_BLOCK_LEN: usize = 16;
/// SM2 默认用户标识（GM/T 0003-2012 默认值）
pub const SM2_DEFAULT_USER_ID: &str = "1234567812345678";

// ---------------------------------------------------------------------------
// SM3 哈希
// ---------------------------------------------------------------------------

/// 计算 SM3 哈希值
///
/// 返回 32 字节的哈希结果。
pub fn sm3_hash(data: &[u8]) -> [u8; SM3_DIGEST_LEN] {
    let mut hasher = Sm3::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; SM3_DIGEST_LEN];
    out.copy_from_slice(&result);
    out
}

/// 计算 SM3 哈希的十六进制字符串表示
pub fn sm3_hash_hex(data: &[u8]) -> String {
    let hash = sm3_hash(data);
    hex_encode(&hash)
}

/// 计算证书的 SM3 指纹
///
/// 对 DER 编码的证书字节计算 SM3 哈希，用于国密证书指纹。
/// 与 SM2/SM3 证书配合使用时，通常以 SM3 作为指纹算法。
pub fn cert_fingerprint_sm3(cert_der: &[u8]) -> [u8; SM3_DIGEST_LEN] {
    sm3_hash(cert_der)
}

/// 计算证书的 SM3 指纹（十六进制字符串）
pub fn cert_fingerprint_sm3_hex(cert_der: &[u8]) -> String {
    sm3_hash_hex(cert_der)
}

// ---------------------------------------------------------------------------
// SM2 签名
// ---------------------------------------------------------------------------

/// SM2 密钥对
pub struct Sm2KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Sm2KeyPair {
    /// 生成新的 SM2 密钥对，使用默认用户标识
    pub fn generate() -> Result<Self, String> {
        Self::generate_with_user_id(SM2_DEFAULT_USER_ID)
    }

    /// 生成新的 SM2 密钥对，指定用户标识
    pub fn generate_with_user_id(user_id: &str) -> Result<Self, String> {
        let mut rng = rand_core::OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let signing_key = SigningKey::new(user_id, &secret_key)
            .map_err(|e| format!("创建 SM2 签名密钥失败: {e}"))?;
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// 从私钥字节和用户标识恢复密钥对
    pub fn from_private_key_bytes(user_id: &str, private_key: &[u8]) -> Result<Self, String> {
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| format!("解析 SM2 私钥失败: {e}"))?;
        let signing_key = SigningKey::new(user_id, &secret_key)
            .map_err(|e| format!("创建 SM2 签名密钥失败: {e}"))?;
        let verifying_key = signing_key.verifying_key().clone();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// 从公钥字节（SEC1 编码）创建验签密钥
    pub fn verifying_key_from_sec1_bytes(
        user_id: &str,
        public_key: &[u8],
    ) -> Result<VerifyingKey, String> {
        VerifyingKey::from_sec1_bytes(user_id, public_key)
            .map_err(|e| format!("解析 SM2 公钥失败: {e}"))
    }

    /// 获取公钥的 SEC1 编码字节
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_sec1_bytes().to_vec()
    }

    /// 获取私钥字节
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.as_nonzero_scalar().to_bytes().to_vec()
    }

    /// 对消息进行 SM2 签名
    ///
    /// 内部使用 SM3 对消息进行哈希，并与用户标识组合后签名。
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// 对消息进行 SM2 验签
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), String> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|e| format!("SM2 验签失败: {e}"))
    }
}

/// 使用公钥字节对消息进行 SM2 验签
pub fn sm2_verify(
    user_id: &str,
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let verifying_key = Sm2KeyPair::verifying_key_from_sec1_bytes(user_id, public_key_sec1)?;
    let sig = Signature::from_slice(signature)
        .map_err(|e| format!("解析 SM2 签名失败: {e}"))?;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| format!("SM2 验签失败: {e}"))
}

// ---------------------------------------------------------------------------
// SM4 对称加解密
// ---------------------------------------------------------------------------

/// 创建 SM4 密码实例
fn create_sm4(key: &[u8]) -> Result<Sm4, String> {
    validate_sm4_key(key)?;
    Sm4::new_from_slice(key).map_err(|e| format!("SM4 密钥初始化失败: {e}"))
}

/// PKCS7 填充
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// PKCS7 去填充
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, String> {
    if data.is_empty() || data.len() % block_size != 0 {
        return Err("数据长度不是分组大小的整数倍".to_string());
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block_size {
        return Err("无效的 PKCS7 填充".to_string());
    }
    // 验证填充字节
    for &b in &data[data.len() - pad_len..] {
        if b as usize != pad_len {
            return Err("无效的 PKCS7 填充".to_string());
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

/// SM4 ECB 模式加密
///
/// 使用 PKCS7 填充，密钥长度必须为 16 字节。
pub fn sm4_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = create_sm4(key)?;
    let padded = pkcs7_pad(plaintext, SM4_BLOCK_LEN);
    let mut ciphertext = Vec::with_capacity(padded.len());

    for chunk in padded.chunks(SM4_BLOCK_LEN) {
        let mut block = Block::<Sm4>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }
    Ok(ciphertext)
}

/// SM4 ECB 模式解密
pub fn sm4_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = create_sm4(key)?;
    if ciphertext.is_empty() || ciphertext.len() % SM4_BLOCK_LEN != 0 {
        return Err("密文长度不是分组大小的整数倍".to_string());
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(SM4_BLOCK_LEN) {
        let mut block = Block::<Sm4>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    pkcs7_unpad(&plaintext, SM4_BLOCK_LEN)
}

/// SM4 CBC 模式加密
///
/// 使用 PKCS7 填充，密钥和 IV 长度均必须为 16 字节。
pub fn sm4_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = create_sm4(key)?;
    if iv.len() != SM4_BLOCK_LEN {
        return Err(format!("SM4 CBC IV 长度必须为 {} 字节", SM4_BLOCK_LEN));
    }

    let padded = pkcs7_pad(plaintext, SM4_BLOCK_LEN);
    let mut ciphertext = Vec::with_capacity(padded.len());
    let mut prev_block = [0u8; SM4_BLOCK_LEN];
    prev_block.copy_from_slice(iv);

    for chunk in padded.chunks(SM4_BLOCK_LEN) {
        let mut block = Block::<Sm4>::default();
        // XOR with previous ciphertext block (or IV for first block)
        for i in 0..SM4_BLOCK_LEN {
            block[i] = chunk[i] ^ prev_block[i];
        }
        cipher.encrypt_block(&mut block);
        prev_block.copy_from_slice(&block);
        ciphertext.extend_from_slice(&block);
    }
    Ok(ciphertext)
}

/// SM4 CBC 模式解密
pub fn sm4_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = create_sm4(key)?;
    if iv.len() != SM4_BLOCK_LEN {
        return Err(format!("SM4 CBC IV 长度必须为 {} 字节", SM4_BLOCK_LEN));
    }
    if ciphertext.is_empty() || ciphertext.len() % SM4_BLOCK_LEN != 0 {
        return Err("密文长度不是分组大小的整数倍".to_string());
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = [0u8; SM4_BLOCK_LEN];
    prev_block.copy_from_slice(iv);

    for chunk in ciphertext.chunks(SM4_BLOCK_LEN) {
        let mut block = Block::<Sm4>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        // XOR with previous ciphertext block (or IV for first block)
        for i in 0..SM4_BLOCK_LEN {
            block[i] ^= prev_block[i];
        }
        prev_block.copy_from_slice(chunk);
        plaintext.extend_from_slice(&block);
    }

    pkcs7_unpad(&plaintext, SM4_BLOCK_LEN)
}

fn validate_sm4_key(key: &[u8]) -> Result<(), String> {
    if key.len() != SM4_KEY_LEN {
        return Err(format!("SM4 密钥长度必须为 {} 字节", SM4_KEY_LEN));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// SM4 填充错误类型
#[derive(Debug)]
pub struct Sm4UnpadError(pub String);

impl std::fmt::Display for Sm4UnpadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Sm4UnpadError {}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SM3 测试 ---

    #[test]
    fn test_sm3_hash_empty() {
        let hash = sm3_hash(b"");
        // SM3("") 的已知测试向量
        let expected = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";
        assert_eq!(hex_encode(&hash), expected);
    }

    #[test]
    fn test_sm3_hash_known() {
        // SM3("abc") 的已知测试向量
        let hash = sm3_hash(b"abc");
        let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        assert_eq!(hex_encode(&hash), expected);
    }

    #[test]
    fn test_sm3_hash_hex() {
        let hex = sm3_hash_hex(b"hello world");
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        // 已知 SM3("hello world")
        let expected = "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88";
        assert_eq!(hex, expected);
    }

    #[test]
    fn test_sm3_hash_length() {
        let hash = sm3_hash(b"test data");
        assert_eq!(hash.len(), SM3_DIGEST_LEN);
    }

    #[test]
    fn test_cert_fingerprint_sm3() {
        let cert_der = b"fake-cert-der-bytes";
        let fp = cert_fingerprint_sm3(cert_der);
        assert_eq!(fp.len(), SM3_DIGEST_LEN);
        let fp_hex = cert_fingerprint_sm3_hex(cert_der);
        assert_eq!(fp_hex.len(), 64);
        // 指纹应等于直接对证书字节做 SM3
        assert_eq!(fp, sm3_hash(cert_der));
    }

    // --- SM2 测试 ---

    #[test]
    fn test_sm2_key_generation() {
        let kp = Sm2KeyPair::generate().expect("生成 SM2 密钥对失败");
        let pub_bytes = kp.public_key_bytes();
        assert!(!pub_bytes.is_empty());
        let priv_bytes = kp.private_key_bytes();
        assert_eq!(priv_bytes.len(), 32); // SM2 私钥 32 字节
    }

    #[test]
    fn test_sm2_sign_verify() {
        let kp = Sm2KeyPair::generate().unwrap();
        let message = b"hello sm2 signature";
        let signature = kp.sign(message);
        assert!(kp.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_sm2_verify_wrong_message() {
        let kp = Sm2KeyPair::generate().unwrap();
        let message = b"original message";
        let signature = kp.sign(message);
        let wrong = b"tampered message";
        assert!(kp.verify(wrong, &signature).is_err());
    }

    #[test]
    fn test_sm2_restore_from_private_key() {
        let kp = Sm2KeyPair::generate().unwrap();
        let priv_bytes = kp.private_key_bytes();
        let pub_bytes = kp.public_key_bytes();

        let restored =
            Sm2KeyPair::from_private_key_bytes(SM2_DEFAULT_USER_ID, &priv_bytes).unwrap();
        assert_eq!(restored.public_key_bytes(), pub_bytes);

        let message = b"restore test";
        let sig = kp.sign(message);
        assert!(restored.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_sm2_verify_with_public_key_bytes() {
        let kp = Sm2KeyPair::generate().unwrap();
        let message = b"verify with pub key";
        let signature = kp.sign(message);
        let sig_der = signature.to_bytes();
        let pub_bytes = kp.public_key_bytes();

        assert!(sm2_verify(
            SM2_DEFAULT_USER_ID,
            &pub_bytes,
            message,
            &sig_der,
        )
        .is_ok());
    }

    // --- SM4 测试 ---

    #[test]
    fn test_sm4_ecb_roundtrip() {
        let key = [0x01u8; 16];
        let plaintext = b"hello sm4 ecb mode";
        let ct = sm4_ecb_encrypt(&key, plaintext).unwrap();
        let pt = sm4_ecb_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_ecb_empty() {
        let key = [0x00u8; 16];
        let ct = sm4_ecb_encrypt(&key, b"").unwrap();
        let pt = sm4_ecb_decrypt(&key, &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_sm4_ecb_invalid_key() {
        let short_key = [0x01u8; 8];
        assert!(sm4_ecb_encrypt(&short_key, b"data").is_err());
    }

    #[test]
    fn test_sm4_ecb_wrong_key_fails() {
        let key1 = [0x01u8; 16];
        let key2 = [0x02u8; 16];
        let ct = sm4_ecb_encrypt(&key1, b"secret").unwrap();
        // 使用错误密钥解密应失败（填充校验不通过）
        assert!(sm4_ecb_decrypt(&key2, &ct).is_err());
    }

    #[test]
    fn test_sm4_cbc_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let plaintext = b"hello sm4 cbc mode padding";
        let ct = sm4_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let pt = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sm4_cbc_wrong_iv_produces_wrong_plaintext() {
        // CBC 模式下，错误的 IV 会导致第一个明文块被篡改，
        // 但后续块不受影响，填充仍可能有效，因此解密不一定报错。
        // 正确的断言是：解密结果与原始明文不同。
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let iv2 = [0x03u8; 16];
        let plaintext = b"this is a longer plaintext that spans multiple blocks for cbc";
        let ct = sm4_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let pt_wrong = sm4_cbc_decrypt(&key, &iv2, &ct).unwrap();
        assert_ne!(pt_wrong, plaintext);
        // 用正确 IV 解密应还原原始明文
        let pt_correct = sm4_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt_correct, plaintext);
    }

    #[test]
    fn test_sm4_cbc_invalid_iv_length() {
        let key = [0x01u8; 16];
        let short_iv = [0x02u8; 8];
        assert!(sm4_cbc_encrypt(&key, &short_iv, b"data").is_err());
    }

    #[test]
    fn test_sm4_ecb_deterministic() {
        // ECB 模式相同输入产生相同输出
        let key = [0x01u8; 16];
        let data = b"deterministic test";
        let ct1 = sm4_ecb_encrypt(&key, data).unwrap();
        let ct2 = sm4_ecb_encrypt(&key, data).unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_sm4_cbc_non_deterministic() {
        // CBC 模式不同 IV 产生不同输出
        let key = [0x01u8; 16];
        let iv1 = [0x02u8; 16];
        let iv2 = [0x03u8; 16];
        let data = b"cbc iv test";
        let ct1 = sm4_cbc_encrypt(&key, &iv1, data).unwrap();
        let ct2 = sm4_cbc_encrypt(&key, &iv2, data).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
