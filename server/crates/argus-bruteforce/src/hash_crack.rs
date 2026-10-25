//! 离线 Hash 破解模块

use md5::{Digest, Md5};
use hex;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::types::HashCrackResult;

/// Hash 类型
#[derive(Debug, Clone, Copy)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashType {
    /// 根据 hash 长度自动识别类型
    pub fn from_hash(hash: &str) -> Option<Self> {
        let len = hash.len();
        match len {
            32 => Some(HashType::Md5),
            40 => Some(HashType::Sha1),
            64 => Some(HashType::Sha256),
            128 => Some(HashType::Sha512),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HashType::Md5 => "md5",
            HashType::Sha1 => "sha1",
            HashType::Sha256 => "sha256",
            HashType::Sha512 => "sha512",
        }
    }

    /// 计算明文的 hash
    pub fn hash(&self, plaintext: &str) -> String {
        match self {
            HashType::Md5 => {
                let mut hasher = Md5::new();
                hasher.update(plaintext.as_bytes());
                hex::encode(hasher.finalize())
            }
            HashType::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(plaintext.as_bytes());
                hex::encode(hasher.finalize())
            }
            HashType::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(plaintext.as_bytes());
                hex::encode(hasher.finalize())
            }
            HashType::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(plaintext.as_bytes());
                hex::encode(hasher.finalize())
            }
        }
    }
}

/// 字典攻击破解单个 hash
pub fn crack_with_dict(hash: &str, dict: &[String]) -> HashCrackResult {
    let hash_lower = hash.to_lowercase();
    let hash_type = HashType::from_hash(&hash_lower);

    if hash_type.is_none() {
        return HashCrackResult {
            hash: hash.to_string(),
            plaintext: None,
            hash_type: "unknown".to_string(),
            cracked: false,
        };
    }

    let hash_type = hash_type.unwrap();

    for word in dict {
        let candidate = hash_type.hash(word);
        if candidate == hash_lower {
            return HashCrackResult {
                hash: hash.to_string(),
                plaintext: Some(word.clone()),
                hash_type: hash_type.as_str().to_string(),
                cracked: true,
            };
        }
    }

    HashCrackResult {
        hash: hash.to_string(),
        plaintext: None,
        hash_type: hash_type.as_str().to_string(),
        cracked: false,
    }
}

/// 批量破解
pub fn crack_batch(hashes: &[String], dict: &[String]) -> Vec<HashCrackResult> {
    hashes.iter().map(|h| crack_with_dict(h, dict)).collect()
}
