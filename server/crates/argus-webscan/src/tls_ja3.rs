//! TLS/JA3 指纹
//!
//! JA3 是一种 TLS 客户端指纹方法，通过对 TLS ClientHello 消息中的
//! 特定字段做 MD5 哈希生成固定长度的指纹，用于识别客户端类型。

use md5::{Digest, Md5};

/// JA3 指纹结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ja3Fingerprint {
    pub ja3_hash: String,
    pub ja3_raw: String,
    pub client_guess: String,
}

/// TLS 扩展信息（用于提取 JA3 数据）
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

impl TlsClientHello {
    /// 从 ClientHello 字节流解析
    /// 格式: version(2) + cipher_suites_len(2) + cipher_suites + extensions...
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let mut offset = 0;
        let version = u16::from_be_bytes([data[0], data[1]]);
        offset = 2;

        // Cipher suites
        if offset + 2 > data.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + cs_len > data.len() {
            return None;
        }
        let mut cipher_suites = Vec::new();
        for i in (0..cs_len).step_by(2) {
            if offset + i + 1 < data.len() {
                let cs = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
                cipher_suites.push(cs);
            }
        }
        offset += cs_len;

        // Extensions
        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();

        if offset + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let ext_end = offset + ext_len;
            while offset + 4 <= ext_end.min(data.len()) {
                let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;

                extensions.push(ext_type);

                // Supported Groups (extension type 0x000a)
                if ext_type == 0x000a && offset + 2 <= data.len() {
                    let groups_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    let groups_start = offset + 2;
                    for i in (0..groups_len).step_by(2) {
                        if groups_start + i + 1 < data.len() {
                            let g = u16::from_be_bytes([data[groups_start + i], data[groups_start + i + 1]]);
                            supported_groups.push(g);
                        }
                    }
                }

                // EC Point Formats (extension type 0x000b)
                if ext_type == 0x000b && offset < data.len() {
                    let pf_len = data[offset] as usize;
                    for i in 1..=pf_len {
                        if offset + i < data.len() {
                            ec_point_formats.push(data[offset + i]);
                        }
                    }
                }

                offset += ext_data_len;
            }
        }

        Some(Self {
            version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats,
        })
    }

    /// 计算 JA3 指纹
    /// JA3 = MD5(SSLVersion,CipherSuites,Extensions,EllipticCurves,EC_Point_Formats)
    pub fn to_ja3(&self) -> Ja3Fingerprint {
        // 构建 JA3 原始字符串
        let cs: Vec<String> = self.cipher_suites.iter().map(|c| format!("{:04x}", c)).collect();
        let exts: Vec<String> = self.extensions.iter().map(|e| format!("{}", e)).collect();
        let groups: Vec<String> = self.supported_groups.iter().map(|g| format!("{}", g)).collect();
        let pf: Vec<String> = self.ec_point_formats.iter().map(|p| format!("{}", p)).collect();

        let ja3_raw = format!(
            "{},{},{},{},{}",
            self.version,
            cs.join("-"),
            exts.join("-"),
            groups.join("-"),
            pf.join("-")
        );

        // 计算 MD5
        let mut hasher = Md5::new();
        hasher.update(ja3_raw.as_bytes());
        let result = hasher.finalize();
        let ja3_hash = format!("{:032x}", result);

        // 猜测客户端类型
        let client_guess = guess_client(&ja3_hash, &self.extensions, &self.cipher_suites);

        Ja3Fingerprint {
            ja3_hash,
            ja3_raw,
            client_guess,
        }
    }
}

/// 根据 JA3 指纹猜测客户端类型
fn guess_client(ja3_hash: &str, extensions: &[u16], cipher_suites: &[u16]) -> String {
    // 已知的 JA3 指纹（常见客户端）
    match ja3_hash {
        "e7d705a3286e19ea42f587b344ee6865" => "Chrome 100+".to_string(),
        "773906a12cbb5b3f3e4c6419d7e9cb3c" => "Firefox 100+".to_string(),
        "cd08e31494f9531cef5f65bbeb70a6a7" => "Safari 15+".to_string(),
        "5e3f0adab1e0e2b7fcca2e3a747f8979" => "curl 7.x".to_string(),
        "b326abb8d4cfa1b6e9d6c9c0e3f8a7d9" => "Python requests".to_string(),
        _ => {
            // 基于 GREASE 和扩展推断
            let has_grease = cipher_suites.iter().any(|c| (*c & 0x0f0f) == 0x0a0a);
            if has_grease {
                "Chrome/Edge (GREASE detected)".to_string()
            } else if extensions.contains(&0x0005) && extensions.contains(&0x0010) {
                "Generic Browser".to_string()
            } else if extensions.len() < 5 {
                "Script/CLI Tool".to_string()
            } else {
                "Unknown".to_string()
            }
        }
    }
}

/// 从原始 TLS 记录提取 ClientHello 并计算 JA3
/// TLS Record: type(1) + version(2) + length(2) + Handshake(4) + ...
pub fn fingerprint_tls_record(data: &[u8]) -> Option<Ja3Fingerprint> {
    if data.len() < 5 {
        return None;
    }

    // TLS Record Header
    let record_type = data[0];
    if record_type != 0x16 {
        return None; // 不是 Handshake
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    // Handshake Header
    let hs_type = data[5];
    if hs_type != 0x01 {
        return None; // 不是 ClientHello
    }

    // 跳过: record_header(5) + handshake_type(1) + length(3) + version(2) + random(32)
    let hello_start = 5 + 1 + 3 + 2 + 32;

    // Session ID
    if data.len() < hello_start + 1 {
        return None;
    }
    let session_id_len = data[hello_start] as usize;
    let cs_start = hello_start + 1 + session_id_len;

    TlsClientHello::parse(&data[cs_start..]).map(|hello| hello.to_ja3())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja3_simple() {
        let hello = TlsClientHello {
            version: 0x0303, // TLS 1.2
            cipher_suites: vec![0xc02f, 0xc030],
            extensions: vec![0x0000, 0x0017, 0x0005],
            supported_groups: vec![0x0017, 0x0018],
            ec_point_formats: vec![0x01, 0x00],
        };

        let ja3 = hello.to_ja3();
        assert!(!ja3.ja3_hash.is_empty());
        assert_eq!(ja3.ja3_hash.len(), 32); // MD5 hex
        assert!(!ja3.ja3_raw.is_empty());
        assert!(ja3.ja3_raw.contains("771")); // 0x0303 = 771
    }

    #[test]
    fn test_ja3_consistency() {
        let hello = TlsClientHello {
            version: 0x0303,
            cipher_suites: vec![0xc02f],
            extensions: vec![0x0000],
            supported_groups: vec![0x0017],
            ec_point_formats: vec![0x01],
        };

        let ja3_1 = hello.to_ja3();
        let ja3_2 = hello.to_ja3();
        assert_eq!(ja3_1.ja3_hash, ja3_2.ja3_hash);
    }

    #[test]
    fn test_ja3_different_clients() {
        let chrome = TlsClientHello {
            version: 0x0303,
            cipher_suites: vec![0x0a0a, 0x1301, 0x0a0a, 0xc02f], // GREASE pattern
            extensions: vec![0x0000, 0x0017, 0x0005],
            supported_groups: vec![0x0017],
            ec_point_formats: vec![0x01],
        };
        let firefox = TlsClientHello {
            version: 0x0303,
            cipher_suites: vec![0x1301, 0xc02f, 0xc030],
            extensions: vec![0x0000, 0x0005, 0x0010],
            supported_groups: vec![0x0017, 0x0018],
            ec_point_formats: vec![0x01, 0x00],
        };

        let chrome_ja3 = chrome.to_ja3();
        let firefox_ja3 = firefox.to_ja3();

        assert_ne!(chrome_ja3.ja3_hash, firefox_ja3.ja3_hash);
        assert!(chrome_ja3.client_guess.contains("Chrome") || chrome_ja3.client_guess.contains("Unknown"));
    }

    #[test]
    fn test_ja3_raw_format() {
        let hello = TlsClientHello {
            version: 0x0303,
            cipher_suites: vec![0xc02f, 0xc030],
            extensions: vec![0x0000, 0x0017],
            supported_groups: vec![0x0017],
            ec_point_formats: vec![0x01],
        };

        let ja3 = hello.to_ja3();
        // 格式: version,ciphers,extensions,groups,point_formats
        assert!(ja3.ja3_raw.contains("771,c02f-c030,0-23,23,1"));
    }

    #[test]
    fn test_parse_empty_data() {
        assert!(TlsClientHello::parse(&[]).is_none());
        assert!(TlsClientHello::parse(&[0x03]).is_none());
    }

    #[test]
    fn test_fingerprint_tls_record_invalid() {
        assert!(fingerprint_tls_record(&[]).is_none());
        assert!(fingerprint_tls_record(&[0x17, 0x03, 0x03, 0x00, 0x01]).is_none()); // 非 Handshake
        assert!(fingerprint_tls_record(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x02]).is_none()); // 非 ClientHello
    }

    #[test]
    fn test_guess_client_known() {
        let result = guess_client("e7d705a3286e19ea42f587b344ee6865", &[], &[]);
        assert!(result.contains("Chrome"));
    }

    #[test]
    fn test_guess_client_grease() {
        let grease_suites = vec![0x0a0a, 0x1301];
        let result = guess_client("unknown123", &[], &grease_suites);
        assert!(result.contains("Chrome") || result.contains("Edge"));
    }

    #[test]
    fn test_guess_client_unknown() {
        let result = guess_client("ffffffffffffffffffffffffffffffff", &[0x0001, 0x0002, 0x0003, 0x0004, 0x0006, 0x0007], &[0x0001, 0x0002]);
        assert_eq!(result, "Unknown");
    }
}
