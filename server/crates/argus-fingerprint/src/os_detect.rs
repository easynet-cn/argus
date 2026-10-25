//! OS 指纹探测（TTL 推测 + banner 线索）

use crate::types::*;
use crate::signature_db::{OsSignatureDb, OsSignature};

/// 通过 banner 线索推测 OS
pub async fn guess_os_by_banner(
    host: &str,
    banners: &[(u16, String)],
    os_db: &OsSignatureDb,
) -> Option<OsGuess> {
    let mut clues: Vec<String> = vec![];
    let mut best_match: Option<&OsSignature> = None;

    for (port, banner) in banners {
        if let Some(sig) = os_db.guess_by_banner(banner) {
            best_match = Some(sig);
            clues.push(format!("banner:{port}:{}", banner.chars().take(50).collect::<String>()));
        }
        // 内置推断
        let lower = banner.to_lowercase();
        if lower.contains("ubuntu") {
            clues.push(format!("banner:{}:ubuntu", port));
            if best_match.is_none() {
                return Some(OsGuess {
                    host: host.to_string(),
                    os: "Linux".to_string(),
                    version: Some("Ubuntu".to_string()),
                    vendor: Some("Canonical".to_string()),
                    confidence: 0.6,
                    clues,
                });
            }
        } else if lower.contains("centos") || lower.contains("red hat") {
            clues.push(format!("banner:{}:centos", port));
            if best_match.is_none() {
                return Some(OsGuess {
                    host: host.to_string(),
                    os: "Linux".to_string(),
                    version: Some("CentOS".to_string()),
                    vendor: Some("Red Hat".to_string()),
                    confidence: 0.6,
                    clues,
                });
            }
        } else if lower.contains("debian") {
            clues.push(format!("banner:{}:debian", port));
            if best_match.is_none() {
                return Some(OsGuess {
                    host: host.to_string(),
                    os: "Linux".to_string(),
                    version: Some("Debian".to_string()),
                    vendor: Some("Debian".to_string()),
                    confidence: 0.6,
                    clues,
                });
            }
        } else if lower.contains("microsoft") || lower.contains("windows") {
            clues.push(format!("banner:{}:windows", port));
            if best_match.is_none() {
                return Some(OsGuess {
                    host: host.to_string(),
                    os: "Windows".to_string(),
                    version: None,
                    vendor: Some("Microsoft".to_string()),
                    confidence: 0.6,
                    clues,
                });
            }
        }
    }

    best_match.map(|sig| OsGuess {
        host: host.to_string(),
        os: sig.os.clone(),
        version: None,
        vendor: sig.vendor.clone(),
        confidence: 0.5,
        clues,
    })
}

/// 通过 TTL 推测 OS（需要 raw socket 权限，无权限时返回 None）
pub fn guess_os_by_ttl(host: &str, ttl: u8) -> OsGuess {
    let (os, vendor, confidence) = match ttl {
        0..=64 => ("Linux".to_string(), Some("Linux".to_string()), 0.7),
        65..=128 => ("Windows".to_string(), Some("Microsoft".to_string()), 0.7),
        129..=255 => ("Network Device".to_string(), None, 0.5),
    };

    OsGuess {
        host: host.to_string(),
        os,
        version: None,
        vendor,
        confidence,
        clues: vec![format!("TTL={}", ttl)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_to_os_guess_linux() {
        let guess = guess_os_by_ttl("192.168.1.1", 64);
        assert_eq!(guess.os, "Linux");
        assert!(guess.confidence >= 0.7);
    }

    #[test]
    fn test_ttl_to_os_guess_windows() {
        let guess = guess_os_by_ttl("192.168.1.1", 128);
        assert_eq!(guess.os, "Windows");
    }

    #[test]
    fn test_ttl_to_os_guess_network_device() {
        let guess = guess_os_by_ttl("192.168.1.1", 255);
        assert_eq!(guess.os, "Network Device");
    }
}
