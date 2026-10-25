//! CPE 2.3 URI 解析与版本匹配

use crate::error::VulnDbError;
use crate::types::CpeEntry;

pub fn parse_cpe_uri(uri: &str) -> Result<CpeEntry, VulnDbError> {
    let parts: Vec<&str> = uri.split(':').collect();
    if parts.len() < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
        return Err(VulnDbError::CpeParse(format!("无效的 CPE URI: {uri}")));
    }
    let part = parts[2].to_string();
    let vendor = parts[3].to_string();
    let product = parts[4].to_string();
    let version = parts.get(5).unwrap_or(&"*").to_string();
    let target_sw = parts.get(9).and_then(|s| if *s == "*" { None } else { Some(s.to_string()) });
    let language = parts.get(6).and_then(|s| if *s == "*" { None } else { Some(s.to_string()) });
    Ok(CpeEntry { part, vendor, product, version, target_sw, language })
}

pub fn cpe_match_version(cpe_version: &str, target_version: &str) -> bool {
    if cpe_version == "*" || cpe_version == "-" { return true; }
    if cpe_version == target_version { return true; }
    if cpe_version.ends_with(".*") {
        let prefix = cpe_version.trim_end_matches(".*");
        return target_version.starts_with(prefix);
    }
    false
}

pub fn cpe_match_range(
    target_version: &str,
    start_inc: Option<&str>, start_exc: Option<&str>,
    end_inc: Option<&str>, end_exc: Option<&str>,
) -> bool {
    let cmp = |a: &str, b: &str| -> std::cmp::Ordering {
        let av: Vec<u64> = a.split('.').filter_map(|s| s.parse().ok()).collect();
        let bv: Vec<u64> = b.split('.').filter_map(|s| s.parse().ok()).collect();
        for i in 0..av.len().max(bv.len()) {
            let ai = av.get(i).copied().unwrap_or(0);
            let bi = bv.get(i).copied().unwrap_or(0);
            match ai.cmp(&bi) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        std::cmp::Ordering::Equal
    };
    if let Some(v) = start_inc {
        if cmp(target_version, v) == std::cmp::Ordering::Less { return false; }
    }
    if let Some(v) = start_exc {
        if cmp(target_version, v) != std::cmp::Ordering::Greater { return false; }
    }
    if let Some(v) = end_inc {
        if cmp(target_version, v) == std::cmp::Ordering::Greater { return false; }
    }
    if let Some(v) = end_exc {
        if cmp(target_version, v) != std::cmp::Ordering::Less { return false; }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_cpe_uri() {
        let cpe = parse_cpe_uri("cpe:2.3:a:apache:http_server:2.4.6:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.part, "a");
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.6");
    }
    
    #[test]
    fn test_parse_cpe_invalid() {
        assert!(parse_cpe_uri("invalid").is_err());
    }
    
    #[test]
    fn test_cpe_match_version_exact() {
        assert!(cpe_match_version("2.4.6", "2.4.6"));
        assert!(!cpe_match_version("2.4.6", "2.4.7"));
    }
    
    #[test]
    fn test_cpe_match_version_wildcard() {
        assert!(cpe_match_version("2.4.*", "2.4.6"));
        assert!(cpe_match_version("2.4.*", "2.4.41"));
        assert!(!cpe_match_version("2.4.*", "2.5.1"));
    }
    
    #[test]
    fn test_cpe_match_version_any() {
        assert!(cpe_match_version("*", "2.4.6"));
        assert!(cpe_match_version("-", "anything"));
    }
    
    #[test]
    fn test_cpe_match_range() {
        assert!(cpe_match_range("2.4.6", Some("2.4.0"), None, None, Some("2.4.10")));
        assert!(!cpe_match_range("2.4.10", Some("2.4.0"), None, None, Some("2.4.10")));
        assert!(cpe_match_range("2.4.10", Some("2.4.0"), None, Some("2.4.10"), None));
        assert!(cpe_match_range("1.0", None, None, None, None));
    }
}
