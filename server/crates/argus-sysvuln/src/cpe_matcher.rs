//! CPE 匹配器
//!
//! 基于 ServiceFingerprint 查询 CVE 知识库

use sea_orm::DatabaseConnection;
use argus_vulndb::repository;
use argus_vulndb::cpe_parser;
use argus_fingerprint::types::ServiceFingerprint;
use crate::types::MatchedCve;

/// CPE 匹配器（passive CVE 查询）
#[derive(Clone)]
pub struct CpeMatcher {
    db: DatabaseConnection,
}

impl CpeMatcher {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 基于 ServiceFingerprint 查询匹配的 CVE 列表
    ///
    /// 优先使用指纹的 cpe_uri；若缺失，则用 vendor + product 构造。
    pub async fn match_fingerprint(&self, fp: &ServiceFingerprint) -> Vec<MatchedCve> {
        // 1. 优先使用指纹 cpe_uri
        if let Some(ref cpe_uri) = fp.cpe_uri {
            return self.match_by_cpe(cpe_uri).await;
        }
        // 2. 兜底：基于 vendor+product 构造（version 不限）
        if let (Some(vendor), Some(product)) = (&fp.vendor, &fp.product) {
            let uri = format!("cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*");
            return self.match_by_cpe(&uri).await;
        }
        vec![]
    }

    /// 基于 CPE URI 查询 CVE 列表
    pub async fn match_by_cpe(&self, cpe_uri: &str) -> Vec<MatchedCve> {
        // 解析 CPE
        let parsed = match cpe_parser::parse_cpe_uri(cpe_uri) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("CPE 解析失败 {cpe_uri}: {e}");
                return vec![];
            }
        };

        // 构造宽松 CPE 用于查询（version = * 以扩大召回）
        let loose_uri = format!(
            "cpe:2.3:{}:{}:{}:*:*:*:*:*:*:*:*",
            parsed.part, parsed.vendor, parsed.product
        );

        let cves = repository::find_by_cpe(&self.db, &loose_uri).await;
        tracing::info!(
            "CPE 匹配查询: uri={cpe_uri}, loose={loose_uri}, 命中 {} 条 CVE",
            cves.len()
        );

        cves.into_iter()
            .map(|cve| MatchedCve {
                cve_id: cve.id.clone(),
                description: cve.description.clone(),
                severity: cve.severity.clone(),
                cvss_v2: cve.cvss_v2,
                cvss_v3: cve.cvss_v3,
                cpe_uri: cpe_uri.to_string(),
                references: parse_references(&cve.references),
            })
            .collect()
    }

    /// 批量匹配多个指纹
    pub async fn match_fingerprints(&self, fps: &[ServiceFingerprint]) -> Vec<MatchedCve> {
        let mut all = Vec::new();
        for fp in fps {
            let matched = self.match_fingerprint(fp).await;
            all.extend(matched);
        }
        // 去重（按 cve_id + cpe_uri）
        let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        all.retain(|m| {
            let key = (m.cve_id.clone(), m.cpe_uri.clone());
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });
        all
    }
}

/// 解析 references JSON 数组为 Vec<String>
fn parse_references(references: &serde_json::Value) -> Vec<String> {
    references
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str().map(|s| s.to_string())
                        .or_else(|| v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_fingerprint::types::{ServiceFingerprint, FingerprintMethod};

    #[test]
    fn test_parse_references_string_array() {
        let v = serde_json::json!(["https://a.com", "https://b.com"]);
        let refs = parse_references(&v);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_parse_references_object_array() {
        let v = serde_json::json!([
            {"url": "https://x.com", "source": "NVD"},
            {"url": "https://y.com"}
        ]);
        let refs = parse_references(&v);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], "https://x.com");
    }

    #[test]
    fn test_parse_references_empty() {
        let v = serde_json::json!(null);
        let refs = parse_references(&v);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_make_service_fingerprint_with_cpe() {
        let fp = ServiceFingerprint {
            host: "127.0.0.1".to_string(),
            port: 80,
            service: "http".to_string(),
            product: Some("apache".to_string()),
            version: Some("2.4.1".to_string()),
            vendor: Some("apache".to_string()),
            cpe_uri: Some("cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*".to_string()),
            banner: None,
            confidence: 0.9,
            method: FingerprintMethod::Banner,
        };
        assert!(fp.cpe_uri.is_some());
    }

    #[test]
    fn test_make_service_fingerprint_without_cpe() {
        let fp = ServiceFingerprint {
            host: "127.0.0.1".to_string(),
            port: 80,
            service: "http".to_string(),
            product: Some("nginx".to_string()),
            version: None,
            vendor: Some("nginx".to_string()),
            cpe_uri: None,
            banner: None,
            confidence: 0.5,
            method: FingerprintMethod::Port,
        };
        assert!(fp.cpe_uri.is_none());
        assert!(fp.vendor.is_some());
    }
}
