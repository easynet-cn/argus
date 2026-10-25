//! YAML 签名数据库加载器

use serde::{Deserialize, Serialize};

/// 服务签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub service: String,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub banner_regex: Option<String>,
    pub version_regex: Option<String>,
    pub cpe_template: Option<String>,  // 如 "cpe:2.3:a:apache:http_server:{version}"
    pub ports: Option<Vec<u16>>,
}

/// Web 应用签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppSignature {
    pub app: String,
    pub categories: Vec<String>,
    pub indicators: Vec<WebAppIndicator>,
    pub version_indicator: Option<String>,
}

/// Web 应用指纹指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppIndicator {
    pub kind: String,       // "header" / "body" / "cookie" / "favicon"
    pub pattern: String,
    pub description: Option<String>,
}

/// OS 签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsSignature {
    pub os: String,
    pub vendor: Option<String>,
    pub ttl_range: Option<(u8, u8)>,
    pub banner_keywords: Vec<String>,
}

/// 服务签名数据库
#[derive(Debug, Clone)]
pub struct ServiceSignatureDb {
    pub signatures: Vec<ServiceSignature>,
}

impl ServiceSignatureDb {
    /// 加载内置默认签名
    pub fn builtin() -> Self {
        let yaml = include_str!("signatures/services.yaml");
        let signatures: Vec<ServiceSignature> = serde_yaml::from_str(yaml).unwrap_or_default();
        Self { signatures }
    }

    /// 从 YAML 字符串加载
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        Ok(Self {
            signatures: serde_yaml::from_str(yaml)?,
        })
    }

    /// 按端口号查找签名
    pub fn by_port(&self, port: u16) -> Vec<&ServiceSignature> {
        self.signatures.iter()
            .filter(|s| s.ports.as_ref().map_or(false, |p| p.contains(&port)))
            .collect()
    }

    /// 匹配 banner
    pub fn match_banner(&self, banner: &str) -> Option<&ServiceSignature> {
        for sig in &self.signatures {
            if let Some(ref regex) = sig.banner_regex {
                if regex::Regex::new(regex).ok().map_or(false, |r| r.is_match(banner)) {
                    return Some(sig);
                }
            }
            // 简单关键字匹配作为 fallback
            if let Some(ref product) = sig.product {
                let lower = banner.to_lowercase();
                let product_lower = product.to_lowercase();
                if lower.contains(&product_lower) {
                    return Some(sig);
                }
            }
        }
        None
    }
}

/// Web 应用签名数据库
#[derive(Debug, Clone)]
pub struct WebAppSignatureDb {
    pub signatures: Vec<WebAppSignature>,
}

impl WebAppSignatureDb {
    pub fn builtin() -> Self {
        let yaml = include_str!("signatures/webapps.yaml");
        let signatures: Vec<WebAppSignature> = serde_yaml::from_str(yaml).unwrap_or_default();
        Self { signatures }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        Ok(Self {
            signatures: serde_yaml::from_str(yaml)?,
        })
    }
}

/// OS 签名数据库
#[derive(Debug, Clone)]
pub struct OsSignatureDb {
    pub signatures: Vec<OsSignature>,
}

impl OsSignatureDb {
    pub fn builtin() -> Self {
        let yaml = include_str!("signatures/os.yaml");
        let signatures: Vec<OsSignature> = serde_yaml::from_str(yaml).unwrap_or_default();
        Self { signatures }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        Ok(Self {
            signatures: serde_yaml::from_str(yaml)?,
        })
    }

    /// 根据 TTL 推测 OS
    pub fn guess_by_ttl(&self, ttl: u8) -> Option<&OsSignature> {
        self.signatures.iter()
            .find(|s| {
                if let Some((low, high)) = s.ttl_range {
                    ttl >= low && ttl <= high
                } else {
                    false
                }
            })
    }

    /// 根据 banner 关键字推测 OS
    pub fn guess_by_banner(&self, banner: &str) -> Option<&OsSignature> {
        let lower = banner.to_lowercase();
        self.signatures.iter()
            .find(|s| s.banner_keywords.iter().any(|kw| lower.contains(kw)))
    }
}
