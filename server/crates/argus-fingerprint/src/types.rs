//! 指纹识别结果类型

use serde::{Deserialize, Serialize};

/// 指纹识别方法
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FingerprintMethod {
    Banner,
    Port,
    Probe,
    HttpHeaders,
}

/// 服务指纹
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub cpe_uri: Option<String>,
    pub banner: Option<String>,
    pub confidence: f32,
    pub method: FingerprintMethod,
}

/// OS 猜测
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsGuess {
    pub host: String,
    pub os: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub confidence: f32,
    pub clues: Vec<String>,
}

/// Web 应用指纹
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppFingerprint {
    pub host: String,
    pub port: u16,
    pub app: String,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub confidence: f32,
    pub indicators: Vec<String>,
}

/// 指纹识别结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub host: String,
    pub services: Vec<ServiceFingerprint>,
    pub os_guess: Option<OsGuess>,
    pub web_apps: Vec<WebAppFingerprint>,
}

impl FingerprintResult {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            services: vec![],
            os_guess: None,
            web_apps: vec![],
        }
    }
}
