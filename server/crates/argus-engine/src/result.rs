//! 插件执行结果

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub vuln_id: String,
    pub name: String,
    pub severity: String,
    pub evidence: String,
    pub cvss: Option<f64>,
    pub cve: Option<String>,
    pub fix_advice: Option<String>,
    pub target: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl PluginResult {
    pub fn new(target: impl Into<String>, name: impl Into<String>, severity: impl Into<String>) -> Self {
        Self {
            vuln_id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            severity: severity.into(),
            evidence: String::new(),
            cvss: None,
            cve: None,
            fix_advice: None,
            target: target.into(),
            port: None,
            service: None,
            timestamp: chrono::Utc::now(),
        }
    }
}
