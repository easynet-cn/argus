//! 漏洞检测引擎类型定义
//!
//! 复用 PluginTemplate + 扩展 metadata

use serde::{Deserialize, Serialize};
use argus_engine::template::{PluginTemplate, TemplateMetadata};

/// 漏洞检测模板（复用 PluginTemplate + metadata 扩展）
///
/// 通过 #[serde(flatten)] 把 PluginTemplate 字段平铺到本结构，
/// YAML 写法与 PluginTemplate 完全兼容，额外字段在 metadata 内。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityTemplate {
    #[serde(flatten)]
    pub inner: PluginTemplate,
}

impl VulnerabilityTemplate {
    /// 从 YAML 字符串解析
    pub fn from_yaml(yaml: &str) -> Result<Self, argus_engine::EngineError> {
        serde_yaml::from_str(yaml)
            .map_err(|e| argus_engine::EngineError::TemplateParse(e.to_string()))
    }

    /// 获取 metadata 引用
    pub fn metadata(&self) -> &TemplateMetadata {
        &self.inner.metadata
    }

    /// 获取模板 ID
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    /// 获取模板名称
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// 获取严重等级
    pub fn severity(&self) -> &str {
        &self.inner.severity
    }
}

/// 匹配到的 CVE 信息（passive CPE 匹配结果）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedCve {
    pub cve_id: String,
    pub description: String,
    pub severity: Option<String>,
    pub cvss_v2: Option<f64>,
    pub cvss_v3: Option<f64>,
    pub cpe_uri: String,
    pub references: Vec<String>,
}

/// 扫描模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanMode {
    /// 主动模板探测（发送 HTTP 请求 + 响应匹配）
    Active,
    /// 被动 CPE 匹配（基于指纹 + CVE 知识库）
    Passive,
    /// 混合模式（先 active，再 passive 补充）
    Hybrid,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::Hybrid
    }
}

/// 漏洞扫描结果（raw_data 中存放）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub host: String,
    pub active_findings: Vec<argus_engine::PluginResult>,
    pub passive_findings: Vec<MatchedCve>,
    pub fingerprints_used: Vec<String>,
}

impl VulnScanResult {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            active_findings: vec![],
            passive_findings: vec![],
            fingerprints_used: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_template_from_yaml() {
        let yaml = r#"
id: CVE-2024-1234-test
name: Test Vuln
severity: high
cve: CVE-2024-1234
cvss: 7.5
description: Test vulnerability
detection:
  method: GET
  path: /test
  match_rule:
    match_type: Body
    pattern: vulnerable
metadata:
  category: test
  tags: [rce, web]
  service: http
"#;
        let tpl = VulnerabilityTemplate::from_yaml(yaml).expect("parse");
        assert_eq!(tpl.id(), "CVE-2024-1234-test");
        assert_eq!(tpl.name(), "Test Vuln");
        assert_eq!(tpl.severity(), "high");
        assert_eq!(tpl.metadata().category, "test");
        assert_eq!(tpl.metadata().tags.len(), 2);
        assert_eq!(tpl.metadata().service.as_deref(), Some("http"));
    }

    #[test]
    fn test_scan_mode_default() {
        assert_eq!(ScanMode::default(), ScanMode::Hybrid);
    }

    #[test]
    fn test_matched_cve_serialization() {
        let m = MatchedCve {
            cve_id: "CVE-2024-1".to_string(),
            description: "test".to_string(),
            severity: Some("HIGH".to_string()),
            cvss_v2: Some(7.5),
            cvss_v3: Some(8.0),
            cpe_uri: "cpe:2.3:a:vendor:product:1.0".to_string(),
            references: vec!["https://nvd.nist.gov".to_string()],
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let back: MatchedCve = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m.cve_id, back.cve_id);
        assert_eq!(m.cvss_v3, back.cvss_v3);
    }

    #[test]
    fn test_vuln_scan_result_new() {
        let r = VulnScanResult::new("192.168.1.1");
        assert_eq!(r.host, "192.168.1.1");
        assert!(r.active_findings.is_empty());
        assert!(r.passive_findings.is_empty());
    }
}
