//! YAML 模板插件
//!
//! 简单的声明式检测规则，适用于 HTTP 请求 + 响应匹配场景

use serde::{Deserialize, Serialize};
use crate::error::EngineError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTemplate {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub cve: Option<String>,
    pub cvss: Option<f64>,
    pub fix_advice: Option<String>,
    pub detection: DetectionConfig,
    #[serde(default)]
    pub metadata: TemplateMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateMetadata {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub cpe: Option<String>,
    #[serde(default)]
    pub reference_urls: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub method: String,
    pub path: String,
    pub headers: Option<Vec<(String, String)>>,
    pub body: Option<String>,
    pub match_rule: MatchRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchRule {
    pub match_type: MatchType,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    Status,
    Body,
    Header,
    BodyRegex,
}

impl PluginTemplate {
    /// 从 YAML 字符串解析模板
    pub fn from_yaml(yaml: &str) -> Result<Self, EngineError> {
        serde_yaml::from_str(yaml).map_err(|e| EngineError::TemplateParse(e.to_string()))
    }

    /// 从文件加载模板
    pub async fn from_file(path: &str) -> Result<Self, EngineError> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| EngineError::TemplateParse(format!("读取文件失败: {e}")))?;
        Self::from_yaml(&content)
    }
}
