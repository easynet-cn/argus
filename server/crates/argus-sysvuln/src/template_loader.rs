//! 漏洞模板加载器
//!
//! 加载内置 YAML 模板 + 从目录加载自定义模板

use argus_engine::template::PluginTemplate;
use argus_engine::EngineError;
use crate::types::VulnerabilityTemplate;

/// 模板加载器
pub struct TemplateLoader {
    templates: Vec<PluginTemplate>,
}

impl TemplateLoader {
    pub fn new() -> Self {
        Self { templates: vec![] }
    }

    /// 加载内置 YAML 模板
    ///
    /// 每个 YAML 文件可包含单个或多个模板（数组形式）
    pub fn load_builtin(&mut self) -> Result<usize, EngineError> {
        let yamls = builtin_template_yamls();
        let mut count = 0;
        for yaml in yamls {
            // 优先按数组解析
            let parsed_count = match serde_yaml::from_str::<Vec<VulnerabilityTemplate>>(yaml) {
                Ok(list) => {
                    for tpl in list {
                        self.templates.push(tpl.inner);
                        count += 1;
                    }
                    continue;
                }
                Err(_) => {
                    // 兜底：按单模板解析
                    VulnerabilityTemplate::from_yaml(yaml)
                        .map(|t| {
                            self.templates.push(t.inner);
                            count += 1;
                        })
                        .err()
                }
            };
            if let Some(e) = parsed_count {
                tracing::warn!("解析内置模板失败: {e}");
            }
        }
        Ok(count)
    }

    /// 从目录加载自定义模板（每个 .yaml/.yml 一个模板）
    pub async fn load_dir(&mut self, dir: &str) -> Result<usize, EngineError> {
        let mut count = 0;
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(e) => e,
            Err(e) => return Err(EngineError::TemplateParse(format!("读取目录失败 {dir}: {e}"))),
        };
        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            EngineError::TemplateParse(format!("读取 entry 失败: {e}"))
        })? {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "yaml" || ext == "yml" {
                    if let Ok(content) = tokio::fs::read_to_string(&path).await {
                        match VulnerabilityTemplate::from_yaml(&content) {
                            Ok(tpl) => {
                                self.templates.push(tpl.inner);
                                count += 1;
                            }
                            Err(e) => {
                                tracing::warn!("解析 {:?} 失败: {e}", path);
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    /// 加载单个 YAML 字符串
    pub fn load_str(&mut self, yaml: &str) -> Result<(), EngineError> {
        let tpl = VulnerabilityTemplate::from_yaml(yaml)?;
        self.templates.push(tpl.inner);
        Ok(())
    }

    /// 获取所有模板的不可变引用
    pub fn templates(&self) -> &[PluginTemplate] {
        &self.templates
    }

    /// 按端口过滤模板
    pub fn filter_by_port(&self, port: u16) -> Vec<&PluginTemplate> {
        self.templates
            .iter()
            .filter(|t| t.metadata.port.map(|p| p == port).unwrap_or(true))
            .collect()
    }

    /// 按服务过滤模板
    pub fn filter_by_service(&self, service: &str) -> Vec<&PluginTemplate> {
        self.templates
            .iter()
            .filter(|t| {
                t.metadata
                    .service
                    .as_ref()
                    .map(|s| s == service)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// 按分类过滤模板
    pub fn filter_by_category(&self, category: &str) -> Vec<&PluginTemplate> {
        self.templates
            .iter()
            .filter(|t| t.metadata.category == category)
            .collect()
    }

    /// 模板数量
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

impl Default for TemplateLoader {
    fn default() -> Self {
        let mut loader = Self::new();
        let _ = loader.load_builtin();
        loader
    }
}

/// 内置 YAML 模板字符串列表
///
/// 覆盖常见默认凭据、信息泄露、配置错误、已知 CVE
pub fn builtin_template_yamls() -> &'static [&'static str] {
    BUILTIN_TEMPLATES
}

/// 内置模板（编译时嵌入）
pub static BUILTIN_TEMPLATES: &[&str] = &[
    include_str!("templates/builtin/default_credentials.yaml"),
    include_str!("templates/builtin/info_leak.yaml"),
    include_str!("templates/builtin/misconfig.yaml"),
    include_str!("templates/builtin/known_cve.yaml"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_templates_load() {
        let mut loader = TemplateLoader::new();
        let count = loader.load_builtin().expect("加载内置模板");
        assert!(count > 0, "应该至少加载到一个内置模板");
        // 4 个分类文件，每个至少 1 条
        assert!(loader.len() >= 4, "内置模板数量不足");
    }

    #[test]
    fn test_default_loader_has_templates() {
        let loader = TemplateLoader::default();
        assert!(!loader.is_empty(), "默认加载器应该包含内置模板");
    }

    #[test]
    fn test_load_str_valid_template() {
        let mut loader = TemplateLoader::new();
        let yaml = r#"
id: test-001
name: Test Template
severity: info
detection:
  method: GET
  path: /test
  match_rule:
    match_type: Body
    pattern: hello
"#;
        loader.load_str(yaml).expect("加载");
        assert_eq!(loader.len(), 1);
    }

    #[test]
    fn test_load_str_invalid_yaml_returns_err() {
        let mut loader = TemplateLoader::new();
        let result = loader.load_str("invalid: : :");
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_by_category() {
        let mut loader = TemplateLoader::new();
        let _ = loader.load_builtin();
        let creds = loader.filter_by_category("default_credentials");
        assert!(!creds.is_empty(), "应该有 default_credentials 类别");
    }

    #[test]
    fn test_filter_by_service_http() {
        let mut loader = TemplateLoader::new();
        let _ = loader.load_builtin();
        let http = loader.filter_by_service("http");
        assert!(!http.is_empty(), "应该有 http 服务的模板");
    }
}
