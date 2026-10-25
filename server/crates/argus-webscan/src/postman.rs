//! Postman Collection 导入
//!
//! 解析 Postman v2.1 Collection JSON，提取请求列表用于扫描。
//! 支持: GET/POST/PUT/DELETE 请求、环境变量、请求头、请求体。

use crate::types::{FormData, FormField};
use std::collections::HashMap;

/// Postman Collection
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanCollection {
    pub info: PostmanInfo,
    pub item: Vec<PostmanItem>,
}

/// Collection 信息
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanInfo {
    #[serde(rename = "_postman_id", default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub schema: String,
}

/// Collection 条目（可以是请求或子文件夹）
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanItem {
    pub name: String,
    #[serde(default)]
    pub item: Option<Vec<PostmanItem>>, // 子文件夹
    #[serde(default)]
    pub request: Option<PostmanRequest>,
}

/// Postman 请求定义
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanRequest {
    pub method: String,
    pub url: PostmanUrl,
    #[serde(default)]
    pub header: Option<Vec<PostmanHeader>>,
    #[serde(default)]
    pub body: Option<PostmanBody>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Postman URL（可以是字符串或对象）
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum PostmanUrl {
    Raw(String),
    Object {
        #[serde(default)]
        raw: String,
        #[serde(default)]
        protocol: Option<String>,
        #[serde(default)]
        host: Option<serde_json::Value>,
        #[serde(default)]
        path: Option<serde_json::Value>,
        #[serde(default)]
        query: Option<Vec<PostmanQueryParam>>,
    },
}

impl PostmanUrl {
    pub fn to_string(&self) -> String {
        match self {
            Self::Raw(s) => s.clone(),
            Self::Object { raw, .. } => {
                if !raw.is_empty() {
                    return raw.clone();
                }
                // 从 host + path 拼接
                let host = self.get_host();
                let path = self.get_path();
                let query = self.get_query();
                let mut url = String::new();
                if !host.is_empty() {
                    if !host.starts_with("http") {
                        url.push_str("https://");
                    }
                    url.push_str(&host);
                }
                if !path.is_empty() {
                    url.push('/');
                    url.push_str(&path);
                }
                if !query.is_empty() {
                    url.push('?');
                    url.push_str(&query);
                }
                url
            }
        }
    }

    fn get_host(&self) -> String {
        match self {
            Self::Object { host: Some(serde_json::Value::Array(arr)), .. } => {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
                    .join(".")
            }
            Self::Object { host: Some(serde_json::Value::String(s)), .. } => s.clone(),
            _ => String::new(),
        }
    }

    fn get_path(&self) -> String {
        match self {
            Self::Object { path: Some(serde_json::Value::Array(arr)), .. } => {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
                    .join("/")
            }
            Self::Object { path: Some(serde_json::Value::String(s)), .. } => s.clone(),
            _ => String::new(),
        }
    }

    fn get_query(&self) -> String {
        match self {
            Self::Object { query: Some(params), .. } => {
                params.iter()
                    .map(|p| format!("{}={}", p.key, p.value.as_deref().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("&")
            }
            _ => String::new(),
        }
    }
}

/// Postman 查询参数
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanQueryParam {
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// Postman 请求头
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanHeader {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// Postman 请求体
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanBody {
    pub mode: String, // raw / urlencoded / formdata / graphql
    #[serde(default)]
    pub raw: Option<String>,
    #[serde(default)]
    pub urlencoded: Option<Vec<PostmanUrlEncoded>>,
    #[serde(default)]
    pub formdata: Option<Vec<PostmanFormData>>,
}

/// URL 编码表单字段
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanUrlEncoded {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// multipart 表单数据
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostmanFormData {
    pub key: String,
    pub value: String,
    #[serde(rename = "type", default)]
    pub field_type: String,
    #[serde(default)]
    pub disabled: Option<bool>,
}

/// 导入后的扫描请求
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanRequest {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub form_data: Option<FormData>,
}

/// Postman 导入器
pub struct PostmanImporter {
    variables: HashMap<String, String>,
}

impl PostmanImporter {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// 设置环境变量
    pub fn set_variable(&mut self, key: &str, value: &str) {
        self.variables.insert(key.to_string(), value.to_string());
    }

    /// 批量设置变量
    pub fn set_variables(&mut self, vars: HashMap<String, String>) {
        self.variables.extend(vars);
    }

    /// 从 JSON 导入 Collection
    pub fn import(&self, json: &str) -> Result<Vec<ScanRequest>, String> {
        let collection: PostmanCollection =
            serde_json::from_str(json).map_err(|e| format!("JSON 解析失败: {e}"))?;
        let mut requests = Vec::new();
        for item in &collection.item {
            self.flatten_items(item, &mut requests);
        }
        Ok(requests)
    }

    /// 递归扁平化 items（处理文件夹嵌套）
    fn flatten_items(&self, item: &PostmanItem, requests: &mut Vec<ScanRequest>) {
        if let Some(sub_items) = &item.item {
            for sub in sub_items {
                self.flatten_items(sub, requests);
            }
        }
        if let Some(req) = &item.request {
            let scan_req = self.convert_request(req, &item.name);
            requests.push(scan_req);
        }
    }

    /// 转换单个 Postman 请求为扫描请求
    fn convert_request(&self, req: &PostmanRequest, name: &str) -> ScanRequest {
        let url = self.replace_variables(&req.url.to_string());
        let headers: Vec<(String, String)> = req
            .header
            .as_ref()
            .map(|h| {
                h.iter()
                    .filter(|h| !h.disabled.unwrap_or(false))
                    .map(|h| (h.key.clone(), self.replace_variables(&h.value)))
                    .collect()
            })
            .unwrap_or_default();

        let (body, form_data) = if let Some(b) = &req.body {
            match b.mode.as_str() {
                "raw" => (b.raw.clone(), None),
                "urlencoded" => {
                    let fields: Vec<FormField> = b
                        .urlencoded
                        .as_ref()
                        .map(|u| {
                            u.iter()
                                .filter(|f| !f.disabled.unwrap_or(false))
                                .map(|f| FormField {
                                    name: f.key.clone(),
                                    field_type: "text".to_string(),
                                    value: f.value.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let body_str = fields
                        .iter()
                        .map(|f| format!("{}={}", f.name, f.value))
                        .collect::<Vec<_>>()
                        .join("&");
                    (Some(body_str), Some(FormData {
                        action: url.clone(),
                        method: req.method.clone(),
                        fields,
                    }))
                }
                "formdata" => {
                    let fields: Vec<FormField> = b
                        .formdata
                        .as_ref()
                        .map(|f| {
                            f.iter()
                                .filter(|f| !f.disabled.unwrap_or(false))
                                .map(|f| FormField {
                                    name: f.key.clone(),
                                    field_type: f.field_type.clone(),
                                    value: f.value.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (None, Some(FormData {
                        action: url.clone(),
                        method: req.method.clone(),
                        fields,
                    }))
                }
                _ => (None, None),
            }
        } else {
            (None, None)
        };

        ScanRequest {
            name: name.to_string(),
            method: req.method.clone(),
            url,
            headers,
            body,
            form_data,
        }
    }

    /// 替换 Postman 变量 {{var_name}}
    fn replace_variables(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (key, value) in &self.variables {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }
        // 清除未替换的变量
        let re = regex::Regex::new(r"\{\{[^}]+\}\}").unwrap();
        re.replace_all(&result, "").to_string()
    }
}

impl Default for PostmanImporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_COLLECTION: &str = r#"{
        "info": {
            "_postman_id": "abc123",
            "name": "Test API Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": {
                        "raw": "{{base_url}}/api/users",
                        "host": ["example", "com"],
                        "path": ["api", "users"]
                    },
                    "header": [
                        {"key": "Authorization", "value": "Bearer {{token}}"},
                        {"key": "Content-Type", "value": "application/json"}
                    ]
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "url": "{{base_url}}/api/users",
                    "header": [
                        {"key": "Content-Type", "value": "application/json"}
                    ],
                    "body": {
                        "mode": "raw",
                        "raw": "{\"name\":\"test\",\"email\":\"test@test.com\"}"
                    }
                }
            },
            {
                "name": "Login",
                "request": {
                    "method": "POST",
                    "url": "{{base_url}}/api/login",
                    "body": {
                        "mode": "urlencoded",
                        "urlencoded": [
                            {"key": "username", "value": "admin"},
                            {"key": "password", "value": "pass123"}
                        ]
                    }
                }
            },
            {
                "name": "Folder",
                "item": [
                    {
                        "name": "Delete User",
                        "request": {
                            "method": "DELETE",
                            "url": "{{base_url}}/api/users/1"
                        }
                    }
                ]
            }
        ]
    }"#;

    #[test]
    fn test_import_collection() {
        let importer = PostmanImporter::new();
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        assert_eq!(requests.len(), 4); // 包括嵌套文件夹中的请求
    }

    #[test]
    fn test_import_get_request() {
        let importer = PostmanImporter::new();
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        let get_req = &requests[0];
        assert_eq!(get_req.name, "Get Users");
        assert_eq!(get_req.method, "GET");
        assert_eq!(get_req.url, "/api/users"); // 未设置变量，被清除
        assert_eq!(get_req.headers.len(), 2);
        assert_eq!(get_req.headers[0].0, "Authorization");
    }

    #[test]
    fn test_import_post_raw_body() {
        let importer = PostmanImporter::new();
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        let post_req = &requests[1];
        assert_eq!(post_req.method, "POST");
        assert!(post_req.body.is_some());
        assert!(post_req.body.as_ref().unwrap().contains("test@test.com"));
    }

    #[test]
    fn test_import_form_body() {
        let importer = PostmanImporter::new();
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        let login_req = &requests[2];
        assert_eq!(login_req.method, "POST");
        assert!(login_req.form_data.is_some());
        let form = login_req.form_data.as_ref().unwrap();
        assert_eq!(form.fields.len(), 2);
        assert_eq!(form.fields[0].name, "username");
        assert_eq!(form.fields[0].value, "admin");
        assert!(login_req.body.as_ref().unwrap().contains("username=admin"));
    }

    #[test]
    fn test_import_nested_folder() {
        let importer = PostmanImporter::new();
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        let delete_req = &requests[3];
        assert_eq!(delete_req.name, "Delete User");
        assert_eq!(delete_req.method, "DELETE");
    }

    #[test]
    fn test_variable_replacement() {
        let mut importer = PostmanImporter::new();
        importer.set_variable("base_url", "https://api.example.com");
        importer.set_variable("token", "jwt_token_123");
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        let get_req = &requests[0];
        assert_eq!(get_req.url, "https://api.example.com/api/users");
        assert_eq!(get_req.headers[0].1, "Bearer jwt_token_123");
    }

    #[test]
    fn test_variable_replacement_batch() {
        let mut importer = PostmanImporter::new();
        let mut vars = HashMap::new();
        vars.insert("base_url".to_string(), "https://test.com".to_string());
        vars.insert("token".to_string(), "xyz".to_string());
        importer.set_variables(vars);
        let requests = importer.import(SAMPLE_COLLECTION).unwrap();
        assert!(requests[0].url.contains("https://test.com"));
    }

    #[test]
    fn test_import_invalid_json() {
        let importer = PostmanImporter::new();
        assert!(importer.import("invalid").is_err());
    }

    #[test]
    fn test_postman_url_raw() {
        let url = PostmanUrl::Raw("https://example.com/api/test".to_string());
        assert_eq!(url.to_string(), "https://example.com/api/test");
    }

    #[test]
    fn test_postman_url_object_with_raw() {
        let url = PostmanUrl::Object {
            raw: "https://example.com/api/test".to_string(),
            protocol: None,
            host: None,
            path: None,
            query: None,
        };
        assert_eq!(url.to_string(), "https://example.com/api/test");
    }

    #[test]
    fn test_postman_url_object_no_raw() {
        let url = PostmanUrl::Object {
            raw: String::new(),
            protocol: Some("https".to_string()),
            host: Some(serde_json::json!(["example", "com"])),
            path: Some(serde_json::json!(["api", "test"])),
            query: None,
        };
        let result = url.to_string();
        assert!(result.contains("example.com"));
        assert!(result.contains("api/test"));
    }

    #[test]
    fn test_replace_variables_no_match() {
        let importer = PostmanImporter::new();
        let result = importer.replace_variables("https://example.com/api/test");
        assert_eq!(result, "https://example.com/api/test");
    }

    #[test]
    fn test_replace_variables_partial() {
        let mut importer = PostmanImporter::new();
        importer.set_variable("base_url", "https://example.com");
        let result = importer.replace_variables("{{base_url}}/api/{{token}}");
        assert_eq!(result, "https://example.com/api/"); // token 未设置被清除
    }
}
