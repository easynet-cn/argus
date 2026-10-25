//! Harbor 镜像仓库 API 客户端
//!
//! Harbor v2 API 集成:
//! - 列出项目
//! - 列出仓库
//! - 列出构件
//! - 获取 manifest
//! - 触发漏洞扫描

use crate::types::*;
use reqwest::Client;
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};

/// Harbor API 客户端
pub struct HarborClient {
    base_url: String,
    client: Client,
    auth_header: Option<String>,
}

impl HarborClient {
    pub fn new(url: &str, username: &str, password: &str) -> Self {
        let auth = if !username.is_empty() {
            let credentials = format!("{}:{}", username, password);
            let encoded = general_purpose::STANDARD.encode(credentials);
            Some(format!("Basic {}", encoded))
        } else {
            None
        };

        Self {
            base_url: url.trim_end_matches('/').to_string(),
            client: Client::new(),
            auth_header: auth,
        }
    }

    /// 创建未认证客户端（公开仓库）
    pub fn anonymous(url: &str) -> Self {
        Self {
            base_url: url.trim_end_matches('/').to_string(),
            client: Client::new(),
            auth_header: None,
        }
    }

    /// 构建带认证的请求
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let req = self.client.get(&url);
        if let Some(auth) = &self.auth_header {
            req.header("Authorization", auth)
        } else {
            req
        }
    }

    /// 健康检查
    pub async fn health(&self) -> Result<bool, String> {
        let resp = self.get("/api/v2.0/health")
            .send()
            .await
            .map_err(|e| format!("Harbor health 请求失败: {e}"))?;
        Ok(resp.status().is_success())
    }

    /// 列出所有项目
    pub async fn list_projects(&self) -> Result<Vec<HarborProject>, String> {
        let resp = self.get("/api/v2.0/projects?with_repositories=true")
            .send()
            .await
            .map_err(|e| format!("列出项目失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        let projects: Vec<ProjectResponse> = resp.json()
            .await
            .map_err(|e| format!("解析项目列表失败: {e}"))?;

        Ok(projects.into_iter().map(|p| HarborProject {
            project_id: p.project_id,
            name: p.name,
            repo_count: p.repo_count.unwrap_or(0),
        }).collect())
    }

    /// 列出项目下的仓库
    pub async fn list_repositories(&self, project: &str) -> Result<Vec<HarborRepository>, String> {
        let path = format!("/api/v2.0/projects/{}/repositories", project);
        let resp = self.get(&path)
            .send()
            .await
            .map_err(|e| format!("列出仓库失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        let repos: Vec<RepoResponse> = resp.json()
            .await
            .map_err(|e| format!("解析仓库列表失败: {e}"))?;

        Ok(repos.into_iter().map(|r| HarborRepository {
            name: r.name,
            artifacts_count: r.artifact_count.unwrap_or(0),
            pull_count: r.pull_count.unwrap_or(0),
        }).collect())
    }

    /// 列出仓库下的构件
    pub async fn list_artifacts(&self, project: &str, repo: &str) -> Result<Vec<HarborArtifact>, String> {
        let path = format!("/api/v2.0/projects/{}/repositories/{}/artifacts", project, repo);
        let resp = self.get(&path)
            .send()
            .await
            .map_err(|e| format!("列出构件失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        let artifacts: Vec<ArtifactResponse> = resp.json()
            .await
            .map_err(|e| format!("解析构件列表失败: {e}"))?;

        Ok(artifacts.into_iter().map(|a| HarborArtifact {
            digest: a.digest,
            tags: a.tags.into_iter().filter_map(|t| t.name).collect(),
            size: format!("{} bytes", a.size),
            os: a.os,
        }).collect())
    }

    /// 获取构件的 manifest
    pub async fn get_manifest(&self, project: &str, repo: &str, reference: &str) -> Result<String, String> {
        let path = format!(
            "/api/v2.0/projects/{}/repositories/{}/manifests/{}",
            project, repo, reference
        );
        let resp = self.get(&path)
            .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
            .send()
            .await
            .map_err(|e| format!("获取 manifest 失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        let manifest: serde_json::Value = resp.json()
            .await
            .map_err(|e| format!("解析 manifest 失败: {e}"))?;

        Ok(serde_json::to_string_pretty(&manifest).unwrap_or_default())
    }

    /// 触发 Harbor 漏洞扫描
    pub async fn trigger_scan(&self, project: &str, repo: &str, reference: &str) -> Result<(), String> {
        let path = format!(
            "/api/v2.0/projects/{}/repositories/{}/artifacts/{}/scan",
            project, repo, reference
        );
        let req = if let Some(auth) = &self.auth_header {
            self.client.post(&format!("{}{}", self.base_url, path))
                .header("Authorization", auth)
        } else {
            self.client.post(&format!("{}{}", self.base_url, path))
        };

        let resp = req.send()
            .await
            .map_err(|e| format!("触发扫描失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        Ok(())
    }

    /// 获取镜像的 config blob（R6.2 修复）
    ///
    /// Harbor/Docker Registry v2 API: 通过 manifest 中 config.digest 拉取 config blob
    /// 返回 JSON 格式的镜像配置（含 Env/Cmd/Entrypoint/WorkingDir 等）
    pub async fn get_config_blob(&self, _project: &str, repo: &str, config_digest: &str) -> Result<serde_json::Value, String> {
        // Docker Registry v2 API: GET /v2/{repository}/blobs/{digest}
        // Harbor 兼容 Docker Registry v2 接口，config blob 通过 blob endpoint 获取
        let path = format!(
            "/v2/{}/blobs/{}",
            repo, config_digest
        );
        let resp = self.get(&path)
            .header("Accept", "application/vnd.docker.container.image.v1+json")
            .send()
            .await
            .map_err(|e| format!("获取 config blob 失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        let config: serde_json::Value = resp.json()
            .await
            .map_err(|e| format!("解析 config blob 失败: {e}"))?;

        Ok(config)
    }

    /// 查询扫描结果
    pub async fn get_scan_result(&self, project: &str, repo: &str, reference: &str) -> Result<serde_json::Value, String> {
        let path = format!(
            "/api/v2.0/projects/{}/repositories/{}/artifacts/{}/scan/report/malware",
            project, repo, reference
        );
        let resp = self.get(&path)
            .send()
            .await
            .map_err(|e| format!("查询扫描结果失败: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Harbor API 错误: {}", resp.status()));
        }

        resp.json().await.map_err(|e| format!("解析扫描结果失败: {e}"))
    }
}

// Harbor API 响应类型
#[derive(Debug, Deserialize)]
struct ProjectResponse {
    #[serde(rename = "project_id")]
    project_id: i64,
    name: String,
    #[serde(rename = "repo_count")]
    repo_count: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct RepoResponse {
    name: String,
    #[serde(rename = "artifact_count")]
    artifact_count: Option<i32>,
    #[serde(rename = "pull_count")]
    pull_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ArtifactResponse {
    digest: String,
    size: u64,
    tags: Vec<ArtifactTag>,
    #[serde(default)]
    os: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactTag {
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymous_client() {
        let client = HarborClient::anonymous("https://demo.goharbor.io");
        assert_eq!(client.base_url, "https://demo.goharbor.io");
        assert!(client.auth_header.is_none());
    }

    #[test]
    fn test_authenticated_client() {
        let client = HarborClient::new("https://harbor.example.com", "admin", "password");
        assert_eq!(client.base_url, "https://harbor.example.com");
        assert!(client.auth_header.is_some());
        assert!(client.auth_header.as_ref().unwrap().starts_with("Basic "));
    }

    #[test]
    fn test_base_url_trim() {
        let client = HarborClient::new("https://harbor.example.com/", "admin", "pass");
        assert_eq!(client.base_url, "https://harbor.example.com");
    }
}
