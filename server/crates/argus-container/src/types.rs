//! 容器扫描类型定义

use serde::{Deserialize, Serialize};

/// 镜像层信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageLayer {
    /// 层 ID (sha256)
    pub id: String,
    /// 层命令 (Dockerfile 指令)
    pub command: Option<String>,
    /// 层大小 (bytes)
    pub size: u64,
    /// 层中的文件列表
    pub files: Vec<String>,
}

/// 敏感文件检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFile {
    /// 文件路径
    pub path: String,
    /// 文件类型 (credential/key/config/binary)
    pub file_type: String,
    /// 严重级别
    pub severity: String,
    /// 描述
    pub description: String,
}

/// 镜像扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageScanResult {
    /// 镜像名称
    pub image: String,
    /// 镜像标签
    pub tag: String,
    /// 镜像 digest
    pub digest: Option<String>,
    /// 层信息
    pub layers: Vec<ImageLayer>,
    /// 敏感文件
    pub sensitive_files: Vec<SensitiveFile>,
    /// 依赖漏洞
    pub vulnerabilities: Vec<DepVuln>,
    /// 基础镜像
    pub base_image: Option<String>,
    /// 操作系统
    pub os: Option<String>,
    /// 架构
    pub architecture: Option<String>,
    /// 敏感环境变量（R6.2: 从 config blob 解析）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_env: Vec<String>,
    /// ENTRYPOINT（R6.2: 从 config blob 解析）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    /// 工作目录（R6.2: 从 config blob 解析）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

impl ImageScanResult {
    pub fn new(image: &str, tag: &str) -> Self {
        Self {
            image: image.to_string(),
            tag: tag.to_string(),
            digest: None,
            layers: vec![],
            sensitive_files: vec![],
            vulnerabilities: vec![],
            base_image: None,
            os: None,
            architecture: None,
            sensitive_env: vec![],
            entrypoint: None,
            working_dir: None,
        }
    }
}

/// 依赖漏洞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepVuln {
    /// CVE ID
    pub cve_id: String,
    /// 受影响包名
    pub package: String,
    /// 受影响版本
    pub version: String,
    /// 修复版本
    pub fixed_version: Option<String>,
    /// 严重级别
    pub severity: String,
    /// CVSS 评分
    pub cvss: Option<f64>,
    /// 描述
    pub description: String,
    /// 数据来源 (NVD/OSV/CISA_KEV)
    pub source: String,
}

/// Harbor 仓库信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarborProject {
    pub project_id: i64,
    pub name: String,
    pub repo_count: i32,
}

/// Harbor 镜像仓库
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarborRepository {
    pub name: String,
    pub artifacts_count: i32,
    pub pull_count: i64,
}

/// Harbor 构件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarborArtifact {
    pub digest: String,
    pub tags: Vec<String>,
    pub size: String,
    pub os: Option<String>,
}

/// 容器扫描参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanParams {
    /// 镜像名称 (如 library/nginx:latest)
    pub image: String,
    /// Harbor URL (可选)
    pub harbor_url: Option<String>,
    /// Harbor 用户名
    pub harbor_username: Option<String>,
    /// Harbor 密码
    pub harbor_password: Option<String>,
    /// 是否扫描依赖漏洞
    pub scan_vulns: bool,
    /// 是否检测敏感文件
    pub scan_sensitive: bool,
}

impl Default for ContainerScanParams {
    fn default() -> Self {
        Self {
            image: String::new(),
            harbor_url: None,
            harbor_username: None,
            harbor_password: None,
            scan_vulns: true,
            scan_sensitive: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_scan_result_new() {
        let r = ImageScanResult::new("nginx", "latest");
        assert_eq!(r.image, "nginx");
        assert_eq!(r.tag, "latest");
        assert!(r.layers.is_empty());
    }

    #[test]
    fn test_container_scan_params_default() {
        let p = ContainerScanParams::default();
        assert!(p.scan_vulns);
        assert!(p.scan_sensitive);
        assert!(p.harbor_url.is_none());
    }
}
