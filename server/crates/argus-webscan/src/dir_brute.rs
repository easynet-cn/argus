//! G5.8 敏感目录字典扫描
//!
//! 使用内置常见目录字典对目标站点进行路径爆破，识别存在的后台/管理/API/配置目录。
//! 分类响应：
//! - 200：目录存在（结合 404 基线可排除 soft-404）
//! - 401/403：目录存在但需要授权
//! - 500：目录存在但服务器错误
//! - 404：不存在
//!
//! 字典包含三类：
//! - 后台/管理类（admin、phpmyadmin、wp-admin 等）
//! - API 类（api/v1、swagger、graphql 等）
//! - 配置/敏感文件类（.git、.env、backup.sql 等）

use crate::types::{HttpResponse, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// G5.8 敏感目录扫描器
pub struct DirBruteScanner {
    http: reqwest::Client,
    /// 并发数（暂未实现并发，预留）
    pub concurrency: usize,
    /// 请求方法
    pub method: Method,
}

/// 探测使用的方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
}

/// 探测结果分类
#[derive(Debug, Clone, PartialEq)]
pub enum DirStatus {
    Exists,
    Forbidden,
    ServerError,
    NotFound,
    Redirect,
    Unknown,
}

/// 探测到的目录条目
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: String,
    pub status: u16,
    pub classification: DirStatus,
    pub length: usize,
    pub server: Option<String>,
}

impl DirBruteScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            http,
            concurrency: 10,
            method: Method::Head,
        }
    }

    /// 使用 GET 方法扫描（HEAD 不被某些服务器支持时使用）
    pub fn with_get_method(mut self) -> Self {
        self.method = Method::Get;
        self
    }

    /// 对目标站点执行完整字典扫描
    pub async fn scan(&self, base_url: &str) -> Vec<DirEntry> {
        let mut entries = Vec::new();
        for path in COMMON_DIRECTORIES {
            let url = join_url(base_url, path);
            if let Some(resp) = self.probe(&url).await {
                let entry = DirEntry {
                    path: path.to_string(),
                    status: resp.status,
                    classification: classify_status(resp.status),
                    length: resp.body.len(),
                    server: extract_server(&resp.headers),
                };
                // 只保留存在的目录
                if entry.classification != DirStatus::NotFound {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    /// 探测单个 URL
    pub async fn probe(&self, url: &str) -> Option<HttpResponse> {
        let req = match self.method {
            Method::Get => self.http.get(url),
            Method::Head => self.http.head(url),
        };
        let resp = req.send().await.ok()?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        // HEAD 通常无 body
        let body = if self.method == Method::Get {
            resp.text().await.unwrap_or_default()
        } else {
            String::new()
        };
        Some(HttpResponse { status, headers, body })
    }

    /// 把扫描结果转为漏洞发现列表
    pub fn to_findings(&self, entries: &[DirEntry], base_url: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for e in entries {
            let sev = match e.classification {
                DirStatus::Exists => self.severity_for_path(&e.path),
                DirStatus::Forbidden => Severity::Low,
                DirStatus::ServerError => Severity::Medium,
                DirStatus::Redirect => Severity::Low,
                DirStatus::Unknown => Severity::Info,
                DirStatus::NotFound => continue,
            };
            let cat = match e.classification {
                DirStatus::Exists => category_for_path(&e.path),
                DirStatus::Forbidden => VulnCategory::SecurityMisconfig,
                DirStatus::ServerError => VulnCategory::SecurityMisconfig,
                DirStatus::Redirect => VulnCategory::SecurityMisconfig,
                DirStatus::Unknown => VulnCategory::SecurityMisconfig,
                DirStatus::NotFound => continue,
            };
            let evidence = format!(
                "{} ({}, {} bytes)",
                e.path,
                status_label(&e.classification),
                e.length
            );
            findings.push(VulnFinding {
                category: cat,
                url: join_url(base_url, &e.path),
                parameter: None,
                payload: None,
                evidence,
                severity: sev,
            });
        }
        findings
    }

    /// 根据路径选择严重程度（敏感文件路径优先级更高）
    fn severity_for_path(&self, path: &str) -> Severity {
        let p = path.to_lowercase();
        // 高危：源代码控制、备份文件、配置文件、数据库备份
        if p.contains(".git/") || p.contains(".svn/") || p.contains(".hg/") {
            return Severity::Critical;
        }
        if p.ends_with(".env")
            || p.ends_with(".env.bak")
            || p.contains(".env.local")
            || p.contains("config.php")
            || p.contains("config.json")
            || p.contains("config.yml")
            || p.contains("config.yaml")
            || p.contains("config.ini")
            || p.contains("settings.json")
            || p.contains("settings.php")
        {
            return Severity::Critical;
        }
        if p.contains("backup")
            || p.ends_with(".sql")
            || p.ends_with(".bak")
            || p.ends_with(".zip")
            || p.ends_with(".tar.gz")
            || p.ends_with(".tar")
        {
            return Severity::Critical;
        }
        // 高危：管理后台、IDE 工程文件、敏感服务
        if p.contains("admin")
            || p.contains("phpmyadmin")
            || p.contains("wp-admin")
            || p.contains("manager")
            || p.contains("console")
            || p.contains("h2-console")
            || p.contains("/.idea/")
            || p.contains(".vscode/")
        {
            return Severity::High;
        }
        // 中危：API 文档、调试端点
        if p.contains("swagger")
            || p.contains("api-docs")
            || p.contains("graphql")
            || p.contains("debug")
            || p.contains("phpinfo")
            || p.contains("info.php")
            || p.contains("server-status")
            || p.contains("actuator")
        {
            return Severity::Medium;
        }
        Severity::Low
    }
}

impl Default for DirBruteScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// 根据状态码分类
pub fn classify_status(status: u16) -> DirStatus {
    match status {
        200..=299 => DirStatus::Exists,
        301 | 302 | 303 | 307 | 308 => DirStatus::Redirect,
        401 | 403 => DirStatus::Forbidden,
        404 => DirStatus::NotFound,
        500..=599 => DirStatus::ServerError,
        _ => DirStatus::Unknown,
    }
}

/// 状态分类的人类可读标签
fn status_label(s: &DirStatus) -> &'static str {
    match s {
        DirStatus::Exists => "found",
        DirStatus::Forbidden => "forbidden",
        DirStatus::ServerError => "server_error",
        DirStatus::NotFound => "not_found",
        DirStatus::Redirect => "redirect",
        DirStatus::Unknown => "unknown",
    }
}

/// 根据路径选择漏洞分类
fn category_for_path(path: &str) -> VulnCategory {
    let p = path.to_lowercase();
    if p.contains(".git/") || p.contains(".env") || p.contains("backup") {
        return VulnCategory::SecurityMisconfig;
    }
    if p.contains("admin") || p.contains("phpmyadmin") || p.contains("manager") {
        return VulnCategory::BrokenAccessControl;
    }
    VulnCategory::SecurityMisconfig
}

/// 从响应头中提取 Server 字段
fn extract_server(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("server") {
            return Some(v.clone());
        }
    }
    None
}

/// 拼接 base_url + path
fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

/// 常见敏感目录字典（后台/API/配置/版本控制）
pub const COMMON_DIRECTORIES: &[&str] = &[
    // === 后台 / 管理类 ===
    "/admin",
    "/admin/",
    "/admin.php",
    "/admin.html",
    "/admin/login",
    "/admin/index.php",
    "/administrator",
    "/administrator/",
    "/admincp",
    "/manage",
    "/manager",
    "/manager/html",
    "/manager/status",
    "/panel",
    "/dashboard",
    "/control",
    "/console",
    "/wp-admin",
    "/wp-admin/",
    "/wp-admin/login.php",
    "/wp-login.php",
    "/wp-content/",
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-config.php.bak",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/phpMyAdmin",
    "/pma",
    "/pma/",
    "/mysql",
    "/mysqladmin",
    "/sqladmin",
    "/adminer.php",
    "/adminer",
    "/dbadmin",
    "/h2-console",
    "/h2-console/",
    "/jmx-console",
    "/weblogic",
    "/tomcat/manager",
    "/manager/text",
    "/site/admin",
    "/user/admin",
    "/users/admin",
    // === API 类 ===
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v2",
    "/api/v2/",
    "/api/users",
    "/api/login",
    "/api/auth",
    "/api/token",
    "/api/swagger",
    "/api-docs",
    "/api/docs",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger.json",
    "/swagger.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/graphql",
    "/graphql.php",
    "/graphiql",
    "/playground",
    "/api/health",
    "/health",
    "/healthz",
    "/actuator",
    "/actuator/",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/metrics",
    "/jolokia",
    // === 配置 / 敏感文件 ===
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/config.ini",
    "/config.xml",
    "/settings.json",
    "/settings.php",
    "/config/database.yml",
    "/config/database.php",
    "/db.php",
    "/database.sql",
    "/backup",
    "/backup/",
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.tar",
    "/backup.tgz",
    "/db.sql",
    "/dump.sql",
    "/data.sql",
    "/site.sql",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/composer.json",
    "/composer.lock",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    // === 版本控制 ===
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.svn/",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/",
    "/.bzr/",
    "/.DS_Store",
    "/.idea/",
    "/.idea/workspace.xml",
    "/.vscode/",
    "/.vscode/settings.json",
    // === 调试 / 信息泄露 ===
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/test.html",
    "/test/",
    "/tests/",
    "/debug",
    "/debug/",
    "/debug.php",
    "/var/log",
    "/logs",
    "/server-status",
    "/server-info",
    "/status",
    "/stat",
    "/.well-known/",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/humans.txt",
    "/security.txt",
    "/tracing",
    "/trace",
    "/.aws/",
    "/.aws/credentials",
    "/.ssh/",
    "/.ssh/id_rsa",
    "/.ssh/id_dsa",
    "/.gitconfig",
    "/.npmrc",
    "/.dockerenv",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    // === 框架/特定文件 ===
    "/index.php.bak",
    "/index.php~",
    "/index.php.swp",
    "/index.php.old",
    "/.htaccess.bak",
    "/web.config.bak",
    "/wp-config.php",
    "/configuration.php",
    "/license.txt",
    "/readme.html",
    "/readme.txt",
    "/README.md",
    "/CHANGELOG.md",
    "/CHANGELOG.txt",
    "/INSTALL.md",
    "/install.php",
    "/install/",
    "/setup.php",
    "/setup/",
    "/upgrade.php",
    "/wp-includes/",
    "/vendor/",
    "/node_modules/",
    "/bower_components/",
    "/_vti_pvt/",
    "/_vti_bin/",
    "/_vti_cnf/",
    "/_vti_txt/",
    "/cgi-bin/",
    "/cgi-bin/php",
    "/cgi-bin/sh",
    "/scripts/",
    "/bin/",
    "/temp/",
    "/tmp/",
    "/upload/",
    "/uploads/",
    "/files/",
    "/static/",
    "/public/",
    "/storage/",
    "/cache/",
    "/log/",
    "/var/",
    "/private/",
    "/internal/",
    "/secret/",
    "/secrets/",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directories_nonempty() {
        assert!(COMMON_DIRECTORIES.len() >= 50);
        // 应包含后台类
        assert!(COMMON_DIRECTORIES.contains(&"/admin"));
        assert!(COMMON_DIRECTORIES.contains(&"/wp-admin"));
        assert!(COMMON_DIRECTORIES.contains(&"/phpmyadmin"));
        // 应包含 API 类
        assert!(COMMON_DIRECTORIES.contains(&"/api/v1"));
        assert!(COMMON_DIRECTORIES.contains(&"/swagger"));
        assert!(COMMON_DIRECTORIES.contains(&"/graphql"));
        // 应包含配置/版本控制类
        assert!(COMMON_DIRECTORIES.contains(&"/.git/HEAD"));
        assert!(COMMON_DIRECTORIES.contains(&"/.env"));
        assert!(COMMON_DIRECTORIES.contains(&"/backup.sql"));
    }

    #[test]
    fn test_classify_status() {
        assert_eq!(classify_status(200), DirStatus::Exists);
        assert_eq!(classify_status(204), DirStatus::Exists);
        assert_eq!(classify_status(301), DirStatus::Redirect);
        assert_eq!(classify_status(302), DirStatus::Redirect);
        assert_eq!(classify_status(401), DirStatus::Forbidden);
        assert_eq!(classify_status(403), DirStatus::Forbidden);
        assert_eq!(classify_status(404), DirStatus::NotFound);
        assert_eq!(classify_status(500), DirStatus::ServerError);
        assert_eq!(classify_status(503), DirStatus::ServerError);
        assert_eq!(classify_status(100), DirStatus::Unknown);
    }

    #[test]
    fn test_join_url() {
        assert_eq!(join_url("https://example.com", "/admin"), "https://example.com/admin");
        assert_eq!(join_url("https://example.com/", "/admin"), "https://example.com/admin");
        assert_eq!(join_url("https://example.com/", "admin"), "https://example.com/admin");
    }

    #[test]
    fn test_severity_for_path_git() {
        let scanner = DirBruteScanner::new();
        assert_eq!(scanner.severity_for_path("/.git/HEAD"), Severity::Critical);
        assert_eq!(scanner.severity_for_path("/.git/config"), Severity::Critical);
    }

    #[test]
    fn test_severity_for_path_env() {
        let scanner = DirBruteScanner::new();
        assert_eq!(scanner.severity_for_path("/.env"), Severity::Critical);
        assert_eq!(scanner.severity_for_path("/.env.bak"), Severity::Critical);
        assert_eq!(scanner.severity_for_path("/config.php"), Severity::Critical);
        assert_eq!(scanner.severity_for_path("/backup.sql"), Severity::Critical);
        assert_eq!(scanner.severity_for_path("/backup.zip"), Severity::Critical);
    }

    #[test]
    fn test_severity_for_path_admin() {
        let scanner = DirBruteScanner::new();
        assert_eq!(scanner.severity_for_path("/admin"), Severity::High);
        assert_eq!(scanner.severity_for_path("/phpmyadmin"), Severity::High);
        assert_eq!(scanner.severity_for_path("/manager"), Severity::High);
        assert_eq!(scanner.severity_for_path("/h2-console"), Severity::High);
    }

    #[test]
    fn test_severity_for_path_api_docs() {
        let scanner = DirBruteScanner::new();
        assert_eq!(scanner.severity_for_path("/swagger"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/api-docs"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/graphql"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/debug"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/phpinfo.php"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/server-status"), Severity::Medium);
        assert_eq!(scanner.severity_for_path("/actuator"), Severity::Medium);
    }

    #[test]
    fn test_severity_for_path_low() {
        let scanner = DirBruteScanner::new();
        assert_eq!(scanner.severity_for_path("/robots.txt"), Severity::Low);
        assert_eq!(scanner.severity_for_path("/sitemap.xml"), Severity::Low);
        assert_eq!(scanner.severity_for_path("/unknown-page"), Severity::Low);
    }

    #[test]
    fn test_to_findings_filters_not_found() {
        let scanner = DirBruteScanner::new();
        let entries = vec![
            DirEntry {
                path: "/admin".to_string(),
                status: 200,
                classification: DirStatus::Exists,
                length: 1024,
                server: Some("nginx".to_string()),
            },
            DirEntry {
                path: "/notreal".to_string(),
                status: 404,
                classification: DirStatus::NotFound,
                length: 0,
                server: None,
            },
        ];
        let findings = scanner.to_findings(&entries, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].url, "https://example.com/admin");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].evidence.contains("found"));
    }

    #[test]
    fn test_to_findings_forbidden_low() {
        let scanner = DirBruteScanner::new();
        let entries = vec![DirEntry {
            path: "/admin".to_string(),
            status: 403,
            classification: DirStatus::Forbidden,
            length: 200,
            server: None,
        }];
        let findings = scanner.to_findings(&entries, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].category, VulnCategory::SecurityMisconfig);
    }

    #[test]
    fn test_to_findings_git_critical() {
        let scanner = DirBruteScanner::new();
        let entries = vec![DirEntry {
            path: "/.git/HEAD".to_string(),
            status: 200,
            classification: DirStatus::Exists,
            length: 40,
            server: None,
        }];
        let findings = scanner.to_findings(&entries, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_extract_server() {
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Server".to_string(), "Apache/2.4.49".to_string()),
        ];
        let s = extract_server(&headers);
        assert_eq!(s, Some("Apache/2.4.49".to_string()));

        let empty: Vec<(String, String)> = vec![];
        assert_eq!(extract_server(&empty), None);
    }

    #[test]
    fn test_category_for_path() {
        assert_eq!(category_for_path("/.git/HEAD"), VulnCategory::SecurityMisconfig);
        assert_eq!(category_for_path("/admin"), VulnCategory::BrokenAccessControl);
        assert_eq!(category_for_path("/phpmyadmin"), VulnCategory::BrokenAccessControl);
        assert_eq!(category_for_path("/api"), VulnCategory::SecurityMisconfig);
    }

    #[test]
    fn test_method_with_get() {
        let scanner = DirBruteScanner::new().with_get_method();
        assert!(matches!(scanner.method, Method::Get));
    }

    #[test]
    fn test_no_duplicate_paths() {
        // 简单校验字典无重复
        let mut seen = std::collections::HashSet::new();
        for path in COMMON_DIRECTORIES {
            assert!(seen.insert(*path), "重复路径: {}", path);
        }
    }
}
