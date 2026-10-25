//! G7.3: 数据安全检测
//!
//! 扫描 APK/IPA/HAP 中的敏感数据存储:
//! - DEX 字节码字符串扫描: 硬编码 API Key / JWT / 私钥 / 密码
//! - SharedPreferences XML: 检测明文存储的 token / 密码
//! - SQLite 数据库: 检测存储的密码 / token (scan header + first 4KB page strings)
//!
//! 由于 Rust 无成熟 DEX 字节码反编译库,本模块按以下策略实现:
//! - DEX: 直接对二进制做字节扫描,提取字符串池中匹配敏感模式的串
//!   (Dalvik 字符串池以 MUTF-8 编码、ULEB128 长度前缀存储,连续可打印串仍可被 grep 出)
//! - SharedPreferences: APK 内 `shared_prefs/*.xml` 是标准 XML,直接解析
//! - SQLite: APK 内 `databases/*.db` 是 SQLite 文件,扫描 page 1 中的明文字符串
//!
//! 输入可以是 ZIP (APK/IPA/HAP) 或裸文件字节流。

use std::io::Read;
use thiserror::Error;
use zip::ZipArchive;

use crate::types::MobileFinding;

/// 数据安全扫描错误
#[derive(Debug, Error)]
pub enum DataSecurityError {
    #[error("文件不存在: {0}")]
    FileNotFound(String),
    #[error("打开 ZIP 失败: {0}")]
    ZipOpen(String),
    #[error("读取 ZIP 条目失败: {0}")]
    ZipRead(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// 数据安全扫描结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataSecurityResult {
    /// 检测到的敏感数据存储风险
    pub findings: Vec<MobileFinding>,
    /// 扫描的 DEX 文件路径列表
    pub scanned_dex: Vec<String>,
    /// 扫描的 SharedPreferences 文件路径列表
    pub scanned_shared_prefs: Vec<String>,
    /// 扫描的 SQLite 数据库路径列表
    pub scanned_sqlite: Vec<String>,
}

/// 数据安全扫描器
pub struct DataSecurityScanner {
    /// 单文件最大扫描字节 (避免超大文件耗时)
    pub max_file_bytes: usize,
}

impl Default for DataSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DataSecurityScanner {
    pub fn new() -> Self {
        Self {
            max_file_bytes: 16 * 1024 * 1024, // 16MB
        }
    }

    /// 从文件路径扫描 (ZIP 或裸文件)
    pub fn scan_file(&self, path: &str) -> Result<DataSecurityResult, DataSecurityError> {
        let data = std::fs::read(path).map_err(|_| {
            DataSecurityError::FileNotFound(path.to_string())
        })?;
        self.scan_bytes(&data)
    }

    /// 从字节数据扫描 (ZIP 或裸文件)
    pub fn scan_bytes(&self, data: &[u8]) -> Result<DataSecurityResult, DataSecurityError> {
        // 尝试当作 ZIP 处理;失败则按裸文件扫描
        let cursor = std::io::Cursor::new(data.to_vec());
        match ZipArchive::new(cursor) {
            Ok(mut zip) => self.scan_zip(&mut zip),
            Err(_) => {
                // 裸文件: 按内容类型分发
                let mut findings = Vec::new();
                let mut scanned_dex = Vec::new();
                let mut scanned_prefs = Vec::new();
                let mut scanned_sqlite = Vec::new();

                if is_dex(data) {
                    scanned_dex.push("(inline)".to_string());
                    findings.extend(scan_dex_strings(data, "(inline)"));
                } else if is_sqlite(data) {
                    scanned_sqlite.push("(inline)".to_string());
                    findings.extend(scan_sqlite_strings(data, "(inline)"));
                } else if let Ok(text) = std::str::from_utf8(data) {
                    if text.contains("<?xml") || text.contains("<map") {
                        scanned_prefs.push("(inline)".to_string());
                        findings.extend(scan_shared_prefs_text(text, "(inline)"));
                    }
                }

                Ok(DataSecurityResult {
                    findings,
                    scanned_dex,
                    scanned_shared_prefs: scanned_prefs,
                    scanned_sqlite,
                })
            }
        }
    }

    /// 扫描 ZIP 包 (APK/IPA/HAP 通用)
    pub fn scan_zip<R: Read + std::io::Seek>(
        &self,
        zip: &mut ZipArchive<R>,
    ) -> Result<DataSecurityResult, DataSecurityError> {
        let mut findings = Vec::new();
        let mut scanned_dex = Vec::new();
        let mut scanned_prefs = Vec::new();
        let mut scanned_sqlite = Vec::new();

        let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
        for name in &names {
            // 跳过超大文件
            let entry_size = {
                let e = match zip.by_name(name) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                e.size()
            };
            if entry_size as usize > self.max_file_bytes {
                continue;
            }

            let data = match read_zip_entry(zip, name) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let lower = name.to_lowercase();

            // DEX 文件
            if lower.ends_with(".dex") || is_dex(&data) {
                scanned_dex.push(name.clone());
                findings.extend(scan_dex_strings(&data, name));
            }
            // SharedPreferences XML
            else if lower.contains("shared_prefs") && lower.ends_with(".xml") {
                scanned_prefs.push(name.clone());
                let text = String::from_utf8_lossy(&data);
                findings.extend(scan_shared_prefs_text(&text, name));
            }
            // 旧版 SharedPreferences 也可能位于 /data/data/<pkg>/shared_prefs/, 这里在 APK 中不常见
            else if lower.starts_with("shared_prefs/") && lower.ends_with(".xml") {
                scanned_prefs.push(name.clone());
                let text = String::from_utf8_lossy(&data);
                findings.extend(scan_shared_prefs_text(&text, name));
            }
            // SQLite 数据库
            else if lower.ends_with(".db") || lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") || is_sqlite(&data) {
                scanned_sqlite.push(name.clone());
                findings.extend(scan_sqlite_strings(&data, name));
            }
        }

        Ok(DataSecurityResult {
            findings,
            scanned_dex,
            scanned_shared_prefs: scanned_prefs,
            scanned_sqlite,
        })
    }
}

impl DataSecurityScanner {
    pub fn with_max_file_bytes(mut self, max_bytes: usize) -> Self {
        self.max_file_bytes = max_bytes;
        self
    }
}

// ============================================================================
// ZIP 辅助
// ============================================================================

fn read_zip_entry<R: Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>, DataSecurityError> {
    let mut entry = zip
        .by_name(name)
        .map_err(|e| DataSecurityError::ZipRead(format!("{}: {}", name, e)))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

// ============================================================================
// 文件类型识别
// ============================================================================

/// 判断是否为 DEX 文件 (魔数 "dex\n")
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"dex\n"
}

/// 判断是否为 SQLite 数据库 (魔数 "SQLite format 3\0")
pub fn is_sqlite(data: &[u8]) -> bool {
    data.len() >= 16 && &data[0..16] == b"SQLite format 3\0"
}

// ============================================================================
// DEX 字符串扫描
// ============================================================================

/// 扫描 DEX 二进制中的字符串, 检测硬编码敏感数据
///
/// 实现策略: 由于 Rust 无成熟 DEX 解析库, 直接对原始字节做可打印字符串提取,
/// 再对提取到的字符串做敏感模式匹配。Dalvik MUTF-8 与 UTF-8 对 ASCII 部分兼容,
/// 因此 ASCII 敏感串 (API Key / JWT / 私钥头) 仍可被检出。
pub fn scan_dex_strings(data: &[u8], source: &str) -> Vec<MobileFinding> {
    let strings = crate::ios_scan::extract_printable_strings(data);
    let mut findings = Vec::new();

    // 敏感模式 (regex / ID / 标题 / 严重级别)
    let patterns: &[(&str, &str, &str, &str)] = &[
        (
            r#"(?i)api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?"#,
            "DATA-001",
            "DEX 硬编码 API Key",
            "high",
        ),
        (
            r#"(?i)secret\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?"#,
            "DATA-002",
            "DEX 硬编码 Secret",
            "high",
        ),
        (
            r#"(?i)access[_-]?token\s*[:=]\s*['"]?[A-Za-z0-9_\-\.]{16,}['"]?"#,
            "DATA-003",
            "DEX 硬编码 Access Token",
            "high",
        ),
        (
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "DATA-004",
            "DEX 硬编码 JWT Token",
            "high",
        ),
        (
            r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----",
            "DATA-005",
            "DEX 硬编码私钥",
            "critical",
        ),
        (
            r#"(?i)password\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{6,}['"]?"#,
            "DATA-006",
            "DEX 硬编码密码",
            "high",
        ),
        (
            // AWS Access Key ID (20 字符, AKIA 开头)
            r"AKIA[0-9A-Z]{16}",
            "DATA-007",
            "DEX 硬编码 AWS Access Key ID",
            "critical",
        ),
        (
            // Google API Key (AIza 开头, 39 字符)
            r"AIza[0-9A-Za-z_\-]{35}",
            "DATA-008",
            "DEX 硬编码 Google API Key",
            "critical",
        ),
        (
            // Slack Token (xoxb-/xoxp-)
            r"xox[baprs]-[0-9A-Za-z-]{10,}",
            "DATA-009",
            "DEX 硬编码 Slack Token",
            "critical",
        ),
    ];

    for (pattern, id, title, severity) in patterns {
        let re = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut hits = 0;
        for s in &strings {
            if re.is_match(s) {
                hits += 1;
                if hits <= 3 {
                    findings.push(MobileFinding {
                        id: id.to_string(),
                        title: title.to_string(),
                        severity: severity.to_string(),
                        category: "data-security".to_string(),
                        description: format!("在 {} 中匹配到 {}", source, title),
                        evidence: truncate(s, 128).to_string(),
                        fix_advice: "将密钥/Token/密码移至服务端或系统密钥库,不要硬编码到代码"
                            .to_string(),
                    });
                }
            }
        }
    }

    findings
}

// ============================================================================
// SharedPreferences 扫描
// ============================================================================

/// 扫描 SharedPreferences XML 文本中的明文敏感数据
///
/// SharedPreferences XML 格式:
/// ```xml
/// <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
/// <map>
///     <string name="token">abc123...</string>
///     <string name="password">secret</string>
/// </map>
/// ```
pub fn scan_shared_prefs_text(text: &str, source: &str) -> Vec<MobileFinding> {
    let mut findings = Vec::new();

    // 提取所有 <string name="KEY">VALUE</string>
    let re = match regex::Regex::new(r#"<string name="([^"]+)">([^<]+)</string>"#) {
        Ok(r) => r,
        Err(_) => return findings,
    };

    for cap in re.captures_iter(text) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let value = cap.get(2).map(|m| m.as_str()).unwrap_or("");

        let key_lower = key.to_lowercase();
        let is_sensitive_key = key_lower.contains("password")
            || key_lower.contains("passwd")
            || key_lower.contains("pwd")
            || key_lower.contains("token")
            || key_lower.contains("secret")
            || key_lower.contains("api_key")
            || key_lower.contains("apikey")
            || key_lower.contains("access_key")
            || key_lower.contains("session")
            || key_lower.contains("auth");

        if !is_sensitive_key {
            continue;
        }

        // 跳过空值
        if value.is_empty() {
            continue;
        }

        let (id, title, severity) = if key_lower.contains("password") || key_lower.contains("passwd") || key_lower.contains("pwd") {
            ("DATA-100", "SharedPreferences 明文存储密码", "critical")
        } else if key_lower.contains("token") || key_lower.contains("session") || key_lower.contains("auth") {
            ("DATA-101", "SharedPreferences 明文存储 Token/会话", "high")
        } else if key_lower.contains("api_key") || key_lower.contains("apikey") || key_lower.contains("access_key") {
            ("DATA-102", "SharedPreferences 明文存储 API Key", "critical")
        } else {
            ("DATA-103", "SharedPreferences 明文存储敏感数据", "high")
        };

        findings.push(MobileFinding {
            id: id.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            category: "data-security".to_string(),
            description: format!("在 {} 中 SharedPreferences 键 '{}' 明文存储敏感数据", source, key),
            evidence: format!("key={}, value_length={}", key, value.len()),
            fix_advice: "使用 Android Keystore 加密存储,或迁至服务端;避免明文存储敏感凭证"
                .to_string(),
        });
    }

    findings
}

// ============================================================================
// SQLite 数据库扫描
// ============================================================================

/// 扫描 SQLite 数据库中的明文敏感数据
///
/// 实现策略: 不解析 B-tree 结构, 直接扫描 page 数据中可打印字符串,
/// 匹配包含 password / token / secret 等关键字的记录。
/// SQLite 页面大小默认 4KB,扫描前若干页面通常足以覆盖 schema + 关键记录。
pub fn scan_sqlite_strings(data: &[u8], source: &str) -> Vec<MobileFinding> {
    let mut findings = Vec::new();

    if !is_sqlite(data) {
        return findings;
    }

    // 提取可打印字符串
    let strings = crate::ios_scan::extract_printable_strings(data);

    // 检测包含敏感关键字的字符串
    let sensitive_keywords = [
        "password", "passwd", "pwd", "token", "secret", "api_key", "apikey",
        "access_key", "session", "auth_token", "refresh_token",
    ];

    let mut found_password = false;
    let mut found_token = false;
    let mut found_secret = false;

    for s in &strings {
        let lower = s.to_lowercase();
        for kw in &sensitive_keywords {
            if lower.contains(kw) {
                // 区分类型
                if (kw == &"password" || kw == &"passwd" || kw == &"pwd") && !found_password {
                    found_password = true;
                    findings.push(MobileFinding {
                        id: "DATA-200".to_string(),
                        title: "SQLite 数据库疑似存储密码".to_string(),
                        severity: "critical".to_string(),
                        category: "data-security".to_string(),
                        description: format!(
                            "在 {} 中 SQLite 数据库扫描到包含 '{}' 关键字的字符串",
                            source, kw
                        ),
                        evidence: format!("keyword={}, sample={}", kw, truncate(s, 80)),
                        fix_advice: "对密码做加盐哈希 (Argon2/bcrypt) 后存储,不要明文落库"
                            .to_string(),
                    });
                } else if (kw == &"token" || kw == &"session" || kw == &"auth_token" || kw == &"refresh_token")
                    && !found_token
                {
                    found_token = true;
                    findings.push(MobileFinding {
                        id: "DATA-201".to_string(),
                        title: "SQLite 数据库疑似存储 Token/会话".to_string(),
                        severity: "high".to_string(),
                        category: "data-security".to_string(),
                        description: format!(
                            "在 {} 中 SQLite 数据库扫描到包含 '{}' 关键字的字符串",
                            source, kw
                        ),
                        evidence: format!("keyword={}, sample={}", kw, truncate(s, 80)),
                        fix_advice: "Token 应存储在 Keystore/Keychain 中,数据库中只存不可逆的 token hash"
                            .to_string(),
                    });
                } else if (kw == &"secret" || kw == &"api_key" || kw == &"apikey" || kw == &"access_key")
                    && !found_secret
                {
                    found_secret = true;
                    findings.push(MobileFinding {
                        id: "DATA-202".to_string(),
                        title: "SQLite 数据库疑似存储 API Key / Secret".to_string(),
                        severity: "critical".to_string(),
                        category: "data-security".to_string(),
                        description: format!(
                            "在 {} 中 SQLite 数据库扫描到包含 '{}' 关键字的字符串",
                            source, kw
                        ),
                        evidence: format!("keyword={}, sample={}", kw, truncate(s, 80)),
                        fix_advice: "API Key/Secret 应移至服务端,或加密后存储".to_string(),
                    });
                }
                break; // 一个字符串只命中一次
            }
        }
    }

    findings
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_is_dex_valid() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        assert!(is_dex(&data));
    }

    #[test]
    fn test_is_dex_invalid() {
        assert!(!is_dex(b"not a dex file"));
        assert!(!is_dex(&[]));
        assert!(!is_dex(b"abc"));
    }

    #[test]
    fn test_is_sqlite_valid() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 64]);
        assert!(is_sqlite(&data));
    }

    #[test]
    fn test_is_sqlite_invalid() {
        assert!(!is_sqlite(b"not a database"));
        assert!(!is_sqlite(&[]));
    }

    #[test]
    fn test_scan_dex_strings_api_key() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00api_key=abcdefghijklmnop\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-001"));
    }

    #[test]
    fn test_scan_dex_strings_jwt() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(
            b"\x00eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y\x00"
                ,);
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-004"));
    }

    #[test]
    fn test_scan_dex_strings_private_key() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-005" && f.severity == "critical"));
    }

    #[test]
    fn test_scan_dex_strings_aws_key() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        // AKIA + 16 字符 = 21 总
        data.extend_from_slice(b"\x00AKIAABCDEFGHIJKLMNOP\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-007"));
    }

    #[test]
    fn test_scan_dex_strings_google_api_key() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        // AIza + 35 字符 = 39 总
        data.extend_from_slice(b"\x00AIzaSyAabcdefghijklmnopqrstuvwxyz0123456789\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-008"));
    }

    #[test]
    fn test_scan_dex_strings_slack_token() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00xoxb-1234567890-abcdefghijklmnopqrstuvwxyz\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.iter().any(|f| f.id == "DATA-009"));
    }

    #[test]
    fn test_scan_dex_strings_no_false_positive() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00https://example.com/path\x00normal log line\x00");
        let findings = scan_dex_strings(&data, "classes.dex");
        assert!(findings.is_empty(), "普通字符串不应触发告警");
    }

    #[test]
    fn test_scan_shared_prefs_password() {
        let xml = r#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">secret123</string>
    <string name="username">alice</string>
</map>"#;
        let findings = scan_shared_prefs_text(xml, "shared_prefs/config.xml");
        assert!(findings.iter().any(|f| f.id == "DATA-100" && f.severity == "critical"));
        // username 不应触发
        assert!(!findings.iter().any(|f| f.evidence.contains("username")));
    }

    #[test]
    fn test_scan_shared_prefs_token() {
        let xml = r#"<map><string name="auth_token">eyJhbGciOiJIUzI1NiJ9.xxx.yyy</string></map>"#;
        let findings = scan_shared_prefs_text(xml, "shared_prefs/session.xml");
        assert!(findings.iter().any(|f| f.id == "DATA-101"));
    }

    #[test]
    fn test_scan_shared_prefs_api_key() {
        let xml = r#"<map><string name="api_key">abcdefghijklmnopqrstuvwxyz</string></map>"#;
        let findings = scan_shared_prefs_text(xml, "shared_prefs/config.xml");
        assert!(findings.iter().any(|f| f.id == "DATA-102"));
    }

    #[test]
    fn test_scan_shared_prefs_empty_value_skipped() {
        let xml = r#"<map><string name="password"></string></map>"#;
        let findings = scan_shared_prefs_text(xml, "shared_prefs/config.xml");
        assert!(findings.is_empty(), "空值不应触发告警");
    }

    #[test]
    fn test_scan_shared_prefs_non_sensitive_skipped() {
        let xml = r#"<map><string name="theme">dark</string><string name="language">en</string></map>"#;
        let findings = scan_shared_prefs_text(xml, "shared_prefs/config.xml");
        assert!(findings.is_empty(), "非敏感键不应触发告警");
    }

    #[test]
    fn test_scan_sqlite_strings_password() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(b"\x00user_password_hash_should_be_here\x00");
        let findings = scan_sqlite_strings(&data, "databases/users.db");
        assert!(findings.iter().any(|f| f.id == "DATA-200" && f.severity == "critical"));
    }

    #[test]
    fn test_scan_sqlite_strings_token() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(b"\x00auth_token_value_here\x00");
        let findings = scan_sqlite_strings(&data, "databases/session.db");
        assert!(findings.iter().any(|f| f.id == "DATA-201"));
    }

    #[test]
    fn test_scan_sqlite_strings_api_key() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(b"\x00api_key_value_here\x00");
        let findings = scan_sqlite_strings(&data, "databases/config.db");
        assert!(findings.iter().any(|f| f.id == "DATA-202"));
    }

    #[test]
    fn test_scan_sqlite_strings_no_match() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(b"\x00normal user name\x00alice\x00bob\x00");
        let findings = scan_sqlite_strings(&data, "databases/users.db");
        assert!(findings.is_empty(), "无敏感关键字不应触发告警");
    }

    #[test]
    fn test_scan_sqlite_strings_not_sqlite() {
        // 非 SQLite 数据应返回空
        let findings = scan_sqlite_strings(b"not a database", "test.db");
        assert!(findings.is_empty());
    }

    /// 端到端测试: 构造包含 DEX / SharedPreferences / SQLite 的 ZIP 包
    #[test]
    fn test_scan_zip_full_apk() {
        let zip_bytes = build_test_zip();
        let cursor = std::io::Cursor::new(zip_bytes);
        let mut zip = ZipArchive::new(cursor).expect("ZIP 应可读取");
        let scanner = DataSecurityScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");

        // 应扫描到三类文件
        assert!(!result.scanned_dex.is_empty(), "应扫描到 DEX 文件");
        assert!(!result.scanned_shared_prefs.is_empty(), "应扫描到 SharedPreferences");
        assert!(!result.scanned_sqlite.is_empty(), "应扫描到 SQLite");

        // 应检测到至少一个 DEX 硬编码密钥
        assert!(result.findings.iter().any(|f| f.id.starts_with("DATA-0")));
        // 应检测到 SharedPreferences 密码明文
        assert!(result.findings.iter().any(|f| f.id == "DATA-100"));
        // 应检测到 SQLite 敏感数据
        assert!(result.findings.iter().any(|f| f.id.starts_with("DATA-2")));
    }

    /// 端到端测试: 裸 DEX 文件扫描
    #[test]
    fn test_scan_bytes_inline_dex() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00api_key=abcdefghijklmnop\x00");
        let scanner = DataSecurityScanner::new();
        let result = scanner.scan_bytes(&data).expect("扫描应成功");
        assert!(result.scanned_dex.iter().any(|s| s == "(inline)"));
        assert!(result.findings.iter().any(|f| f.id == "DATA-001"));
    }

    /// 端到端测试: 裸 SQLite 文件扫描
    #[test]
    fn test_scan_bytes_inline_sqlite() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(b"\x00user_password_here\x00");
        let scanner = DataSecurityScanner::new();
        let result = scanner.scan_bytes(&data).expect("扫描应成功");
        assert!(result.scanned_sqlite.iter().any(|s| s == "(inline)"));
        assert!(result.findings.iter().any(|f| f.id == "DATA-200"));
    }

    /// 端到端测试: 非法 ZIP 字节流 (走裸文件路径)
    #[test]
    fn test_scan_bytes_invalid_zip_inline() {
        let scanner = DataSecurityScanner::new();
        let result = scanner.scan_bytes(b"plain text data").expect("应不报错");
        assert!(result.findings.is_empty());
        assert!(result.scanned_dex.is_empty());
    }

    #[test]
    fn test_scan_file_not_found() {
        let scanner = DataSecurityScanner::new();
        let result = scanner.scan_file("/nonexistent/path.apk");
        assert!(matches!(result, Err(DataSecurityError::FileNotFound(_))));
    }

    #[test]
    fn test_with_max_file_bytes() {
        let scanner = DataSecurityScanner::new().with_max_file_bytes(100);
        assert_eq!(scanner.max_file_bytes, 100);
    }

    /// 构造测试用 ZIP 包 (包含 DEX + SharedPreferences + SQLite)
    fn build_test_zip() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();

            // classes.dex (伪造 DEX 头 + 硬编码 API Key)
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex = vec![0u8; 120];
            dex[0..4].copy_from_slice(b"dex\n");
            dex[4..7].copy_from_slice(b"039");
            dex.extend_from_slice(b"\x00api_key=abcdefghijklmnop\x00");
            zip.write_all(&dex).unwrap();

            // shared_prefs/config.xml (明文密码)
            zip.start_file("shared_prefs/config.xml", opts).unwrap();
            let xml = r#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">secret123</string>
    <string name="username">alice</string>
</map>"#;
            zip.write_all(xml.as_bytes()).unwrap();

            // databases/users.db (伪造 SQLite + password 字符串)
            zip.start_file("databases/users.db", opts).unwrap();
            let mut db = b"SQLite format 3\0".to_vec();
            db.extend_from_slice(&[0u8; 32]);
            db.extend_from_slice(b"\x00user_password_here\x00");
            zip.write_all(&db).unwrap();

            zip.finish().unwrap();
        }
        buf
    }
}
