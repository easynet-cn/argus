//! G7.1: iOS 应用 (IPA) 安全扫描
//!
//! IPA 是 ZIP 格式，目录结构:
//! - `Payload/APPNAME.app/Info.plist`         应用元数据 (bundle ID / 版本 / 权限)
//! - `Payload/APPNAME.app/embedded.mobileprovision`  Provisioning Profile
//! - `Payload/APPNAME.app/APPNAME`            Mach-O 主二进制
//! - `Payload/APPNAME.app/Frameworks/*.dylib` 动态库
//!
//! 本模块负责:
//! 1. 解析 IPA ZIP 包结构
//! 2. 解析 Info.plist (XML plist 优先；binary plist 仅识别 magic 并跳过)
//! 3. 提取 embedded.mobileprovision 中的 Profile plist
//! 4. 用 goblin 解析 Mach-O 主二进制的库依赖
//! 5. 检测硬编码密钥、不安全 API、缺失 ATS 等风险

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use thiserror::Error;
use zip::ZipArchive;

use crate::types::MobileFinding;

/// iOS 扫描错误
#[derive(Debug, Error)]
pub enum IosScanError {
    #[error("文件不存在: {0}")]
    FileNotFound(String),
    #[error("打开 IPA (ZIP) 失败: {0}")]
    ZipOpen(String),
    #[error("读取 ZIP 条目失败: {0}")]
    ZipRead(String),
    #[error("Info.plist 缺失")]
    InfoPlistMissing,
    #[error("Info.plist 解析失败: {0}")]
    InfoPlistParse(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// IPA 应用元数据（来自 Info.plist）
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IpaInfo {
    /// Bundle Identifier (CFBundleIdentifier)
    pub bundle_id: String,
    /// 应用显示名 (CFBundleDisplayName)
    pub display_name: String,
    /// 可执行文件名 (CFBundleExecutable)
    pub executable: String,
    /// Bundle 短版本号 (CFBundleShortVersionString)
    pub short_version: String,
    /// Bundle 版本号 (CFBundleVersion)
    pub bundle_version: String,
    /// 最低 iOS 版本 (MinimumOSVersion)
    pub min_os_version: String,
    /// 支持的设备 (UIDeviceFamily 转字符串)
    pub device_family: String,
    /// 文件大小 (bytes)
    pub file_size: u64,
    /// Info.plist 中所有 key/value（用于扩展检测）
    pub raw_plist: HashMap<String, String>,
    /// 申请的权限 Usage Description 键 (NS*UsageDescription)
    pub permission_usages: Vec<String>,
    /// 是否开启 App Transport Security (NSAppTransportSecurity.NSAllowsArbitraryLoads)
    pub allows_arbitrary_loads: bool,
    /// Provisioning Profile 信息
    pub provisioning_profile: Option<ProvisioningProfile>,
    /// Mach-O 主二进制的动态库依赖
    pub libraries: Vec<String>,
}

/// Provisioning Profile 关键字段
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProvisioningProfile {
    /// AppIDName
    pub app_id_name: String,
    /// TeamName
    pub team_name: String,
    /// 创建时间
    pub creation_date: String,
    /// 过期时间
    pub expiration_date: String,
    /// 是否过期
    pub is_expired: bool,
    /// entitlements 中的 com.apple.developer.associated-domains
    pub associated_domains: Vec<String>,
}

/// iOS 扫描结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IosScanResult {
    /// 解析得到的 IPA 元数据
    pub info: IpaInfo,
    /// 安全发现列表
    pub findings: Vec<MobileFinding>,
}

/// iOS 应用扫描器
pub struct IosScanner;

impl IosScanner {
    pub fn new() -> Self {
        Self
    }

    /// 从文件路径扫描 IPA
    pub fn scan_file(&self, path: &str) -> Result<IosScanResult, IosScanError> {
        if !Path::new(path).exists() {
            return Err(IosScanError::FileNotFound(path.to_string()));
        }
        let data = std::fs::read(path)?;
        self.scan_bytes(&data)
    }

    /// 从字节数据扫描 IPA
    pub fn scan_bytes(&self, data: &[u8]) -> Result<IosScanResult, IosScanError> {
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut zip =
            ZipArchive::new(cursor).map_err(|e| IosScanError::ZipOpen(e.to_string()))?;

        let mut info = IpaInfo {
            file_size: data.len() as u64,
            ..IpaInfo::default()
        };

        // 1. 定位 .app 目录前缀
        let app_dir = find_app_dir(&mut zip).ok_or(IosScanError::InfoPlistMissing)?;

        // 2. 解析 Info.plist
        let plist_path = format!("{}/Info.plist", app_dir);
        let plist_data = read_zip_entry(&mut zip, &plist_path)?;
        let parsed = parse_info_plist(&plist_data)?;
        info.bundle_id = parsed.get("CFBundleIdentifier").cloned().unwrap_or_default();
        info.display_name = parsed
            .get("CFBundleDisplayName")
            .or_else(|| parsed.get("CFBundleName"))
            .cloned()
            .unwrap_or_default();
        info.executable = parsed.get("CFBundleExecutable").cloned().unwrap_or_default();
        info.short_version = parsed
            .get("CFBundleShortVersionString")
            .cloned()
            .unwrap_or_default();
        info.bundle_version = parsed.get("CFBundleVersion").cloned().unwrap_or_default();
        info.min_os_version = parsed.get("MinimumOSVersion").cloned().unwrap_or_default();
        info.device_family = parsed.get("UIDeviceFamily").cloned().unwrap_or_default();

        // 权限 Usage Description 键
        info.permission_usages = parsed
            .keys()
            .filter(|k| k.starts_with("NS") && k.ends_with("UsageDescription"))
            .cloned()
            .collect();

        // ATS 检测
        if let Some(ats) = parsed.get("NSAppTransportSecurity") {
            info.allows_arbitrary_loads =
                ats.contains("NSAllowsArbitraryLoads") && ats.contains("true");
        }

        info.raw_plist = parsed;

        // 3. 解析 embedded.mobileprovision（CMS 包装的 plist）
        let profile_path = format!("{}/embedded.mobileprovision", app_dir);
        if let Ok(prov_data) = read_zip_entry(&mut zip, &profile_path) {
            info.provisioning_profile = parse_provisioning_profile(&prov_data);
        }

        // 4. 解析 Mach-O 主二进制
        if !info.executable.is_empty() {
            let exec_path = format!("{}/{}", app_dir, info.executable);
            if let Ok(exec_data) = read_zip_entry(&mut zip, &exec_path) {
                info.libraries = parse_macho_libraries(&exec_data);
                // 同时扫描字符串用于硬编码密钥检测
                let strings = extract_printable_strings(&exec_data);
                let findings_exec = scan_executable_strings(&strings, &info.bundle_id);
                let mut findings = self.build_findings(&info);
                findings.extend(findings_exec);
                return Ok(IosScanResult { info, findings });
            }
        }

        let findings = self.build_findings(&info);
        Ok(IosScanResult { info, findings })
    }

    /// 基于 IPA 元数据生成检测发现
    fn build_findings(&self, info: &IpaInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();

        // ATS 缺失 / 显式允许明文流量
        if info.allows_arbitrary_loads {
            findings.push(MobileFinding {
                id: "IOS-001".to_string(),
                title: "App Transport Security 允许任意明文加载".to_string(),
                severity: "high".to_string(),
                category: "ios-config".to_string(),
                description: "Info.plist 中 NSAppTransportSecurity.NSAllowsArbitraryLoads=true，"
                    .to_string()
                    + "应用可发起未加密 HTTP 请求，存在中间人窃听风险",
                evidence: "NSAllowsArbitraryLoads=true".to_string(),
                fix_advice: "将 NSAllowsArbitraryLoads 设为 false，仅对必要域名配置 NSExceptionDomains"
                    .to_string(),
            });
        }

        // Provisioning Profile 过期
        if let Some(p) = &info.provisioning_profile {
            if p.is_expired {
                findings.push(MobileFinding {
                    id: "IOS-002".to_string(),
                    title: "Provisioning Profile 已过期".to_string(),
                    severity: "medium".to_string(),
                    category: "ios-config".to_string(),
                    description: format!(
                        "embedded.mobileprovision 已于 {} 过期",
                        p.expiration_date
                    ),
                    evidence: format!("expiration_date={}", p.expiration_date),
                    fix_advice: "在 Apple Developer 后台重新生成并打包 IPA".to_string(),
                });
            }
        }

        // 最低 iOS 版本过低
        if let Ok(min_ver) = info.min_os_version.parse::<f32>() {
            if min_ver > 0.0 && min_ver < 13.0 {
                findings.push(MobileFinding {
                    id: "IOS-003".to_string(),
                    title: "最低 iOS 版本过低 (MinimumOSVersion < 13.0)".to_string(),
                    severity: "low".to_string(),
                    category: "ios-config".to_string(),
                    description: format!(
                        "应用声明最低支持 iOS {},可能使用已废弃/不安全 API",
                        info.min_os_version
                    ),
                    evidence: format!("MinimumOSVersion={}", info.min_os_version),
                    fix_advice: "提升 MinimumOSVersion 至 13.0 或更高版本".to_string(),
                });
            }
        }

        // 不安全的动态库依赖（私有 API 标识）
        for lib in &info.libraries {
            let lower = lib.to_lowercase();
            if lower.contains("/private/") || lower.contains("swift/") && lower.contains("obsolete") {
                findings.push(MobileFinding {
                    id: "IOS-004".to_string(),
                    title: "Mach-O 引用可疑/私有动态库".to_string(),
                    severity: "medium".to_string(),
                    category: "ios-binary".to_string(),
                    description: format!("主二进制依赖动态库: {}", lib),
                    evidence: format!("LC_LOAD_DYLIB: {}", lib),
                    fix_advice: "移除对私有/已废弃框架的依赖,仅使用公共 API".to_string(),
                });
            }
        }

        findings
    }
}

impl Default for IosScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ZIP 辅助
// ============================================================================

/// 读取 ZIP 条目数据
fn read_zip_entry<R: Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>, IosScanError> {
    let mut entry = zip
        .by_name(name)
        .map_err(|e| IosScanError::ZipRead(format!("{}: {}", name, e)))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

/// 定位 IPA 中 `Payload/APPNAME.app` 目录前缀
fn find_app_dir<R: Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
) -> Option<String> {
    for name in zip.file_names() {
        // 形如 Payload/MyApp.app/Info.plist
        if let Some(idx) = name.find("Payload/") {
            let rest = &name[idx + "Payload/".len()..];
            if let Some(end) = rest.find('/') {
                let app_name = &rest[..end];
                if app_name.ends_with(".app") {
                    return Some(format!("Payload/{}", app_name));
                }
            }
        }
    }
    None
}

// ============================================================================
// Info.plist 解析（XML plist 优先；binary plist 仅识别 magic 并跳过）
// ============================================================================

/// 解析 Info.plist，返回扁平化 key→value 字符串字典
///
/// 当前实现:
/// - XML plist: 通过简单的标签匹配解析顶层 <dict> 的 key/value 对
/// - Binary plist (bplist): 检测 magic 后跳过 (TODO: 接入 bplist 解析库)
pub fn parse_info_plist(data: &[u8]) -> Result<HashMap<String, String>, IosScanError> {
    // binary plist magic: "bplist00"
    if data.len() >= 8 && &data[..8] == b"bplist00" {
        // TODO: 接入 binary plist 解析库 (如 plist crate)，当前跳过
        tracing::warn!("Info.plist 为 binary plist 格式，当前暂未支持，跳过解析");
        return Ok(HashMap::new());
    }

    // XML plist
    let text = String::from_utf8_lossy(data);
    parse_xml_plist(&text).map_err(IosScanError::InfoPlistParse)
}

/// 解析 XML plist 顶层 <dict>，扁平化为 key→value 字符串
///
/// 支持的基本类型: <string>, <integer>, <real>, <true/>, <false/>, <date>
/// 嵌套 <dict>/<array> 会序列化为 JSON 字符串占位
fn parse_xml_plist(text: &str) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();

    // 定位顶层 <dict>...</dict>, 使用深度跟踪避免误匹配嵌套闭合标签
    let dict_open = text
        .find("<dict>")
        .or_else(|| text.find("<dict "))
        .ok_or("未找到顶层 <dict>")?;
    let body_start = text[dict_open..]
        .find('>')
        .ok_or("无效 <dict> 标签")?
        + dict_open
        + 1;
    let body_end = find_matching_close_tag(text, body_start, "dict")
        .ok_or("未找到顶层 </dict>")?;
    let body = &text[body_start..body_end];

    // 简单状态机: 遇到 <key>NAME</key> 后,下一个非空元素即为其值
    let mut current_key: Option<String> = None;
    let mut pos = 0;
    while pos < body.len() {
        let lt = match body[pos..].find('<') {
            Some(i) => i,
            None => break,
        };
        let abs = pos + lt;
        let gt = match body[abs..].find('>') {
            Some(i) => i,
            None => break,
        };
        let tag_end = abs + gt;
        let tag_content = &body[abs + 1..tag_end]; // 不含尖括号
        let is_self_closing = tag_content.ends_with('/');
        let tag_name = tag_content.split_whitespace().next().unwrap_or("");
        let after = tag_end + 1;

        if tag_name == "key" {
            // <key>VALUE</key>
            if let Some(close) = body[after..].find("</key>") {
                let value = &body[after..after + close];
                current_key = Some(decode_xml_entities(value).trim().to_string());
                pos = after + close + "</key>".len();
                continue;
            } else {
                break;
            }
        } else if tag_name == "dict" || tag_name == "array" {
            // 嵌套结构: 使用深度跟踪找到匹配的闭合标签
            let close_pos = match find_matching_close_tag(body, after, tag_name) {
                Some(p) => p,
                None => break,
            };
            let close_tag_len = format!("</{}>", tag_name).len();
            let nested = &body[after..close_pos];
            if let Some(k) = current_key.take() {
                let flattened = flatten_nested(nested, tag_name);
                map.insert(k, flattened);
            }
            pos = close_pos + close_tag_len;
            continue;
        } else if is_self_closing {
            // <true/> <false/> 等
            if let Some(k) = current_key.take() {
                let v = match tag_name {
                    "true" => "true".to_string(),
                    "false" => "false".to_string(),
                    _ => "".to_string(),
                };
                map.insert(k, v);
            }
            pos = after;
            continue;
        } else {
            // 普通值: <string>VALUE</string>
            let close_tag = format!("</{}>", tag_name);
            if let Some(close) = body[after..].find(&close_tag) {
                let value = &body[after..after + close];
                if let Some(k) = current_key.take() {
                    map.insert(k, decode_xml_entities(value).trim().to_string());
                }
                pos = after + close + close_tag.len();
                continue;
            } else {
                break;
            }
        }
    }

    Ok(map)
}

/// 从 start 位置开始,查找与当前打开的 `tag_name` 匹配的闭合标签位置
///
/// 使用深度跟踪,正确处理同名标签的嵌套 (如 dict 内嵌 dict)
fn find_matching_close_tag(body: &str, start: usize, tag_name: &str) -> Option<usize> {
    let open_tag_prefix = format!("<{}", tag_name);
    let close_tag = format!("</{}>", tag_name);
    let mut depth: usize = 1;
    let mut pos = start;
    while pos < body.len() {
        // 寻找下一个开/闭标签
        let next_open = body[pos..]
            .find(&open_tag_prefix)
            .map(|i| i + pos);
        let next_close = body[pos..].find(&close_tag).map(|i| i + pos);
        match (next_open, next_close) {
            (Some(no), Some(nc)) if no < nc => {
                // 先遇到开标签, 深度+1, 跳过该开标签
                // 注意: 开标签后面可能是空白字符或 '>', 都需跳过 <tag 的前缀
                depth += 1;
                pos = no + open_tag_prefix.len();
            }
            (_, Some(nc)) => {
                // 先遇到闭标签, 深度-1
                depth -= 1;
                if depth == 0 {
                    return Some(nc);
                }
                pos = nc + close_tag.len();
            }
            // 仅剩 (None, None) 与 (Some, None) 两种情况:
            // 都意味着已无闭标签可匹配, 返回 None
            _ => return None,
        }
    }
    None
}

/// 将嵌套 <dict>/<array> 内容扁平化为简易字符串
///
/// - dict: 输出 "key1=value1,key2=value2" 形式, 便于上层通过 `contains` 检测特定键
/// - array: 输出 "[v1,v2,v3]" 形式
fn flatten_nested(content: &str, kind: &str) -> String {
    if kind == "dict" {
        // 对 dict, 提取 <key>NAME</key> 紧跟的下一个值, 拼成 "key=value"
        let mut pairs = Vec::new();
        let mut pos = 0;
        while let Some(k_open) = content[pos..].find("<key>") {
            let abs = pos + k_open + "<key>".len();
            let k_close = match content[abs..].find("</key>") {
                Some(c) => c,
                None => break,
            };
            let key = decode_xml_entities(&content[abs..abs + k_close]).trim().to_string();
            let after_key = abs + k_close + "</key>".len();

            // 查找下一个元素 (跳过空白)
            let next_lt = match content[after_key..].find('<') {
                Some(p) => after_key + p,
                None => break,
            };
            let next_gt = match content[next_lt..].find('>') {
                Some(p) => next_lt + p,
                None => break,
            };
            let tag_content = &content[next_lt + 1..next_gt];
            // 标签名取首个以空白或 '/' 分隔的 token (兼容 <true/> <false/> 自闭合)
            let tag_name = tag_content
                .split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            let after_tag = next_gt + 1;

            let value = if tag_content.ends_with('/') {
                // 自闭合: <true/> <false/>
                match tag_name {
                    "true" => "true".to_string(),
                    "false" => "false".to_string(),
                    _ => String::new(),
                }
            } else if tag_name == "dict" || tag_name == "array" {
                // 嵌套结构: 递归扁平化
                let close_pos = match find_matching_close_tag(content, after_tag, tag_name) {
                    Some(p) => p,
                    None => break,
                };
                let nested = &content[after_tag..close_pos];
                flatten_nested(nested, tag_name)
            } else {
                // <string>VALUE</string> 等普通值
                let close_tag = format!("</{}>", tag_name);
                match content[after_tag..].find(&close_tag) {
                    Some(c) => decode_xml_entities(&content[after_tag..after_tag + c])
                        .trim()
                        .to_string(),
                    None => String::new(),
                }
            };
            pairs.push(format!("{}={}", key, value));
            // 推进 pos 到当前值之后
            pos = after_tag;
            if !tag_content.ends_with('/') && tag_name != "dict" && tag_name != "array" {
                let close_tag = format!("</{}>", tag_name);
                if let Some(c) = content[after_tag..].find(&close_tag) {
                    pos = after_tag + c + close_tag.len();
                }
            } else if tag_name == "dict" || tag_name == "array" {
                let close_tag = format!("</{}>", tag_name);
                if let Some(c) = content[after_tag..].find(&close_tag) {
                    pos = after_tag + c + close_tag.len();
                }
            }
        }
        return pairs.join(",");
    }

    // array: 提取所有 <string>...</string> 与 <true/> <false/>
    let mut items = Vec::new();
    let mut pos = 0;
    while let Some(s) = content[pos..].find("<string>") {
        let abs = pos + s + "<string>".len();
        if let Some(e) = content[abs..].find("</string>") {
            items.push(decode_xml_entities(&content[abs..abs + e]).trim().to_string());
            pos = abs + e + "</string>".len();
        } else {
            break;
        }
    }
    // 同时提取 <true/> <false/>
    let mut pos = 0;
    while let Some(s) = content[pos..].find('<') {
        let abs = pos + s;
        if let Some(e) = content[abs..].find('>') {
            let tag = &content[abs + 1..abs + e];
            if tag == "true" || tag == "false" {
                items.push(tag.to_string());
            }
            pos = abs + e + 1;
        } else {
            break;
        }
    }
    format!("[{}]", items.join(","))
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

// ============================================================================
// embedded.mobileprovision 解析
// ============================================================================

/// 从 embedded.mobileprovision (CMS 包装) 中提取 plist 文本并解析关键字段
pub fn parse_provisioning_profile(data: &[u8]) -> Option<ProvisioningProfile> {
    let text = String::from_utf8_lossy(data);
    // mobileprovision 文件结构: binary CMS 头 + "<plist" ... "</plist>" + binary 尾部
    let plist_start = text.find("<plist")?;
    let plist_end = text.find("</plist>")?;
    let plist_xml = &text[plist_start..plist_end + "</plist>".len()];

    let map = parse_xml_plist(plist_xml).ok()?;
    let mut profile = ProvisioningProfile {
        app_id_name: map.get("AppIDName").cloned().unwrap_or_default(),
        team_name: map.get("TeamName").cloned().unwrap_or_default(),
        creation_date: map.get("CreationDate").cloned().unwrap_or_default(),
        expiration_date: map.get("ExpirationDate").cloned().unwrap_or_default(),
        is_expired: false,
        associated_domains: Vec::new(),
    };

    // 过期检测: 简化判断 - 比较 ExpirationDate 与当前时间
    if !profile.expiration_date.is_empty() {
        profile.is_expired = is_date_expired(&profile.expiration_date);
    }

    // entitlements 中的 com.apple.developer.associated-domains
    // flatten_nested 后 Entitlements 形如 "key1=val1,key2=[a,b,c]"
    // 需从中提取 associated-domains=[...] 内的列表
    if let Some(ent) = map.get("Entitlements") {
        let needle = "com.apple.developer.associated-domains=[";
        if let Some(start) = ent.find(needle) {
            let arr_start = start + needle.len();
            if let Some(end) = ent[arr_start..].find(']') {
                let arr_content = &ent[arr_start..arr_start + end];
                if !arr_content.is_empty() {
                    profile.associated_domains = arr_content
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
    }

    Some(profile)
}

/// 简化的 ISO 时间比较: 判断给定时间是否早于当前
fn is_date_expired(date_str: &str) -> bool {
    // 形如 "2023-09-23T10:00:00Z"
    if date_str.len() < 10 {
        return false;
    }
    let now = chrono::Utc::now();
    // 解析 "YYYY-MM-DD" 前缀
    let y = date_str[0..4].parse::<i32>().unwrap_or(0);
    let m = date_str[5..7].parse::<u32>().unwrap_or(0);
    let d = date_str[8..10].parse::<u32>().unwrap_or(0);
    if y == 0 || m == 0 || d == 0 {
        return false;
    }
    let expired = chrono::NaiveDate::from_ymd_opt(y, m, d)
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map(|dt| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc))
        .map(|dt| dt < now)
        .unwrap_or(false);
    expired
}

// ============================================================================
// Mach-O 解析 (goblin)
// ============================================================================

/// 用 goblin 解析 Mach-O 二进制的动态库依赖 (LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB)
///
/// 支持单架构 (thin) 与多架构 (fat / universal) Mach-O 二进制
pub fn parse_macho_libraries(data: &[u8]) -> Vec<String> {
    let mut libs = Vec::new();
    // goblin 支持解析 universal (fat) 二进制
    match goblin::mach::Mach::parse(data) {
        Ok(mach) => match mach {
            goblin::mach::Mach::Binary(bin) => {
                for lib in bin.libs {
                    libs.push(lib.to_string());
                }
            }
            goblin::mach::Mach::Fat(multi_arch) => {
                // 遍历 fat 二进制中的每个架构
                for arch_result in &multi_arch {
                    if let Ok(arch) = arch_result {
                        match arch {
                            goblin::mach::SingleArch::MachO(fat_bin) => {
                                for lib in &fat_bin.libs {
                                    libs.push(lib.to_string());
                                }
                            }
                            // 静态 archive 不包含 LC_LOAD_DYLIB, 跳过
                            goblin::mach::SingleArch::Archive(_) => {}
                        }
                    }
                }
            }
        },
        Err(e) => {
            tracing::debug!("Mach-O 解析失败: {}", e);
        }
    }
    libs
}

// ============================================================================
// 字符串提取与硬编码密钥检测
// ============================================================================

/// 从二进制数据中提取可打印字符串 (长度 >= 6 的连续 ASCII 可打印字符)
pub fn extract_printable_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::with_capacity(32);
    for &b in data {
        if (32..=126).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= 6 {
                if let Ok(s) = std::str::from_utf8(&current) {
                    strings.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        if let Ok(s) = std::str::from_utf8(&current) {
            strings.push(s.to_string());
        }
    }
    strings
}

/// 扫描 Mach-O 字符串, 检测硬编码密钥 / 不安全 API 使用
pub fn scan_executable_strings(strings: &[String], bundle_id: &str) -> Vec<MobileFinding> {
    let mut findings = Vec::new();
    let _ = bundle_id;

    // 常见硬编码密钥模式
    let patterns: &[(&str, &str, &str, &str)] = &[
        // (regex, 漏洞 ID, 标题, 严重级别)
        (
            r#"(?i)api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?"#,
            "IOS-101",
            "硬编码 API Key",
            "high",
        ),
        (
            r#"(?i)secret\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?"#,
            "IOS-102",
            "硬编码 Secret",
            "high",
        ),
        (
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "IOS-103",
            "硬编码 JWT Token",
            "high",
        ),
        (
            r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----",
            "IOS-104",
            "硬编码私钥",
            "critical",
        ),
    ];

    for (pattern, id, title, severity) in patterns {
        let re = match regex::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut hits = 0;
        for s in strings {
            if re.is_match(s) {
                hits += 1;
                if hits <= 3 {
                    findings.push(MobileFinding {
                        id: id.to_string(),
                        title: title.to_string(),
                        severity: severity.to_string(),
                        category: "ios-binary".to_string(),
                        description: format!("在主二进制字符串中匹配到 {}", title),
                        evidence: truncate(s, 128).to_string(),
                        fix_advice: format!("将密钥/Token 移至服务端或 Keychain,不要硬编码到二进制"),
                    });
                }
            }
        }
    }

    // 不安全 API 使用检测 (NSStringFromClass 等反射调用 + 私有 API 标识)
    let insecure_apis: &[(&str, &str, &str)] = &[
        ("_dlsym", "IOS-110", "使用 dlsym 动态符号查找,可能调用私有 API"),
        ("objc_getClass(\"UI", "IOS-111", "通过 objc_getClass 反射访问 UIKit 私有类"),
        ("SSLCertificateChainVerificationDisabled", "IOS-112", "禁用 SSL 证书链验证"),
    ];

    for s in strings {
        for (needle, id, desc) in insecure_apis {
            if s.contains(needle) {
                findings.push(MobileFinding {
                    id: id.to_string(),
                    title: desc.to_string(),
                    severity: "high".to_string(),
                    category: "ios-binary".to_string(),
                    description: format!("{} (匹配字符串: {})", desc, truncate(s, 80)),
                    evidence: truncate(s, 128).to_string(),
                    fix_advice: "避免使用私有/不安全 API,改用公共 API 完成同等功能".to_string(),
                });
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

    /// 构造最小 XML Info.plist 字节
    fn sample_xml_plist() -> Vec<u8> {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.testapp</string>
    <key>CFBundleDisplayName</key>
    <string>TestApp</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.2.3</string>
    <key>CFBundleVersion</key>
    <string>123</string>
    <key>MinimumOSVersion</key>
    <string>12.0</string>
    <key>NSCameraUsageDescription</key>
    <string>Need camera for scanning</string>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>"#;
        xml.as_bytes().to_vec()
    }

    #[test]
    fn test_parse_xml_plist_basic() {
        let data = sample_xml_plist();
        let map = parse_info_plist(&data).expect("XML plist 解析应成功");
        assert_eq!(map.get("CFBundleIdentifier").map(|s| s.as_str()), Some("com.example.testapp"));
        assert_eq!(map.get("CFBundleDisplayName").map(|s| s.as_str()), Some("TestApp"));
        assert_eq!(map.get("CFBundleShortVersionString").map(|s| s.as_str()), Some("1.2.3"));
        assert_eq!(map.get("MinimumOSVersion").map(|s| s.as_str()), Some("12.0"));
        assert!(map.contains_key("NSCameraUsageDescription"));
        // 嵌套 dict 应被扁平化为字符串
        let ats = map.get("NSAppTransportSecurity").expect("ATS 应存在");
        assert!(ats.contains("NSAllowsArbitraryLoads"));
        assert!(ats.contains("true"));
    }

    #[test]
    fn test_parse_info_plist_binary_skipped() {
        // binary plist magic: "bplist00"
        let mut data = b"bplist00".to_vec();
        data.extend_from_slice(&[0u8; 32]);
        let result = parse_info_plist(&data).expect("binary plist 不应报错");
        assert!(result.is_empty(), "binary plist 当前应返回空字典");
    }

    #[test]
    fn test_parse_xml_plist_missing_dict() {
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#;
        let result = parse_xml_plist(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_xml_entities() {
        assert_eq!(decode_xml_entities("a&amp;b"), "a&b");
        assert_eq!(decode_xml_entities("&lt;tag&gt;"), "<tag>");
        assert_eq!(decode_xml_entities("&quot;hi&quot;"), "\"hi\"");
    }

    #[test]
    fn test_is_date_expired_past() {
        // 2020 年已过期
        assert!(is_date_expired("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn test_is_date_expired_future() {
        // 2099 年未过期
        assert!(!is_date_expired("2099-01-01T00:00:00Z"));
    }

    #[test]
    fn test_is_date_expired_invalid() {
        assert!(!is_date_expired("invalid"));
        assert!(!is_date_expired(""));
    }

    #[test]
    fn test_parse_provisioning_profile_extracts_fields() {
        let prov = r#"binary-header-junk
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>com.example.testapp</string>
    <key>TeamName</key>
    <string>Example Inc.</string>
    <key>CreationDate</key>
    <string>2020-01-01T00:00:00Z</string>
    <key>ExpirationDate</key>
    <string>2020-06-01T00:00:00Z</string>
    <key>Entitlements</key>
    <dict>
        <key>com.apple.developer.associated-domains</key>
        <array>
            <string>example.com</string>
            <string>api.example.com</string>
        </array>
    </dict>
</dict>
</plist>
trailing-junk"#;
        let profile = parse_provisioning_profile(prov.as_bytes()).expect("应解析成功");
        assert_eq!(profile.app_id_name, "com.example.testapp");
        assert_eq!(profile.team_name, "Example Inc.");
        assert!(profile.is_expired, "2020 年过期时间应被识别为已过期");
        assert!(profile.associated_domains.contains(&"example.com".to_string()));
        assert!(profile.associated_domains.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn test_parse_provisioning_profile_no_plist() {
        // 无 plist 内容
        assert!(parse_provisioning_profile(b"junk without plist").is_none());
    }

    #[test]
    fn test_parse_macho_libraries_invalid_data() {
        // 空数据 / 非法数据应返回空 Vec,不 panic
        let libs = parse_macho_libraries(&[]);
        assert!(libs.is_empty());
        let libs = parse_macho_libraries(b"not a mach-o binary");
        assert!(libs.is_empty());
    }

    #[test]
    fn test_extract_printable_strings_basic() {
        let data = b"\x00\x01Hello World\x00ABC\x00abcdef\x00";
        let strings = extract_printable_strings(data);
        // "Hello World" (11 chars), "ABC" (3 chars, 过短被过滤), "abcdef" (6 chars)
        assert!(strings.iter().any(|s| s == "Hello World"));
        assert!(!strings.iter().any(|s| s == "ABC"));
        assert!(strings.iter().any(|s| s == "abcdef"));
    }

    #[test]
    fn test_extract_printable_strings_min_length() {
        // 5 字符不输出, 6 字符输出
        let data = b"abcde\x00abcdef\x00";
        let strings = extract_printable_strings(data);
        assert!(!strings.iter().any(|s| s == "abcde"));
        assert!(strings.iter().any(|s| s == "abcdef"));
    }

    #[test]
    fn test_scan_executable_strings_api_key() {
        let strings = vec![
            "api_key=abcdefghijklmnop".to_string(),
            "https://example.com".to_string(),
        ];
        let findings = scan_executable_strings(&strings, "com.example.app");
        assert!(findings.iter().any(|f| f.id == "IOS-101"));
    }

    #[test]
    fn test_scan_executable_strings_jwt() {
        let strings = vec![
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                .to_string(),
        ];
        let findings = scan_executable_strings(&strings, "com.example.app");
        assert!(findings.iter().any(|f| f.id == "IOS-103"));
    }

    #[test]
    fn test_scan_executable_strings_private_key() {
        let strings = vec!["-----BEGIN RSA PRIVATE KEY-----".to_string()];
        let findings = scan_executable_strings(&strings, "com.example.app");
        assert!(findings.iter().any(|f| f.id == "IOS-104" && f.severity == "critical"));
    }

    #[test]
    fn test_scan_executable_strings_insecure_api() {
        let strings = vec!["call _dlsym now".to_string()];
        let findings = scan_executable_strings(&strings, "com.example.app");
        assert!(findings.iter().any(|f| f.id == "IOS-110"));
    }

    #[test]
    fn test_scan_executable_strings_no_false_positive() {
        let strings = vec![
            "https://example.com".to_string(),
            "normal log message".to_string(),
        ];
        let findings = scan_executable_strings(&strings, "com.example.app");
        assert!(findings.is_empty(), "普通字符串不应触发告警");
    }

    #[test]
    fn test_build_findings_ats() {
        let scanner = IosScanner::new();
        let info = IpaInfo {
            allows_arbitrary_loads: true,
            ..IpaInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "IOS-001"));
    }

    #[test]
    fn test_build_findings_expired_profile() {
        let scanner = IosScanner::new();
        let info = IpaInfo {
            provisioning_profile: Some(ProvisioningProfile {
                is_expired: true,
                expiration_date: "2020-01-01T00:00:00Z".to_string(),
                ..ProvisioningProfile::default()
            }),
            ..IpaInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "IOS-002"));
    }

    #[test]
    fn test_build_findings_low_min_os() {
        let scanner = IosScanner::new();
        let info = IpaInfo {
            min_os_version: "10.0".to_string(),
            ..IpaInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "IOS-003"));
    }

    #[test]
    fn test_build_findings_high_min_os_no_alert() {
        let scanner = IosScanner::new();
        let info = IpaInfo {
            min_os_version: "15.0".to_string(),
            ..IpaInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(!findings.iter().any(|f| f.id == "IOS-003"));
    }

    /// 端到端测试: 构造最小合法 IPA ZIP 包扫描
    #[test]
    fn test_scan_bytes_minimal_ipa() {
        let zip_bytes = build_minimal_ipa();
        let scanner = IosScanner::new();
        let result = scanner.scan_bytes(&zip_bytes).expect("扫描应成功");
        assert_eq!(result.info.bundle_id, "com.example.testapp");
        assert_eq!(result.info.display_name, "TestApp");
        assert_eq!(result.info.short_version, "1.2.3");
        // ATS 配置应被检测到
        assert!(result.info.allows_arbitrary_loads);
        // 至少有一个 IOS-001 ATS 告警
        assert!(result.findings.iter().any(|f| f.id == "IOS-001"));
        // 应解析到权限 Usage Description
        assert!(result
            .info
            .permission_usages
            .iter()
            .any(|p| p == "NSCameraUsageDescription"));
    }

    /// 构造最小合法 IPA ZIP 字节流
    fn build_minimal_ipa() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();

            // Payload/TestApp.app/Info.plist
            zip.start_file("Payload/TestApp.app/Info.plist", opts).unwrap();
            zip.write_all(&sample_xml_plist()).unwrap();

            // Payload/TestApp.app/embedded.mobileprovision (最小 plist)
            zip.start_file("Payload/TestApp.app/embedded.mobileprovision", opts).unwrap();
            let prov = r#"binary-header
<plist version="1.0">
<dict>
    <key>AppIDName</key>
    <string>TestAppID</string>
    <key>TeamName</key>
    <string>Example Inc.</string>
    <key>ExpirationDate</key>
    <string>2099-01-01T00:00:00Z</string>
</dict>
</plist>
trailing"#;
            zip.write_all(prov.as_bytes()).unwrap();

            // Payload/TestApp.app/TestApp (主可执行, 这里放一个无效数据, goblin 解析会返回空 libs)
            zip.start_file("Payload/TestApp.app/TestApp", opts).unwrap();
            zip.write_all(b"not a real mach-o binary").unwrap();

            zip.finish().unwrap();
        }
        buf
    }

    #[test]
    fn test_scan_bytes_missing_plist() {
        // 无 Info.plist 的 ZIP 应返回 InfoPlistMissing 错误
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("README.txt", opts).unwrap();
            zip.write_all(b"no plist here").unwrap();
            zip.finish().unwrap();
        }
        let scanner = IosScanner::new();
        let result = scanner.scan_bytes(&buf);
        assert!(matches!(result, Err(IosScanError::InfoPlistMissing)));
    }

    #[test]
    fn test_scan_file_not_found() {
        let scanner = IosScanner::new();
        let result = scanner.scan_file("/nonexistent/path.ipa");
        assert!(matches!(result, Err(IosScanError::FileNotFound(_))));
    }

    #[test]
    fn test_scan_bytes_invalid_zip() {
        let scanner = IosScanner::new();
        let result = scanner.scan_bytes(b"not a zip file");
        assert!(matches!(result, Err(IosScanError::ZipOpen(_))));
    }

    #[test]
    fn test_find_app_dir_extracts_payload() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("Payload/MyApp.app/Info.plist", opts).unwrap();
            zip.write_all(b"<x/>").unwrap();
            zip.start_file("Payload/MyApp.app/MyApp", opts).unwrap();
            zip.write_all(b"binary").unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let app_dir = find_app_dir(&mut zip).expect("应找到 .app 目录");
        assert_eq!(app_dir, "Payload/MyApp.app");
    }
}
