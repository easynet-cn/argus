//! G7.2: HarmonyOS 应用 (HAP) 安全扫描
//!
//! HAP 是 ZIP 格式,核心内容:
//! - `module.json`     新版模块配置 (Stage 模型, API 9+)
//! - `config.json`     旧版模块配置 (FA 模型, API 8-)
//! - `resources/`      资源文件
//! - `libs/`           Native 库
//!
//! 本模块负责:
//! 1. 解析 HAP ZIP 包结构
//! 2. 解析 module.json / config.json,提取应用元数据 / 权限 / Abilities
//! 3. 检测危险权限、不安全配置
//! 4. 在资源/JSON 文件中检测硬编码密钥

use std::io::Read;
use std::path::Path;
use thiserror::Error;
use zip::ZipArchive;

use crate::types::MobileFinding;

/// HarmonyOS 扫描错误
#[derive(Debug, Error)]
pub enum HarmonyScanError {
    #[error("文件不存在: {0}")]
    FileNotFound(String),
    #[error("打开 HAP (ZIP) 失败: {0}")]
    ZipOpen(String),
    #[error("读取 ZIP 条目失败: {0}")]
    ZipRead(String),
    #[error("module.json / config.json 缺失")]
    ManifestMissing,
    #[error("module.json / config.json 解析失败: {0}")]
    ManifestParse(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// HAP 应用元数据
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HapInfo {
    /// 包名 (app.bundleName 或 config.json 的 package)
    pub bundle_name: String,
    /// 应用名 (app.name 或 "app.info.bundleName")
    pub app_name: String,
    /// 厂商 (app.vendor)
    pub vendor: String,
    /// 版本名 (app.versionName)
    pub version_name: String,
    /// 版本号 (app.versionCode)
    pub version_code: i64,
    /// 最低 API 版本 (module.deviceTypes / apiVersion)
    pub min_api_version: i32,
    /// 目标 API 版本
    pub target_api_version: i32,
    /// 模块名 (module.name)
    pub module_name: String,
    /// 模块类型 (entry / feature / shared)
    pub module_type: String,
    /// 设备类型 (default / tablet / tv / ...)
    pub device_types: Vec<String>,
    /// 请求的权限 (module.requestPermissions)
    pub request_permissions: Vec<HapPermission>,
    /// Ability 列表 (Stage 模型: abilities; FA 模型: abilities)
    pub abilities: Vec<HapAbility>,
    /// 文件大小 (bytes)
    pub file_size: u64,
    /// 是否旧版 FA 模型 (config.json)
    pub is_fa_model: bool,
}

/// HarmonyOS 权限请求
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HapPermission {
    /// 权限名 (ohos.permission.*)
    pub name: String,
    /// 使用原因
    pub reason: String,
    /// 使用场景 (inuse / always)
    pub used_scene: String,
}

/// HarmonyOS Ability
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HapAbility {
    /// Ability 名称
    pub name: String,
    /// 类型 (page / service / data)
    pub r#type: String,
    /// 是否导出
    pub visible: bool,
    /// 启动模式
    pub launch_type: Option<String>,
}

/// HAP 扫描结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HarmonyScanResult {
    pub info: HapInfo,
    pub findings: Vec<MobileFinding>,
}

/// HarmonyOS HAP 扫描器
pub struct HarmonyScanner;

impl HarmonyScanner {
    pub fn new() -> Self {
        Self
    }

    /// 从文件路径扫描 HAP
    pub fn scan_file(&self, path: &str) -> Result<HarmonyScanResult, HarmonyScanError> {
        if !Path::new(path).exists() {
            return Err(HarmonyScanError::FileNotFound(path.to_string()));
        }
        let data = std::fs::read(path)?;
        self.scan_bytes(&data)
    }

    /// 从字节数据扫描 HAP
    pub fn scan_bytes(&self, data: &[u8]) -> Result<HarmonyScanResult, HarmonyScanError> {
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut zip =
            ZipArchive::new(cursor).map_err(|e| HarmonyScanError::ZipOpen(e.to_string()))?;

        let mut info = HapInfo {
            file_size: data.len() as u64,
            ..HapInfo::default()
        };

        // 1. 优先解析 module.json (Stage 模型), 否则尝试 config.json (FA 模型)
        let module_json_data = read_zip_entry(&mut zip, "module.json");
        let config_json_data = read_zip_entry(&mut zip, "config.json");

        let (parsed_info, raw_json) = if let Ok(json_bytes) = module_json_data {
            let v = parse_module_json(&json_bytes)?;
            (v, String::from_utf8_lossy(&json_bytes).to_string())
        } else if let Ok(json_bytes) = config_json_data {
            let mut v = parse_config_json(&json_bytes)?;
            v.is_fa_model = true;
            (v, String::from_utf8_lossy(&json_bytes).to_string())
        } else {
            return Err(HarmonyScanError::ManifestMissing);
        };

        info.bundle_name = parsed_info.bundle_name;
        info.app_name = parsed_info.app_name;
        info.vendor = parsed_info.vendor;
        info.version_name = parsed_info.version_name;
        info.version_code = parsed_info.version_code;
        info.min_api_version = parsed_info.min_api_version;
        info.target_api_version = parsed_info.target_api_version;
        info.module_name = parsed_info.module_name;
        info.module_type = parsed_info.module_type;
        info.device_types = parsed_info.device_types;
        info.request_permissions = parsed_info.request_permissions;
        info.abilities = parsed_info.abilities;
        info.is_fa_model = parsed_info.is_fa_model;

        // 2. 检测硬编码密钥 (扫描所有 JSON / 资源文件)
        let mut secret_findings = Vec::new();
        let mut scanned_count = 0u32;
        let max_scan = 200u32; // 限制扫描条目数避免大包耗时
        for i in 0..zip.len() {
            if scanned_count >= max_scan {
                break;
            }
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.name().to_string();
            let size = entry.size() as usize;
            // 仅扫描小文本资源 (json/xml/txt), 跳过二进制
            if size > 1024 * 1024 {
                continue;
            }
            let is_text = name.ends_with(".json")
                || name.ends_with(".xml")
                || name.ends_with(".txt")
                || name.ends_with(".css")
                || name.ends_with(".js")
                || name.ends_with(".ts")
                || name.ends_with(".hap");
            if !is_text {
                continue;
            }
            scanned_count += 1;
            let mut buf = Vec::with_capacity(size);
            if entry.read_to_end(&mut buf).is_err() {
                continue;
            }
            let text = String::from_utf8_lossy(&buf);
            secret_findings.extend(scan_resource_strings(&text, &name));
        }

        // 3. 扫描 module.json / config.json 自身的硬编码密钥
        secret_findings.extend(scan_resource_strings(&raw_json, "module.json"));

        // 4. 基于元数据生成检测发现
        let mut findings = self.build_findings(&info);
        findings.extend(secret_findings);

        Ok(HarmonyScanResult { info, findings })
    }

    /// 基于 HAP 元数据生成检测发现
    fn build_findings(&self, info: &HapInfo) -> Vec<MobileFinding> {
        let mut findings = Vec::new();

        // 危险权限使用
        let dangerous_permissions: &[(&str, &str, &str)] = &[
            (
                "ohos.permission.READ_CONTACTS",
                "HARMONY-001",
                "读取通讯录权限",
            ),
            (
                "ohos.permission.WRITE_CONTACTS",
                "HARMONY-001",
                "写入通讯录权限",
            ),
            (
                "ohos.permission.SEND_MESSAGES",
                "HARMONY-002",
                "发送短信权限",
            ),
            (
                "ohos.permission.READ_MESSAGES",
                "HARMONY-002",
                "读取短信权限",
            ),
            (
                "ohos.permission.RECEIVE_SMS",
                "HARMONY-002",
                "接收短信权限",
            ),
            (
                "ohos.permission.CALL_PHONE",
                "HARMONY-003",
                "拨打电话权限",
            ),
            (
                "ohos.permission.READ_CALL_LOG",
                "HARMONY-003",
                "读取通话记录权限",
            ),
            (
                "ohos.permission.WRITE_CALL_LOG",
                "HARMONY-003",
                "写入通话记录权限",
            ),
            (
                "ohos.permission.LOCATION",
                "HARMONY-004",
                "定位权限",
            ),
            (
                "ohos.permission.LOCATION_IN_BACKGROUND",
                "HARMONY-004",
                "后台定位权限",
            ),
            (
                "ohos.permission.MICROPHONE",
                "HARMONY-005",
                "麦克风权限",
            ),
            (
                "ohos.permission.CAMERA",
                "HARMONY-005",
                "相机权限",
            ),
            (
                "ohos.permission.READ_MEDIA",
                "HARMONY-006",
                "读取媒体文件权限",
            ),
            (
                "ohos.permission.WRITE_MEDIA",
                "HARMONY-006",
                "写入媒体文件权限",
            ),
            (
                "ohos.permission.SYSTEM_FLOAT_WINDOW",
                "HARMONY-007",
                "悬浮窗权限",
            ),
        ];

        let mut reported_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for perm in &info.request_permissions {
            for (needle, id, label) in dangerous_permissions {
                if perm.name == *needle && !reported_ids.contains(id) {
                    reported_ids.insert(id);
                    findings.push(MobileFinding {
                        id: id.to_string(),
                        title: format!("申请 {} 权限", label),
                        severity: "medium".to_string(),
                        category: "harmony-permission".to_string(),
                        description: format!(
                            "应用申请 {} (reason: {})",
                            perm.name,
                            if perm.reason.is_empty() { "(未声明用途)" } else { &perm.reason }
                        ),
                        evidence: format!("requestPermissions: {}", perm.name),
                        fix_advice: "确认是否确需该权限,并在 reason 中说明使用场景;不需要时移除"
                            .to_string(),
                    });
                }
            }

            // 未声明使用原因的权限 (HarmonyOS 规范要求所有权限都需声明 reason)
            if perm.reason.is_empty() {
                findings.push(MobileFinding {
                    id: "HARMONY-100".to_string(),
                    title: format!("权限 {} 未声明使用原因", perm.name),
                    severity: "low".to_string(),
                    category: "harmony-permission".to_string(),
                    description: format!(
                        "requestPermissions 中 {} 缺少 reason 字段",
                        perm.name
                    ),
                    evidence: format!("permission={}, reason=<empty>", perm.name),
                    fix_advice: "为每个权限填写 reason 字段说明使用场景".to_string(),
                });
            }
        }

        // 检测 ability visible=true 但无权限保护
        for ability in &info.abilities {
            if ability.visible && ability.r#type == "service" {
                findings.push(MobileFinding {
                    id: "HARMONY-200".to_string(),
                    title: "Service Ability 可被外部调用 (visible=true)".to_string(),
                    severity: "medium".to_string(),
                    category: "harmony-component".to_string(),
                    description: format!(
                        "Service Ability '{}' 设置 visible=true,可被其他应用拉起",
                        ability.name
                    ),
                    evidence: format!("ability={}, visible=true, type=service", ability.name),
                    fix_advice: "若不需要外部调用,将 visible 设为 false;否则需配合权限校验"
                        .to_string(),
                });
            }
        }

        // FA 模型 (config.json) 通常对应较低 API 版本,提示兼容性风险
        if info.is_fa_model {
            findings.push(MobileFinding {
                id: "HARMONY-300".to_string(),
                title: "使用旧版 FA 模型 (config.json)".to_string(),
                severity: "low".to_string(),
                category: "harmony-config".to_string(),
                description: "HAP 使用 config.json (FA 模型),HarmonyOS 推荐 Stage 模型 (module.json)"
                    .to_string(),
                evidence: "manifest=config.json".to_string(),
                fix_advice: "迁移到 Stage 模型 (module.json) 以使用最新 API 与安全特性".to_string(),
            });
        }

        findings
    }
}

impl Default for HarmonyScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ZIP 辅助
// ============================================================================

fn read_zip_entry<R: Read + std::io::Seek>(
    zip: &mut ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>, HarmonyScanError> {
    let mut entry = zip
        .by_name(name)
        .map_err(|e| HarmonyScanError::ZipRead(format!("{}: {}", name, e)))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

// ============================================================================
// module.json 解析 (Stage 模型, API 9+)
// ============================================================================

/// 解析 module.json (Stage 模型),返回 HapInfo
pub fn parse_module_json(data: &[u8]) -> Result<HapInfo, HarmonyScanError> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| HarmonyScanError::ManifestParse(format!("JSON 解析失败: {}", e)))?;

    let mut info = HapInfo::default();

    // app 节点
    if let Some(app) = v.get("app").and_then(|a| a.as_object()) {
        info.bundle_name = app
            .get("bundleName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.vendor = app
            .get("vendor")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.version_name = app
            .get("versionName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.version_code = app
            .get("versionCode")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        // 部分 module.json 兼容 minAPIVersion
        info.min_api_version = app
            .get("minAPIVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        info.target_api_version = app
            .get("targetAPIVersion")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
    }

    // module 节点
    if let Some(module) = v.get("module").and_then(|m| m.as_object()) {
        info.module_name = module
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.module_type = module
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(dtypes) = module.get("deviceTypes").and_then(|v| v.as_array()) {
            info.device_types = dtypes
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(api) = module.get("apiVersion") {
            if let Some(min) = api.get("compatible").and_then(|v| v.as_i64()) {
                info.min_api_version = min as i32;
            }
            if let Some(tgt) = api.get("target").and_then(|v| v.as_i64()) {
                info.target_api_version = tgt as i32;
            }
        }

        // requestPermissions
        if let Some(perms) = module.get("requestPermissions").and_then(|v| v.as_array()) {
            for p in perms {
                if let Some(pobj) = p.as_object() {
                    info.request_permissions.push(HapPermission {
                        name: pobj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        reason: pobj
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        used_scene: pobj
                            .get("usedScene")
                            .map(|v| v.to_string())
                            .unwrap_or_default(),
                    });
                }
            }
        }

        // abilities (Stage 模型)
        if let Some(abs) = module.get("abilities").and_then(|v| v.as_array()) {
            for a in abs {
                if let Some(aobj) = a.as_object() {
                    info.abilities.push(HapAbility {
                        name: aobj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        r#type: aobj
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("page")
                            .to_string(),
                        visible: aobj
                            .get("visible")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        launch_type: aobj
                            .get("launchType")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            }
        }

        // extensionAbilities (Service / Data 能力)
        if let Some(exts) = module.get("extensionAbilities").and_then(|v| v.as_array()) {
            for a in exts {
                if let Some(aobj) = a.as_object() {
                    info.abilities.push(HapAbility {
                        name: aobj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        r#type: aobj
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("service")
                            .to_string(),
                        visible: aobj
                            .get("visible")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        launch_type: None,
                    });
                }
            }
        }
    }

    Ok(info)
}

// ============================================================================
// config.json 解析 (FA 模型, API 8-)
// ============================================================================

/// 解析 config.json (FA 模型),返回 HapInfo
pub fn parse_config_json(data: &[u8]) -> Result<HapInfo, HarmonyScanError> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| HarmonyScanError::ManifestParse(format!("JSON 解析失败: {}", e)))?;

    let mut info = HapInfo::default();

    // app 节点
    if let Some(app) = v.get("app").and_then(|a| a.as_object()) {
        info.bundle_name = app
            .get("bundleName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.vendor = app
            .get("vendor")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    // deviceConfig
    if let Some(_) = v.get("deviceConfig") {
        // 兼容字段, 暂不处理
    }

    // module 节点
    if let Some(module) = v.get("module").and_then(|m| m.as_object()) {
        info.module_name = module
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info.module_type = module
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(dtypes) = module.get("deviceType").and_then(|v| v.as_array()) {
            info.device_types = dtypes
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(ver) = module.get("apiVersion").and_then(|v| v.as_object()) {
            if let Some(min) = ver.get("compatible").and_then(|v| v.as_i64()) {
                info.min_api_version = min as i32;
            }
            if let Some(tgt) = ver.get("target").and_then(|v| v.as_i64()) {
                info.target_api_version = tgt as i32;
            }
        }

        // reqPermissions (FA 模型权限)
        if let Some(perms) = module.get("reqPermissions").and_then(|v| v.as_array()) {
            for p in perms {
                if let Some(pobj) = p.as_object() {
                    info.request_permissions.push(HapPermission {
                        name: pobj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        reason: pobj
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        used_scene: String::new(),
                    });
                }
            }
        }

        // abilities (FA 模型)
        if let Some(abs) = module.get("abilities").and_then(|v| v.as_array()) {
            for a in abs {
                if let Some(aobj) = a.as_object() {
                    info.abilities.push(HapAbility {
                        name: aobj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        r#type: aobj
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("page")
                            .to_string(),
                        visible: aobj
                            .get("visible")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        launch_type: aobj
                            .get("launchType")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            }
        }
    }

    Ok(info)
}

// ============================================================================
// 危险权限分类
// ============================================================================

// 注: HarmonyOS 规范要求所有权限 (含 ohos.permission.* 系统权限) 都需在
// requestPermissions 中声明 reason 字段, 因此不再需要单独判断系统权限。

// ============================================================================
// 硬编码密钥检测
// ============================================================================

/// 在资源文件文本中扫描硬编码密钥,返回发现列表
pub fn scan_resource_strings(text: &str, source: &str) -> Vec<MobileFinding> {
    let mut findings = Vec::new();

    let patterns: &[(&str, &str, &str, &str)] = &[
        (
            r#"(?i)["']?api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9]{16,}["']?"#,
            "HARMONY-400",
            "硬编码 API Key",
            "high",
        ),
        (
            r#"(?i)["']?secret["']?\s*[:=]\s*["']?[A-Za-z0-9]{16,}["']?"#,
            "HARMONY-401",
            "硬编码 Secret",
            "high",
        ),
        (
            r#"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#,
            "HARMONY-402",
            "硬编码 JWT Token",
            "high",
        ),
        (
            r#"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"#,
            "HARMONY-403",
            "硬编码私钥",
            "critical",
        ),
        (
            r#"(?i)["']?password["']?\s*[:=]\s*["']?[A-Za-z0-9!@#$%^&*]{8,}["']?"#,
            "HARMONY-404",
            "硬编码密码",
            "high",
        ),
    ];

    for (pattern, id, title, severity) in patterns {
        // 使用 bytes::Regex 以支持非 UTF-8 友好匹配, 同时兼容 UTF-8 文本
        let re = match regex::bytes::Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut hits = 0;
        for m in re.find_iter(text.as_bytes()) {
            hits += 1;
            // 取首个匹配作为证据样本
            if hits == 1 {
                let evidence_str = std::str::from_utf8(m.as_bytes()).unwrap_or("<binary>");
                findings.push(MobileFinding {
                    id: id.to_string(),
                    title: title.to_string(),
                    severity: severity.to_string(),
                    category: "harmony-secret".to_string(),
                    description: format!("在 {} 中匹配到 {}", source, title),
                    evidence: format!("source={}, sample={}", source, truncate_str(evidence_str, 128)),
                    fix_advice: "将密钥/Token 移至服务端或系统密钥库,不要硬编码到资源文件"
                        .to_string(),
                });
            }
            if hits >= 5 {
                break;
            }
        }
        // 多次命中升级描述 (避免无限增加 finding, 仅报告首次)
        let _ = hits;
    }

    findings
}

/// 截断字符串到最大长度
fn truncate_str(s: &str, max: usize) -> &str {
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

    fn sample_module_json() -> Vec<u8> {
        let json = r#"{
            "app": {
                "bundleName": "com.example.testhap",
                "vendor": "Example",
                "versionName": "1.0.0",
                "versionCode": 100,
                "minAPIVersion": 9,
                "targetAPIVersion": 10
            },
            "module": {
                "name": "entry",
                "type": "entry",
                "deviceTypes": ["default", "tablet"],
                "apiVersion": {
                    "compatible": 9,
                    "target": 10
                },
                "requestPermissions": [
                    {
                        "name": "ohos.permission.READ_CONTACTS",
                        "reason": "用于备份通讯录",
                        "usedScene": {
                            "abilities": ["EntryAbility"],
                            "when": "inuse"
                        }
                    },
                    {
                        "name": "ohos.permission.SEND_MESSAGES",
                        "reason": ""
                    },
                    {
                        "name": "ohos.permission.CAMERA",
                        "reason": "扫码"
                    }
                ],
                "abilities": [
                    {
                        "name": "EntryAbility",
                        "type": "page",
                        "visible": true,
                        "launchType": "singleton"
                    }
                ],
                "extensionAbilities": [
                    {
                        "name": "ServiceExtAbility",
                        "type": "service",
                        "visible": true
                    }
                ]
            }
        }"#;
        json.as_bytes().to_vec()
    }

    fn sample_config_json() -> Vec<u8> {
        let json = r#"{
            "app": {
                "bundleName": "com.example.fahap",
                "vendor": "OldExample"
            },
            "module": {
                "name": "entry",
                "type": "entry",
                "deviceType": ["phone"],
                "apiVersion": {
                    "compatible": 5,
                    "target": 5
                },
                "reqPermissions": [
                    {"name": "ohos.permission.READ_CONTACTS", "reason": "备份"},
                    {"name": "ohos.permission.LOCATION"}
                ],
                "abilities": [
                    {"name": "MainAbility", "type": "page", "visible": true}
                ]
            }
        }"#;
        json.as_bytes().to_vec()
    }

    #[test]
    fn test_parse_module_json_basic() {
        let data = sample_module_json();
        let info = parse_module_json(&data).expect("module.json 解析应成功");
        assert_eq!(info.bundle_name, "com.example.testhap");
        assert_eq!(info.vendor, "Example");
        assert_eq!(info.version_name, "1.0.0");
        assert_eq!(info.version_code, 100);
        assert_eq!(info.min_api_version, 9);
        assert_eq!(info.target_api_version, 10);
        assert_eq!(info.module_name, "entry");
        assert_eq!(info.module_type, "entry");
        assert_eq!(info.device_types.len(), 2);
        assert!(info.device_types.contains(&"default".to_string()));
        assert!(info.device_types.contains(&"tablet".to_string()));
        assert!(!info.is_fa_model);
    }

    #[test]
    fn test_parse_module_json_permissions() {
        let data = sample_module_json();
        let info = parse_module_json(&data).expect("解析成功");
        assert_eq!(info.request_permissions.len(), 3);
        assert_eq!(info.request_permissions[0].name, "ohos.permission.READ_CONTACTS");
        assert_eq!(info.request_permissions[0].reason, "用于备份通讯录");
        // SEND_MESSAGES reason 为空字符串
        assert_eq!(info.request_permissions[1].name, "ohos.permission.SEND_MESSAGES");
        assert!(info.request_permissions[1].reason.is_empty());
    }

    #[test]
    fn test_parse_module_json_abilities_with_extension() {
        let data = sample_module_json();
        let info = parse_module_json(&data).expect("解析成功");
        // abilities + extensionAbilities 应都加入
        assert_eq!(info.abilities.len(), 2);
        let ext = info
            .abilities
            .iter()
            .find(|a| a.name == "ServiceExtAbility")
            .expect("应包含 Extension Ability");
        assert_eq!(ext.r#type, "service");
        assert!(ext.visible);
    }

    #[test]
    fn test_parse_config_json_basic() {
        let data = sample_config_json();
        let info = parse_config_json(&data).expect("config.json 解析应成功");
        assert_eq!(info.bundle_name, "com.example.fahap");
        assert_eq!(info.min_api_version, 5);
        assert_eq!(info.target_api_version, 5);
        // reqPermissions
        assert_eq!(info.request_permissions.len(), 2);
        assert_eq!(info.request_permissions[0].name, "ohos.permission.READ_CONTACTS");
        // deviceType (注意 FA 模型用 deviceType, 不是 deviceTypes)
        assert_eq!(info.device_types.len(), 1);
        assert_eq!(info.device_types[0], "phone");
    }

    #[test]
    fn test_parse_module_json_invalid() {
        let result = parse_module_json(b"{not valid json");
        assert!(matches!(result, Err(HarmonyScanError::ManifestParse(_))));
    }

    #[test]
    fn test_parse_module_json_empty() {
        let result = parse_module_json(b"{}");
        // 空 JSON 对象应返回默认 HapInfo, 不报错
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(info.bundle_name.is_empty());
    }

    #[test]
    fn test_scan_resource_strings_api_key() {
        let text = r#"{"apiKey": "abcdefghijklmnopqrstuvwxyz"}"#;
        let findings = scan_resource_strings(text, "config.json");
        assert!(findings.iter().any(|f| f.id == "HARMONY-400"));
    }

    #[test]
    fn test_scan_resource_strings_jwt() {
        let text = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6y";
        let findings = scan_resource_strings(text, "resources/base/profile.json");
        assert!(findings.iter().any(|f| f.id == "HARMONY-402"));
    }

    #[test]
    fn test_scan_resource_strings_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let findings = scan_resource_strings(text, "config.json");
        assert!(findings.iter().any(|f| f.id == "HARMONY-403" && f.severity == "critical"));
    }

    #[test]
    fn test_scan_resource_strings_password() {
        let text = r#"{"password": "supersecret123"}"#;
        let findings = scan_resource_strings(text, "config.json");
        assert!(findings.iter().any(|f| f.id == "HARMONY-404"));
    }

    #[test]
    fn test_scan_resource_strings_no_false_positive() {
        let text = r#"{"name": "John Doe", "age": 30}"#;
        let findings = scan_resource_strings(text, "config.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_build_findings_dangerous_permissions() {
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            request_permissions: vec![HapPermission {
                name: "ohos.permission.READ_CONTACTS".to_string(),
                reason: "test".to_string(),
                ..HapPermission::default()
            }],
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "HARMONY-001"));
    }

    #[test]
    fn test_build_findings_sms_permission() {
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            request_permissions: vec![HapPermission {
                name: "ohos.permission.SEND_MESSAGES".to_string(),
                reason: "test".to_string(),
                ..HapPermission::default()
            }],
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "HARMONY-002"));
    }

    #[test]
    fn test_build_findings_missing_reason() {
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            request_permissions: vec![HapPermission {
                name: "ohos.permission.READ_CONTACTS".to_string(),
                reason: "".to_string(),
                ..HapPermission::default()
            }],
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "HARMONY-100"));
    }

    #[test]
    fn test_build_findings_visible_service() {
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            abilities: vec![HapAbility {
                name: "ServiceAbility".to_string(),
                r#type: "service".to_string(),
                visible: true,
                ..HapAbility::default()
            }],
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "HARMONY-200"));
    }

    #[test]
    fn test_build_findings_fa_model() {
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            is_fa_model: true,
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        assert!(findings.iter().any(|f| f.id == "HARMONY-300"));
    }

    #[test]
    fn test_build_findings_no_duplicate_permission_ids() {
        // 同一危险权限 ID 不应重复报告 (例如 READ_CONTACTS + WRITE_CONTACTS 都映射到 HARMONY-001)
        let scanner = HarmonyScanner::new();
        let info = HapInfo {
            request_permissions: vec![
                HapPermission {
                    name: "ohos.permission.READ_CONTACTS".to_string(),
                    reason: "r".to_string(),
                    ..HapPermission::default()
                },
                HapPermission {
                    name: "ohos.permission.WRITE_CONTACTS".to_string(),
                    reason: "r".to_string(),
                    ..HapPermission::default()
                },
            ],
            ..HapInfo::default()
        };
        let findings = scanner.build_findings(&info);
        let count = findings.iter().filter(|f| f.id == "HARMONY-001").count();
        assert_eq!(count, 1, "HARMONY-001 应只报一次");
    }

    /// 端到端测试: 构造最小合法 HAP ZIP 包扫描
    #[test]
    fn test_scan_bytes_minimal_hap() {
        let zip_bytes = build_minimal_hap();
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_bytes(&zip_bytes).expect("扫描应成功");
        assert_eq!(result.info.bundle_name, "com.example.testhap");
        assert_eq!(result.info.version_name, "1.0.0");
        assert!(!result.info.is_fa_model);
        // 应检测到 READ_CONTACTS
        assert!(result.findings.iter().any(|f| f.id == "HARMONY-001"));
        // 应检测到 SEND_MESSAGES (且无 reason)
        assert!(result.findings.iter().any(|f| f.id == "HARMONY-002"));
        assert!(result.findings.iter().any(|f| f.id == "HARMONY-100"));
    }

    /// 端到端测试: FA 模型 (config.json) HAP
    #[test]
    fn test_scan_bytes_fa_model_hap() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("config.json", opts).unwrap();
            zip.write_all(&sample_config_json()).unwrap();
            zip.finish().unwrap();
        }
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_bytes(&buf).expect("扫描应成功");
        assert!(result.info.is_fa_model);
        assert_eq!(result.info.bundle_name, "com.example.fahap");
        assert!(result.findings.iter().any(|f| f.id == "HARMONY-300"));
    }

    #[test]
    fn test_scan_bytes_missing_manifest() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("README.txt", opts).unwrap();
            zip.write_all(b"no manifest here").unwrap();
            zip.finish().unwrap();
        }
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_bytes(&buf);
        assert!(matches!(result, Err(HarmonyScanError::ManifestMissing)));
    }

    #[test]
    fn test_scan_file_not_found() {
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_file("/nonexistent/path.hap");
        assert!(matches!(result, Err(HarmonyScanError::FileNotFound(_))));
    }

    #[test]
    fn test_scan_bytes_invalid_zip() {
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_bytes(b"not a zip file");
        assert!(matches!(result, Err(HarmonyScanError::ZipOpen(_))));
    }

    /// 端到端测试: 资源文件中硬编码密钥扫描
    #[test]
    fn test_scan_bytes_finds_resource_secret() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("module.json", opts).unwrap();
            zip.write_all(&sample_module_json()).unwrap();
            zip.start_file("resources/base/profile/config.json", opts).unwrap();
            zip.write_all(br#"{"apiKey": "abcdefghijklmnopqrstuvwxyz"}"#).unwrap();
            zip.finish().unwrap();
        }
        let scanner = HarmonyScanner::new();
        let result = scanner.scan_bytes(&buf).expect("扫描应成功");
        assert!(result.findings.iter().any(|f| f.id == "HARMONY-400"));
    }

    fn build_minimal_hap() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("module.json", opts).unwrap();
            zip.write_all(&sample_module_json()).unwrap();
            zip.finish().unwrap();
        }
        buf
    }
}
