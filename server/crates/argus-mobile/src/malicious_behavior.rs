//! G7.4: 恶意行为检测
//!
//! 通过 DEX 字节码字符串扫描,检测 Android 应用可能存在的恶意行为:
//! - **短信发送**: 调用 `SmsManager.sendTextMessage` / `sendMultipartTextMessage` 等
//! - **通话记录读取/上传**: 调用 `TelephonyManager` / `CallLog.Calls` 读取通话记录
//! - **通讯录上传**: 调用 `ContactsContract.Contacts` / `ContactsContract.CommonDataKinds`
//!   读取联系人后,通过 `HttpURLConnection` / `OkHttpClient` 上传
//! - **设备信息收集**: 读取 IMEI / IMSI / Android ID / MAC 地址
//! - **动态代码加载**: `DexClassLoader` / `PathClassLoader` 加载外部代码
//! - **反射调用私有 API**: `Class.forName` + `getDeclaredMethod` 组合
//! - **Root/调试检测**: 检查 su / Magisk 等路径
//!
//! ## 实现策略
//! 由于 Rust 生态无成熟的 DEX 字节码反编译库,本模块采用**字节流字符串扫描**:
//! - DEX 字符串池中的类名/方法名以 MUTF-8 编码存储,与 ASCII/UTF-8 兼容
//! - 直接对原始字节做可打印字符串提取后,通过精确字符串匹配识别危险 API
//! - 该策略对 obfuscator (如 ProGuard) 后的二进制效果有限,但对未混淆或弱混淆样本有效
//!
//! 输入可以是 ZIP (APK) 或裸 DEX 文件字节流。

use std::io::Read;
use thiserror::Error;
use zip::ZipArchive;

use crate::types::MobileFinding;

/// 恶意行为扫描错误
#[derive(Debug, Error)]
pub enum MaliciousScanError {
    #[error("文件不存在: {0}")]
    FileNotFound(String),
    #[error("打开 ZIP 失败: {0}")]
    ZipOpen(String),
    #[error("读取 ZIP 条目失败: {0}")]
    ZipRead(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

/// 恶意行为扫描结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MaliciousScanResult {
    /// 检测到的恶意行为风险
    pub findings: Vec<MobileFinding>,
    /// 扫描的 DEX 文件路径列表
    pub scanned_dex: Vec<String>,
    /// 行为类别统计
    pub behavior_summary: BehaviorSummary,
}

/// 行为类别统计
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BehaviorSummary {
    /// 短信相关 API 调用次数
    pub sms_apis: usize,
    /// 通话记录相关 API 调用次数
    pub call_log_apis: usize,
    /// 通讯录相关 API 调用次数
    pub contacts_apis: usize,
    /// 设备信息收集 API 调用次数
    pub device_info_apis: usize,
    /// 动态加载 API 调用次数
    pub dynamic_load_apis: usize,
    /// 反射调用 API 调用次数
    pub reflection_apis: usize,
    /// 网络 API 调用次数
    pub network_apis: usize,
}

/// 恶意行为扫描器
pub struct MaliciousBehaviorScanner {
    /// 单文件最大扫描字节
    pub max_file_bytes: usize,
}

impl Default for MaliciousBehaviorScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl MaliciousBehaviorScanner {
    pub fn new() -> Self {
        Self {
            max_file_bytes: 32 * 1024 * 1024, // 32MB
        }
    }

    /// 从文件路径扫描 (APK ZIP 或裸 DEX)
    pub fn scan_file(&self, path: &str) -> Result<MaliciousScanResult, MaliciousScanError> {
        let data = std::fs::read(path).map_err(|_| {
            MaliciousScanError::FileNotFound(path.to_string())
        })?;
        self.scan_bytes(&data)
    }

    /// 从字节数据扫描 (APK ZIP 或裸 DEX)
    pub fn scan_bytes(&self, data: &[u8]) -> Result<MaliciousScanResult, MaliciousScanError> {
        let cursor = std::io::Cursor::new(data.to_vec());
        match ZipArchive::new(cursor) {
            Ok(mut zip) => self.scan_zip(&mut zip),
            Err(_) => {
                // 裸 DEX 文件 (或其他裸文件)
                let mut summary = BehaviorSummary::default();
                let mut findings = Vec::new();
                let mut scanned_dex = Vec::new();
                if crate::data_security::is_dex(data) {
                    scanned_dex.push("(inline)".to_string());
                    findings.extend(scan_dex_malicious_apis(data, "(inline)", &mut summary));
                }
                Ok(MaliciousScanResult {
                    findings,
                    scanned_dex,
                    behavior_summary: summary,
                })
            }
        }
    }

    /// 扫描 APK ZIP 中的所有 DEX 文件
    pub fn scan_zip<R: Read + std::io::Seek>(
        &self,
        zip: &mut ZipArchive<R>,
    ) -> Result<MaliciousScanResult, MaliciousScanError> {
        let mut findings = Vec::new();
        let mut scanned_dex = Vec::new();
        let mut summary = BehaviorSummary::default();

        let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
        for name in &names {
            if !name.ends_with(".dex") {
                continue;
            }
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
            if !crate::data_security::is_dex(&data) {
                continue;
            }
            scanned_dex.push(name.clone());
            findings.extend(scan_dex_malicious_apis(&data, name, &mut summary));
        }

        // 跨 DEX 综合判断: 如果同时出现"读取通讯录"+"网络上传"两类 API, 提升告警
        if summary.contacts_apis > 0 && summary.network_apis > 0 {
            findings.push(MobileFinding {
                id: "MAL-900".to_string(),
                title: "疑似通讯录上传行为 (联系人读取 + 网络上传组合)".to_string(),
                severity: "high".to_string(),
                category: "malicious-behavior".to_string(),
                description: format!(
                    "应用同时调用 ContactsContract 读取联系人 ({}次) 与网络上传 API ({}次),可能存在隐私泄露",
                    summary.contacts_apis, summary.network_apis
                ),
                evidence: format!(
                    "contacts_apis={}, network_apis={}",
                    summary.contacts_apis, summary.network_apis
                ),
                fix_advice: "仅在用户明确知情同意后读取通讯录,上传行为应有明显提示且支持关闭"
                    .to_string(),
            });
        }
        if summary.call_log_apis > 0 && summary.network_apis > 0 {
            findings.push(MobileFinding {
                id: "MAL-901".to_string(),
                title: "疑似通话记录上传行为 (通话记录读取 + 网络上传组合)".to_string(),
                severity: "high".to_string(),
                category: "malicious-behavior".to_string(),
                description: format!(
                    "应用同时调用 CallLog 读取通话记录 ({}次) 与网络上传 API ({}次),可能存在隐私泄露",
                    summary.call_log_apis, summary.network_apis
                ),
                evidence: format!(
                    "call_log_apis={}, network_apis={}",
                    summary.call_log_apis, summary.network_apis
                ),
                fix_advice: "仅在用户明确知情同意后读取通话记录,上传行为应有明显提示且支持关闭"
                    .to_string(),
            });
        }
        if summary.sms_apis > 0 && summary.network_apis > 0 {
            findings.push(MobileFinding {
                id: "MAL-902".to_string(),
                title: "疑似短信内容上传行为 (短信读取 + 网络上传组合)".to_string(),
                severity: "high".to_string(),
                category: "malicious-behavior".to_string(),
                description: format!(
                    "应用同时调用 SmsManager/短信 API ({}次) 与网络上传 API ({}次),可能存在短信窃取",
                    summary.sms_apis, summary.network_apis
                ),
                evidence: format!(
                    "sms_apis={}, network_apis={}",
                    summary.sms_apis, summary.network_apis
                ),
                fix_advice: "短信读取行为应仅用于明确声明的功能,避免与网络上传组合使用".to_string(),
            });
        }

        Ok(MaliciousScanResult {
            findings,
            scanned_dex,
            behavior_summary: summary,
        })
    }
}

impl MaliciousBehaviorScanner {
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
) -> Result<Vec<u8>, MaliciousScanError> {
    let mut entry = zip
        .by_name(name)
        .map_err(|e| MaliciousScanError::ZipRead(format!("{}: {}", name, e)))?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

// ============================================================================
// 恶意行为 API 模式定义
// ============================================================================

/// 行为类别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorKind {
    Sms,
    CallLog,
    Contacts,
    DeviceInfo,
    DynamicLoad,
    Reflection,
    Network,
}

/// 单条危险 API 模式定义
struct ApiPattern {
    /// 需要匹配的精确字符串 (DEX 字符串池中以类名/方法名形式存在)
    needle: &'static str,
    /// 漏洞 ID
    id: &'static str,
    /// 标题
    title: &'static str,
    /// 严重级别
    severity: &'static str,
    /// 行为类别
    kind: BehaviorKind,
    /// 描述
    description: &'static str,
    /// 修复建议
    fix_advice: &'static str,
}

/// 危险 API 模式表
///
/// 注意: 这些字符串在 DEX 中以 L<path>; (类引用) 或 <init> 等形式存在,
/// 我们用子串匹配保证鲁棒性。
fn api_patterns() -> &'static [ApiPattern] {
    &[
        // ===== 短信相关 =====
        ApiPattern {
            needle: "android/telephony/SmsManager",
            id: "MAL-101",
            title: "调用 SmsManager 短信 API",
            severity: "medium",
            kind: BehaviorKind::Sms,
            description: "应用调用 android.telephony.SmsManager,具备发送/接收短信能力",
            fix_advice: "若非必要,移除短信 API 调用;发送短信应有用户二次确认",
        },
        ApiPattern {
            needle: "sendTextMessage",
            id: "MAL-102",
            title: "调用 SmsManager.sendTextMessage 发送短信",
            severity: "high",
            kind: BehaviorKind::Sms,
            description: "应用调用 SmsManager.sendTextMessage,可向指定号码发送短信,存在扣费/诈骗风险",
            fix_advice: "发送短信前应明确告知用户目标号码与内容,避免在后台静默发送",
        },
        ApiPattern {
            needle: "sendMultipartTextMessage",
            id: "MAL-103",
            title: "调用 SmsManager.sendMultipartTextMessage 发送长短信",
            severity: "high",
            kind: BehaviorKind::Sms,
            description: "应用调用 SmsManager.sendMultipartTextMessage,可发送长短信",
            fix_advice: "发送短信前应明确告知用户目标号码与内容,避免在后台静默发送",
        },
        ApiPattern {
            needle: "sendDataMessage",
            id: "MAL-104",
            title: "调用 SmsManager.sendDataMessage 发送数据短信",
            severity: "high",
            kind: BehaviorKind::Sms,
            description: "应用调用 SmsManager.sendDataMessage,可发送二进制数据短信",
            fix_advice: "数据短信常用于特殊场景,普通应用应避免使用",
        },
        ApiPattern {
            needle: "android/provider/Telephony$Sms",
            id: "MAL-105",
            title: "读取 SMS 数据库",
            severity: "high",
            kind: BehaviorKind::Sms,
            description: "应用访问 android.provider.Telephony.Sms,可读取用户短信内容",
            fix_advice: "短信内容包含验证码等敏感信息,应避免读取;必要时应明确告知用户",
        },
        // ===== 通话记录 =====
        ApiPattern {
            needle: "android/provider/CallLog",
            id: "MAL-201",
            title: "访问 CallLog 通话记录",
            severity: "medium",
            kind: BehaviorKind::CallLog,
            description: "应用访问 android.provider.CallLog,可读取通话记录",
            fix_advice: "仅在必要功能时读取通话记录,并在隐私政策中声明",
        },
        ApiPattern {
            needle: "CallLog$Calls",
            id: "MAL-202",
            title: "查询 CallLog.Calls 通话记录详情",
            severity: "medium",
            kind: BehaviorKind::CallLog,
            description: "应用查询 CallLog.Calls,可读取通话号码/时间/时长",
            fix_advice: "仅在必要功能时读取通话记录,并在隐私政策中声明",
        },
        ApiPattern {
            needle: "android/telephony/TelephonyManager",
            id: "MAL-203",
            title: "访问 TelephonyManager 电话服务",
            severity: "low",
            kind: BehaviorKind::CallLog,
            description: "应用访问 TelephonyManager,可获取设备电话状态/号码等信息",
            fix_advice: "仅在必要功能时使用,避免获取不必要的电话信息",
        },
        // ===== 通讯录 =====
        ApiPattern {
            needle: "android/provider/ContactsContract",
            id: "MAL-301",
            title: "访问 ContactsContract 通讯录",
            severity: "medium",
            kind: BehaviorKind::Contacts,
            description: "应用访问 android.provider.ContactsContract,可读取联系人",
            fix_advice: "仅在必要功能时读取通讯录,并在隐私政策中声明;上传前需用户明确同意",
        },
        ApiPattern {
            needle: "ContactsContract$Contacts",
            id: "MAL-302",
            title: "读取 Contacts 联系人列表",
            severity: "medium",
            kind: BehaviorKind::Contacts,
            description: "应用读取 ContactsContract.Contacts,可获取所有联系人",
            fix_advice: "仅在必要功能时读取通讯录,避免全量上传",
        },
        ApiPattern {
            needle: "ContactsContract$CommonDataKinds",
            id: "MAL-303",
            title: "读取 CommonDataKinds 联系人详情",
            severity: "medium",
            kind: BehaviorKind::Contacts,
            description: "应用读取 ContactsContract.CommonDataKinds,可获取电话/邮箱等详细字段",
            fix_advice: "仅在必要功能时读取所需字段,避免读取全部详情",
        },
        ApiPattern {
            needle: "ContactsContract$PhoneLookup",
            id: "MAL-304",
            title: "PhoneLookup 来电号码匹配联系人",
            severity: "low",
            kind: BehaviorKind::Contacts,
            description: "应用使用 PhoneLookup 查询来电号码对应的联系人",
            fix_advice: "来电场景下使用相对合理,但仍应在隐私政策中声明",
        },
        // ===== 设备信息收集 =====
        ApiPattern {
            needle: "getDeviceId",
            id: "MAL-401",
            title: "获取 IMEI (getDeviceId)",
            severity: "medium",
            kind: BehaviorKind::DeviceInfo,
            description: "应用调用 getDeviceId 获取设备 IMEI,Android 10+ 已限制",
            fix_advice: "Android 10+ 不应使用 IMEI,改用 Android ID 或实例 ID",
        },
        ApiPattern {
            needle: "getSubscriberId",
            id: "MAL-402",
            title: "获取 IMSI (getSubscriberId)",
            severity: "high",
            kind: BehaviorKind::DeviceInfo,
            description: "应用调用 getSubscriberId 获取 IMSI,可用于唯一标识用户",
            fix_advice: "IMSI 是高度敏感标识符,普通应用不应读取",
        },
        ApiPattern {
            needle: "getLine1Number",
            id: "MAL-403",
            title: "获取手机号码 (getLine1Number)",
            severity: "high",
            kind: BehaviorKind::DeviceInfo,
            description: "应用调用 getLine1Number 读取本机号码",
            fix_advice: "手机号码属于个人隐私,不应读取;必要时引导用户手动输入",
        },
        ApiPattern {
            needle: "getSimSerialNumber",
            id: "MAL-404",
            title: "获取 SIM 卡序列号 (getSimSerialNumber)",
            severity: "high",
            kind: BehaviorKind::DeviceInfo,
            description: "应用调用 getSimSerialNumber 读取 SIM 卡 ICCID",
            fix_advice: "SIM 卡序列号是设备唯一标识,普通应用不应读取",
        },
        ApiPattern {
            needle: "Settings$Secure",
            id: "MAL-405",
            title: "访问 Settings.Secure (含 Android ID)",
            severity: "low",
            kind: BehaviorKind::DeviceInfo,
            description: "应用访问 Settings.Secure,可能读取 ANDROID_ID",
            fix_advice: "ANDROID_ID 可被重置,可适当使用;避免作为唯一追踪标识",
        },
        ApiPattern {
            needle: "getMacAddress",
            id: "MAL-406",
            title: "获取 MAC 地址 (getMacAddress)",
            severity: "medium",
            kind: BehaviorKind::DeviceInfo,
            description: "应用调用 getMacAddress 读取网卡 MAC 地址,Android 6+ 已限制",
            fix_advice: "Android 6+ 返回固定值 02:00:00:00:00:00,不应依赖该 API",
        },
        // ===== 动态加载 =====
        ApiPattern {
            needle: "dalvik/system/DexClassLoader",
            id: "MAL-501",
            title: "使用 DexClassLoader 动态加载 DEX",
            severity: "high",
            kind: BehaviorKind::DynamicLoad,
            description: "应用使用 DexClassLoader,可在运行时加载外部 DEX,常被恶意软件用于绕过静态检测",
            fix_advice: "避免动态加载外部代码;如需插件化,应从可信源加载并校验完整性",
        },
        ApiPattern {
            needle: "dalvik/system/PathClassLoader",
            id: "MAL-502",
            title: "使用 PathClassLoader",
            severity: "low",
            kind: BehaviorKind::DynamicLoad,
            description: "应用使用 PathClassLoader,系统默认类加载器,但也可用于加载外部 DEX",
            fix_advice: "确认是否用于加载外部代码,如非必要应避免使用",
        },
        ApiPattern {
            needle: "dalvik/system/InMemoryDexClassLoader",
            id: "MAL-503",
            title: "使用 InMemoryDexClassLoader 内存加载 DEX",
            severity: "high",
            kind: BehaviorKind::DynamicLoad,
            description: "应用使用 InMemoryDexClassLoader 从内存加载 DEX,无需落盘,高度可疑",
            fix_advice: "内存加载 DEX 是常见恶意软件技巧,普通应用不应使用",
        },
        ApiPattern {
            needle: "Runtime.exec",
            id: "MAL-504",
            title: "调用 Runtime.exec 执行外部命令",
            severity: "medium",
            kind: BehaviorKind::DynamicLoad,
            description: "应用调用 Runtime.exec,可执行 shell 命令",
            fix_advice: "避免执行外部命令,必要时应对参数做严格校验",
        },
        // ===== 反射调用 =====
        ApiPattern {
            needle: "Class.forName",
            id: "MAL-601",
            title: "使用 Class.forName 反射",
            severity: "low",
            kind: BehaviorKind::Reflection,
            description: "应用使用 Class.forName 反射加载类,可能调用私有 API",
            fix_advice: "反思自身代码是否必要使用反射,避免访问私有/系统 API",
        },
        ApiPattern {
            needle: "getDeclaredMethod",
            id: "MAL-602",
            title: "使用 getDeclaredMethod 获取私有方法",
            severity: "medium",
            kind: BehaviorKind::Reflection,
            description: "应用使用 getDeclaredMethod 获取声明方法,常用于调用私有 API",
            fix_advice: "避免通过反射调用私有方法,使用公共 API 完成同等功能",
        },
        ApiPattern {
            needle: "setAccessible",
            id: "MAL-603",
            title: "调用 setAccessible 绕过访问控制",
            severity: "medium",
            kind: BehaviorKind::Reflection,
            description: "应用调用 setAccessible(true),可访问 private 成员",
            fix_advice: "私有成员被设计为不可外部访问,绕过访问控制可能违反平台规范",
        },
        // ===== 网络 =====
        ApiPattern {
            needle: "java/net/HttpURLConnection",
            id: "MAL-701",
            title: "使用 HttpURLConnection 网络通信",
            severity: "low",
            kind: BehaviorKind::Network,
            description: "应用使用 HttpURLConnection 发起 HTTP 请求",
            fix_advice: "确认请求目标合法,使用 HTTPS 并校验证书",
        },
        ApiPattern {
            needle: "okhttp3/OkHttpClient",
            id: "MAL-702",
            title: "使用 OkHttp 网络通信",
            severity: "low",
            kind: BehaviorKind::Network,
            description: "应用使用 OkHttp 发起 HTTP 请求",
            fix_advice: "确认请求目标合法,使用 HTTPS 并校验证书",
        },
        ApiPattern {
            needle: "libcore/io/Os",
            id: "MAL-703",
            title: "使用 Os 底层网络/文件操作",
            severity: "medium",
            kind: BehaviorKind::Network,
            description: "应用直接使用 libcore.io.Os,绕过 Java 网络 API",
            fix_advice: "底层 Os API 通常被系统使用,普通应用应避免直接调用",
        },
    ]
}

/// 扫描 DEX 文件中的危险 API 调用模式
///
/// `summary` 用于累计各类别 API 调用次数,供跨 DEX 综合判断使用
pub fn scan_dex_malicious_apis(
    data: &[u8],
    source: &str,
    summary: &mut BehaviorSummary,
) -> Vec<MobileFinding> {
    let strings = crate::ios_scan::extract_printable_strings(data);
    let mut findings = Vec::new();
    let patterns = api_patterns();

    for pat in patterns {
        let mut hits = 0;
        for s in &strings {
            if s.contains(pat.needle) {
                hits += 1;
                // 同一模式最多报告 3 次,避免 finding 爆炸
                if hits <= 3 {
                    findings.push(MobileFinding {
                        id: pat.id.to_string(),
                        title: pat.title.to_string(),
                        severity: pat.severity.to_string(),
                        category: "malicious-behavior".to_string(),
                        description: format!("{} (来源: {})", pat.description, source),
                        evidence: format!("needle={}, sample={}", pat.needle, truncate(s, 96)),
                        fix_advice: pat.fix_advice.to_string(),
                    });
                }
            }
        }
        // 累计统计
        match pat.kind {
            BehaviorKind::Sms => summary.sms_apis += hits,
            BehaviorKind::CallLog => summary.call_log_apis += hits,
            BehaviorKind::Contacts => summary.contacts_apis += hits,
            BehaviorKind::DeviceInfo => summary.device_info_apis += hits,
            BehaviorKind::DynamicLoad => summary.dynamic_load_apis += hits,
            BehaviorKind::Reflection => summary.reflection_apis += hits,
            BehaviorKind::Network => summary.network_apis += hits,
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

    /// 构造包含若干危险 API 字符串的伪造 DEX 数据
    fn build_malicious_dex() -> Vec<u8> {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        // 注入多个危险 API 引用字符串
        data.extend_from_slice(
            b"\x00Landroid/telephony/SmsManager;\x00sendTextMessage\x00\
Landroid/provider/CallLog$Calls;\x00\
Landroid/provider/ContactsContract$Contacts;\x00\
getDeviceId\x00getSubscriberId\x00\
Ldalvik/system/DexClassLoader;\x00\
Class.forName\x00getDeclaredMethod\x00\
Lokhttp3/OkHttpClient;\x00Landroid/provider/ContactsContract;\x00"
                ,);
        data
    }

    #[test]
    fn test_scan_dex_sms_manager() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Landroid/telephony/SmsManager;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-101"));
        assert!(summary.sms_apis > 0);
    }

    #[test]
    fn test_scan_dex_send_text_message() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00sendTextMessage\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-102" && f.severity == "high"));
        assert!(summary.sms_apis > 0);
    }

    #[test]
    fn test_scan_dex_call_log() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Landroid/provider/CallLog$Calls;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-202"));
        assert!(summary.call_log_apis > 0);
    }

    #[test]
    fn test_scan_dex_contacts() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Landroid/provider/ContactsContract;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-301"));
        assert!(summary.contacts_apis > 0);
    }

    #[test]
    fn test_scan_dex_contacts_common_data_kinds() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00ContactsContract$CommonDataKinds\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-303"));
    }

    #[test]
    fn test_scan_dex_device_id() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00getDeviceId\x00getSubscriberId\x00getLine1Number\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-401"));
        assert!(findings.iter().any(|f| f.id == "MAL-402"));
        assert!(findings.iter().any(|f| f.id == "MAL-403"));
        assert!(summary.device_info_apis >= 3);
    }

    #[test]
    fn test_scan_dex_dex_class_loader() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Ldalvik/system/DexClassLoader;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-501" && f.severity == "high"));
        assert!(summary.dynamic_load_apis > 0);
    }

    #[test]
    fn test_scan_dex_in_memory_dex_loader() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Ldalvik/system/InMemoryDexClassLoader;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-503"));
    }

    #[test]
    fn test_scan_dex_runtime_exec() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Runtime.exec\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-504"));
    }

    #[test]
    fn test_scan_dex_reflection() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Class.forName\x00getDeclaredMethod\x00setAccessible\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-601"));
        assert!(findings.iter().any(|f| f.id == "MAL-602"));
        assert!(findings.iter().any(|f| f.id == "MAL-603"));
        assert!(summary.reflection_apis >= 3);
    }

    #[test]
    fn test_scan_dex_network() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00Lokhttp3/OkHttpClient;\x00Ljava/net/HttpURLConnection;\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        assert!(findings.iter().any(|f| f.id == "MAL-701"));
        assert!(findings.iter().any(|f| f.id == "MAL-702"));
        assert!(summary.network_apis >= 2);
    }

    #[test]
    fn test_scan_dex_no_false_positive() {
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        data.extend_from_slice(b"\x00hello world\x00normal string\x00android/app/Activity\x00");
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        // Activity 是合法 API, 不应触发告警
        assert!(findings.is_empty(), "普通字符串不应触发恶意行为告警");
        assert_eq!(summary.sms_apis, 0);
        assert_eq!(summary.contacts_apis, 0);
    }

    #[test]
    fn test_scan_dex_max_3_hits_per_pattern() {
        // 同一模式多次出现, 最多报告 3 次
        let mut data = vec![0u8; 120];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"039");
        for _ in 0..10 {
            data.extend_from_slice(b"\x00sendTextMessage\x00");
        }
        let mut summary = BehaviorSummary::default();
        let findings = scan_dex_malicious_apis(&data, "classes.dex", &mut summary);
        let count = findings.iter().filter(|f| f.id == "MAL-102").count();
        assert_eq!(count, 3, "同模式最多报 3 次");
        // 但 summary 应累计所有命中
        assert_eq!(summary.sms_apis, 10);
    }

    /// 端到端: 跨 DEX 综合判断 (通讯录 + 网络 = 上传行为)
    #[test]
    fn test_scan_zip_contacts_upload_detected() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex = vec![0u8; 120];
            dex[0..4].copy_from_slice(b"dex\n");
            dex[4..7].copy_from_slice(b"039");
            dex.extend_from_slice(
                b"\x00Landroid/provider/ContactsContract;\x00Lokhttp3/OkHttpClient;\x00",);
            zip.write_all(&dex).unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        // 应检测到通讯录读取 (MAL-301)
        assert!(result.findings.iter().any(|f| f.id == "MAL-301"));
        // 应检测到网络通信 (MAL-702)
        assert!(result.findings.iter().any(|f| f.id == "MAL-702"));
        // 应触发综合判断: 通讯录上传 (MAL-900)
        assert!(result.findings.iter().any(|f| f.id == "MAL-900" && f.severity == "high"));
        // 统计应正确
        assert!(result.behavior_summary.contacts_apis > 0);
        assert!(result.behavior_summary.network_apis > 0);
    }

    /// 端到端: 短信 + 网络组合 = 短信上传
    #[test]
    fn test_scan_zip_sms_upload_detected() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex = vec![0u8; 120];
            dex[0..4].copy_from_slice(b"dex\n");
            dex[4..7].copy_from_slice(b"039");
            dex.extend_from_slice(
                b"\x00Landroid/provider/Telephony$Sms;\x00Ljava/net/HttpURLConnection;\x00",);
            zip.write_all(&dex).unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        assert!(result.findings.iter().any(|f| f.id == "MAL-105"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-701"));
        // 短信 + 网络组合
        assert!(result.findings.iter().any(|f| f.id == "MAL-902"));
    }

    /// 端到端: 通话记录 + 网络组合 = 通话记录上传
    #[test]
    fn test_scan_zip_call_log_upload_detected() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex = vec![0u8; 120];
            dex[0..4].copy_from_slice(b"dex\n");
            dex[4..7].copy_from_slice(b"039");
            dex.extend_from_slice(
                b"\x00Landroid/provider/CallLog;\x00Lokhttp3/OkHttpClient;\x00",);
            zip.write_all(&dex).unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        assert!(result.findings.iter().any(|f| f.id == "MAL-201"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-702"));
        // 通话记录 + 网络组合
        assert!(result.findings.iter().any(|f| f.id == "MAL-901"));
    }

    /// 端到端: 仅网络,不触发上传组合告警
    #[test]
    fn test_scan_zip_network_only_no_combination_alert() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex = vec![0u8; 120];
            dex[0..4].copy_from_slice(b"dex\n");
            dex[4..7].copy_from_slice(b"039");
            dex.extend_from_slice(b"\x00Lokhttp3/OkHttpClient;\x00");
            zip.write_all(&dex).unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        assert!(result.findings.iter().any(|f| f.id == "MAL-702"));
        // 不应触发任何 MAL-9xx 组合告警
        assert!(!result.findings.iter().any(|f| f.id.starts_with("MAL-9")));
    }

    /// 端到端: 多 DEX 文件应都扫描,统计累加
    #[test]
    fn test_scan_zip_multi_dex() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            // classes.dex: 含 SmsManager
            zip.start_file("classes.dex", opts).unwrap();
            let mut dex1 = vec![0u8; 120];
            dex1[0..4].copy_from_slice(b"dex\n");
            dex1[4..7].copy_from_slice(b"039");
            dex1.extend_from_slice(b"\x00Landroid/telephony/SmsManager;\x00");
            zip.write_all(&dex1).unwrap();
            // classes2.dex: 含 OkHttp
            zip.start_file("classes2.dex", opts).unwrap();
            let mut dex2 = vec![0u8; 120];
            dex2[0..4].copy_from_slice(b"dex\n");
            dex2[4..7].copy_from_slice(b"039");
            dex2.extend_from_slice(b"\x00Lokhttp3/OkHttpClient;\x00");
            zip.write_all(&dex2).unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        // 两 DEX 应都被扫描
        assert_eq!(result.scanned_dex.len(), 2);
        assert!(result.scanned_dex.contains(&"classes.dex".to_string()));
        assert!(result.scanned_dex.contains(&"classes2.dex".to_string()));
        // 跨 DEX 综合判断: 短信 + 网络应触发 MAL-902
        assert!(result.findings.iter().any(|f| f.id == "MAL-902"));
        assert!(result.behavior_summary.sms_apis > 0);
        assert!(result.behavior_summary.network_apis > 0);
    }

    /// 端到端: 裸 DEX 文件扫描
    #[test]
    fn test_scan_bytes_inline_dex() {
        let data = build_malicious_dex();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_bytes(&data).expect("扫描应成功");
        assert!(result.scanned_dex.iter().any(|s| s == "(inline)"));
        // 应检测到多个恶意行为
        assert!(result.findings.iter().any(|f| f.id == "MAL-101"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-102"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-202"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-302"));
        assert!(result.findings.iter().any(|f| f.id == "MAL-401"));
    }

    /// 端到端: 非 ZIP 也非 DEX 的数据不应报错
    #[test]
    fn test_scan_bytes_plain_text() {
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_bytes(b"plain text data").expect("应不报错");
        assert!(result.findings.is_empty());
        assert!(result.scanned_dex.is_empty());
    }

    #[test]
    fn test_scan_file_not_found() {
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_file("/nonexistent/path.apk");
        assert!(matches!(result, Err(MaliciousScanError::FileNotFound(_))));
    }

    #[test]
    fn test_with_max_file_bytes() {
        let scanner = MaliciousBehaviorScanner::new().with_max_file_bytes(50);
        assert_eq!(scanner.max_file_bytes, 50);
    }

    #[test]
    fn test_behavior_kind_equality() {
        assert_eq!(BehaviorKind::Sms, BehaviorKind::Sms);
        assert_ne!(BehaviorKind::Sms, BehaviorKind::Network);
    }

    /// 端到端: 空 ZIP (无 DEX) 不应报错
    #[test]
    fn test_scan_zip_empty() {
        let mut buf = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            zip.start_file("README.txt", opts).unwrap();
            zip.write_all(b"no dex here").unwrap();
            zip.finish().unwrap();
        }
        let cursor = std::io::Cursor::new(buf);
        let mut zip = ZipArchive::new(cursor).unwrap();
        let scanner = MaliciousBehaviorScanner::new();
        let result = scanner.scan_zip(&mut zip).expect("扫描应成功");
        assert!(result.findings.is_empty());
        assert!(result.scanned_dex.is_empty());
    }
}
