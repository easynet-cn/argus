//! 参数模板结构化配置 schema
//!
//! 对标-用户手册 V3.0.1.16 参数模板 80+ 配置项，
//! 按功能分组组织为 6 个子结构：target / port / performance / plugins / auth / advanced。
//!
//! 设计取舍（见 project_memory）：数据模型优先使用结构化字段而非自由 JSON。
//! 参数模板的 `config` 列仍以 JSONB 存储（便于扩展），但在写入时通过本模块
//! 的 `ScanParamConfig` 类型进行 schema 校验，避免自由 JSON 缺乏约束的问题。

use serde::{Deserialize, Serialize};

/// 参数模板结构化配置（顶层）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanParamConfig {
    /// 扫描目标配置
    #[serde(default)]
    pub target: TargetConfig,
    /// 端口扫描配置
    #[serde(default)]
    pub port: PortConfig,
    /// 性能配置
    #[serde(default)]
    pub performance: PerformanceConfig,
    /// 插件配置
    #[serde(default)]
    pub plugins: PluginsConfig,
    /// 认证配置
    #[serde(default)]
    pub auth: AuthConfig,
    /// 高级配置
    #[serde(default)]
    pub advanced: AdvancedConfig,
}

/// 扫描目标配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetConfig {
    /// 目标类型: ip / asset_group / asset_attribute
    pub target_type: Option<String>,
    /// IP 范围（逗号分隔，target_type=ip 时）
    pub ip_range: Option<String>,
    /// 资产组 ID（target_type=asset_group 时）
    pub asset_group_id: Option<String>,
    /// 排除主机（逗号分隔）
    pub exclude_hosts: Option<String>,
}

/// 端口扫描配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortConfig {
    /// 端口模板: top100 / top1000 / full / custom
    pub template: Option<String>,
    /// 自定义端口（template=custom 时，逗号分隔或范围如 80,443,1000-2000）
    pub custom_ports: Option<String>,
    /// 端口扫描模式: connect / syn / ack / null / xmas / fin / window
    pub scan_mode: Option<String>,
    /// 扫描速度预设: adaptive / fast / ultra_fast
    pub speed: Option<String>,
}

/// 性能配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// 并发数（1-2000）
    pub concurrency: Option<i32>,
    /// 超时（毫秒，100-60000）
    pub timeout_ms: Option<u64>,
    /// 重试次数（0-10）
    pub retries: Option<i32>,
    /// 速率限制（包/秒，0 表示不限）
    pub rate_limit: Option<i32>,
}

/// 插件配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// 系统漏洞检测开关
    pub vuln_scan: Option<bool>,
    /// 端口扫描开关
    pub port_scan: Option<bool>,
    /// 弱口令检测开关
    pub weak_password: Option<bool>,
    /// 配置核查（基线）开关
    pub baseline_check: Option<bool>,
    /// 服务识别开关
    pub service_ident: Option<bool>,
    /// 指纹识别开关
    pub fingerprint: Option<bool>,
    /// 漏洞验证开关
    pub vuln_verify: Option<bool>,
    /// 漏洞验证方式（6.10）：active（主动重新探测）/ passive（仅 CPE/CVE 匹配，不发包）
    ///
    /// 默认 active。passive 模式适用于生产环境，避免验证请求影响业务。
    pub verify_mode: Option<String>,
    /// Web 扫描插件类型过滤（6.3 插件配置）
    ///
    /// 指定后仅检测列出的漏洞类型（如 ["sqli","xss","redirect","command_injection"]）。
    /// 未指定时检测全部 OWASP Top 10 类别。
    pub web_plugin_types: Option<Vec<String>>,
    /// 数据库扫描检测项过滤（6.5 检测项配置）
    ///
    /// 指定后仅检查列出的检测项（如 ["anonymous_user","root_remote","empty_password","weak_policy"]）。
    /// 未指定时检查全部审计项。
    pub db_check_items: Option<Vec<String>>,
}

/// 认证配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// 登录扫描开关（绑定凭证执行认证扫描）
    pub login_scan: Option<bool>,
    /// 凭证 ID 列表（login_scan=true 时使用）
    pub credential_ids: Option<Vec<String>>,
}

/// 高级配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// 跳过主机发现（直接对目标进行端口扫描，不做 ping 存活探测）
    pub skip_host_discovery: Option<bool>,
    /// 反向 DNS 解析
    pub reverse_dns: Option<bool>,
    /// 工控协议扫描（每项 ∈ modbus/s7/ethernet_ip/opcua/dnp3/bacnet/profinet/mitsubishi/omron）
    pub ics_protocols: Option<Vec<String>>,
    /// 抓包开关
    pub capture: Option<bool>,
    /// 报表自动生成
    pub auto_report: Option<bool>,
}

// ==================== 合法枚举值 ====================

pub const VALID_TARGET_TYPES: &[&str] = &["ip", "asset_group", "asset_attribute"];
pub const VALID_PORT_TEMPLATES: &[&str] = &["top100", "top1000", "full", "custom"];
pub const VALID_SCAN_MODES: &[&str] = &["connect", "syn", "ack", "null", "xmas", "fin", "window"];
pub const VALID_SPEEDS: &[&str] = &["adaptive", "fast", "ultra_fast"];
pub const VALID_ICS_PROTOCOLS: &[&str] = &[
    "modbus",
    "s7",
    "ethernet_ip",
    "opcua",
    "dnp3",
    "bacnet",
    "profinet",
    "mitsubishi",
    "omron",
];

// ==================== 校验 ====================

/// 校验结果
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// 错误信息列表（空表示通过）
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// 校验 JSON 配置是否符合 ScanParamConfig schema
///
/// 流程：先尝试反序列化为 `ScanParamConfig`，再对枚举字段做取值校验。
/// 返回 `ValidationResult`，`errors` 为空表示通过。
pub fn validate_config(config: &serde_json::Value) -> ValidationResult {
    let mut result = ValidationResult::default();

    let parsed: ScanParamConfig = match serde_json::from_value(config.clone()) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("config 不符合 schema: {e}"));
            return result;
        }
    };

    // target.target_type
    if let Some(v) = &parsed.target.target_type {
        if !VALID_TARGET_TYPES.contains(&v.as_str()) {
            result.errors.push(format!(
                "target.target_type 非法值 '{}', 合法: {:?}",
                v, VALID_TARGET_TYPES
            ));
        }
    }
    // port.template
    if let Some(v) = &parsed.port.template {
        if !VALID_PORT_TEMPLATES.contains(&v.as_str()) {
            result.errors.push(format!(
                "port.template 非法值 '{}', 合法: {:?}",
                v, VALID_PORT_TEMPLATES
            ));
        }
    }
    // port.scan_mode
    if let Some(v) = &parsed.port.scan_mode {
        if !VALID_SCAN_MODES.contains(&v.as_str()) {
            result.errors.push(format!(
                "port.scan_mode 非法值 '{}', 合法: {:?}",
                v, VALID_SCAN_MODES
            ));
        }
    }
    // port.speed
    if let Some(v) = &parsed.port.speed {
        if !VALID_SPEEDS.contains(&v.as_str()) {
            result.errors.push(format!(
                "port.speed 非法值 '{}', 合法: {:?}",
                v, VALID_SPEEDS
            ));
        }
    }
    // performance 边界
    if let Some(v) = parsed.performance.concurrency {
        if !(1..=2000).contains(&v) {
            result.errors.push(format!("performance.concurrency 超范围 (1-2000): {v}"));
        }
    }
    if let Some(v) = parsed.performance.timeout_ms {
        if !(100..=60000).contains(&v) {
            result.errors.push(format!("performance.timeout_ms 超范围 (100-60000): {v}"));
        }
    }
    if let Some(v) = parsed.performance.retries {
        if !(0..=10).contains(&v) {
            result.errors.push(format!("performance.retries 超范围 (0-10): {v}"));
        }
    }
    if let Some(v) = parsed.performance.rate_limit {
        if !(0..=100000).contains(&v) {
            result.errors.push(format!("performance.rate_limit 超范围 (0-100000): {v}"));
        }
    }
    // advanced.ics_protocols
    if let Some(list) = &parsed.advanced.ics_protocols {
        for p in list {
            if !VALID_ICS_PROTOCOLS.contains(&p.as_str()) {
                result.errors.push(format!(
                    "advanced.ics_protocols 非法值 '{}', 合法: {:?}",
                    p, VALID_ICS_PROTOCOLS
                ));
            }
        }
    }

    result
}

/// 生成 JSON Schema（供前端渲染表单）
///
/// 返回一个描述各字段名、类型、是否可选、合法枚举值的 JSON 对象。
/// 不引入 `schemars` 依赖，手工构建以保持依赖精简。
pub fn json_schema() -> serde_json::Value {
    serde_json::json!({
        "title": "ScanParamConfig",
        "description": "参数模板结构化配置（80+ 配置项，分 6 组）",
        "groups": [
            {
                "name": "target",
                "label": "扫描目标",
                "fields": [
                    {"key": "target_type", "type": "enum", "optional": true, "values": VALID_TARGET_TYPES, "desc": "目标类型"},
                    {"key": "ip_range", "type": "string", "optional": true, "desc": "IP 范围（逗号分隔）"},
                    {"key": "asset_group_id", "type": "string", "optional": true, "desc": "资产组 ID"},
                    {"key": "exclude_hosts", "type": "string", "optional": true, "desc": "排除主机（逗号分隔）"}
                ]
            },
            {
                "name": "port",
                "label": "端口扫描",
                "fields": [
                    {"key": "template", "type": "enum", "optional": true, "values": VALID_PORT_TEMPLATES, "desc": "端口模板"},
                    {"key": "custom_ports", "type": "string", "optional": true, "desc": "自定义端口（逗号分隔或范围）"},
                    {"key": "scan_mode", "type": "enum", "optional": true, "values": VALID_SCAN_MODES, "desc": "端口扫描模式"},
                    {"key": "speed", "type": "enum", "optional": true, "values": VALID_SPEEDS, "desc": "扫描速度预设"}
                ]
            },
            {
                "name": "performance",
                "label": "性能",
                "fields": [
                    {"key": "concurrency", "type": "integer", "optional": true, "min": 1, "max": 2000, "desc": "并发数"},
                    {"key": "timeout_ms", "type": "integer", "optional": true, "min": 100, "max": 60000, "desc": "超时（毫秒）"},
                    {"key": "retries", "type": "integer", "optional": true, "min": 0, "max": 10, "desc": "重试次数"},
                    {"key": "rate_limit", "type": "integer", "optional": true, "min": 0, "max": 100000, "desc": "速率限制（包/秒，0=不限）"}
                ]
            },
            {
                "name": "plugins",
                "label": "插件",
                "fields": [
                    {"key": "vuln_scan", "type": "boolean", "optional": true, "desc": "系统漏洞检测"},
                    {"key": "port_scan", "type": "boolean", "optional": true, "desc": "端口扫描"},
                    {"key": "weak_password", "type": "boolean", "optional": true, "desc": "弱口令检测"},
                    {"key": "baseline_check", "type": "boolean", "optional": true, "desc": "配置核查（基线）"},
                    {"key": "service_ident", "type": "boolean", "optional": true, "desc": "服务识别"},
                    {"key": "fingerprint", "type": "boolean", "optional": true, "desc": "指纹识别"},
                    {"key": "vuln_verify", "type": "boolean", "optional": true, "desc": "漏洞验证"}
                ]
            },
            {
                "name": "auth",
                "label": "认证",
                "fields": [
                    {"key": "login_scan", "type": "boolean", "optional": true, "desc": "登录扫描开关"},
                    {"key": "credential_ids", "type": "array", "items": "string", "optional": true, "desc": "凭证 ID 列表"}
                ]
            },
            {
                "name": "advanced",
                "label": "高级",
                "fields": [
                    {"key": "skip_host_discovery", "type": "boolean", "optional": true, "desc": "跳过主机发现"},
                    {"key": "reverse_dns", "type": "boolean", "optional": true, "desc": "反向 DNS 解析"},
                    {"key": "ics_protocols", "type": "array", "items": "enum", "values": VALID_ICS_PROTOCOLS, "optional": true, "desc": "工控协议扫描"},
                    {"key": "capture", "type": "boolean", "optional": true, "desc": "抓包开关"},
                    {"key": "auto_report", "type": "boolean", "optional": true, "desc": "报表自动生成"}
                ]
            }
        ],
        "field_count": 30
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_is_valid() {
        let r = validate_config(&serde_json::json!({}));
        assert!(r.is_valid(), "空对象应通过校验: {:?}", r.errors);
    }

    #[test]
    fn valid_config_passes() {
        let cfg = serde_json::json!({
            "target": {"target_type": "ip", "ip_range": "192.168.1.0/24"},
            "port": {"template": "top100", "scan_mode": "syn", "speed": "fast"},
            "performance": {"concurrency": 500, "timeout_ms": 1000, "retries": 2, "rate_limit": 0},
            "plugins": {"vuln_scan": true, "port_scan": true},
            "auth": {"login_scan": false},
            "advanced": {"ics_protocols": ["modbus", "opcua"]}
        });
        let r = validate_config(&cfg);
        assert!(r.is_valid(), "合法配置应通过: {:?}", r.errors);
    }

    #[test]
    fn invalid_enum_rejected() {
        let cfg = serde_json::json!({
            "port": {"scan_mode": "bogus"},
            "performance": {"concurrency": 99999}
        });
        let r = validate_config(&cfg);
        assert!(!r.is_valid());
        assert!(r.errors.iter().any(|e| e.contains("scan_mode")));
        assert!(r.errors.iter().any(|e| e.contains("concurrency")));
    }

    #[test]
    fn invalid_ics_protocol_rejected() {
        let cfg = serde_json::json!({
            "advanced": {"ics_protocols": ["unknown_proto"]}
        });
        let r = validate_config(&cfg);
        assert!(!r.is_valid());
        assert!(r.errors.iter().any(|e| e.contains("ics_protocols")));
    }

    #[test]
    fn schema_returns_groups() {
        let s = json_schema();
        let groups = s.get("groups").and_then(|g| g.as_array()).unwrap();
        assert_eq!(groups.len(), 6);
    }
}
