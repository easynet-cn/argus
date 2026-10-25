//! 基线核查类型定义
//!
//! 定义采集项、合规规则、核查结果等核心数据结构

use serde::{Deserialize, Serialize};

/// 采集方式
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CollectMethod {
    /// SSH 远程登录采集
    Ssh,
    /// SMB 远程登录采集（Windows）
    Smb,
    /// Telnet 远程登录采集（网络设备）
    Telnet,
    /// 离线脚本采集（Agent 模式）
    Agent,
    /// 离线数据导入（用户上传采集脚本输出的 JSON）
    Offline,
}

impl CollectMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            CollectMethod::Ssh => "ssh",
            CollectMethod::Smb => "smb",
            CollectMethod::Telnet => "telnet",
            CollectMethod::Agent => "agent",
            CollectMethod::Offline => "offline",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ssh" => Some(CollectMethod::Ssh),
            "smb" => Some(CollectMethod::Smb),
            "telnet" => Some(CollectMethod::Telnet),
            "agent" => Some(CollectMethod::Agent),
            "offline" => Some(CollectMethod::Offline),
            _ => None,
        }
    }
}

/// 采集项：描述如何从目标主机获取一项配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectItem {
    /// 采集项 ID（唯一）
    pub id: String,
    /// 采集项名称
    pub name: String,
    /// 采集方式
    pub method: CollectMethod,
    /// 采集命令（SSH/Telnet 为 shell 命令，SMB 为 WMI 查询，Agent 为脚本路径）
    pub command: String,
    /// 采集项描述
    pub description: Option<String>,
}

/// 合规级别（对标 GB/T 22239 等保三级）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceLevel {
    /// 符合
    Compliant,
    /// 不符合
    NonCompliant,
    /// 不适用
    NotApplicable,
    /// 无法判定（采集失败等）
    Unknown,
}

impl ComplianceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceLevel::Compliant => "compliant",
            ComplianceLevel::NonCompliant => "non_compliant",
            ComplianceLevel::NotApplicable => "not_applicable",
            ComplianceLevel::Unknown => "unknown",
        }
    }
}

/// 合规规则：描述如何判定一项配置是否合规
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    /// 规则 ID
    pub id: String,
    /// 规则名称
    pub name: String,
    /// 所属基线类别（如"身份鉴别"、"访问控制"）
    pub category: String,
    /// 等保要求条款编号（对标 GB/T 22239）
    pub requirement_id: String,
    /// 严重级别（high/medium/low）
    pub severity: String,
    /// 关联的采集项 ID
    pub collect_item_id: String,
    /// 判定逻辑（Rhai 脚本表达式）
    /// 脚本上下文变量 `output` 为采集命令的输出文本
    /// 返回值：true=合规，false=不合规
    pub check_script: String,
    /// 期望值描述（人类可读）
    pub expected: Option<String>,
    /// 修复建议
    pub fix_advice: Option<String>,
}

/// 单项核查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// 规则 ID
    pub rule_id: String,
    /// 规则名称
    pub rule_name: String,
    /// 所属类别
    pub category: String,
    /// 等保要求条款编号
    pub requirement_id: String,
    /// 严重级别
    pub severity: String,
    /// 合规级别
    pub compliance: ComplianceLevel,
    /// 采集到的原始输出
    pub collected_output: Option<String>,
    /// 不合规时的说明
    pub message: Option<String>,
    /// 修复建议
    pub fix_advice: Option<String>,
}

/// 基线核查参数（从 API 传入）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineParams {
    /// 目标主机
    pub host: String,
    /// SSH 端口
    pub port: Option<u16>,
    /// 采集方式
    pub method: String,
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
    /// 基线规则集名称（如 "gbt22239_l3_linux" / "gbt22239_l3_windows"）
    pub rule_set: Option<String>,
    /// 超时（毫秒）
    pub timeout_ms: Option<u64>,
    /// 离线采集数据（method=offline 时使用）
    /// 格式：{ "item_id": "command_output", ... }
    pub offline_data: Option<serde_json::Value>,
}

impl Default for BaselineParams {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: Some(22),
            method: "ssh".to_string(),
            username: String::new(),
            password: String::new(),
            rule_set: Some("gbt22239_l3_linux".to_string()),
            timeout_ms: Some(10000),
            offline_data: None,
        }
    }
}

/// 基线核查总结报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    /// 总规则数
    pub total: usize,
    /// 合规数
    pub compliant: usize,
    /// 不合规数
    pub non_compliant: usize,
    /// 不适用数
    pub not_applicable: usize,
    /// 无法判定数
    pub unknown: usize,
    /// 合规率（0.0 - 1.0）
    pub compliance_rate: f64,
}

impl BaselineSummary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let total = results.len();
        let compliant = results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::Compliant)
            .count();
        let non_compliant = results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::NonCompliant)
            .count();
        let not_applicable = results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::NotApplicable)
            .count();
        let unknown = results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::Unknown)
            .count();
        let compliance_rate = if total > 0 {
            compliant as f64 / total as f64
        } else {
            0.0
        };
        Self {
            total,
            compliant,
            non_compliant,
            not_applicable,
            unknown,
            compliance_rate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_method_round_trip() {
        for m in &[
            CollectMethod::Ssh,
            CollectMethod::Smb,
            CollectMethod::Telnet,
            CollectMethod::Agent,
        ] {
            let s = m.as_str();
            let back = CollectMethod::from_str(s).unwrap();
            assert_eq!(*m, back);
        }
        assert!(CollectMethod::from_str("invalid").is_none());
    }

    #[test]
    fn test_summary_empty() {
        let s = BaselineSummary::from_results(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.compliance_rate, 0.0);
    }

    #[test]
    fn test_summary_with_results() {
        let results = vec![
            CheckResult {
                rule_id: "r1".into(),
                rule_name: "test1".into(),
                category: "cat".into(),
                requirement_id: "8.1.1".into(),
                severity: "high".into(),
                compliance: ComplianceLevel::Compliant,
                collected_output: None,
                message: None,
                fix_advice: None,
            },
            CheckResult {
                rule_id: "r2".into(),
                rule_name: "test2".into(),
                category: "cat".into(),
                requirement_id: "8.1.2".into(),
                severity: "high".into(),
                compliance: ComplianceLevel::NonCompliant,
                collected_output: None,
                message: Some("密码策略不合规".into()),
                fix_advice: None,
            },
        ];
        let s = BaselineSummary::from_results(&results);
        assert_eq!(s.total, 2);
        assert_eq!(s.compliant, 1);
        assert_eq!(s.non_compliant, 1);
        assert!((s.compliance_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_baseline_params_default() {
        let p = BaselineParams::default();
        assert_eq!(p.port, Some(22));
        assert_eq!(p.method, "ssh");
        assert_eq!(p.rule_set, Some("gbt22239_l3_linux".to_string()));
    }
}
