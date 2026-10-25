//! 合规报告生成模块
//!
//! 生成基线核查合规报告，支持多种输出格式

pub mod html;
pub mod json;

use crate::types::{BaselineSummary, CheckResult, ComplianceLevel};
use serde::{Deserialize, Serialize};

/// 基线核查报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineReport {
    /// 目标主机
    pub host: String,
    /// 规则集名称
    pub rule_set: String,
    /// 核查时间
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// 总结
    pub summary: BaselineSummary,
    /// 详细结果
    pub results: Vec<CheckResult>,
}

impl BaselineReport {
    pub fn new(host: String, rule_set: String, results: Vec<CheckResult>) -> Self {
        let summary = BaselineSummary::from_results(&results);
        Self {
            host,
            rule_set,
            timestamp: chrono::Utc::now(),
            summary,
            results,
        }
    }

    /// 按类别分组返回结果
    pub fn grouped_by_category(&self) -> Vec<(String, Vec<&CheckResult>)> {
        use std::collections::BTreeMap;
        let mut groups: BTreeMap<String, Vec<&CheckResult>> = BTreeMap::new();
        for r in &self.results {
            groups.entry(r.category.clone()).or_default().push(r);
        }
        groups.into_iter().collect()
    }

    /// 输出 JSON 格式
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// 输出 HTML 格式
    pub fn to_html(&self) -> String {
        html::render_report(self)
    }

    /// 输出简要文本摘要
    pub fn to_text_summary(&self) -> String {
        let s = &self.summary;
        let mut text = format!(
            "===== 基线核查报告 =====\n\
             目标: {}\n\
             规则集: {}\n\
             核查时间: {}\n\
             总规则数: {}\n\
             合规: {}\n\
             不合规: {}\n\
             不适用: {}\n\
             无法判定: {}\n\
             合规率: {:.1}%\n",
            self.host,
            self.rule_set,
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            s.total,
            s.compliant,
            s.non_compliant,
            s.not_applicable,
            s.unknown,
            s.compliance_rate * 100.0
        );
        // 列出不合规项
        let non_compliant: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.compliance == ComplianceLevel::NonCompliant)
            .collect();
        if !non_compliant.is_empty() {
            text.push_str("\n不合规项:\n");
            for r in non_compliant {
                text.push_str(&format!(
                    "  - [{}] {} ({}): {}\n",
                    r.severity,
                    r.rule_name,
                    r.requirement_id,
                    r.message.as_deref().unwrap_or("不合规")
                ));
                if let Some(advice) = &r.fix_advice {
                    text.push_str(&format!("    修复建议: {advice}\n"));
                }
            }
        }
        text
    }
}

/// 从 raw_data 反序列化报告（用于从数据库恢复）
pub fn report_from_json(json: &str) -> Result<BaselineReport, String> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_results() -> Vec<CheckResult> {
        vec![
            CheckResult {
                rule_id: "r1".to_string(),
                rule_name: "测试1".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "high".to_string(),
                compliance: ComplianceLevel::Compliant,
                collected_output: None,
                message: None,
                fix_advice: None,
            },
            CheckResult {
                rule_id: "r2".to_string(),
                rule_name: "测试2".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "medium".to_string(),
                compliance: ComplianceLevel::NonCompliant,
                collected_output: None,
                message: Some("不合规".to_string()),
                fix_advice: Some("修改配置".to_string()),
            },
        ]
    }

    #[test]
    fn test_report_creation() {
        let r = BaselineReport::new("192.168.1.1".to_string(), "gbt22239_l3_linux".to_string(), make_results());
        assert_eq!(r.host, "192.168.1.1");
        assert_eq!(r.summary.total, 2);
        assert_eq!(r.summary.compliant, 1);
        assert_eq!(r.summary.non_compliant, 1);
    }

    #[test]
    fn test_grouped_by_category() {
        let r = BaselineReport::new("h".to_string(), "rs".to_string(), make_results());
        let groups = r.grouped_by_category();
        assert_eq!(groups.len(), 2); // 身份鉴别 + 访问控制
    }

    #[test]
    fn test_to_json() {
        let r = BaselineReport::new("h".to_string(), "rs".to_string(), make_results());
        let json = r.to_json();
        assert!(json.contains("\"host\""));
        assert!(json.contains("\"summary\""));
    }

    #[test]
    fn test_to_text_summary() {
        let r = BaselineReport::new("h".to_string(), "rs".to_string(), make_results());
        let text = r.to_text_summary();
        assert!(text.contains("基线核查报告"));
        assert!(text.contains("合规率"));
        assert!(text.contains("不合规项"));
    }

    #[test]
    fn test_to_html() {
        let r = BaselineReport::new("h".to_string(), "rs".to_string(), make_results());
        let html = r.to_html();
        assert!(html.contains("<html"));
        assert!(html.contains("基线核查报告"));
    }

    #[test]
    fn test_report_from_json() {
        let r = BaselineReport::new("h".to_string(), "rs".to_string(), make_results());
        let json = r.to_json();
        let back = report_from_json(&json).unwrap();
        assert_eq!(back.host, r.host);
        assert_eq!(back.summary.total, r.summary.total);
    }
}
