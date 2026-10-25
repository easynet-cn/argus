//! HTML 合规报告渲染
//!
//! 生成可视化的基线核查报告 HTML 页面

use crate::report::BaselineReport;
use crate::types::ComplianceLevel;

/// 渲染 HTML 报告
pub fn render_report(report: &BaselineReport) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n");
    html.push_str(&format!("<title>基线核查报告 - {}</title>\n", escape_html(&report.host)));
    html.push_str("<style>\n");
    html.push_str(CSS);
    html.push_str("</style>\n</head>\n<body>\n");

    // 标题
    html.push_str("<div class=\"header\">\n");
    html.push_str("<h1>基线核查合规报告</h1>\n");
    html.push_str(&format!(
        "<p>目标主机: <strong>{}</strong> | 规则集: <strong>{}</strong></p>\n",
        escape_html(&report.host),
        escape_html(&report.rule_set)
    ));
    html.push_str(&format!(
        "<p>核查时间: {}</p>\n",
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    html.push_str("</div>\n");

    // 概要
    let s = &report.summary;
    let rate_color = if s.compliance_rate >= 0.8 {
        "#27ae60"
    } else if s.compliance_rate >= 0.6 {
        "#f39c12"
    } else {
        "#e74c3c"
    };
    html.push_str("<div class=\"summary\">\n");
    html.push_str("<h2>合规概要</h2>\n");
    html.push_str("<div class=\"stats\">\n");
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"label\">总规则</span><span class=\"value\">{}</span></div>\n",
        s.total
    ));
    html.push_str(&format!(
        "<div class=\"stat compliant\"><span class=\"label\">合规</span><span class=\"value\">{}</span></div>\n",
        s.compliant
    ));
    html.push_str(&format!(
        "<div class=\"stat non-compliant\"><span class=\"label\">不合规</span><span class=\"value\">{}</span></div>\n",
        s.non_compliant
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"label\">不适用</span><span class=\"value\">{}</span></div>\n",
        s.not_applicable
    ));
    html.push_str(&format!(
        "<div class=\"stat\"><span class=\"label\">无法判定</span><span class=\"value\">{}</span></div>\n",
        s.unknown
    ));
    html.push_str("</div>\n");
    html.push_str(&format!(
        "<div class=\"rate\" style=\"border-color:{rate_color}\"><span>合规率</span><strong style=\"color:{rate_color}\">{:.1}%</strong></div>\n",
        s.compliance_rate * 100.0
    ));
    html.push_str("</div>\n");

    // 按类别分组详情
    let groups = report.grouped_by_category();
    for (category, results) in groups {
        html.push_str("<div class=\"category\">\n");
        html.push_str(&format!("<h2>{}</h2>\n", escape_html(&category)));
        html.push_str("<table>\n<thead><tr><th>规则</th><th>条款</th><th>级别</th><th>合规</th><th>说明</th><th>修复建议</th></tr></thead>\n<tbody>\n");
        for r in results {
            let (cls, label) = match r.compliance {
                ComplianceLevel::Compliant => ("compliant", "合规"),
                ComplianceLevel::NonCompliant => ("non-compliant", "不合规"),
                ComplianceLevel::NotApplicable => ("na", "不适用"),
                ComplianceLevel::Unknown => ("unknown", "未知"),
            };
            let sev_cls = r.severity.as_str();
            html.push_str(&format!(
                "<tr class=\"{cls}\"><td>{}</td><td>{}</td><td class=\"sev sev-{sev_cls}\">{}</td><td>{label}</td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&r.rule_name),
                escape_html(&r.requirement_id),
                escape_html(&r.severity),
                escape_html(r.message.as_deref().unwrap_or("")),
                escape_html(r.fix_advice.as_deref().unwrap_or(""))
            ));
        }
        html.push_str("</tbody></table>\n</div>\n");
    }

    html.push_str("</body>\n</html>\n");
    html
}

/// HTML 转义
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const CSS: &str = r#"
body { font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
.header { background: #2c3e50; color: white; padding: 20px 30px; border-radius: 8px; margin-bottom: 20px; }
.header h1 { margin: 0 0 10px 0; }
.header p { margin: 5px 0; }
.summary { background: white; padding: 20px 30px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.stats { display: flex; gap: 15px; margin: 15px 0; }
.stat { flex: 1; text-align: center; padding: 15px; background: #f8f9fa; border-radius: 6px; border: 1px solid #e0e0e0; }
.stat .label { display: block; font-size: 12px; color: #888; margin-bottom: 5px; }
.stat .value { display: block; font-size: 24px; font-weight: bold; }
.stat.compliant .value { color: #27ae60; }
.stat.non-compliant .value { color: #e74c3c; }
.rate { margin-top: 15px; padding: 15px; text-align: center; border: 2px solid; border-radius: 6px; }
.rate span { display: block; font-size: 14px; color: #888; margin-bottom: 5px; }
.rate strong { font-size: 28px; }
.category { background: white; padding: 20px 30px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.category h2 { border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 0; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th { background: #34495e; color: white; padding: 10px; text-align: left; font-size: 13px; }
td { padding: 10px; border-bottom: 1px solid #e0e0e0; font-size: 13px; }
tr.compliant { background: #eafaf1; }
tr.non-compliant { background: #fdedec; }
tr.na { background: #fef9e7; }
tr.unknown { background: #f4f6f7; }
.sev-high { color: #e74c3c; font-weight: bold; }
.sev-medium { color: #f39c12; }
.sev-low { color: #95a5a6; }
"#;
