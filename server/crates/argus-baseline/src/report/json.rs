//! JSON 报告输出

use crate::report::BaselineReport;

pub fn render_report(report: &BaselineReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}
