//! Argus 基线核查引擎
//!
//! 支持 SSH/SMB/Telnet 远程登录采集 + 配置规则 DSL 引擎 + 合规报告生成
//! 内置 GB/T 22239 等保三级基线规则集（Linux/Windows）

pub mod collector;
pub mod report;
pub mod rule_engine;
pub mod rules;
pub mod scanner;
pub mod types;
pub mod vsphere_rules;

pub use scanner::BaselineScanner;
pub use rule_engine::RuleEngine;
pub use report::BaselineReport;
pub use types::{
    BaselineParams, BaselineSummary, CheckResult, CollectItem, CollectMethod,
    ComplianceLevel, ComplianceRule,
};
pub use rules::{load_rule_set, list_builtin_rule_sets, RuleSet};
pub use collector::{Collector, create_collector};
