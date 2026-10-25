//! 内置基线规则集
//!
//! 对标 GB/T 22239 等保三级要求，覆盖 Linux/Windows 常见配置基线
//! 规则分为采集项（CollectItem）和合规规则（ComplianceRule）两部分

pub mod gbt22239_l3_linux;
pub mod db_rules;
pub mod gbt22239_l3_windows;
pub mod firewall_rules;
pub mod network_device_rules;

use crate::types::{CollectItem, ComplianceRule};

/// 基线规则集
#[derive(Debug, Clone)]
pub struct RuleSet {
    /// 规则集名称
    pub name: String,
    /// 规则集描述
    pub description: String,
    /// 采集项列表
    pub collect_items: Vec<CollectItem>,
    /// 合规规则列表
    pub rules: Vec<ComplianceRule>,
}

impl RuleSet {
    /// 根据采集项 ID 查找采集项
    pub fn find_collect_item(&self, id: &str) -> Option<&CollectItem> {
        self.collect_items.iter().find(|c| c.id == id)
    }

    /// 根据采集项 ID 查找所有关联规则
    pub fn rules_for_item(&self, collect_item_id: &str) -> Vec<&ComplianceRule> {
        self.rules
            .iter()
            .filter(|r| r.collect_item_id == collect_item_id)
            .collect()
    }
}

/// 根据名称加载内置规则集
pub fn load_rule_set(name: &str) -> Option<RuleSet> {
    match name {
        "gbt22239_l3_linux" => Some(gbt22239_l3_linux::rule_set()),
        "gbt22239_l3_windows" => Some(gbt22239_l3_windows::rule_set()),
        "mysql_baseline" => Some(db_rules::mysql_baseline()),
        "postgresql_baseline" => Some(db_rules::postgresql_baseline()),
        "redis_baseline" => Some(db_rules::redis_baseline()),
        "mongodb_baseline" => Some(db_rules::mongodb_baseline()),
        "security_device_baseline" => Some(firewall_rules::security_device_baseline()),
        "network_device_baseline" => Some(network_device_rules::network_device_baseline()),
        "vsphere_baseline" => Some(crate::vsphere_rules::vsphere_baseline()),
        _ => None,
    }
}

/// 列出所有内置规则集名称
pub fn list_builtin_rule_sets() -> Vec<&'static str> {
    vec![
        "gbt22239_l3_linux",
        "gbt22239_l3_windows",
        "mysql_baseline",
        "postgresql_baseline",
        "redis_baseline",
        "mongodb_baseline",
        "security_device_baseline",
        "network_device_baseline",
        "vsphere_baseline",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_linux_rules() {
        let rs = load_rule_set("gbt22239_l3_linux");
        assert!(rs.is_some());
        let rs = rs.unwrap();
        assert!(!rs.collect_items.is_empty());
        assert!(!rs.rules.is_empty());
    }

    #[test]
    fn test_load_windows_rules() {
        let rs = load_rule_set("gbt22239_l3_windows");
        assert!(rs.is_some());
    }

    #[test]
    fn test_load_unknown_returns_none() {
        assert!(load_rule_set("unknown").is_none());
    }

    #[test]
    fn test_list_builtin() {
        let names = list_builtin_rule_sets();
        assert!(names.contains(&"gbt22239_l3_linux"));
    }

    #[test]
    fn test_find_collect_item() {
        let rs = load_rule_set("gbt22239_l3_linux").unwrap();
        let first = &rs.collect_items[0];
        let found = rs.find_collect_item(&first.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, first.id);
    }

    #[test]
    fn test_rules_for_item() {
        let rs = load_rule_set("gbt22239_l3_linux").unwrap();
        if let Some(first_item) = rs.collect_items.first() {
            let rules = rs.rules_for_item(&first_item.id);
            assert!(!rules.is_empty(), "采集项应至少关联一条规则");
        }
    }

    #[test]
    fn test_linux_rules_count_50_plus() {
        let rs = load_rule_set("gbt22239_l3_linux").unwrap();
        assert!(rs.rules.len() >= 50, "Linux 规则数应 >= 50，当前 {}", rs.rules.len());
        assert!(rs.collect_items.len() >= 30, "Linux 采集项数应 >= 30，当前 {}", rs.collect_items.len());
    }

    #[test]
    fn test_windows_rules_count_20_plus() {
        let rs = load_rule_set("gbt22239_l3_windows").unwrap();
        assert!(rs.rules.len() >= 20, "Windows 规则数应 >= 20，当前 {}", rs.rules.len());
        assert!(rs.collect_items.len() >= 14, "Windows 采集项数应 >= 14，当前 {}", rs.collect_items.len());
    }

    #[test]
    fn test_load_security_device_baseline() {
        let rs = load_rule_set("security_device_baseline");
        assert!(rs.is_some(), "security_device_baseline 规则集应可加载");
        let rs = rs.unwrap();
        assert_eq!(rs.name, "security_device_baseline");
        assert!(!rs.collect_items.is_empty());
        assert!(!rs.rules.is_empty());
    }

    #[test]
    fn test_load_network_device_baseline() {
        let rs = load_rule_set("network_device_baseline");
        assert!(rs.is_some(), "network_device_baseline 规则集应可加载");
        let rs = rs.unwrap();
        assert_eq!(rs.name, "network_device_baseline");
        assert!(!rs.collect_items.is_empty());
        assert!(!rs.rules.is_empty());
    }

    #[test]
    fn test_security_device_rule_refs_valid_collect_items() {
        let rs = load_rule_set("security_device_baseline").unwrap();
        for rule in &rs.rules {
            assert!(
                rs.find_collect_item(&rule.collect_item_id).is_some(),
                "安全设备规则 {} 引用了不存在的采集项 {}",
                rule.id,
                rule.collect_item_id
            );
        }
    }

    #[test]
    fn test_network_device_rule_refs_valid_collect_items() {
        let rs = load_rule_set("network_device_baseline").unwrap();
        for rule in &rs.rules {
            assert!(
                rs.find_collect_item(&rule.collect_item_id).is_some(),
                "网络设备规则 {} 引用了不存在的采集项 {}",
                rule.id,
                rule.collect_item_id
            );
        }
    }

    #[test]
    fn test_list_builtin_includes_new_sets() {
        let names = list_builtin_rule_sets();
        assert!(names.contains(&"security_device_baseline"));
        assert!(names.contains(&"network_device_baseline"));
    }

    #[test]
    fn test_linux_rule_refs_valid_collect_items() {
        let rs = load_rule_set("gbt22239_l3_linux").unwrap();
        for rule in &rs.rules {
            assert!(
                rs.find_collect_item(&rule.collect_item_id).is_some(),
                "Linux 规则 {} 引用了不存在的采集项 {}",
                rule.id,
                rule.collect_item_id
            );
        }
    }

    #[test]
    fn test_windows_rule_refs_valid_collect_items() {
        let rs = load_rule_set("gbt22239_l3_windows").unwrap();
        for rule in &rs.rules {
            assert!(
                rs.find_collect_item(&rule.collect_item_id).is_some(),
                "Windows 规则 {} 引用了不存在的采集项 {}",
                rule.id,
                rule.collect_item_id
            );
        }
    }

    #[test]
    fn test_all_rule_scripts_validate() {
        use crate::rule_engine::RuleEngine;
        for name in list_builtin_rule_sets() {
            let rs = load_rule_set(name).unwrap();
            for rule in &rs.rules {
                let result = RuleEngine::validate_script(&rule.check_script);
                assert!(
                    result.is_ok(),
                    "规则集 {} 中规则 {} 脚本语法无效: {:?}",
                    name,
                    rule.id,
                    result.err()
                );
            }
        }
    }

    #[test]
    fn test_linux_new_rules_compliance() {
        use crate::rule_engine::RuleEngine;
        let rs = load_rule_set("gbt22239_l3_linux").unwrap();
        let engine = RuleEngine::new();

        // SSH 端口变更：非 22 应合规
        let rule = rs.rules.iter().find(|r| r.id == "ssh_port_changed").unwrap();
        let result = engine.evaluate(rule, "X11Forwarding no
Port 2222");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
        // 默认 22 应不合规
        let result = engine.evaluate(rule, "Port 22
UseDNS no");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));

        // core dump 限制
        let rule = rs.rules.iter().find(|r| r.id == "core_dump_disabled").unwrap();
        let result = engine.evaluate(rule, "*       soft    core    0
root    hard    core    0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // umask 027 合规
        let rule = rs.rules.iter().find(|r| r.id == "umask_strict").unwrap();
        let result = engine.evaluate(rule, "umask 027");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // dccp 模块未加载（输出 NONE）应合规
        let rule = rs.rules.iter().find(|r| r.id == "dccp_disabled").unwrap();
        let result = engine.evaluate(rule, "NONE");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // pam_su 限制
        let rule = rs.rules.iter().find(|r| r.id == "pam_su_restricted").unwrap();
        let result = engine.evaluate(rule, "auth       required    pam_wheel.so use_uid");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_windows_new_rules_compliance() {
        use crate::rule_engine::RuleEngine;
        let rs = load_rule_set("gbt22239_l3_windows").unwrap();
        let engine = RuleEngine::new();

        // 匿名访问限制
        let rule = rs.rules.iter().find(|r| r.id == "win_anonymous_restricted").unwrap();
        let result = engine.evaluate(rule, "RestrictAnonymous    REG_DWORD    0x1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // 禁用自动登录
        let rule = rs.rules.iter().find(|r| r.id == "win_auto_logon_disabled").unwrap();
        let result = engine.evaluate(rule, "AutoAdminLogon    REG_SZ    0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // 密码历史 >= 5
        let rule = rs.rules.iter().find(|r| r.id == "win_pass_history").unwrap();
        let result = engine.evaluate(rule, "Length of password history maintained   5");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));

        // 密码复杂度启用
        let rule = rs.rules.iter().find(|r| r.id == "win_password_complexity_on").unwrap();
        let result = engine.evaluate(rule, "PasswordComplexity = 1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }
}
