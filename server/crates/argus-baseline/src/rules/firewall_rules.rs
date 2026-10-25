//! G3.1 安全设备基线规则
//!
//! 对标 GB/T 22239 等保三级要求，覆盖防火墙 / IDS / IPS 等安全设备配置基线
//! 安全设备通常通过 SSH/Telnet 登录进行配置管理，本规则集基于常见厂商
//! （Cisco ASA / 华为 / H3C / Hillstone / 深信服等）的 running-config 输出做数据驱动匹配
//!
//! 覆盖检查点：
//! - SSH/Telnet 访问限制
//! - 管理接口隔离
//! - 强身份鉴别
//! - 日志配置
//! - 访问控制策略

use crate::rules::RuleSet;
use crate::types::{CollectItem, CollectMethod, ComplianceRule};

/// G3.1 安全设备（防火墙/IDS/IPS）基线规则集
pub fn security_device_baseline() -> RuleSet {
    RuleSet {
        name: "security_device_baseline".to_string(),
        description: "G3.1 安全设备（防火墙/IDS/IPS）基线核查规则集".to_string(),
        collect_items: collect_items(),
        rules: compliance_rules(),
    }
}

fn collect_items() -> Vec<CollectItem> {
    vec![
        // ===== 运行配置（核心采集项）=====
        CollectItem {
            id: "fw_running_config".to_string(),
            name: "安全设备运行配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config".to_string(),
            description: Some("采集安全设备 running-config 全量配置".to_string()),
        },
        // ===== 身份鉴别：SSH/Telnet 访问限制 =====
        CollectItem {
            id: "fw_ssh_config".to_string(),
            name: "SSH 管理访问配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include ssh".to_string(),
            description: Some("采集 SSH 服务相关配置（如 ssh version / ssh server / aaa authentication ssh）".to_string()),
        },
        CollectItem {
            id: "fw_telnet_config".to_string(),
            name: "Telnet 管理访问配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include telnet".to_string(),
            description: Some("采集 Telnet 服务相关配置".to_string()),
        },
        // ===== 身份鉴别：强认证 =====
        CollectItem {
            id: "fw_aaa_config".to_string(),
            name: "AAA 认证配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include aaa".to_string(),
            description: Some("采集 AAA 认证授权配置".to_string()),
        },
        CollectItem {
            id: "fw_admin_users".to_string(),
            name: "管理员账户配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include username".to_string(),
            description: Some("采集本地管理员账户及密码加密方式".to_string()),
        },
        CollectItem {
            id: "fw_password_policy".to_string(),
            name: "密码策略配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include password|password-policy".to_string(),
            description: Some("采集密码策略与密码加密配置".to_string()),
        },
        // ===== 管理接口隔离 =====
        CollectItem {
            id: "fw_management_if".to_string(),
            name: "管理接口配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include management-interface|management access|http|mgmt".to_string(),
            description: Some("采集管理接口隔离与 HTTP/HTTPS 管理访问配置".to_string()),
        },
        // ===== 日志配置 =====
        CollectItem {
            id: "fw_logging_config".to_string(),
            name: "日志配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include logging".to_string(),
            description: Some("采集日志服务器、日志级别等配置".to_string()),
        },
        // ===== 访问控制策略 =====
        CollectItem {
            id: "fw_access_policy".to_string(),
            name: "访问控制策略".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include access-list|access-group|policy".to_string(),
            description: Some("采集访问控制列表与策略配置".to_string()),
        },
        // ===== 其他安全相关 =====
        CollectItem {
            id: "fw_snmp_config".to_string(),
            name: "SNMP 配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include snmp".to_string(),
            description: Some("采集 SNMP 团体字及版本配置".to_string()),
        },
        CollectItem {
            id: "fw_banner_config".to_string(),
            name: "登录 Banner 配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include banner".to_string(),
            description: Some("采集登录 Banner/MOTD 配置".to_string()),
        },
        CollectItem {
            id: "fw_ntp_config".to_string(),
            name: "NTP 时间同步配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include ntp".to_string(),
            description: Some("采集 NTP 时间同步配置".to_string()),
        },
        CollectItem {
            id: "fw_session_timeout".to_string(),
            name: "会话超时配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include timeout|exec-timeout|idle-timeout".to_string(),
            description: Some("采集管理会话超时配置".to_string()),
        },
    ]
}

fn compliance_rules() -> Vec<ComplianceRule> {
    vec![
        // ===== 身份鉴别：SSH/Telnet 访问限制 =====
        ComplianceRule {
            id: "fw_ssh_enabled".to_string(),
            name: "启用 SSH 加密管理访问".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_ssh_config".to_string(),
            check_script: "contains(output, 'ssh')".to_string(),
            expected: Some("运行配置中存在 ssh 相关配置".to_string()),
            fix_advice: Some("启用 SSH 服务: ssh server enable / ssh version 2".to_string()),
        },
        ComplianceRule {
            id: "fw_ssh_version_2".to_string(),
            name: "SSH 使用版本 2".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_ssh_config".to_string(),
            check_script: "contains(output, 'ssh version 2') || contains(output, 'ssh server version 2') || matches_regex(output, 'ssh.*version.*2')".to_string(),
            expected: Some("ssh version 2".to_string()),
            fix_advice: Some("配置 SSH 版本 2: ssh server version 2 或 ssh version 2".to_string()),
        },
        ComplianceRule {
            id: "fw_telnet_disabled".to_string(),
            name: "禁用 Telnet 明文管理访问".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_telnet_config".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'telnet server') && not_contains(output, 'transport input telnet')".to_string(),
            expected: Some("无 telnet server / transport input telnet 配置".to_string()),
            fix_advice: Some("禁用 Telnet: no telnet server / transport input ssh（移除 telnet）".to_string()),
        },
        // ===== 身份鉴别：强认证 =====
        ComplianceRule {
            id: "fw_aaa_configured".to_string(),
            name: "已配置 AAA 认证".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_aaa_config".to_string(),
            check_script: "contains(output, 'aaa') && (contains(output, 'authentication') || contains(output, 'authentication-server'))".to_string(),
            expected: Some("aaa authentication 配置存在".to_string()),
            fix_advice: Some("配置 AAA 认证: aaa authentication login default group radius local".to_string()),
        },
        ComplianceRule {
            id: "fw_aaa_tacacs_radius".to_string(),
            name: "AAA 使用 TACACS+/RADIUS 集中认证".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.2".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_aaa_config".to_string(),
            check_script: "contains(output, 'tacacs') || contains(output, 'radius')".to_string(),
            expected: Some("配置了 tacacs+ 或 radius 服务器".to_string()),
            fix_advice: Some("配置 TACACS+/RADIUS 服务器: aaa-server protocol tacacs+ 或 radius".to_string()),
        },
        ComplianceRule {
            id: "fw_admin_password_encrypted".to_string(),
            name: "管理员密码已加密存储".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_admin_users".to_string(),
            check_script: "contains(output, 'username') && (contains(output, 'encrypted') || contains(output, 'secret') || matches_regex(output, '\\$[0-9]+\\$') || matches_regex(output, 'password.*encrypted'))".to_string(),
            expected: Some("username ... password encrypted/secret".to_string()),
            fix_advice: Some("使用加密密码: username <name> password encrypted <hash> 或 secret".to_string()),
        },
        ComplianceRule {
            id: "fw_password_encryption_on".to_string(),
            name: "启用密码加密服务".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_password_policy".to_string(),
            check_script: "contains(output, 'service password-encryption') || contains(output, 'password encryption') || contains(output, 'password-control')".to_string(),
            expected: Some("service password-encryption 或 password encryption aes".to_string()),
            fix_advice: Some("启用密码加密: service password-encryption 或 password encryption aes".to_string()),
        },
        ComplianceRule {
            id: "fw_password_min_length".to_string(),
            name: "密码最小长度 >= 8".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.1.2".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_password_policy".to_string(),
            check_script: "matches_regex(output, '(min.*length|min-length|min-length|password-length)\\s*=?\\s*([8-9]|[1-9][0-9]+)')".to_string(),
            expected: Some("密码最小长度 >= 8".to_string()),
            fix_advice: Some("配置密码最小长度: password-policy min-length 8 或 password-control length 8".to_string()),
        },
        // ===== 管理接口隔离 =====
        ComplianceRule {
            id: "fw_management_acl".to_string(),
            name: "管理访问受 ACL 限制".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.3".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_management_if".to_string(),
            check_script: "contains(output, 'access-group') || contains(output, 'access-list') || contains(output, 'acl')".to_string(),
            expected: Some("管理口配置了 access-group / access-list 限制".to_string()),
            fix_advice: Some("为管理口配置 ACL: management-access <if> 并应用 access-group".to_string()),
        },
        ComplianceRule {
            id: "fw_http_restricted".to_string(),
            name: "HTTP/HTTPS 管理访问受限制".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.3".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_management_if".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'http server enable') || contains(output, 'http') && (contains(output, 'access-group') || contains(output, 'access-list') || contains(output, 'https') || contains(output, 'ssl'))".to_string(),
            expected: Some("禁用 HTTP 或仅允许 HTTPS".to_string()),
            fix_advice: Some("禁用明文 HTTP 管理: no http server 或改用 https (http secure-server)".to_string()),
        },
        ComplianceRule {
            id: "fw_management_if_isolated".to_string(),
            name: "管理接口已隔离".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.3".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_management_if".to_string(),
            check_script: "contains(output, 'management-interface') || contains(output, 'management access') || contains(output, 'mgmt') || contains(output, 'management-only')".to_string(),
            expected: Some("配置了独立管理接口".to_string()),
            fix_advice: Some("配置独立管理接口: management-interface <if> 或 management-only".to_string()),
        },
        // ===== 日志配置 =====
        ComplianceRule {
            id: "fw_logging_enabled".to_string(),
            name: "日志功能已启用".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.1.4".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_logging_config".to_string(),
            check_script: "contains(output, 'logging') && (contains(output, 'enable') || contains(output, 'on') || contains(output, 'trap') || contains(output, 'host'))".to_string(),
            expected: Some("logging enable / logging on 配置存在".to_string()),
            fix_advice: Some("启用日志: logging enable 或 logging on".to_string()),
        },
        ComplianceRule {
            id: "fw_logging_server".to_string(),
            name: "已配置日志服务器".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.1.4".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_logging_config".to_string(),
            check_script: "matches_regex(output, 'logging\\s+(host\\s+)?[0-9]{1,3}(\\.[0-9]{1,3}){3}')".to_string(),
            expected: Some("logging host <IP>".to_string()),
            fix_advice: Some("配置日志服务器: logging host <ip> 或 logging <ip>".to_string()),
        },
        ComplianceRule {
            id: "fw_logging_level".to_string(),
            name: "日志级别 >= informational".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.1.4".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_logging_config".to_string(),
            check_script: "contains(output, 'informational') || contains(output, 'debugging') || contains(output, 'notifications') || matches_regex(output, 'logging\\s+(trap|level)\\s+(informational|debugging|notifications|warnings|errors|critical|alerts|emergencies)')".to_string(),
            expected: Some("logging trap informational 或更高级别".to_string()),
            fix_advice: Some("配置日志级别: logging trap informational".to_string()),
        },
        ComplianceRule {
            id: "fw_logging_timestamp".to_string(),
            name: "日志时间戳已启用".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.1.4".to_string(),
            severity: "low".to_string(),
            collect_item_id: "fw_logging_config".to_string(),
            check_script: "contains(output, 'timestamp') || contains(output, 'datetime')".to_string(),
            expected: Some("日志记录时间戳".to_string()),
            fix_advice: Some("配置日志时间戳: logging timestamp 或 service timestamps log datetime".to_string()),
        },
        // ===== 访问控制策略 =====
        ComplianceRule {
            id: "fw_acl_configured".to_string(),
            name: "已配置访问控制策略".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.5".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_access_policy".to_string(),
            check_script: "contains(output, 'access-list') || contains(output, 'access-group') || contains(output, 'policy')".to_string(),
            expected: Some("存在 access-list / access-group / policy 配置".to_string()),
            fix_advice: Some("配置访问控制策略并应用到接口: access-list ... access-group <acl> in interface <if>".to_string()),
        },
        ComplianceRule {
            id: "fw_default_deny".to_string(),
            name: "存在默认拒绝规则".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.5".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_access_policy".to_string(),
            check_script: "contains(output, 'deny ip any any') || contains(output, 'deny any any') || contains(output, 'deny any') || matches_regex(output, 'deny.*any.*any')".to_string(),
            expected: Some("存在 deny ip any any / deny any any 默认拒绝规则".to_string()),
            fix_advice: Some("在 ACL 末尾添加默认拒绝: access-list <id> deny ip any any".to_string()),
        },
        ComplianceRule {
            id: "fw_acl_applied".to_string(),
            name: "访问控制策略已应用到接口".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.5".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_access_policy".to_string(),
            check_script: "contains(output, 'access-group') || contains(output, 'apply') || matches_regex(output, 'policy.*interface|interface.*policy')".to_string(),
            expected: Some("ACL 通过 access-group 或 policy apply 应用到接口".to_string()),
            fix_advice: Some("将 ACL 应用到接口: access-group <acl> in interface <if>".to_string()),
        },
        // ===== 其他安全相关 =====
        ComplianceRule {
            id: "fw_snmp_community_strong".to_string(),
            name: "SNMP 团体字非默认 public/private".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.1.6".to_string(),
            severity: "high".to_string(),
            collect_item_id: "fw_snmp_config".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'public') && not_contains(output, 'private')".to_string(),
            expected: Some("SNMP 团体字非 public/private".to_string()),
            fix_advice: Some("修改 SNMP 团体字为复杂字符串，并使用 SNMPv3: snmp-server community <complex> 或 snmp-server user ... v3".to_string()),
        },
        ComplianceRule {
            id: "fw_snmp_v3".to_string(),
            name: "使用 SNMPv3 加密版本".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.1.6".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_snmp_config".to_string(),
            check_script: "is_empty(output) || contains(output, 'v3') || contains(output, 'version 3') || contains(output, 'snmp-server user')".to_string(),
            expected: Some("使用 SNMPv3".to_string()),
            fix_advice: Some("升级到 SNMPv3: snmp-server view / snmp-server group / snmp-server user ... v3".to_string()),
        },
        ComplianceRule {
            id: "fw_banner_configured".to_string(),
            name: "已配置登录 Banner".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.1.7".to_string(),
            severity: "low".to_string(),
            collect_item_id: "fw_banner_config".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("banner motd / login banner 已配置".to_string()),
            fix_advice: Some("配置登录 Banner: banner motd ^C 未经授权禁止访问 ^C".to_string()),
        },
        ComplianceRule {
            id: "fw_ntp_configured".to_string(),
            name: "NTP 时间同步已配置".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.1.7".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_ntp_config".to_string(),
            check_script: "matches_regex(output, 'ntp\\s+server\\s+[0-9]{1,3}(\\.[0-9]{1,3}){3}') || contains(output, 'ntp-service')".to_string(),
            expected: Some("ntp server <IP> 配置存在".to_string()),
            fix_advice: Some("配置 NTP 服务器: ntp server <ip> 或 ntp-service unicast-peer <ip>".to_string()),
        },
        ComplianceRule {
            id: "fw_session_timeout_set".to_string(),
            name: "管理会话超时已配置".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.1.3".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "fw_session_timeout".to_string(),
            check_script: "matches_regex(output, '(exec-timeout|idle-timeout|timeout)\\s+([1-9][0-9]{0,4})')".to_string(),
            expected: Some("exec-timeout / idle-timeout 已设置".to_string()),
            fix_advice: Some("配置会话超时: exec-timeout 5 0 或 idle-timeout 5".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_device_baseline_basic() {
        let rs = security_device_baseline();
        assert_eq!(rs.name, "security_device_baseline");
        assert!(!rs.collect_items.is_empty(), "采集项不应为空");
        assert!(!rs.rules.is_empty(), "合规规则不应为空");
    }

    #[test]
    fn test_collect_items_use_telnet() {
        let rs = security_device_baseline();
        // 安全设备默认通过 Telnet/SSH 采集
        for item in &rs.collect_items {
            assert!(
                item.method == CollectMethod::Telnet || item.method == CollectMethod::Ssh,
                "采集项 {} 应使用 Telnet/SSH 方式，实际 {:?}",
                item.id,
                item.method
            );
        }
    }

    #[test]
    fn test_rules_count_meets_minimum() {
        let rs = security_device_baseline();
        assert!(
            rs.rules.len() >= 15,
            "安全设备规则数应 >= 15，当前 {}",
            rs.rules.len()
        );
        assert!(
            rs.collect_items.len() >= 10,
            "安全设备采集项数应 >= 10，当前 {}",
            rs.collect_items.len()
        );
    }

    #[test]
    fn test_rule_refs_valid_collect_items() {
        let rs = security_device_baseline();
        for rule in &rs.rules {
            assert!(
                rs.find_collect_item(&rule.collect_item_id).is_some(),
                "规则 {} 引用了不存在的采集项 {}",
                rule.id,
                rule.collect_item_id
            );
        }
    }

    #[test]
    fn test_all_rules_have_fix_advice() {
        let rs = security_device_baseline();
        for rule in &rs.rules {
            assert!(
                rule.fix_advice.is_some(),
                "规则 {} 缺少修复建议",
                rule.id
            );
        }
    }

    #[test]
    fn test_all_scripts_validate() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        for rule in &rs.rules {
            let result = RuleEngine::validate_script(&rule.check_script);
            assert!(
                result.is_ok(),
                "规则 {} 脚本语法无效: {:?}",
                rule.id,
                result.err()
            );
        }
    }

    #[test]
    fn test_ssh_enabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_ssh_enabled").unwrap();
        // 配置中包含 ssh 应合规
        let result = engine.evaluate(rule, "ssh version 2\nssh 0.0.0.0 0.0.0.0 inside");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_ssh_version_2_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_ssh_version_2").unwrap();
        let result = engine.evaluate(rule, "ssh version 2");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_ssh_version_2_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_ssh_version_2").unwrap();
        // 无 ssh version 2 配置应不合规
        let result = engine.evaluate(rule, "ssh 0.0.0.0 0.0.0.0 inside");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_telnet_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_telnet_disabled").unwrap();
        // 无 Telnet 配置（空输出）应合规
        let result = engine.evaluate(rule, "");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_telnet_disabled_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_telnet_disabled").unwrap();
        // 启用了 Telnet server 应不合规
        let result = engine.evaluate(rule, "telnet server enable");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_aaa_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_aaa_configured").unwrap();
        let result = engine.evaluate(rule, "aaa authentication ssh console LOCAL\naaa authentication enable console LOCAL");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_admin_password_encrypted_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_admin_password_encrypted").unwrap();
        let result = engine.evaluate(rule, "username admin password encrypted $6$abcd1234");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_password_encryption_on_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_password_encryption_on").unwrap();
        let result = engine.evaluate(rule, "service password-encryption");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_logging_server_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_logging_server").unwrap();
        let result = engine.evaluate(rule, "logging host 10.0.0.10\nlogging trap informational");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_logging_level_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_logging_level").unwrap();
        let result = engine.evaluate(rule, "logging trap informational");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_default_deny_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_default_deny").unwrap();
        let result = engine.evaluate(rule, "access-list OUTSIDE extended deny ip any any");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_snmp_community_strong_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_snmp_community_strong").unwrap();
        // 使用了非 public/private 的团体字应合规
        let result = engine.evaluate(rule, "snmp-server community Str0ngC0mmunity123 RO");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_snmp_community_strong_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_snmp_community_strong").unwrap();
        // 使用 public 应不合规
        let result = engine.evaluate(rule, "snmp-server community public RO");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_ntp_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_ntp_configured").unwrap();
        let result = engine.evaluate(rule, "ntp server 10.0.0.1\nntp authenticate");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_session_timeout_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_session_timeout_set").unwrap();
        let result = engine.evaluate(rule, "exec-timeout 5 0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_banner_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = security_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "fw_banner_configured").unwrap();
        let result = engine.evaluate(rule, "banner motd ^C Authorized access only ^C");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }
}
