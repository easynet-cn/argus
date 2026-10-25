//! G3.2 网络设备基线规则
//!
//! 对标 GB/T 22239 等保三级要求，覆盖 Cisco / 华为 / H3C 等厂商网络设备
//! （路由器 / 交换机）配置基线。设备通过 SSH/Telnet 登录后执行 `show running-config`
//! 或厂商等价命令采集配置，规则基于 running-config 输出做数据驱动匹配
//!
//! 覆盖检查点：
//! - Telnet/SSH 配置
//! - running-config 安全（密码加密、ACL、NTP）
//! - SNMP 团体字
//! - Banner / 超时设置
//! - 未使用的服务/端口

use crate::rules::RuleSet;
use crate::types::{CollectItem, CollectMethod, ComplianceRule};

/// G3.2 网络设备（Cisco/华为/H3C）基线规则集
pub fn network_device_baseline() -> RuleSet {
    RuleSet {
        name: "network_device_baseline".to_string(),
        description: "G3.2 网络设备（Cisco/华为/H3C）基线核查规则集".to_string(),
        collect_items: collect_items(),
        rules: compliance_rules(),
    }
}

fn collect_items() -> Vec<CollectItem> {
    vec![
        // ===== 运行配置（核心采集项）=====
        CollectItem {
            id: "nw_running_config".to_string(),
            name: "网络设备运行配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config".to_string(),
            description: Some("采集网络设备 running-config 全量配置".to_string()),
        },
        // ===== 身份鉴别：Telnet/SSH 配置 =====
        CollectItem {
            id: "nw_line_vty".to_string(),
            name: "VTY 线路配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | section line vty".to_string(),
            description: Some("采集 line vty 配置（传输协议、超时、ACL 等）".to_string()),
        },
        CollectItem {
            id: "nw_ssh_config".to_string(),
            name: "SSH 服务配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include ssh|ip ssh|stelnet".to_string(),
            description: Some("采集 SSH 服务及版本配置".to_string()),
        },
        CollectItem {
            id: "nw_telnet_config".to_string(),
            name: "Telnet 服务配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include telnet".to_string(),
            description: Some("采集 Telnet 服务配置".to_string()),
        },
        // ===== 身份鉴别：密码加密 =====
        CollectItem {
            id: "nw_password_encryption".to_string(),
            name: "密码加密配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include service password-encryption|password-control|enable secret|enable password".to_string(),
            description: Some("采集密码加密与 enable 密码配置".to_string()),
        },
        CollectItem {
            id: "nw_local_users".to_string(),
            name: "本地用户配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include username|local-user".to_string(),
            description: Some("采集本地用户及密码加密方式".to_string()),
        },
        // ===== 访问控制：ACL =====
        CollectItem {
            id: "nw_acl_config".to_string(),
            name: "ACL 访问控制列表".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include access-list|ip access-list|acl".to_string(),
            description: Some("采集 ACL 配置".to_string()),
        },
        CollectItem {
            id: "nw_ntp_config".to_string(),
            name: "NTP 时间同步配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include ntp".to_string(),
            description: Some("采集 NTP 配置".to_string()),
        },
        // ===== 入侵防范：SNMP =====
        CollectItem {
            id: "nw_snmp_config".to_string(),
            name: "SNMP 配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include snmp".to_string(),
            description: Some("采集 SNMP 团体字及版本".to_string()),
        },
        // ===== 可信根：Banner / 超时 =====
        CollectItem {
            id: "nw_banner_config".to_string(),
            name: "登录 Banner 配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include banner|header".to_string(),
            description: Some("采集 Banner / MOTD 配置".to_string()),
        },
        CollectItem {
            id: "nw_timeout_config".to_string(),
            name: "会话超时配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include exec-timeout|idle-timeout|timeout".to_string(),
            description: Some("采集 VTY/Console 会话超时".to_string()),
        },
        // ===== 入侵防范：未使用服务/端口 =====
        CollectItem {
            id: "nw_unused_services".to_string(),
            name: "未使用服务与端口".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | include no service|no ip|shutdown|cdp run|no cdp|finger|tcp-small-servers|udp-small-servers|bootp".to_string(),
            description: Some("采集未使用服务关闭情况（CDP/finger/small-servers/bootp 等）".to_string()),
        },
        CollectItem {
            id: "nw_console_config".to_string(),
            name: "Console 口配置".to_string(),
            method: CollectMethod::Telnet,
            command: "show running-config | section line con".to_string(),
            description: Some("采集 Console 口登录认证与超时".to_string()),
        },
    ]
}

fn compliance_rules() -> Vec<ComplianceRule> {
    vec![
        // ===== 身份鉴别：Telnet/SSH 配置 =====
        ComplianceRule {
            id: "nw_ssh_enabled".to_string(),
            name: "启用 SSH 加密管理访问".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_ssh_config".to_string(),
            check_script: "contains(output, 'ip ssh') || contains(output, 'ssh server') || contains(output, 'stelnet')".to_string(),
            expected: Some("ip ssh enable / ssh server enable".to_string()),
            fix_advice: Some("启用 SSH: ip ssh version 2 或 stelnet server enable（华为/H3C）".to_string()),
        },
        ComplianceRule {
            id: "nw_ssh_version_2".to_string(),
            name: "SSH 使用版本 2".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_ssh_config".to_string(),
            check_script: "contains(output, 'version 2') || matches_regex(output, 'ip ssh version\\s+2')".to_string(),
            expected: Some("ip ssh version 2".to_string()),
            fix_advice: Some("配置 SSH 版本 2: ip ssh version 2".to_string()),
        },
        ComplianceRule {
            id: "nw_telnet_disabled".to_string(),
            name: "禁用 Telnet 明文管理访问".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_telnet_config".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'transport input telnet') && not_contains(output, 'telnet server') && not_contains(output, 'telnet ipv6 server')".to_string(),
            expected: Some("无 transport input telnet / telnet server 配置".to_string()),
            fix_advice: Some("禁用 Telnet: transport input ssh（line vty 下）或 undo telnet server enable".to_string()),
        },
        ComplianceRule {
            id: "nw_vty_transport_ssh".to_string(),
            name: "VTY 线路仅允许 SSH 协议".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.2.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_line_vty".to_string(),
            check_script: "contains(output, 'transport input ssh') || contains(output, 'transport input ssh') && not_contains(output, 'transport input telnet')".to_string(),
            expected: Some("transport input ssh".to_string()),
            fix_advice: Some("在 line vty 下配置: transport input ssh".to_string()),
        },
        ComplianceRule {
            id: "nw_vty_acl".to_string(),
            name: "VTY 线路配置 ACL 限制".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.2.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_line_vty".to_string(),
            check_script: "contains(output, 'access-class') || contains(output, 'access-group') || matches_regex(output, 'access-class\\s+[0-9]+')".to_string(),
            expected: Some("access-class <acl> in（line vty 下）".to_string()),
            fix_advice: Some("在 line vty 下配置 ACL: access-class <acl> in".to_string()),
        },
        // ===== 身份鉴别：密码加密 =====
        ComplianceRule {
            id: "nw_password_encryption_on".to_string(),
            name: "启用全局密码加密".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_password_encryption".to_string(),
            check_script: "contains(output, 'service password-encryption') || contains(output, 'password-control')".to_string(),
            expected: Some("service password-encryption".to_string()),
            fix_advice: Some("启用密码加密: service password-encryption（Cisco）或 password-control enable（华为/H3C）".to_string()),
        },
        ComplianceRule {
            id: "nw_enable_secret_used".to_string(),
            name: "Enable 特权密码使用 secret 加密".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_password_encryption".to_string(),
            check_script: "contains(output, 'enable secret') || contains(output, 'super password') && (contains(output, 'cipher') || contains(output, 'encrypted'))".to_string(),
            expected: Some("enable secret <password>".to_string()),
            fix_advice: Some("使用加密的 enable 密码: enable secret <pwd>（Cisco）或 super password cipher <pwd>（H3C）".to_string()),
        },
        ComplianceRule {
            id: "nw_no_enable_password_plain".to_string(),
            name: "禁用明文 enable password".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.2".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_password_encryption".to_string(),
            check_script: "not_contains(output, 'enable password') || contains(output, 'enable secret')".to_string(),
            expected: Some("无明文 enable password 或已使用 enable secret".to_string()),
            fix_advice: Some("使用 enable secret 替换 enable password: no enable password; enable secret <pwd>".to_string()),
        },
        ComplianceRule {
            id: "nw_local_user_secret".to_string(),
            name: "本地用户密码使用加密存储".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.2.2".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_local_users".to_string(),
            check_script: "contains(output, 'secret') || contains(output, 'cipher') || contains(output, 'password encrypted')".to_string(),
            expected: Some("username ... secret / password cipher".to_string()),
            fix_advice: Some("本地用户使用加密密码: username <u> secret <pwd> 或 local-user <u> password cipher <pwd>".to_string()),
        },
        // ===== 访问控制：ACL =====
        ComplianceRule {
            id: "nw_acl_configured".to_string(),
            name: "已配置 ACL 访问控制".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.2.3".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_acl_config".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("存在 access-list / ip access-list 配置".to_string()),
            fix_advice: Some("配置 ACL: ip access-list extended <name> ...".to_string()),
        },
        // ===== NTP =====
        ComplianceRule {
            id: "nw_ntp_configured".to_string(),
            name: "NTP 时间同步已配置".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.2.4".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_ntp_config".to_string(),
            check_script: "matches_regex(output, 'ntp\\s+server\\s+[0-9]{1,3}(\\.[0-9]{1,3}){3}') || contains(output, 'ntp-service') || contains(output, 'ntp unicast-peer')".to_string(),
            expected: Some("ntp server <IP>".to_string()),
            fix_advice: Some("配置 NTP 服务器: ntp server <ip> 或 ntp-service unicast-peer <ip>".to_string()),
        },
        ComplianceRule {
            id: "nw_ntp_auth".to_string(),
            name: "NTP 认证已启用".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.2.4".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_ntp_config".to_string(),
            check_script: "contains(output, 'ntp authenticate') || contains(output, 'ntp authentication') || contains(output, 'ntp-service authentication')".to_string(),
            expected: Some("ntp authenticate / ntp authentication".to_string()),
            fix_advice: Some("启用 NTP 认证: ntp authenticate; ntp authentication-key ...".to_string()),
        },
        // ===== SNMP 团体字 =====
        ComplianceRule {
            id: "nw_snmp_no_public".to_string(),
            name: "SNMP 团体字非默认 public".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.5".to_string(),
            severity: "high".to_string(),
            collect_item_id: "nw_snmp_config".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'community public') && not_contains(output, 'community private')".to_string(),
            expected: Some("SNMP 团体字非 public/private".to_string()),
            fix_advice: Some("修改默认团体字为复杂字符串: snmp-server community <complex> RO".to_string()),
        },
        ComplianceRule {
            id: "nw_snmp_v3".to_string(),
            name: "使用 SNMPv3 加密版本".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.5".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_snmp_config".to_string(),
            check_script: "is_empty(output) || contains(output, 'v3') || contains(output, 'version 3') || contains(output, 'snmp-server user') || contains(output, 'snmp-agent group v3')".to_string(),
            expected: Some("使用 SNMPv3".to_string()),
            fix_advice: Some("升级到 SNMPv3: snmp-server user ... v3 或 snmp-agent group <g> v3".to_string()),
        },
        // ===== Banner / 超时 =====
        ComplianceRule {
            id: "nw_banner_configured".to_string(),
            name: "已配置登录 Banner".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.2.6".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_banner_config".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("banner motd / header login 已配置".to_string()),
            fix_advice: Some("配置 Banner: banner motd ^C 未经授权禁止访问 ^C 或 header login（华为/H3C）".to_string()),
        },
        ComplianceRule {
            id: "nw_exec_timeout_set".to_string(),
            name: "VTY 会话超时已配置".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.2.6".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_timeout_config".to_string(),
            check_script: "matches_regex(output, 'exec-timeout\\s+([1-9][0-9]{0,3})') || matches_regex(output, 'idle-timeout\\s+([1-9][0-9]{0,3})')".to_string(),
            expected: Some("exec-timeout <min> <sec> 或 idle-timeout <min>".to_string()),
            fix_advice: Some("在 line vty 下配置: exec-timeout 5 0 或 idle-timeout 5".to_string()),
        },
        ComplianceRule {
            id: "nw_console_timeout_set".to_string(),
            name: "Console 口超时已配置".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.2.6".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_console_config".to_string(),
            check_script: "contains(output, 'exec-timeout') || contains(output, 'idle-timeout')".to_string(),
            expected: Some("line con 0 下配置 exec-timeout".to_string()),
            fix_advice: Some("在 line con 0 下配置: exec-timeout 5 0 或 idle-timeout 5".to_string()),
        },
        // ===== 未使用服务/端口 =====
        ComplianceRule {
            id: "nw_cdp_disabled".to_string(),
            name: "CDP 协议已关闭（或受控）".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no cdp run') || contains(output, 'undo cdp enable') || contains(output, 'no cdp enable')".to_string(),
            expected: Some("no cdp run 或全局关闭 CDP".to_string()),
            fix_advice: Some("禁用 CDP: no cdp run（Cisco）或 undo cdp enable（华为/H3C）".to_string()),
        },
        ComplianceRule {
            id: "nw_finger_disabled".to_string(),
            name: "finger 服务已关闭".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no finger') || contains(output, 'no service finger') || is_empty(output) || not_contains(output, 'finger')".to_string(),
            expected: Some("no service finger".to_string()),
            fix_advice: Some("禁用 finger 服务: no service finger".to_string()),
        },
        ComplianceRule {
            id: "nw_small_servers_disabled".to_string(),
            name: "small-servers 服务已关闭".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no service tcp-small-servers') || contains(output, 'no service udp-small-servers') || is_empty(output) || not_contains(output, 'small-servers')".to_string(),
            expected: Some("no service tcp-small-servers; no service udp-small-servers".to_string()),
            fix_advice: Some("禁用 small-servers: no service tcp-small-servers; no service udp-small-servers".to_string()),
        },
        ComplianceRule {
            id: "nw_bootp_disabled".to_string(),
            name: "BOOTP/DHCP 服务已关闭".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "low".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no ip bootp server') || contains(output, 'no service dhcp') || is_empty(output) || not_contains(output, 'bootp')".to_string(),
            expected: Some("no ip bootp server".to_string()),
            fix_advice: Some("禁用 BOOTP: no ip bootp server".to_string()),
        },
        ComplianceRule {
            id: "nw_http_server_disabled".to_string(),
            name: "HTTP 明文管理服务已关闭".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no ip http server') || is_empty(output) || not_contains(output, 'ip http server')".to_string(),
            expected: Some("no ip http server".to_string()),
            fix_advice: Some("禁用 HTTP 管理: no ip http server（如需远程管理改用 HTTPS）".to_string()),
        },
        ComplianceRule {
            id: "nw_source_route_disabled".to_string(),
            name: "禁用 IP 源路由".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.2.7".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "nw_unused_services".to_string(),
            check_script: "contains(output, 'no ip source-route') || is_empty(output) || not_contains(output, 'ip source-route')".to_string(),
            expected: Some("no ip source-route".to_string()),
            fix_advice: Some("禁用源路由: no ip source-route".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_device_baseline_basic() {
        let rs = network_device_baseline();
        assert_eq!(rs.name, "network_device_baseline");
        assert!(!rs.collect_items.is_empty(), "采集项不应为空");
        assert!(!rs.rules.is_empty(), "合规规则不应为空");
    }

    #[test]
    fn test_collect_items_use_telnet() {
        let rs = network_device_baseline();
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
        let rs = network_device_baseline();
        assert!(
            rs.rules.len() >= 20,
            "网络设备规则数应 >= 20，当前 {}",
            rs.rules.len()
        );
        assert!(
            rs.collect_items.len() >= 12,
            "网络设备采集项数应 >= 12，当前 {}",
            rs.collect_items.len()
        );
    }

    #[test]
    fn test_rule_refs_valid_collect_items() {
        let rs = network_device_baseline();
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
        let rs = network_device_baseline();
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
        let rs = network_device_baseline();
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
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_ssh_enabled").unwrap();
        let result = engine.evaluate(rule, "ip ssh version 2");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_ssh_version_2_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_ssh_version_2").unwrap();
        let result = engine.evaluate(rule, "ip ssh version 2");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_telnet_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_telnet_disabled").unwrap();
        // 空输出（未启用 Telnet）应合规
        let result = engine.evaluate(rule, "");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_telnet_disabled_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_telnet_disabled").unwrap();
        let result = engine.evaluate(rule, "telnet server enable");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_vty_transport_ssh_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_vty_transport_ssh").unwrap();
        let result = engine.evaluate(rule, "line vty 0 4\n transport input ssh");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vty_acl_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_vty_acl").unwrap();
        let result = engine.evaluate(rule, "line vty 0 4\n access-class 10 in");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_password_encryption_on_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_password_encryption_on").unwrap();
        let result = engine.evaluate(rule, "service password-encryption");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_enable_secret_used_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_enable_secret_used").unwrap();
        let result = engine.evaluate(rule, "enable secret 5 $1$abcd$...");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_no_enable_password_plain_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_no_enable_password_plain").unwrap();
        // 仅启用 secret 应合规
        let result = engine.evaluate(rule, "enable secret 5 $1$abcd$...");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_no_enable_password_plain_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_no_enable_password_plain").unwrap();
        // 存在明文 enable password 且无 secret 应不合规
        let result = engine.evaluate(rule, "enable password cisco123");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_local_user_secret_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_local_user_secret").unwrap();
        let result = engine.evaluate(rule, "username admin secret 5 $1$abcd$...");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_ntp_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_ntp_configured").unwrap();
        let result = engine.evaluate(rule, "ntp server 10.0.0.1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_ntp_auth_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_ntp_auth").unwrap();
        let result = engine.evaluate(rule, "ntp authenticate\nntp authentication-key 1 md5 abcde");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_snmp_no_public_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "snmp-server community Str0ngC0mm RO");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_snmp_no_public_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "snmp-server community public RO");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_banner_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_banner_configured").unwrap();
        let result = engine.evaluate(rule, "banner motd ^C Authorized access only ^C");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_exec_timeout_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_exec_timeout_set").unwrap();
        let result = engine.evaluate(rule, "line vty 0 4\n exec-timeout 5 0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_cdp_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_cdp_disabled").unwrap();
        let result = engine.evaluate(rule, "no cdp run");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_http_server_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_http_server_disabled").unwrap();
        let result = engine.evaluate(rule, "no ip http server");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_source_route_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = network_device_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "nw_source_route_disabled").unwrap();
        let result = engine.evaluate(rule, "no ip source-route");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }
}
