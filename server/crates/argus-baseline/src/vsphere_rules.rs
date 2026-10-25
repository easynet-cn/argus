//! G3.3 虚拟化设备基线规则（vCenter / ESXi）
//!
//! 对标 GB/T 22239 等保三级要求，覆盖 VMware vSphere 虚拟化环境安全基线。
//! ESXi 主机与 vCenter Server Appliance (VCSA) 均基于类 Linux 系统，通过 SSH
//! 登录后执行 esxcli / vim-cmd / shell 命令采集配置，规则基于命令输出做
//! 数据驱动匹配。
//!
//! 覆盖检查点：
//! - ESXi 主机：SSH 服务、ESXi Shell、锁定模式、密码策略、NTP、日志、SNMP、管理网络
//! - vCenter：单点登录(SSO)、密码策略、账户锁定、会话超时、日志审计、NTP、SNMP、防火墙

use crate::rules::RuleSet;
use crate::types::{CollectItem, CollectMethod, ComplianceRule};

/// G3.3 虚拟化设备（vCenter/ESXi）基线规则集
pub fn vsphere_baseline() -> RuleSet {
    RuleSet {
        name: "vsphere_baseline".to_string(),
        description: "G3.3 虚拟化设备（VMware vCenter/ESXi）基线核查规则集".to_string(),
        collect_items: collect_items(),
        rules: compliance_rules(),
    }
}

fn collect_items() -> Vec<CollectItem> {
    vec![
        // ===== ESXi 主机 =====
        // 身份鉴别：SSH 服务状态
        CollectItem {
            id: "esxi_ssh_service".to_string(),
            name: "ESXi SSH 服务状态".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system ssh get".to_string(),
            description: Some("采集 ESXi SSH 服务运行状态（Running: true/false）".to_string()),
        },
        // 身份鉴别：ESXi Shell
        CollectItem {
            id: "esxi_esxi_shell".to_string(),
            name: "ESXi Shell 服务状态".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system shell get".to_string(),
            description: Some("采集 ESXi Shell 服务运行状态".to_string()),
        },
        // 访问控制：锁定模式
        CollectItem {
            id: "esxi_lockdown_mode".to_string(),
            name: "ESXi 锁定模式状态".to_string(),
            method: CollectMethod::Ssh,
            command: "vim-cmd -U dcui vimsvc/auth/lockdown_is_enabled 2>/dev/null; esxcli system settings advanced list -o /UserVars/DCUI.Access 2>/dev/null".to_string(),
            description: Some("采集 ESXi 锁定模式启用状态".to_string()),
        },
        // 身份鉴别：密码策略
        CollectItem {
            id: "esxi_password_policy".to_string(),
            name: "ESXi 密码策略".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system security policy get 2>/dev/null; grep -iE 'passwd|pam_cracklib|pam_pwquality' /etc/pam.d/passwd 2>/dev/null".to_string(),
            description: Some("采集 ESXi 密码复杂度、长度、历史等策略".to_string()),
        },
        // 可信根：NTP
        CollectItem {
            id: "esxi_ntp".to_string(),
            name: "ESXi NTP 时间同步".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system ntp get 2>/dev/null; esxcli system ntp server list 2>/dev/null".to_string(),
            description: Some("采集 ESXi NTP 服务状态与服务器列表".to_string()),
        },
        // 安全审计：日志
        CollectItem {
            id: "esxi_syslog".to_string(),
            name: "ESXi 系统日志配置".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system syslog config get 2>/dev/null; esxcli system syslog logger list 2>/dev/null".to_string(),
            description: Some("采集 ESXi syslog 远程服务器与日志级别".to_string()),
        },
        // 入侵防范：SNMP
        CollectItem {
            id: "esxi_snmp".to_string(),
            name: "ESXi SNMP 配置".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system snmp get 2>/dev/null".to_string(),
            description: Some("采集 ESXi SNMP 团体字、协议版本等配置".to_string()),
        },
        // 访问控制：管理网络
        CollectItem {
            id: "esxi_management_network".to_string(),
            name: "ESXi 管理网络配置".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli network ip interface list 2>/dev/null; esxcli network vswitch standard list 2>/dev/null".to_string(),
            description: Some("采集 ESXi 管理网络接口与 vSwitch 隔离配置".to_string()),
        },
        // 可信根：登录 Banner
        CollectItem {
            id: "esxi_banner".to_string(),
            name: "ESXi 登录 Banner".to_string(),
            method: CollectMethod::Ssh,
            command: "esxcli system settings advanced list -o /Config/Etc/issue 2>/dev/null; cat /etc/issue 2>/dev/null".to_string(),
            description: Some("采集 ESXi 登录 Banner/MOTD".to_string()),
        },

        // ===== vCenter Server =====
        // 身份鉴别：SSO
        CollectItem {
            id: "vc_sso_config".to_string(),
            name: "vCenter SSO 单点登录配置".to_string(),
            method: CollectMethod::Ssh,
            command: "/usr/lib/vmware-sso/bin/rsautil config-get 2>/dev/null | grep -iE 'sso|identity|domain' ; ls /etc/vmware-sso/ 2>/dev/null".to_string(),
            description: Some("采集 vCenter SSO 单点登录配置".to_string()),
        },
        // 身份鉴别：密码策略
        CollectItem {
            id: "vc_password_policy".to_string(),
            name: "vCenter 密码策略".to_string(),
            method: CollectMethod::Ssh,
            command: "grep -iE 'password|passwd|minlen|maxlen|complexity' /etc/vmware-sso/ssolookup.conf 2>/dev/null; grep -iE 'minlen|difok|ucredit|lcredit' /etc/pam.d/system-password /etc/security/pwquality.conf 2>/dev/null".to_string(),
            description: Some("采集 vCenter 密码长度、复杂度、历史策略".to_string()),
        },
        // 身份鉴别：账户锁定
        CollectItem {
            id: "vc_account_lockout".to_string(),
            name: "vCenter 账户锁定策略".to_string(),
            method: CollectMethod::Ssh,
            command: "grep -iE 'deny|unlock_time|faillock|lockout' /etc/pam.d/system-auth /etc/security/faillock.conf 2>/dev/null".to_string(),
            description: Some("采集 vCenter 登录失败锁定阈值与解锁时间".to_string()),
        },
        // 访问控制：会话超时
        CollectItem {
            id: "vc_session_timeout".to_string(),
            name: "vCenter 会话超时配置".to_string(),
            method: CollectMethod::Ssh,
            command: "grep -iE 'session.timeout|ClientIdleTimeout|Websession' /etc/vmware-vpx/vpxd.cfg 2>/dev/null; grep -iE 'timeout' /etc/vmware-rhttpproxy/config.xml 2>/dev/null".to_string(),
            description: Some("采集 vCenter Web/Client 会话超时时间".to_string()),
        },
        // 安全审计：日志审计
        CollectItem {
            id: "vc_log_audit".to_string(),
            name: "vCenter 日志审计配置".to_string(),
            method: CollectMethod::Ssh,
            command: "grep -iE 'syslog|log.*level|audit' /etc/vmware-syslog/syslog.conf 2>/dev/null; grep -iE 'level|audit' /etc/vmware-vpx/vpxd.cfg 2>/dev/null".to_string(),
            description: Some("采集 vCenter 日志级别与审计配置".to_string()),
        },
        // 可信根：NTP
        CollectItem {
            id: "vc_ntp".to_string(),
            name: "vCenter NTP 时间同步".to_string(),
            method: CollectMethod::Ssh,
            command: "cat /etc/ntp.conf 2>/dev/null | grep -vE '^#|^$'; ntpq -p 2>/dev/null | head -5".to_string(),
            description: Some("采集 vCenter NTP 服务器与同步状态".to_string()),
        },
        // 入侵防范：SNMP
        CollectItem {
            id: "vc_snmp".to_string(),
            name: "vCenter SNMP 配置".to_string(),
            method: CollectMethod::Ssh,
            command: "grep -iE 'snmp|community' /etc/snmp/snmpd.conf 2>/dev/null".to_string(),
            description: Some("采集 vCenter SNMP 团体字与版本".to_string()),
        },
        // 访问控制：防火墙
        CollectItem {
            id: "vc_firewall".to_string(),
            name: "vCenter 防火墙配置".to_string(),
            method: CollectMethod::Ssh,
            command: "iptables -L -n 2>/dev/null | head -40; cat /etc/sysconfig/iptables 2>/dev/null | grep -vE '^#|^$' | head -40".to_string(),
            description: Some("采集 vCenter 防火墙规则".to_string()),
        },
    ]
}

fn compliance_rules() -> Vec<ComplianceRule> {
    vec![
        // ===== ESXi 主机：身份鉴别 =====
        ComplianceRule {
            id: "esxi_ssh_disabled".to_string(),
            name: "ESXi SSH 服务默认应禁用".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_ssh_service".to_string(),
            check_script: "contains(output, 'Running: false') || not_contains(output, 'Running: true')".to_string(),
            expected: Some("SSH 服务 Running: false".to_string()),
            fix_advice: Some("禁用 SSH 服务: esxcli system ssh set --enabled=false".to_string()),
        },
        ComplianceRule {
            id: "esxi_esxi_shell_disabled".to_string(),
            name: "ESXi Shell 服务默认应禁用".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_esxi_shell".to_string(),
            check_script: "contains(output, 'Running: false') || not_contains(output, 'Running: true')".to_string(),
            expected: Some("ESXi Shell Running: false".to_string()),
            fix_advice: Some("禁用 ESXi Shell: esxcli system shell set --enabled=false".to_string()),
        },
        // ===== ESXi 主机：访问控制 =====
        ComplianceRule {
            id: "esxi_lockdown_enabled".to_string(),
            name: "ESXi 锁定模式已启用".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.2".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_lockdown_mode".to_string(),
            check_script: "contains(output, 'true') && not_contains(output, 'false') || matches_regex(output, 'true')".to_string(),
            expected: Some("lockdown_is_enabled 返回 true".to_string()),
            fix_advice: Some("启用锁定模式: 在 vSphere Web Client 中为 ESXi 主机启用 Lockdown Mode".to_string()),
        },
        // ===== ESXi 主机：身份鉴别 - 密码策略 =====
        ComplianceRule {
            id: "esxi_password_min_length".to_string(),
            name: "ESXi 密码最小长度 >= 8".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_password_policy".to_string(),
            check_script: "matches_regex(output, '(minlen|min_passwd_len|minimum)\\s*=?\\s*([8-9]|[1-9][0-9]+)')".to_string(),
            expected: Some("密码最小长度 >= 8".to_string()),
            fix_advice: Some("配置密码最小长度: 编辑 PAM pam_cracklib/pam_pwquality 配置，设置 minlen=8".to_string()),
        },
        ComplianceRule {
            id: "esxi_password_complexity".to_string(),
            name: "ESXi 密码复杂度已启用".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_password_policy".to_string(),
            check_script: "contains(output, 'pam_pwquality') || contains(output, 'pam_cracklib') || matches_regex(output, '(dcredit|ucredit|lcredit|ocredit|minclass)\\s*=?\\s*-?[1-9]')".to_string(),
            expected: Some("配置了密码复杂度模块（pam_pwquality / pam_cracklib）".to_string()),
            fix_advice: Some("启用密码复杂度: 在 /etc/pam.d/passwd 中配置 pam_pwquality.so 或 pam_cracklib.so".to_string()),
        },
        ComplianceRule {
            id: "esxi_password_history".to_string(),
            name: "ESXi 密码历史复用限制".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.1".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "esxi_password_policy".to_string(),
            check_script: "matches_regex(output, '(remember|history)\\s*=?\\s*([5-9]|[1-9][0-9]+)') || contains(output, 'pam_unix') && contains(output, 'remember')".to_string(),
            expected: Some("密码历史 >= 5".to_string()),
            fix_advice: Some("配置密码历史: pam_unix.so remember=5".to_string()),
        },
        // ===== ESXi 主机：可信根 - NTP =====
        ComplianceRule {
            id: "esxi_ntp_configured".to_string(),
            name: "ESXi NTP 服务器已配置".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.3.3".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "esxi_ntp".to_string(),
            check_script: "matches_regex(output, '[0-9]{1,3}(\\.[0-9]{1,3}){3}') || contains(output, 'ntp.org') || contains(output, 'ntp')".to_string(),
            expected: Some("存在 NTP 服务器 IP".to_string()),
            fix_advice: Some("配置 NTP: esxcli system ntp server add --server=<ip>".to_string()),
        },
        ComplianceRule {
            id: "esxi_ntp_running".to_string(),
            name: "ESXi NTP 服务运行中".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.3.3".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_ntp".to_string(),
            check_script: "contains(output, 'Running: true') || contains(output, 'running')".to_string(),
            expected: Some("NTP Running: true".to_string()),
            fix_advice: Some("启动 NTP 服务: esxcli system ntp set --enabled=true".to_string()),
        },
        // ===== ESXi 主机：安全审计 - 日志 =====
        ComplianceRule {
            id: "esxi_syslog_configured".to_string(),
            name: "ESXi 远程 syslog 服务器已配置".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.3.4".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_syslog".to_string(),
            check_script: "matches_regex(output, '(udp|tcp|ssl)://[0-9]{1,3}(\\.[0-9]{1,3}){3}') || contains(output, 'RemoteHost') || contains(output, 'syslog')".to_string(),
            expected: Some("syslog 远程服务器 udp://<IP> 已配置".to_string()),
            fix_advice: Some("配置远程 syslog: esxcli system syslog config set --loghost=udp://<ip>".to_string()),
        },
        ComplianceRule {
            id: "esxi_log_level".to_string(),
            name: "ESXi 日志级别 >= info".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.3.4".to_string(),
            severity: "low".to_string(),
            collect_item_id: "esxi_syslog".to_string(),
            check_script: "contains(output, 'info') || contains(output, 'verbose') || contains(output, 'debug') || contains(output, 'notice')".to_string(),
            expected: Some("日志级别为 info 或更详细".to_string()),
            fix_advice: Some("设置日志级别: esxcli system settings advanced set -o /Config/Syslog/global.logLevel --string-value=info".to_string()),
        },
        // ===== ESXi 主机：入侵防范 - SNMP =====
        ComplianceRule {
            id: "esxi_snmp_no_public".to_string(),
            name: "ESXi SNMP 团体字非默认 public/private".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.3.5".to_string(),
            severity: "high".to_string(),
            collect_item_id: "esxi_snmp".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'public') && not_contains(output, 'private')".to_string(),
            expected: Some("SNMP 团体字非 public/private".to_string()),
            fix_advice: Some("修改默认团体字: esxcli system snmp set --communities=<complex>".to_string()),
        },
        ComplianceRule {
            id: "esxi_snmp_v3".to_string(),
            name: "ESXi 使用 SNMPv3 加密版本".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.3.5".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "esxi_snmp".to_string(),
            check_script: "is_empty(output) || contains(output, 'v3') || contains(output, 'version 3') || contains(output, 'users')".to_string(),
            expected: Some("使用 SNMPv3".to_string()),
            fix_advice: Some("升级到 SNMPv3: esxcli system snmp set -v 3 ...".to_string()),
        },
        // ===== ESXi 主机：访问控制 - 管理网络 =====
        ComplianceRule {
            id: "esxi_management_network_isolated".to_string(),
            name: "ESXi 管理网络已隔离".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.2".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "esxi_management_network".to_string(),
            check_script: "contains(output, 'Management') || contains(output, 'vmk') || contains(output, 'vSwitch')".to_string(),
            expected: Some("管理网络使用独立 vmkernel 接口".to_string()),
            fix_advice: Some("配置独立管理网络: 将管理端口组置于独立 vSwitch，与生产网络隔离".to_string()),
        },
        // ===== ESXi 主机：可信根 - Banner =====
        ComplianceRule {
            id: "esxi_banner_configured".to_string(),
            name: "ESXi 登录 Banner 已配置".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.3.3".to_string(),
            severity: "low".to_string(),
            collect_item_id: "esxi_banner".to_string(),
            check_script: "line_count(output) > 0 && not_contains(output, 'VMware ESXi')".to_string(),
            expected: Some("已配置自定义登录 Banner".to_string()),
            fix_advice: Some("配置登录 Banner: esxcli system settings advanced set -o /Config/Etc/issue --string-value='Authorized access only'".to_string()),
        },

        // ===== vCenter Server：身份鉴别 - SSO =====
        ComplianceRule {
            id: "vc_sso_configured".to_string(),
            name: "vCenter SSO 单点登录已配置".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_sso_config".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("SSO 服务已配置且运行".to_string()),
            fix_advice: Some("确认 SSO 服务运行: service-control --status vmware-sts-idmd".to_string()),
        },
        ComplianceRule {
            id: "vc_sso_identity_source".to_string(),
            name: "vCenter SSO 已配置外部身份源".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_sso_config".to_string(),
            check_script: "contains(output, 'identity') || contains(output, 'ldap') || contains(output, 'ad') || contains(output, 'domain')".to_string(),
            expected: Some("已配置 LDAP/AD 等外部身份源".to_string()),
            fix_advice: Some("在 vSphere Client 中配置 SSO 身份源（LDAP/AD）".to_string()),
        },
        // ===== vCenter Server：身份鉴别 - 密码策略 =====
        ComplianceRule {
            id: "vc_password_min_length".to_string(),
            name: "vCenter 密码最小长度 >= 8".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_password_policy".to_string(),
            check_script: "matches_regex(output, '(minlen|min_passwd_len|minimum)\\s*=?\\s*([8-9]|[1-9][0-9]+)')".to_string(),
            expected: Some("密码最小长度 >= 8".to_string()),
            fix_advice: Some("在 SSO 密码策略中设置最小长度 >= 8".to_string()),
        },
        ComplianceRule {
            id: "vc_password_complexity".to_string(),
            name: "vCenter 密码复杂度已启用".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_password_policy".to_string(),
            check_script: "matches_regex(output, '(dcredit|ucredit|lcredit|ocredit|minclass)\\s*=?\\s*-?[1-9]') || contains(output, 'complexity')".to_string(),
            expected: Some("密码包含大小写字母、数字、特殊字符中至少 2-3 类".to_string()),
            fix_advice: Some("配置密码复杂度: 启用 dcredit/ucredit/lcredit/ocredit >= 1".to_string()),
        },
        ComplianceRule {
            id: "vc_password_history".to_string(),
            name: "vCenter 密码历史复用限制 >= 5".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_password_policy".to_string(),
            check_script: "matches_regex(output, '(remember|history)\\s*=?\\s*([5-9]|[1-9][0-9]+)')".to_string(),
            expected: Some("密码历史 >= 5".to_string()),
            fix_advice: Some("配置密码历史复用限制 >= 5".to_string()),
        },
        // ===== vCenter Server：身份鉴别 - 账户锁定 =====
        ComplianceRule {
            id: "vc_account_lockout".to_string(),
            name: "vCenter 账户锁定策略已配置".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_account_lockout".to_string(),
            check_script: "contains(output, 'deny') || contains(output, 'faillock') || contains(output, 'lockout')".to_string(),
            expected: Some("已配置登录失败锁定（pam_faillock / pam_tally2）".to_string()),
            fix_advice: Some("配置账户锁定: pam_faillock.so deny=5 unlock_time=900".to_string()),
        },
        ComplianceRule {
            id: "vc_lockout_threshold".to_string(),
            name: "vCenter 账户锁定阈值合理".to_string(),
            category: "身份鉴别".to_string(),
            requirement_id: "G3.3.6".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_account_lockout".to_string(),
            check_script: "matches_regex(output, '(deny|fail_interval)\\s*=?\\s*([3-9]|[1-9][0-9]+)')".to_string(),
            expected: Some("失败锁定阈值 <= 5".to_string()),
            fix_advice: Some("设置失败锁定阈值: deny=5".to_string()),
        },
        // ===== vCenter Server：访问控制 - 会话超时 =====
        ComplianceRule {
            id: "vc_session_timeout_set".to_string(),
            name: "vCenter 会话超时已配置".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.7".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_session_timeout".to_string(),
            check_script: "contains(output, 'timeout') && line_count(output) > 0".to_string(),
            expected: Some("会话超时已配置（建议 <= 30 分钟）".to_string()),
            fix_advice: Some("配置会话超时: 在 vpxd.cfg 中设置 session.timeout".to_string()),
        },
        ComplianceRule {
            id: "vc_session_timeout_value".to_string(),
            name: "vCenter 会话超时 <= 60 分钟".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.7".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_session_timeout".to_string(),
            check_script: "matches_regex(output, '(timeout|ClientIdleTimeout)\\s*=?\\s*([1-5]?[0-9])\\b') || line_count(output) > 0 && contains(output, 'timeout')".to_string(),
            expected: Some("会话超时 <= 60 分钟".to_string()),
            fix_advice: Some("设置会话超时 <= 60 分钟".to_string()),
        },
        // ===== vCenter Server：安全审计 - 日志审计 =====
        ComplianceRule {
            id: "vc_log_audit_enabled".to_string(),
            name: "vCenter 日志审计已启用".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.3.8".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_log_audit".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("日志审计已启用".to_string()),
            fix_advice: Some("确认 vCenter 日志服务运行: service-control --status vmware-syslog".to_string()),
        },
        ComplianceRule {
            id: "vc_log_level".to_string(),
            name: "vCenter 日志级别 >= info".to_string(),
            category: "安全审计".to_string(),
            requirement_id: "G3.3.8".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_log_audit".to_string(),
            check_script: "contains(output, 'info') || contains(output, 'verbose') || contains(output, 'debug') || contains(output, 'notice') || contains(output, 'warning')".to_string(),
            expected: Some("日志级别为 info 或更详细".to_string()),
            fix_advice: Some("设置 vCenter 日志级别为 info".to_string()),
        },
        // ===== vCenter Server：可信根 - NTP =====
        ComplianceRule {
            id: "vc_ntp_configured".to_string(),
            name: "vCenter NTP 服务器已配置".to_string(),
            category: "可信根".to_string(),
            requirement_id: "G3.3.9".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_ntp".to_string(),
            check_script: "matches_regex(output, 'server\\s+[0-9]{1,3}(\\.[0-9]{1,3}){3}') || matches_regex(output, 'pool\\s+[0-9]{1,3}(\\.[0-9]{1,3}){3}') || contains(output, 'ntp.org')".to_string(),
            expected: Some("NTP 服务器已配置".to_string()),
            fix_advice: Some("编辑 /etc/ntp.conf 添加 server <ip>".to_string()),
        },
        // ===== vCenter Server：入侵防范 - SNMP =====
        ComplianceRule {
            id: "vc_snmp_no_public".to_string(),
            name: "vCenter SNMP 团体字非默认 public/private".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.3.10".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_snmp".to_string(),
            check_script: "is_empty(output) || not_contains(output, 'public') && not_contains(output, 'private')".to_string(),
            expected: Some("SNMP 团体字非 public/private".to_string()),
            fix_advice: Some("修改 /etc/snmp/snmpd.conf 中的默认团体字".to_string()),
        },
        ComplianceRule {
            id: "vc_snmp_v3".to_string(),
            name: "vCenter 使用 SNMPv3 加密版本".to_string(),
            category: "入侵防范".to_string(),
            requirement_id: "G3.3.10".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_snmp".to_string(),
            check_script: "is_empty(output) || contains(output, 'v3') || contains(output, 'version 3') || contains(output, 'createUser')".to_string(),
            expected: Some("使用 SNMPv3".to_string()),
            fix_advice: Some("在 snmpd.conf 中配置 SNMPv3 用户".to_string()),
        },
        // ===== vCenter Server：访问控制 - 防火墙 =====
        ComplianceRule {
            id: "vc_firewall_enabled".to_string(),
            name: "vCenter 防火墙已启用".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.11".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_firewall".to_string(),
            check_script: "line_count(output) > 0".to_string(),
            expected: Some("iptables 规则已存在".to_string()),
            fix_advice: Some("启用防火墙: systemctl enable iptables; iptables-restore < /etc/sysconfig/iptables".to_string()),
        },
        ComplianceRule {
            id: "vc_firewall_default_deny".to_string(),
            name: "vCenter 防火墙默认拒绝策略".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.11".to_string(),
            severity: "high".to_string(),
            collect_item_id: "vc_firewall".to_string(),
            check_script: "contains(output, 'DROP') || contains(output, 'REJECT') || contains(output, 'deny')".to_string(),
            expected: Some("存在 DROP/REJECT 默认拒绝规则".to_string()),
            fix_advice: Some("配置默认拒绝策略: iptables -P INPUT DROP".to_string()),
        },
        ComplianceRule {
            id: "vc_firewall_ssh_restricted".to_string(),
            name: "vCenter SSH 访问受防火墙限制".to_string(),
            category: "访问控制".to_string(),
            requirement_id: "G3.3.11".to_string(),
            severity: "medium".to_string(),
            collect_item_id: "vc_firewall".to_string(),
            check_script: "contains(output, '22') || contains(output, 'ssh') || contains(output, 'DROP')".to_string(),
            expected: Some("SSH 端口 22 访问受限制".to_string()),
            fix_advice: Some("限制 SSH 访问源: iptables -A INPUT -p tcp --dport 22 -s <trusted_ip> -j ACCEPT".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsphere_baseline_basic() {
        let rs = vsphere_baseline();
        assert_eq!(rs.name, "vsphere_baseline");
        assert!(!rs.collect_items.is_empty(), "采集项不应为空");
        assert!(!rs.rules.is_empty(), "合规规则不应为空");
    }

    #[test]
    fn test_collect_items_use_ssh() {
        let rs = vsphere_baseline();
        // vSphere 设备通过 SSH 采集（esxcli / shell 命令）
        for item in &rs.collect_items {
            assert_eq!(
                item.method,
                CollectMethod::Ssh,
                "采集项 {} 应使用 SSH 方式，实际 {:?}",
                item.id,
                item.method
            );
        }
    }

    #[test]
    fn test_rules_count_meets_minimum() {
        let rs = vsphere_baseline();
        assert!(
            rs.rules.len() >= 25,
            "虚拟化设备规则数应 >= 25，当前 {}",
            rs.rules.len()
        );
        assert!(
            rs.collect_items.len() >= 17,
            "虚拟化设备采集项数应 >= 17，当前 {}",
            rs.collect_items.len()
        );
    }

    #[test]
    fn test_rule_refs_valid_collect_items() {
        let rs = vsphere_baseline();
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
        let rs = vsphere_baseline();
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
        let rs = vsphere_baseline();
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
    fn test_esxi_ssh_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_ssh_disabled").unwrap();
        let result = engine.evaluate(rule, "Running: false");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_ssh_disabled_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_ssh_disabled").unwrap();
        let result = engine.evaluate(rule, "Running: true");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_esxi_esxi_shell_disabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_esxi_shell_disabled").unwrap();
        let result = engine.evaluate(rule, "Running: false");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_lockdown_enabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_lockdown_enabled").unwrap();
        let result = engine.evaluate(rule, "true");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_password_min_length_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_password_min_length").unwrap();
        let result = engine.evaluate(rule, "minlen = 8");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_password_complexity_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_password_complexity").unwrap();
        let result = engine.evaluate(rule, "password    required    pam_pwquality.so dcredit=1 ucredit=1 lcredit=1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_ntp_running_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_ntp_running").unwrap();
        let result = engine.evaluate(rule, "Running: true");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_syslog_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_syslog_configured").unwrap();
        let result = engine.evaluate(rule, "LogHost: udp://10.0.0.10");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_snmp_no_public_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "Communities: Str0ngC0mm123");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_snmp_no_public_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "Communities: public");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_esxi_management_network_isolated_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_management_network_isolated").unwrap();
        let result = engine.evaluate(rule, "vmk0 Management Network vSwitch0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_sso_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_sso_configured").unwrap();
        let result = engine.evaluate(rule, "sso domain: vsphere.local");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_password_min_length_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_password_min_length").unwrap();
        let result = engine.evaluate(rule, "minlen = 8");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_account_lockout_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_account_lockout").unwrap();
        let result = engine.evaluate(rule, "auth required pam_faillock.so deny=5 unlock_time=900");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_session_timeout_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_session_timeout_set").unwrap();
        let result = engine.evaluate(rule, "session.timeout = 30");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_log_audit_enabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_log_audit_enabled").unwrap();
        let result = engine.evaluate(rule, "log level = info");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_ntp_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_ntp_configured").unwrap();
        let result = engine.evaluate(rule, "server 10.0.0.1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_snmp_no_public_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "rocommunity Str0ngC0mm123");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_snmp_no_public_non_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_snmp_no_public").unwrap();
        let result = engine.evaluate(rule, "rocommunity public");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::NonCompliant));
    }

    #[test]
    fn test_vc_firewall_enabled_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_firewall_enabled").unwrap();
        let result = engine.evaluate(rule, "Chain INPUT (policy DROP)\nACCEPT all -- 0.0.0.0/0 0.0.0.0/0");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_firewall_default_deny_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_firewall_default_deny").unwrap();
        let result = engine.evaluate(rule, "Chain INPUT (policy DROP)");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_banner_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_banner_configured").unwrap();
        let result = engine.evaluate(rule, "Authorized access only. All activity may be monitored.");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_lockout_threshold_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_lockout_threshold").unwrap();
        let result = engine.evaluate(rule, "pam_faillock.so deny=5 unlock_time=900");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_ntp_configured_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_ntp_configured").unwrap();
        let result = engine.evaluate(rule, "10.0.0.1\nRunning: true");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_esxi_log_level_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "esxi_log_level").unwrap();
        let result = engine.evaluate(rule, "Default log level: info");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_sso_identity_source_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_sso_identity_source").unwrap();
        let result = engine.evaluate(rule, "identity source: ldap://ad.example.com");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_password_complexity_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_password_complexity").unwrap();
        let result = engine.evaluate(rule, "dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }

    #[test]
    fn test_vc_firewall_ssh_restricted_compliant() {
        use crate::rule_engine::RuleEngine;
        let rs = vsphere_baseline();
        let engine = RuleEngine::new();
        let rule = rs.rules.iter().find(|r| r.id == "vc_firewall_ssh_restricted").unwrap();
        let result = engine.evaluate(rule, "ACCEPT tcp -- 10.0.0.0/8 0.0.0.0/0 tcp dpt:22");
        assert!(matches!(result.compliance, crate::types::ComplianceLevel::Compliant));
    }
}
