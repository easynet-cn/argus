//! 内置基线策略模板 seed 数据
//!
//! 基线管理要求：系统内置等保2.0/CIS 基线策略模板，用户可直接引用。
//! 本迁移预置 6 套内置基线策略模板：
//! 1. 等保2.0 - Linux 系统安全基线
//! 2. 等保2.0 - Windows 系统安全基线
//! 3. 等保2.0 - 网络设备安全基线
//! 4. CIS - Linux 系统基线
//! 5. CIS - Windows 系统基线
//! 6. 等保2.0 - MySQL 数据库基线

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = chrono::Utc::now().naive_utc();

        // ===== 1. 等保2.0 - Linux 系统安全基线 =====
        let linux_rules = serde_json::json!({
            "rules": [
                {"id": "dgj2-linux-001", "name": "密码最小长度", "description": "检查密码最小长度是否 >= 8", "check_type": "password_policy", "expected": "PASS_MIN_LEN >= 8", "severity": "high", "remediation": "编辑 /etc/login.defs 设置 PASS_MIN_LEN 8"},
                {"id": "dgj2-linux-002", "name": "密码最大天数", "description": "检查密码最大使用天数是否 <= 90", "check_type": "password_policy", "expected": "PASS_MAX_DAYS <= 90", "severity": "medium", "remediation": "编辑 /etc/login.defs 设置 PASS_MAX_DAYS 90"},
                {"id": "dgj2-linux-003", "name": "密码复杂度", "description": "检查是否启用密码复杂度策略", "check_type": "password_policy", "expected": "pam_pwquality 启用", "severity": "high", "remediation": "安装 pam_pwquality 并配置 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1"},
                {"id": "dgj2-linux-004", "name": "历史密码记录", "description": "检查密码历史记录数是否 >= 5", "check_type": "password_policy", "expected": "remember >= 5", "severity": "medium", "remediation": "在 pam_unix.conf 中设置 remember=5"},
                {"id": "dgj2-linux-005", "name": "账户锁定策略", "description": "检查连续失败登录是否锁定", "check_type": "account_lock", "expected": "pam_faillock 启用", "severity": "high", "remediation": "配置 pam_faillock deny=5 unlock_time=600"},
                {"id": "dgj2-linux-006", "name": "空口令限制", "description": "检查是否禁止空口令登录", "check_type": "password_policy", "expected": "nullok 禁用", "severity": "critical", "remediation": "移除 pam_unix 中的 nullok 选项"},
                {"id": "dgj2-linux-007", "name": "root 直接 SSH 登录", "description": "检查是否禁止 root 通过 SSH 直接登录", "check_type": "ssh_config", "expected": "PermitRootLogin no", "severity": "high", "remediation": "编辑 /etc/ssh/sshd_config 设置 PermitRootLogin no"},
                {"id": "dgj2-linux-008", "name": "SSH 协议版本", "description": "检查 SSH 是否仅使用协议 2", "check_type": "ssh_config", "expected": "Protocol 2", "severity": "high", "remediation": "编辑 /etc/ssh/sshd_config 设置 Protocol 2"},
                {"id": "dgj2-linux-009", "name": "SSH 空闲超时", "description": "检查 SSH 空闲超时是否设置", "check_type": "ssh_config", "expected": "ClientAliveInterval <= 600", "severity": "medium", "remediation": "设置 ClientAliveInterval 600 和 ClientAliveCountMax 0"},
                {"id": "dgj2-linux-010", "name": "文件权限-passwd", "description": "检查 /etc/passwd 文件权限", "check_type": "file_permission", "expected": "0644", "severity": "medium", "remediation": "chmod 644 /etc/passwd"},
                {"id": "dgj2-linux-011", "name": "文件权限-shadow", "description": "检查 /etc/shadow 文件权限", "check_type": "file_permission", "expected": "0600", "severity": "high", "remediation": "chmod 600 /etc/shadow"},
                {"id": "dgj2-linux-012", "name": "文件权限-hosts.allow", "description": "检查 /etc/hosts.allow 权限", "check_type": "file_permission", "expected": "0644", "severity": "low", "remediation": "chmod 644 /etc/hosts.allow"},
                {"id": "dgj2-linux-013", "name": "不必要的服务-telnet", "description": "检查是否禁用 telnet 服务", "check_type": "service_check", "expected": "telnet 禁用", "severity": "critical", "remediation": "systemctl disable telnet.socket"},
                {"id": "dgj2-linux-014", "name": "不必要的服务-rsh", "description": "检查是否禁用 rsh 服务", "check_type": "service_check", "expected": "rsh 禁用", "severity": "high", "remediation": "systemctl disable rsh.socket"},
                {"id": "dgj2-linux-015", "name": "日志审计-syslog", "description": "检查 syslog/rsyslog 是否启用", "check_type": "log_audit", "expected": "rsyslog 运行", "severity": "high", "remediation": "systemctl enable rsyslog"},
                {"id": "dgj2-linux-016", "name": "日志保留", "description": "检查日志保留时间是否 >= 6 个月", "check_type": "log_audit", "expected": "logrotate >= 180 days", "severity": "medium", "remediation": "配置 /etc/logrotate.d/syslog rotate 180"},
                {"id": "dgj2-linux-017", "name": "内核参数-IP转发", "description": "检查是否禁用 IP 转发", "check_type": "kernel_param", "expected": "net.ipv4.ip_forward=0", "severity": "medium", "remediation": "sysctl -w net.ipv4.ip_forward=0"},
                {"id": "dgj2-linux-018", "name": "内核参数-SYN Cookie", "description": "检查是否启用 SYN Cookie", "check_type": "kernel_param", "expected": "net.ipv4.tcp_syncookies=1", "severity": "medium", "remediation": "sysctl -w net.ipv4.tcp_syncookies=1"},
                {"id": "dgj2-linux-019", "name": "内核参数-源路由", "description": "检查是否禁用源路由", "check_type": "kernel_param", "expected": "net.ipv4.conf.all.accept_source_route=0", "severity": "medium", "remediation": "sysctl -w net.ipv4.conf.all.accept_source_route=0"},
                {"id": "dgj2-linux-020", "name": "SUID 文件检查", "description": "检查异常 SUID 文件", "check_type": "file_permission", "expected": "无异常 SUID", "severity": "high", "remediation": "find / -perm -4000 -type f -exec chmod u-s {} \\;"}
            ]
        });
        insert_baseline(manager, "dgj2-linux-baseline", "等保2.0-Linux系统安全基线", &linux_rules, "system", "等保2.0", "high", "等保2.0 Linux 系统安全基线检查模板，涵盖密码策略/SSH/文件权限/服务/日志审计/内核参数 20 项检查", now).await?;

        // ===== 2. 等保2.0 - Windows 系统安全基线 =====
        let windows_rules = serde_json::json!({
            "rules": [
                {"id": "dgj2-win-001", "name": "密码最小长度", "description": "检查密码最小长度是否 >= 8", "check_type": "password_policy", "expected": "MinimumPasswordLength >= 8", "severity": "high", "remediation": "secpol.msc → 账户策略 → 密码策略 → 密码最小长度 8"},
                {"id": "dgj2-win-002", "name": "密码最大使用期", "description": "检查密码最大使用期限是否 <= 90 天", "check_type": "password_policy", "expected": "MaximumPasswordAge <= 90", "severity": "medium", "remediation": "secpol.msc → 密码最长使用期限 90"},
                {"id": "dgj2-win-003", "name": "密码复杂度", "description": "检查是否启用密码复杂度", "check_type": "password_policy", "expected": "PasswordComplexity=Enabled", "severity": "high", "remediation": "secpol.msc → 密码必须符合复杂性要求 已启用"},
                {"id": "dgj2-win-004", "name": "账户锁定阈值", "description": "检查账户锁定阈值是否 <= 5 次", "check_type": "account_lock", "expected": "LockoutBadCount <= 5", "severity": "high", "remediation": "secpol.msc → 账户锁定阈值 5 次"},
                {"id": "dgj2-win-005", "name": "账户锁定时间", "description": "检查账户锁定时间是否 >= 30 分钟", "check_type": "account_lock", "expected": "LockoutDuration >= 30", "severity": "medium", "remediation": "secpol.msc → 账户锁定持续时间 30 分钟"},
                {"id": "dgj2-win-006", "name": "Guest 账户禁用", "description": "检查 Guest 账户是否禁用", "check_type": "account_check", "expected": "Guest 禁用", "severity": "high", "remediation": "net user Guest /active:no"},
                {"id": "dgj2-win-007", "name": "空密码限制", "description": "检查是否禁止空密码", "check_type": "password_policy", "expected": "LimitBlankPasswordUse=1", "severity": "critical", "remediation": "secpol.msc → 账户：使用空白密码的本地账户只允许控制台登录 已启用"},
                {"id": "dgj2-win-008", "name": "远程桌面-NLA", "description": "检查 RDP 是否启用网络级认证", "check_type": "remote_access", "expected": "UserAuthentication=1", "severity": "high", "remediation": "系统属性 → 远程 → 仅允许使用 NLA 的远程桌面连接"},
                {"id": "dgj2-win-009", "name": "自动更新", "description": "检查是否启用自动更新", "check_type": "system_update", "expected": "Windows Update 启用", "severity": "medium", "remediation": "启用 Windows Update 自动更新"},
                {"id": "dgj2-win-010", "name": "审核策略-登录", "description": "检查是否审核登录事件", "check_type": "audit_policy", "expected": "AuditLogonEvents=Success,Failure", "severity": "high", "remediation": "auditpol /set /subcategory:Logon /success:enable /failure:enable"},
                {"id": "dgj2-win-011", "name": "审核策略-账户管理", "description": "检查是否审核账户管理事件", "check_type": "audit_policy", "expected": "AuditAccountManage=Success,Failure", "severity": "medium", "remediation": "auditpol /set /subcategory:'User Account Management' /success:enable /failure:enable"},
                {"id": "dgj2-win-012", "name": "审核策略-对象访问", "description": "检查是否审核对象访问", "check_type": "audit_policy", "expected": "AuditObjectAccess=Success,Failure", "severity": "medium", "remediation": "auditpol /set /subcategory:'File System' /success:enable /failure:enable"},
                {"id": "dgj2-win-013", "name": "事件日志大小", "description": "检查安全事件日志最大大小是否 >= 128MB", "check_type": "log_config", "expected": "MaxSize >= 131072KB", "severity": "low", "remediation": "事件查看器 → 安全日志最大大小 128MB"},
                {"id": "dgj2-win-014", "name": "共享权限", "description": "检查默认共享是否关闭", "check_type": "share_config", "expected": "Admin$ 等默认共享关闭", "severity": "medium", "remediation": "删除默认共享 net share Admin$ /delete"},
                {"id": "dgj2-win-015", "name": "防火墙启用", "description": "检查 Windows 防火墙是否启用", "check_type": "firewall", "expected": "DomainProfile Enabled=1", "severity": "high", "remediation": "netsh advfirewall set allprofiles state on"}
            ]
        });
        insert_baseline(manager, "dgj2-windows-baseline", "等保2.0-Windows系统安全基线", &windows_rules, "system", "等保2.0", "high", "等保2.0 Windows 系统安全基线检查模板，涵盖密码策略/账户锁定/Guest/RDP/自动更新/审核策略/事件日志/共享/防火墙 15 项检查", now).await?;

        // ===== 3. 等保2.0 - 网络设备安全基线 =====
        let network_rules = serde_json::json!({
            "rules": [
                {"id": "dgj2-net-001", "name": "SNMP 社区字串", "description": "检查 SNMP 社区字串是否非 public", "check_type": "snmp_config", "expected": "community != public", "severity": "high", "remediation": "修改 SNMP community 为非默认值"},
                {"id": "dgj2-net-002", "name": "SNMP 版本", "description": "检查是否禁用 SNMPv1/v2c", "check_type": "snmp_config", "expected": "SNMPv3 only", "severity": "medium", "remediation": "仅启用 SNMPv3"},
                {"id": "dgj2-net-003", "name": "SSH 版本", "description": "检查 SSH 是否使用版本 2", "check_type": "ssh_config", "expected": "SSH v2", "severity": "high", "remediation": "配置 SSH 版本 2"},
                {"id": "dgj2-net-004", "name": "Telnet 禁用", "description": "检查是否禁用 Telnet 管理", "check_type": "remote_access", "expected": "Telnet 禁用", "severity": "critical", "remediation": "no enable service telnet"},
                {"id": "dgj2-net-005", "name": "HTTP 管理禁用", "description": "检查是否禁用 HTTP 管理接口", "check_type": "remote_access", "expected": "HTTP 管理禁用", "severity": "high", "remediation": "no ip http server / no ip http secure-server"},
                {"id": "dgj2-net-006", "name": "控制台口令", "description": "检查控制台是否设置口令", "check_type": "console_config", "expected": "console 有口令", "severity": "high", "remediation": "line con 0 → password"},
                {"id": "dgj2-net-007", "name": "VTY 超时", "description": "检查 VTY 空闲超时是否设置", "check_type": "vty_config", "expected": "exec-timeout <= 10:00", "severity": "medium", "remediation": "line vty 0 4 → exec-timeout 10 0"},
                {"id": "dgj2-net-008", "name": "登录失败锁定", "description": "检查是否配置登录失败锁定", "check_type": "account_lock", "expected": "login block-for 300 attempts 5", "severity": "high", "remediation": "login block-for 300 attempts 5"},
                {"id": "dgj2-net-009", "name": "NTP 同步", "description": "检查是否配置 NTP 时间同步", "check_type": "ntp_config", "expected": "NTP 配置", "severity": "low", "remediation": "ntp server <IP>"},
                {"id": "dgj2-net-010", "name": "日志记录", "description": "检查是否启用日志记录", "check_type": "log_config", "expected": "logging 启用", "severity": "medium", "remediation": "logging <IP> / logging trap informational"},
                {"id": "dgj2-net-011", "name": "ACL 管理", "description": "检查管理口是否配置 ACL", "check_type": "acl_config", "expected": "VTY 有 ACL", "severity": "high", "remediation": "access-list permit <管理网段> → line vty → access-class"},
                {"id": "dgj2-net-012", "name": "未用端口关闭", "description": "检查未用端口是否关闭", "check_type": "port_config", "expected": "未用端口 shutdown", "severity": "medium", "remediation": "interface → shutdown"},
                {"id": "dgj2-net-013", "name": "CDP 禁用", "description": "检查对外端口是否禁用 CDP", "check_type": "cdp_config", "expected": "外部接口 no cdp enable", "severity": "low", "remediation": "interface → no cdp enable"},
                {"id": "dgj2-net-014", "name": "密码加密", "description": "检查是否启用密码加密存储", "check_type": "password_encryption", "expected": "service password-encryption", "severity": "high", "remediation": "service password-encryption"},
                {"id": "dgj2-net-015", "name": "Banner 警告", "description": "检查是否配置登录警告 Banner", "check_type": "banner_config", "expected": "banner 配置", "severity": "low", "remediation": "banner login ^C 警告信息 ^C"}
            ]
        });
        insert_baseline(manager, "dgj2-network-baseline", "等保2.0-网络设备安全基线", &network_rules, "network", "等保2.0", "high", "等保2.0 网络设备安全基线检查模板，涵盖 SNMP/SSH/Telnet/HTTP/控制台/VTY/ACL/CDP/密码加密/Banner 15 项检查", now).await?;

        // ===== 4. CIS - Linux 系统基线 =====
        let cis_linux_rules = serde_json::json!({
            "rules": [
                {"id": "cis-linux-001", "name": "文件系统分区-separate", "description": "检查 /tmp /var /home 是否独立分区", "check_type": "filesystem", "expected": "独立分区", "severity": "low", "remediation": "为 /tmp /var /home 创建独立分区"},
                {"id": "cis-linux-002", "name": "fstab 选项-tmp", "description": "检查 /tmp 是否设置 nodev/nosuid/noexec", "check_type": "filesystem", "expected": "nodev,nosuid,noexec", "severity": "medium", "remediation": "fstab 中 /tmp 添加 nodev,nosuid,noexec"},
                {"id": "cis-linux-003", "name": "fstab 选项-var", "description": "检查 /var 是否设置 nodev", "check_type": "filesystem", "expected": "nodev", "severity": "low", "remediation": "fstab 中 /var 添加 nodev"},
                {"id": "cis-linux-004", "name": "fstab 选项-shm", "description": "检查 /dev/shm 是否设置 nodev/nosuid/noexec", "check_type": "filesystem", "expected": "nodev,nosuid,noexec", "severity": "medium", "remediation": "fstab 中 /dev/shm 添加 nodev,nosuid,noexec"},
                {"id": "cis-linux-005", "name": "AIDE 安装", "description": "检查是否安装 AIDE/HIDS 文件完整性监控", "check_type": "fim", "expected": "AIDE 已安装", "severity": "high", "remediation": "yum install aide && aide --init"},
                {"id": "cis-linux-006", "name": "bootloader 密码", "description": "检查 GRUB 是否设置密码", "check_type": "boot_security", "expected": "GRUB 密码已设", "severity": "medium", "remediation": "grub2-setpassword"},
                {"id": "cis-linux-007", "name": "单个用户限制", "description": "检查单用户模式是否需密码", "check_type": "boot_security", "expected": "single 模式需要 root 密码", "severity": "medium", "remediation": "编辑 /etc/sysconfig/init 设置 SINGLE=/.sbin/sulogin"},
                {"id": "cis-linux-008", "name": "sysctl-源路由", "description": "检查是否禁用 IP 源路由", "check_type": "kernel_param", "expected": "net.ipv4.conf.all.accept_source_route=0", "severity": "medium", "remediation": "sysctl -w net.ipv4.conf.all.accept_source_route=0"},
                {"id": "cis-linux-009", "name": "sysctl-重定向", "description": "检查是否禁用 ICMP 重定向", "check_type": "kernel_param", "expected": "net.ipv4.conf.all.accept_redirects=0", "severity": "medium", "remediation": "sysctl -w net.ipv4.conf.all.accept_redirects=0"},
                {"id": "cis-linux-010", "name": "sysctl-反向过滤", "description": "检查是否启用反向路径过滤", "check_type": "kernel_param", "expected": "net.ipv4.conf.all.rp_filter=1", "severity": "medium", "remediation": "sysctl -w net.ipv4.conf.all.rp_filter=1"},
                {"id": "cis-linux-011", "name": "sysctl-ICMP 不可达", "description": "检查是否禁用发送 ICMP 不可达", "check_type": "kernel_param", "expected": "net.ipv4.icmp_ignore_bogus_error_responses=1", "severity": "low", "remediation": "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"},
                {"id": "cis-linux-012", "name": "sysctl-广播 ping", "description": "检查是否禁用广播 ping 响应", "check_type": "kernel_param", "expected": "net.ipv4.icmp_echo_ignore_broadcasts=1", "severity": "medium", "remediation": "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"},
                {"id": "cis-linux-013", "name": "cron 守护进程", "description": "检查 cron 守护进程是否启用", "check_type": "service_check", "expected": "crond 启用", "severity": "low", "remediation": "systemctl enable crond"},
                {"id": "cis-linux-014", "name": "at 守护进程", "description": "检查 atd 是否禁用（非必要时）", "check_type": "service_check", "expected": "atd 禁用", "severity": "low", "remediation": "systemctl disable atd"},
                {"id": "cis-linux-015", "name": "NFS 禁用", "description": "检查 NFS 相关服务是否禁用", "check_type": "service_check", "expected": "nfs/rpcbind 禁用", "severity": "medium", "remediation": "systemctl disable nfs rpcbind"},
                {"id": "cis-linux-016", "name": "DHCP 禁用", "description": "检查 DHCP 服务端是否禁用", "check_type": "service_check", "expected": "dhcpd 禁用", "severity": "low", "remediation": "systemctl disable dhcpd"},
                {"id": "cis-linux-017", "name": "rsyslog 安装", "description": "检查 rsyslog 是否安装并运行", "check_type": "log_audit", "expected": "rsyslog 运行", "severity": "high", "remediation": "yum install rsyslog && systemctl enable rsyslog"},
                {"id": "cis-linux-018", "name": "rsyslog 远程日志", "description": "检查是否配置远程日志服务器", "check_type": "log_audit", "expected": "远程日志配置", "severity": "medium", "remediation": "在 rsyslog.conf 添加 *.* @@<远程IP>:514"},
                {"id": "cis-linux-019", "name": "logrotate 频率", "description": "检查 logrotate 是否每日轮转", "check_type": "log_audit", "expected": "daily", "severity": "low", "remediation": "logrotate.conf 设置 daily"},
                {"id": "cis-linux-020", "name": "auditd 安装", "description": "检查 auditd 是否安装并运行", "check_type": "log_audit", "expected": "auditd 运行", "severity": "high", "remediation": "yum install audit && systemctl enable auditd"},
                {"id": "cis-linux-021", "name": "auditd 日志保留", "description": "检查 auditd 日志保留是否 >= 6 个月", "check_type": "log_audit", "expected": "num_logs >= 26 / max_log_file >= 100MB", "severity": "medium", "remediation": "auditd.conf 设置 num_logs 26 max_log_file 100"},
                {"id": "cis-linux-022", "name": "crontab 权限", "description": "检查 /etc/crontab 权限", "check_type": "file_permission", "expected": "0600 root:root", "severity": "low", "remediation": "chown root:root /etc/crontab && chmod 600 /etc/crontab"},
                {"id": "cis-linux-023", "name": "SSH MaxAuthTries", "description": "检查 SSH 认证最大尝试次数", "check_type": "ssh_config", "expected": "MaxAuthTries <= 4", "severity": "medium", "remediation": "sshd_config 设置 MaxAuthTries 4"},
                {"id": "cis-linux-024", "name": "SSH IgnoreRhosts", "description": "检查是否禁用 rhosts 认证", "check_type": "ssh_config", "expected": "IgnoreRhosts yes", "severity": "high", "remediation": "sshd_config 设置 IgnoreRhosts yes"},
                {"id": "cis-linux-025", "name": "SSH X11Forward", "description": "检查是否禁用 X11 转发", "check_type": "ssh_config", "expected": "X11Forwarding no", "severity": "low", "remediation": "sshd_config 设置 X11Forwarding no"}
            ]
        });
        insert_baseline(manager, "cis-linux-baseline", "CIS-Linux系统基线", &cis_linux_rules, "system", "CIS", "high", "CIS Benchmark Linux 系统基线检查模板，涵盖文件系统/GRUB/sysctl/服务/日志/审计/SSH 25 项检查", now).await?;

        // ===== 5. CIS - Windows 系统基线 =====
        let cis_windows_rules = serde_json::json!({
            "rules": [
                {"id": "cis-win-001", "name": "远程桌面-NLA", "description": "检查 RDP 是否启用网络级认证", "check_type": "remote_access", "expected": "UserAuthentication=1", "severity": "high", "remediation": "系统属性 → 远程 → 仅允许使用 NLA"},
                {"id": "cis-win-002", "name": "RDP 加密级别", "description": "检查 RDP 加密级别", "check_type": "remote_access", "expected": "MinEncryptionLevel=High", "severity": "medium", "remediation": "gpedit.msc → RDP → 设置加密级别为高"},
                {"id": "cis-win-003", "name": "NTLM 限制", "description": "检查是否限制 NTLM 认证", "check_type": "auth_config", "expected": "NTLM 限制策略", "severity": "medium", "remediation": "gpedit.msc → 本地策略 → 安全选项 → 网络安全: 限制 NTLM"},
                {"id": "cis-win-004", "name": "LDAP 签名", "description": "检查是否要求 LDAP 签名", "check_type": "auth_config", "expected": "LDAPSigningRequirements=Require", "severity": "medium", "remediation": "gpedit.msc → 域控制器 → LDAP 签名要求"},
                {"id": "cis-win-005", "name": "BitLocker", "description": "检查是否启用 BitLocker 磁盘加密", "check_type": "encryption", "expected": "BitLocker 已启用", "severity": "high", "remediation": "启用 BitLocker 全盘加密"},
                {"id": "cis-win-006", "name": "屏幕保护锁屏", "description": "检查屏幕保护是否启用密码保护", "check_type": "session_config", "expected": "ScreenSaverIsSecure=1", "severity": "low", "remediation": "gpedit.msc → 屏幕保护 → 密码保护已启用"},
                {"id": "cis-win-007", "name": "屏幕保护超时", "description": "检查屏幕保护超时是否 <= 15 分钟", "check_type": "session_config", "expected": "ScreenSaveTimeOut <= 900", "severity": "low", "remediation": "设置屏幕保护超时为 15 分钟"},
                {"id": "cis-win-008", "name": "UAC 启用", "description": "检查 UAC 是否启用", "check_type": "security_config", "expected": "EnableLUA=1", "severity": "high", "remediation": "控制面板 → 用户账户 → 更改用户账户控制设置"},
                {"id": "cis-win-009", "name": "PowerShell 脚本执行", "description": "检查 PowerShell 执行策略", "check_type": "security_config", "expected": "ExecutionPolicy=RemoteSigned", "severity": "medium", "remediation": "Set-ExecutionPolicy RemoteSigned"},
                {"id": "cis-win-010", "name": "Windows Defender", "description": "检查 Windows Defender 是否启用", "check_type": "security_config", "expected": "DisableAntiSpyware=0", "severity": "high", "remediation": "启用 Windows Defender 防病毒"},
                {"id": "cis-win-011", "name": "凭据委派", "description": "检查是否限制凭据委派", "check_type": "auth_config", "expected": "AllowDelegated=0", "severity": "medium", "remediation": "gpedit.msc → 凭据委派 → 限制委派"},
                {"id": "cis-win-012", "name": "SMBv1 禁用", "description": "检查是否禁用 SMBv1", "check_type": "service_check", "expected": "SMB1 禁用", "severity": "critical", "remediation": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"},
                {"id": "cis-win-013", "name": "LLMNR 禁用", "description": "检查是否禁用 LLMNR", "check_type": "network_config", "expected": "EnableLLMNR=0", "severity": "medium", "remediation": "gpedit.msc → DNS 客户端 → 关闭多播名称解析"},
                {"id": "cis-win-014", "name": "WPAD 禁用", "description": "检查是否禁用 WPAD 自动检测", "check_type": "network_config", "expected": "EnableAutoProxy=0", "severity": "low", "remediation": "禁用 IE WPAD 自动检测"},
                {"id": "cis-win-015", "name": "匿名 SAM 枚举", "description": "检查是否限制匿名 SAM 枚举", "check_type": "security_config", "expected": "RestrictAnonymousSAM=1", "severity": "high", "remediation": "gpedit.msc → 限制对 SAM 的匿名访问"}
            ]
        });
        insert_baseline(manager, "cis-windows-baseline", "CIS-Windows系统基线", &cis_windows_rules, "system", "CIS", "high", "CIS Benchmark Windows 系统基线检查模板，涵盖 RDP/NTLM/LDAP/BitLocker/UAC/PowerShell/Defender/SMBv1/LLMNR 15 项检查", now).await?;

        // ===== 6. 等保2.0 - MySQL 数据库基线 =====
        let mysql_rules = serde_json::json!({
            "rules": [
                {"id": "dgj2-mysql-001", "name": "root 密码", "description": "检查 root 是否设置强密码", "check_type": "password_policy", "expected": "root 密码非空且复杂", "severity": "critical", "remediation": "ALTER USER 'root'@'localhost' IDENTIFIED BY '强密码'"},
                {"id": "dgj2-mysql-002", "name": "匿名用户", "description": "检查是否删除匿名用户", "check_type": "account_check", "expected": "无匿名用户", "severity": "high", "remediation": "DROP USER ''@'localhost'; DROP USER ''@'hostname'"},
                {"id": "dgj2-mysql-003", "name": "test 数据库", "description": "检查是否删除 test 数据库", "check_type": "database_config", "expected": "test 库已删", "severity": "medium", "remediation": "DROP DATABASE test"},
                {"id": "dgj2-mysql-004", "name": "远程 root 登录", "description": "检查是否禁止 root 远程登录", "check_type": "account_check", "expected": "root 仅限 localhost", "severity": "high", "remediation": "REVOKE ALL ON *.* FROM 'root'@'%'; DROP USER 'root'@'%'"},
                {"id": "dgj2-mysql-005", "name": "文件权限-mysql 配置", "description": "检查 my.cnf 权限", "check_type": "file_permission", "expected": "0640 mysql:mysql", "severity": "medium", "remediation": "chmod 640 /etc/my.cnf && chown mysql:mysql /etc/my.cnf"},
                {"id": "dgj2-mysql-006", "name": "数据目录权限", "description": "检查数据目录权限", "check_type": "file_permission", "expected": "0700 mysql:mysql", "severity": "high", "remediation": "chmod 700 /var/lib/mysql && chown -R mysql:mysql /var/lib/mysql"},
                {"id": "dgj2-mysql-007", "name": "log-bin 启用", "description": "检查是否启用二进制日志", "check_type": "log_config", "expected": "log_bin 启用", "severity": "medium", "remediation": "my.cnf 中添加 log-bin=mysql-bin"},
                {"id": "dgj2-mysql-008", "name": "错误日志", "description": "检查是否启用错误日志", "check_type": "log_config", "expected": "log_error 启用", "severity": "low", "remediation": "my.cnf 中添加 log-error=/var/log/mysqld.log"},
                {"id": "dgj2-mysql-009", "name": "general_log", "description": "检查是否关闭通用查询日志（生产环境）", "check_type": "log_config", "expected": "general_log=OFF", "severity": "low", "remediation": "SET GLOBAL general_log = 'OFF'"},
                {"id": "dgj2-mysql-010", "name": "bind-address", "description": "检查绑定地址是否非 0.0.0.0", "check_type": "network_config", "expected": "bind-address != 0.0.0.0", "severity": "high", "remediation": "my.cnf 设置 bind-address=127.0.0.1 或内网 IP"},
                {"id": "dgj2-mysql-011", "name": "skip-symbolic-links", "description": "检查是否禁用符号链接", "check_type": "security_config", "expected": "skip_symbolic_links=1", "severity": "medium", "remediation": "my.cnf 添加 skip_symbolic_links"},
                {"id": "dgj2-mysql-012", "name": "本地 infile", "description": "检查是否禁用 LOCAL INFILE", "check_type": "security_config", "expected": "local_infile=0", "severity": "medium", "remediation": "my.cnf 添加 local-infile=0"},
                {"id": "dgj2-mysql-013", "name": "安全连接", "description": "检查是否启用 SSL 连接", "check_type": "encryption", "expected": "have_ssl=Yes", "severity": "medium", "remediation": "my.cnf 配置 ssl-ca/ssl-cert/ssl-key"},
                {"id": "dgj2-mysql-014", "name": "密码验证插件", "description": "检查是否安装密码验证插件", "check_type": "password_policy", "expected": "validate_password 启用", "severity": "high", "remediation": "INSTALL PLUGIN validate_password SONAME 'validate_password.so'"},
                {"id": "dgj2-mysql-015", "name": "审计插件", "description": "检查是否安装审计插件", "check_type": "log_audit", "expected": "audit 插件启用", "severity": "medium", "remediation": "INSTALL PLUGIN audit SONAME 'libaudit_plugin.so'"}
            ]
        });
        insert_baseline(manager, "dgj2-mysql-baseline", "等保2.0-MySQL数据库基线", &mysql_rules, "database", "等保2.0", "high", "等保2.0 MySQL 数据库安全基线检查模板，涵盖 root 密码/匿名用户/test 库/远程登录/文件权限/日志/网络/SSL/密码验证/审计 15 项检查", now).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for id in &[
            "dgj2-linux-baseline",
            "dgj2-windows-baseline",
            "dgj2-network-baseline",
            "cis-linux-baseline",
            "cis-windows-baseline",
            "dgj2-mysql-baseline",
        ] {
            let sql = format!("DELETE FROM config_templates WHERE id = '{}'", id);
            conn.execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}

/// 辅助函数：插入内置基线策略模板
async fn insert_baseline(
    manager: &SchemaManager<'_>,
    id: &str,
    name: &str,
    rule_set: &serde_json::Value,
    config_type: &str,
    category: &str,
    security_level: &str,
    description: &str,
    now: chrono::NaiveDateTime,
) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let rule_set_str = serde_json::to_string(rule_set).unwrap_or_else(|_| "{}".to_string());
    let sql = format!(
        "INSERT INTO config_templates (id, name, rule_set, is_builtin, config_type, category, security_level, description, created_at, updated_at) VALUES ('{}', '{}', '{}', true, '{}', '{}', '{}', '{}', '{}', '{}')",
        id,
        name.replace('\'', "''"),
        rule_set_str.replace('\'', "''"),
        config_type,
        category,
        security_level,
        description.replace('\'', "''"),
        now,
        now
    );
    conn.execute_unprepared(&sql).await?;
    Ok(())
}
