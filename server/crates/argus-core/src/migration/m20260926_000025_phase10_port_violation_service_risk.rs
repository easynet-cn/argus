//! 端口违规配置子模块 + 协议/服务风险等级
//!
//! 要求：端口管理包含违规配置（端口标签特征管理）和协议/服务风险等级两个子模块。
//! 本迁移创建 service_risk_levels（服务风险等级库）和 port_violation_rules（违规端口规则）两张表，
//! 并预置常见服务的风险等级和违规端口规则。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 服务风险等级库
        manager
            .create_table(
                Table::create()
                    .table(ServiceRiskLevel::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ServiceRiskLevel::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(ServiceRiskLevel::ServiceName).string_len(64).not_null())
                    .col(ColumnDef::new(ServiceRiskLevel::DefaultPort).integer())
                    .col(ColumnDef::new(ServiceRiskLevel::Protocol).string_len(8).not_null().default("tcp"))
                    .col(ColumnDef::new(ServiceRiskLevel::RiskLevel).string_len(16).not_null().default("medium"))
                    .col(ColumnDef::new(ServiceRiskLevel::Description).text())
                    .col(ColumnDef::new(ServiceRiskLevel::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(ServiceRiskLevel::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(ServiceRiskLevel::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_service_risk_name")
                    .table(ServiceRiskLevel::Table)
                    .col(ServiceRiskLevel::ServiceName)
                    .to_owned(),
            )
            .await?;

        // 端口违规规则
        manager
            .create_table(
                Table::create()
                    .table(PortViolationRule::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(PortViolationRule::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(PortViolationRule::Name).string_len(128).not_null())
                    .col(ColumnDef::new(PortViolationRule::Port).integer().not_null())
                    .col(ColumnDef::new(PortViolationRule::Protocol).string_len(8).not_null().default("tcp"))
                    .col(ColumnDef::new(PortViolationRule::ServiceName).string_len(64))
                    .col(ColumnDef::new(PortViolationRule::RiskLevel).string_len(16).not_null().default("medium"))
                    .col(ColumnDef::new(PortViolationRule::Description).text())
                    .col(ColumnDef::new(PortViolationRule::Remediation).text())
                    .col(ColumnDef::new(PortViolationRule::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(PortViolationRule::Enabled).boolean().not_null().default(true))
                    .col(ColumnDef::new(PortViolationRule::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(PortViolationRule::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_port_violation_port")
                    .table(PortViolationRule::Table)
                    .col(PortViolationRule::Port)
                    .to_owned(),
            )
            .await?;

        // 预置内置服务风险等级（service_name, default_port, protocol, risk_level, description）
        let builtin_services: &[(i32, &str, &str, &str, &str)] = &[
            // (port, service, protocol, risk_level, description)
            (21, "FTP", "tcp", "high", "明文传输，易被嗅探凭据"),
            (22, "SSH", "tcp", "medium", "加密远程登录，弱口令风险"),
            (23, "Telnet", "tcp", "critical", "明文传输，应禁用"),
            (25, "SMTP", "tcp", "low", "邮件发送，开放中继风险"),
            (53, "DNS", "udp", "medium", "域名解析，可被 DNS 劫持/放大攻击"),
            (69, "TFTP", "udp", "high", "无认证文件传输"),
            (79, "Finger", "tcp", "medium", "用户信息泄露"),
            (80, "HTTP", "tcp", "low", "Web 服务，明文传输"),
            (110, "POP3", "tcp", "medium", "邮件接收，明文传输"),
            (111, "RPC", "tcp", "high", "PortMapper，可被枚举服务"),
            (135, "MS-RPC", "tcp", "high", "Windows RPC，可被远程利用"),
            (139, "NetBIOS-SSN", "tcp", "high", "Windows 文件共享，信息泄露"),
            (143, "IMAP", "tcp", "medium", "邮件接收，明文传输"),
            (161, "SNMP", "udp", "high", "社区字串泄露设备信息"),
            (389, "LDAP", "tcp", "medium", "目录服务，未认证访问风险"),
            (443, "HTTPS", "tcp", "low", "加密 Web 服务"),
            (445, "SMB", "tcp", "high", "Windows 文件共享，勒索/蠕虫传播入口"),
            (465, "SMTPS", "tcp", "low", "加密邮件发送"),
            (512, "rexec", "tcp", "high", "远程执行，明文认证"),
            (513, "rlogin", "tcp", "high", "远程登录，明文认证"),
            (514, "syslog", "udp", "medium", "系统日志，明文传输"),
            (587, "SMTP-Submit", "tcp", "low", "邮件提交，建议启用"),
            (636, "LDAPS", "tcp", "low", "加密目录服务"),
            (873, "Rsync", "tcp", "medium", "文件同步，未授权访问风险"),
            (993, "IMAPS", "tcp", "low", "加密邮件接收"),
            (995, "POP3S", "tcp", "low", "加密邮件接收"),
            (1080, "SOCKS", "tcp", "medium", "代理服务，可被滥用"),
            (1433, "MSSQL", "tcp", "high", "数据库，弱口令/未授权访问"),
            (1521, "Oracle", "tcp", "high", "数据库，弱口令/未授权访问"),
            (2049, "NFS", "tcp", "high", "网络文件系统，未授权访问"),
            (2375, "Docker", "tcp", "critical", "Docker API 未授权访问，可致 RCE"),
            (3306, "MySQL", "tcp", "high", "数据库，弱口令/未授权访问"),
            (3389, "RDP", "tcp", "high", "远程桌面，弱口令/BlueKeep"),
            (5432, "PostgreSQL", "tcp", "high", "数据库，弱口令/未授权访问"),
            (5900, "VNC", "tcp", "high", "远程桌面，弱口令/未授权访问"),
            (5984, "CouchDB", "tcp", "high", "数据库，未授权访问"),
            (6379, "Redis", "tcp", "high", "数据库，未授权访问"),
            (7001, "WebLogic", "tcp", "high", "中间件，历史 RCE 漏洞"),
            (8080, "HTTP-Alt", "tcp", "medium", "备用 Web 端口"),
            (8443, "HTTPS-Alt", "tcp", "medium", "备用加密 Web 端口"),
            (9000, "PHP-FPM", "tcp", "high", "PHP-FPM 未授权访问可致 RCE"),
            (9200, "Elasticsearch", "tcp", "high", "搜索引擎，未授权访问"),
            (11211, "Memcached", "tcp", "high", "缓存服务，未授权访问/放大攻击"),
            (27017, "MongoDB", "tcp", "high", "数据库，未授权访问"),
        ];

        let conn = manager.get_connection();
        let now = chrono::Utc::now().naive_utc();
        for (idx, (port, name, protocol, level, desc)) in builtin_services.iter().enumerate() {
            let id = format!("srv-builtin-{:04}", idx + 1);
            let sql = format!(
                "INSERT INTO service_risk_levels (id, service_name, default_port, protocol, risk_level, description, is_builtin, created_at, updated_at) VALUES ('{}', '{}', {}, '{}', '{}', '{}', true, '{}', '{}')",
                id, name, port, protocol, level, desc.replace('\'', "''"), now, now
            );
            conn.execute_unprepared(&sql).await?;
        }

        // 预置内置端口违规规则（高危服务开放即违规）
        let builtin_violations: &[(i32, &str, &str, &str, &str, &str, &str)] = &[
            // (port, name, protocol, service, risk_level, desc, remediation)
            (23, "违规开放 Telnet 服务", "tcp", "Telnet", "critical", "Telnet 明文传输凭据，存在被嗅探风险", "禁用 Telnet，改用 SSH 加密远程登录"),
            (21, "违规开放 FTP 服务", "tcp", "FTP", "high", "FTP 明文传输凭据，存在被嗅探风险", "改用 SFTP/FTPS，或限制源 IP 访问"),
            (69, "违规开放 TFTP 服务", "udp", "TFTP", "high", "TFTP 无认证，可被未授权读取/写入文件", "禁用 TFTP，或限制源 IP 和目录访问"),
            (3389, "违规开放 RDP 服务", "tcp", "RDP", "high", "RDP 远程桌面存在弱口令和已知漏洞风险", "限制源 IP，启用网络级认证(NLA)，使用强口令"),
            (445, "违规开放 SMB 服务", "tcp", "SMB", "high", "SMB 是勒索病毒/蠕虫传播的主要入口", "限制源 IP，禁用 SMBv1，启用签名"),
            (135, "违规开放 MS-RPC 端口", "tcp", "MS-RPC", "high", "Windows RPC 暴露在外网可被远程利用", "限制内网访问，关闭对外暴露"),
            (139, "违规开放 NetBIOS-SSN", "tcp", "NetBIOS-SSN", "high", "NetBIOS 会话服务暴露存在信息泄露和远程利用风险", "限制内网访问，关闭对外暴露"),
            (2375, "违规开放 Docker API", "tcp", "Docker", "critical", "Docker API 未授权访问可直接 RCE 控制主机", "禁用外网访问，启用 TLS 认证或绑定本地套接字"),
            (9000, "违规开放 PHP-FPM 端口", "tcp", "PHP-FPM", "high", "PHP-FPM 直接暴露可被未授权执行任意代码", "限制仅本机/Nginx 反代访问，不对外暴露"),
            (6379, "违规开放 Redis 端口", "tcp", "Redis", "high", "Redis 未授权访问可致数据泄露和 RCE", "启用认证，绑定本机，禁止外网访问"),
            (27017, "违规开放 MongoDB 端口", "tcp", "MongoDB", "high", "MongoDB 未授权访问可致数据泄露", "启用认证，绑定本机，禁止外网访问"),
            (9200, "违规开放 Elasticsearch 端口", "tcp", "Elasticsearch", "high", "Elasticsearch 未授权访问可致数据泄露和 RCE", "启用安全模块，绑定内网，禁止外网访问"),
            (11211, "违规开放 Memcached 端口", "tcp", "Memcached", "high", "Memcached 未授权访问可被用于放大攻击", "启用认证，绑定本机，禁止外网访问"),
        ];

        for (idx, (port, name, protocol, service, level, desc, rem)) in builtin_violations.iter().enumerate() {
            let id = format!("pv-builtin-{:04}", idx + 1);
            let sql = format!(
                "INSERT INTO port_violation_rules (id, name, port, protocol, service_name, risk_level, description, remediation, is_builtin, enabled, created_at, updated_at) VALUES ('{}', '{}', {}, '{}', '{}', '{}', '{}', '{}', true, true, '{}', '{}')",
                id, name, port, protocol, service, level, desc.replace('\'', "''"), rem.replace('\'', "''"), now, now
            );
            conn.execute_unprepared(&sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PortViolationRule::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ServiceRiskLevel::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum ServiceRiskLevel {
    Table,
    Id,
    ServiceName,
    DefaultPort,
    Protocol,
    RiskLevel,
    Description,
    IsBuiltin,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum PortViolationRule {
    Table,
    Id,
    Name,
    Port,
    Protocol,
    ServiceName,
    RiskLevel,
    Description,
    Remediation,
    IsBuiltin,
    Enabled,
    CreatedAt,
    UpdatedAt,
}
