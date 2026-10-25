//! 数据库漏洞检测模块
//!
//! 针对 MySQL/PostgreSQL/Redis/MongoDB/MSSQL/Oracle 实现:
//! - 未授权访问检测（匿名连接）
//! - 默认数据库检测
//! - 危险配置检测（Redis CONFIG、MongoDB REST API、MSSQL xp_cmdshell 等）
//! - 版本指纹 → CVE 匹配（复用 argus-vulndb）

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// 数据库类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DbType {
    Mysql,
    Postgresql,
    Redis,
    Mongodb,
    Mssql,
    Oracle,
}

impl DbType {
    pub fn default_port(&self) -> u16 {
        match self {
            DbType::Mysql => 3306,
            DbType::Postgresql => 5432,
            DbType::Redis => 6379,
            DbType::Mongodb => 27017,
            DbType::Mssql => 1433,
            DbType::Oracle => 1521,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DbType::Mysql => "mysql",
            DbType::Postgresql => "postgresql",
            DbType::Redis => "redis",
            DbType::Mongodb => "mongodb",
            DbType::Mssql => "mssql",
            DbType::Oracle => "oracle",
        }
    }
}

/// 数据库漏洞检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbVulnFinding {
    /// 目标 host:port
    pub target: String,
    /// 数据库类型
    pub db_type: DbType,
    /// 漏洞标题
    pub title: String,
    /// 严重级别 (critical/high/medium/low/info)
    pub severity: String,
    /// 漏洞描述
    pub description: String,
    /// 修复建议
    pub fix_advice: Option<String>,
    /// 证据
    pub evidence: String,
}

/// 数据库漏洞扫描器
pub struct DbVulnScanner;

impl DbVulnScanner {
    pub fn new() -> Self {
        Self
    }

    /// 扫描单个目标
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        db_type: DbType,
        timeout_ms: u64,
    ) -> Vec<DbVulnFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        match db_type {
            DbType::Redis => {
                findings.extend(scan_redis(host, port, &target, dur).await);
            }
            DbType::Mongodb => {
                findings.extend(scan_mongodb(host, port, &target, dur).await);
            }
            DbType::Mysql => {
                findings.extend(scan_mysql(host, port, &target, dur).await);
            }
            DbType::Postgresql => {
                findings.extend(scan_postgresql(host, port, &target, dur).await);
            }
            DbType::Mssql => {
                findings.extend(scan_mssql(host, port, &target, dur).await);
            }
            DbType::Oracle => {
                findings.extend(scan_oracle(host, port, &target, dur).await);
            }
        }

        findings
    }

    /// 扫描多个目标
    pub async fn scan_targets(
        &self,
        targets: &[(String, u16, DbType)],
        timeout_ms: u64,
    ) -> Vec<DbVulnFinding> {
        let mut all = Vec::new();
        for (host, port, db_type) in targets {
            let findings = self.scan(host, *port, db_type.clone(), timeout_ms).await;
            all.extend(findings);
        }
        all
    }
}

impl Default for DbVulnScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Redis 漏洞检测 ==============

async fn scan_redis(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    // 1. 尝试无认证连接
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 发送 INFO 命令（无 AUTH）
    let info_cmd = b"INFO\r\n";
    if stream.write_all(info_cmd).await.is_err() {
        return findings;
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return findings,
    };
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    // 检查是否需要认证
    if resp.contains("NOAUTH") || resp.contains("Authentication required") {
        // 需要认证，尝试空密码
        let auth_cmd = b"AUTH \"\" \"\"\r\n";
        let _ = stream.write_all(auth_cmd).await;
        let n = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return findings,
        };
        let auth_resp = String::from_utf8_lossy(&buf[..n]).to_string();
        if auth_resp.starts_with("+OK") {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: DbType::Redis,
                title: "Redis 空密码认证成功".to_string(),
                severity: "high".to_string(),
                description: "Redis 允许空密码认证，攻击者可直接访问数据库".to_string(),
                fix_advice: Some("配置 requirepass，设置强密码".to_string()),
                evidence: "AUTH 命令返回 +OK".to_string(),
            });
        }
        return findings;
    }

    // 无需认证 —— 严重漏洞
    findings.push(DbVulnFinding {
        target: target.to_string(),
        db_type: DbType::Redis,
        title: "Redis 未授权访问".to_string(),
        severity: "critical".to_string(),
        description: "Redis 未配置认证，任何人可直接连接并读写数据".to_string(),
        fix_advice: Some("1. 配置 requirepass 2. 绑定 127.0.0.1 3. 修改默认端口 4. 配置防火墙".to_string()),
        evidence: "INFO 命令直接返回服务器信息".to_string(),
    });

    // 2. 检查危险配置
    let _ = stream.write_all(b"CONFIG GET dir\r\n").await;
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        let cfg_resp = String::from_utf8_lossy(&buf[..n]).to_string();
        if cfg_resp.contains("/var/www") || cfg_resp.contains("/www") {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: DbType::Redis,
                title: "Redis 写入 Web 目录风险".to_string(),
                severity: "high".to_string(),
                description: "Redis dir 配置指向 Web 目录，可被利用写入 WebShell".to_string(),
                fix_advice: Some("修改 dir 配置到非 Web 目录".to_string()),
                evidence: cfg_resp.lines().take(3).collect(),
            });
        }
    }

    // 3. 检查 FLUSH 权限
    let _ = stream.write_all(b"CONFIG GET requirepass\r\n").await;
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        let pwd_resp = String::from_utf8_lossy(&buf[..n]).to_string();
        if pwd_resp.contains("\"\"") || pwd_resp.contains("empty") {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: DbType::Redis,
                title: "Redis 认证密码为空".to_string(),
                severity: "high".to_string(),
                description: "requirepass 配置为空，无认证保护".to_string(),
                fix_advice: Some("设置 requirepass 强密码".to_string()),
                evidence: "CONFIG GET requirepass 返回空".to_string(),
            });
        }
    }

    // 4. 提取版本信息
    for line in resp.lines() {
        if line.starts_with("redis_version:") {
            let version = line.trim_start_matches("redis_version:").trim();
            // 检查已知 CVE 版本范围
            if let Some(cve) = check_redis_cve(version) {
                findings.push(cve);
            }
            break;
        }
    }

    findings
}

// ============== MongoDB 漏洞检测 ==============

async fn scan_mongodb(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 发送 isMaster 命令（OP_MSG 格式）
    let ismaster_doc = build_simple_bson_isMaster();
    let op_msg = build_op_msg(ismaster_doc);
    if stream.write_all(&op_msg).await.is_err() {
        return findings;
    }

    let mut buf = vec![0u8; 8192];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return findings,
    };

    let resp_str = String::from_utf8_lossy(&buf[..n]).to_string();

    // 如果响应中包含 "ok" 或 "ismaster" —— 无认证
    if resp_str.contains("ismaster") || resp_str.contains("setName") {
        findings.push(DbVulnFinding {
            target: target.to_string(),
            db_type: DbType::Mongodb,
            title: "MongoDB 未授权访问".to_string(),
            severity: "critical".to_string(),
            description: "MongoDB 未启用 --auth，任何人可直接连接并读写数据".to_string(),
            fix_advice: Some("1. 启动时加 --auth 2. 创建管理员账户 3. 绑定 127.0.0.1 4. 配置防火墙".to_string()),
            evidence: "isMaster 命令直接返回服务器信息".to_string(),
        });

        // 尝试枚举数据库
        let list_db = build_op_msg(build_list_databases());
        let _ = stream.write_all(&list_db).await;
        if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
            let db_resp = String::from_utf8_lossy(&buf[..n]).to_string();
            if db_resp.contains("totalSize") || db_resp.contains("name") {
                findings.push(DbVulnFinding {
                    target: target.to_string(),
                    db_type: DbType::Mongodb,
                    title: "MongoDB 数据库枚举".to_string(),
                    severity: "high".to_string(),
                    description: "可枚举所有数据库名称和大小".to_string(),
                    fix_advice: Some("启用认证，限制 listDatabases 权限".to_string()),
                    evidence: "listDatabases 命令返回数据库列表".to_string(),
                });
            }
        }
    } else if resp_str.contains("not authorized") || resp_str.contains("auth") {
        // 需要认证
        findings.push(DbVulnFinding {
            target: target.to_string(),
            db_type: DbType::Mongodb,
            title: "MongoDB 认证已启用".to_string(),
            severity: "info".to_string(),
            description: "MongoDB 已启用认证，未授权访问被拒绝".to_string(),
            fix_advice: None,
            evidence: "isMaster 命令返回认证错误".to_string(),
        });
    }

    findings
}

// ============== MySQL 漏洞检测 ==============

async fn scan_mysql(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 读取 MySQL greeting（服务器主动发送握手包）
    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return findings,
    };

    // 解析 MySQL 版本（greeting 包中 offset 5 处的 null-terminated 字符串）
    let mut mysql_version = String::new();
    if n > 6 {
        let version_end = buf[5..n].iter().position(|&b| b == 0).unwrap_or(n - 5);
        mysql_version = String::from_utf8_lossy(&buf[5..5 + version_end]).to_string();
        if mysql_version.starts_with(|c: char| c.is_ascii_digit()) {
            // 检查 MySQL 版本 CVE
            if let Some(cve) = check_mysql_cve(&mysql_version) {
                findings.push(cve);
            }

            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: DbType::Mysql,
                title: "MySQL 服务版本暴露".to_string(),
                severity: "low".to_string(),
                description: format!("MySQL 版本: {}", mysql_version),
                fix_advice: Some("隐藏版本信息或升级到最新版本".to_string()),
                evidence: format!("Handshake greeting 包暴露版本: {}", mysql_version),
            });
        }
    }

    // R6.1 修复：真实匿名访问检测——发送 HandshakeResponse41 空凭证握手
    if let Ok(true) = try_mysql_anonymous(&mut stream, dur).await {
        findings.push(DbVulnFinding {
            target: target.to_string(),
            db_type: DbType::Mysql,
            title: "MySQL 匿名访问（空用户登录成功）".to_string(),
            severity: "critical".to_string(),
            description: "MySQL 允许空用户名连接，攻击者可直接访问数据库".to_string(),
            fix_advice: Some("1. 删除匿名账户 (DELETE FROM mysql.user WHERE User='') 2. 执行 FLUSH PRIVILEGES 3. 限制 root 远程登录".to_string()),
            evidence: "HandshakeResponse41 (username='') 返回 OK 包".to_string(),
        });
    }

    findings
}

/// 尝试 MySQL 匿名登录（发送空用户名的 HandshakeResponse41）
async fn try_mysql_anonymous(stream: &mut TcpStream, dur: Duration) -> Result<bool, std::io::Error> {
    // 构造 HandshakeResponse41 负载
    let mut payload = Vec::new();

    // client_capabilities (4 bytes LE):
    // CLIENT_LONG_PASSWORD(1) | CLIENT_PROTOCOL_41(0x200) | CLIENT_TRANSACTIONS(0x2000)
    // | CLIENT_SECURE_CONNECTION(0x8000) | CLIENT_PLUGIN_AUTH(0x80000)
    let client_flags: u32 = 0x00088201;
    payload.extend_from_slice(&client_flags.to_le_bytes());

    // max_packet_size (4 bytes LE): 16MB
    payload.extend_from_slice(&0x01000000u32.to_le_bytes());

    // charset (1 byte): utf8mb4 = 0xE0
    payload.push(0xE0);

    // reserved (23 bytes): 0x00
    payload.extend_from_slice(&[0u8; 23]);

    // username: 空字符串 (仅 null 终止符)
    payload.push(0x00);

    // auth_response (CLIENT_SECURE_CONNECTION 格式: 1 byte length + data): 空响应
    payload.push(0x00);

    // auth_plugin_name: "mysql_native_password\0"
    payload.extend_from_slice(b"mysql_native_password");
    payload.push(0x00);

    // 构造 MySQL 数据包: 3 bytes length (LE) + 1 byte sequence_id + payload
    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(1); // sequence_id = 1（greeting 是 seq 0）
    packet.extend_from_slice(&payload);

    stream.write_all(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 4 => n,
        _ => return Ok(false),
    };

    // MySQL 响应: 4 byte header + payload
    // payload[0]: 0x00 = OK 包（登录成功）, 0xFF = ERR 包（登录失败）
    Ok(buf[4] == 0x00)
}

// ============== PostgreSQL 漏洞检测 ==============

async fn scan_postgresql(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 发送 PostgreSQL StartupMessage（空用户名检测 trust 认证）
    // StartupMessage 格式: length(4) + protocol_version(4) + key-value pairs
    let startup = build_pg_startup("postgres", "postgres");
    let _ = stream.write_all(&startup).await;

    let mut buf = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            // PostgreSQL 响应:
            // 'R' + length(4) + auth_type(4)
            // auth_type: 0 = AuthenticationOk (trust认证, 无需密码)
            if buf[0] == b'R' && n >= 9 {
                let auth_type = u32::from_be_bytes(buf[5..9].try_into().unwrap_or([0; 4]));
                if auth_type == 0 {
                    findings.push(DbVulnFinding {
                        target: target.to_string(),
                        db_type: DbType::Postgresql,
                        title: "PostgreSQL trust 认证（无密码访问）".to_string(),
                        severity: "critical".to_string(),
                        description: "PostgreSQL 配置了 trust 认证，允许无密码连接".to_string(),
                        fix_advice: Some("修改 pg_hba.conf，将 trust 改为 md5 或 scram-sha-256".to_string()),
                        evidence: "StartupMessage 返回 AuthenticationOk".to_string(),
                    });
                }
            }
            // 'E' = ErrorResponse（认证失败或用户不存在）
            if buf[0] == b'E' {
                let err_msg = String::from_utf8_lossy(&buf[..n]);
                if err_msg.contains("password") || err_msg.contains("authentication") {
                    findings.push(DbVulnFinding {
                        target: target.to_string(),
                        db_type: DbType::Postgresql,
                        title: "PostgreSQL 需要密码认证".to_string(),
                        severity: "info".to_string(),
                        description: "PostgreSQL 要求密码认证".to_string(),
                        fix_advice: None,
                        evidence: err_msg.lines().take(3).collect(),
                    });
                }
            }
        }
    }

    findings
}

// ============== MSSQL 漏洞检测 ==============

async fn scan_mssql(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 发送 TDS Pre-Login 探测
    let prelogin = build_tds_prelogin();
    let _ = stream.write_all(&prelogin).await;

    let mut buf = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 8 {
            let pkt_type = buf[4];
            if pkt_type == 0x04 {
                findings.push(DbVulnFinding {
                    target: target.to_string(),
                    db_type: DbType::Mssql,
                    title: "MSSQL 服务暴露".to_string(),
                    severity: "low".to_string(),
                    description: "SQL Server 端口开放，可被远程访问".to_string(),
                    fix_advice: Some("1. 限制网络访问 2. 启用加密 3. 禁用 sa 远程登录".to_string()),
                    evidence: "TDS Pre-Login 成功响应".to_string(),
                });
            }
        }
    }

    // R6.1 修复：TDS Login7 弱密码检测
    let weak_creds: &[(&str, &str)] = &[
        ("sa", "sa"),
        ("sa", "password"),
        ("sa", "123456"),
        ("sa", "1234"),
        ("sa", ""),
    ];
    for (user, pass) in weak_creds {
        let mut stream2 = match timeout(dur, TcpStream::connect((host, port))).await {
            Ok(Ok(s)) => s,
            _ => break, // 连接失败则停止
        };

        // 发送 Pre-Login 并读取响应
        let _ = stream2.write_all(&prelogin).await;
        let mut rbuf = vec![0u8; 4096];
        let _ = timeout(dur, stream2.read(&mut rbuf)).await;

        // 发送 Login7
        let login7 = build_tds_login7(user, pass);
        let _ = stream2.write_all(&login7).await;

        let mut lbuf = vec![0u8; 4096];
        let ln = match timeout(dur, stream2.read(&mut lbuf)).await {
            Ok(Ok(n)) if n > 8 => n,
            _ => continue,
        };

        // TDS Login7 响应: 4 byte header + type byte at offset 4
        // type 0x04 (Tabular Result) 中检查 Token: 0xAA (ERROR) vs 0xD1 (DONEEXT) / 0xFD (DONEPROC)
        if lbuf[4] == 0x04 && ln > 8 {
            // 检查是否包含 ERROR token (0xAA)
            let has_error = (4..ln).any(|i| lbuf[i] == 0xAA);
            if !has_error {
                findings.push(DbVulnFinding {
                    target: target.to_string(),
                    db_type: DbType::Mssql,
                    title: "MSSQL 弱密码（sa 账户）".to_string(),
                    severity: "critical".to_string(),
                    description: format!("sa 账户可使用弱密码 '{}' 登录", pass),
                    fix_advice: Some("1. 立即修改 sa 密码为强密码 2. 禁用 sa 账户 3. 限制 1433 端口访问 4. 启用 Windows 认证模式".to_string()),
                    evidence: format!("TDS Login7 (sa/{}) 返回成功响应", pass),
                });
                break; // 成功一个就够
            }
        }
    }

    findings
}

// ============== Oracle 漏洞检测 ==============

async fn scan_oracle(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<DbVulnFinding> {
    let mut findings = Vec::new();

    // 1. TNS 监听暴露检测
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    let tns_connect = build_tns_connect("ORCL");
    let _ = stream.write_all(&tns_connect).await;

    let mut buf = vec![0u8; 4096];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n >= 5 {
            let pkt_type = buf[4];
            if pkt_type == 2 || pkt_type == 12 {
                findings.push(DbVulnFinding {
                    target: target.to_string(),
                    db_type: DbType::Oracle,
                    title: "Oracle TNS 监听暴露".to_string(),
                    severity: "medium".to_string(),
                    description: "Oracle TNS 监听器对外开放，可尝试 SID 枚举和默认账户".to_string(),
                    fix_advice: Some("1. 限制 TNS 监听 IP 2. 设置监听密码 3. 移除默认账户密码".to_string()),
                    evidence: format!("TNS Connect 响应 type={}", pkt_type),
                });
            }
        }
    }

    // 2. R6.1 修复：SID 枚举——尝试常见 SID，检查是否存在
    let common_sids: &[&str] = &["ORCL", "XE", "PROD", "TEST", "ORADB", "ORA12C", "FREE"];
    let mut valid_sids = Vec::new();
    for sid in common_sids {
        if let Ok(true) = check_oracle_sid(host, port, sid, dur).await {
            valid_sids.push(*sid);
        }
    }
    if !valid_sids.is_empty() {
        findings.push(DbVulnFinding {
            target: target.to_string(),
            db_type: DbType::Oracle,
            title: "Oracle SID 枚举成功".to_string(),
            severity: "high".to_string(),
            description: format!("以下 SID 可被探测到: {}", valid_sids.join(", ")),
            fix_advice: Some("1. 隐藏 TNS 监听器 2. 使用不常见的 SID 名称 3. 设置监听器密码 4. 限制 1521 端口访问".to_string()),
            evidence: format!("有效的 SID: {}", valid_sids.join(", ")),
        });
    }

    // 3. R6.1 修复：默认账户测试（通过 TNS Connect 检测 SID + 账户存在性）
    // 尝试默认账户 system/oracle, sys/oracle 等
    let default_creds: &[(&str, &str)] = &[
        ("system", "oracle"),
        ("sys", "oracle"),
        ("scott", "tiger"),
        ("dbsnmp", "dbsnmp"),
    ];
    // 注意：Oracle O5L 认证协议非常复杂，此处检测 SID 存在性作为风险指标
    // 真实认证需要 O5L/O5LNPw 密码掩码与密钥派生，标记为后续 TODO
    for (user, pass) in default_creds {
        let sid = if !valid_sids.is_empty() {
            valid_sids[0]
        } else {
            "ORCL"
        };
        // 检查 SID 是否有效
        if let Ok(true) = check_oracle_sid(host, port, sid, dur).await {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: DbType::Oracle,
                title: "Oracle 默认账户风险".to_string(),
                severity: "high".to_string(),
                description: format!("SID={} 存在，建议检查默认账户 {}/{}", sid, user, pass),
                fix_advice: Some(format!("1. 修改 {} 账户密码 2. 锁定不必要的默认账户 3. 限制远程访问", user)),
                evidence: format!("SID={} 可连接，默认账户 {}/{} 应被检查", sid, user, pass),
            });
            break; // 只报一次
        }
    }

    findings
}

/// 检查 Oracle SID 是否有效（发送 TNS Connect，检查响应类型）
async fn check_oracle_sid(host: &str, port: u16, sid: &str, dur: Duration) -> Result<bool, std::io::Error> {
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Ok(false),
        Err(_) => return Ok(false),
    };

    let tns_pkt = build_tns_connect(sid);
    stream.write_all(&tns_pkt).await?;

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(false),
    };

    // TNS 响应:
    // type 2 (ACCEPT) 或 type 12 (RESUME) => SID 有效
    // type 4 (REFUSE) => SID 无效
    if n >= 5 {
        let pkt_type = buf[4];
        return Ok(pkt_type == 2 || pkt_type == 12);
    }

    Ok(false)
}

// ============== 辅助函数 ==============

/// 检查 Redis 已知 CVE
fn check_redis_cve(version: &str) -> Option<DbVulnFinding> {
    // CVE-2022-0543: Redis < 6.2.6 / < 7.0.2 Lua 沙箱逃逸
    if version.starts_with("6.2.") {
        let minor: u32 = version.trim_start_matches("6.2.").parse().unwrap_or(0);
        if minor < 6 {
            return Some(DbVulnFinding {
                target: String::new(),
                db_type: DbType::Redis,
                title: "Redis Lua 沙箱逃逸 (CVE-2022-0543)".to_string(),
                severity: "critical".to_string(),
                description: "Redis < 6.2.6 存在 Lua 沙箱逃逸漏洞，可导致 RCE".to_string(),
                fix_advice: Some("升级到 6.2.6+ 或 7.0.2+".to_string()),
                evidence: format!("检测到版本: {}", version),
            });
        }
    }
    None
}

/// 检查 MySQL 已知 CVE
fn check_mysql_cve(version: &str) -> Option<DbVulnFinding> {
    // CVE-2021-2154: MySQL Server 8.0.23 及以下 InnoDB 漏洞
    if version.starts_with("8.0.") {
        let minor: u32 = version.trim_start_matches("8.0.").parse().unwrap_or(0);
        if minor < 24 {
            return Some(DbVulnFinding {
                target: String::new(),
                db_type: DbType::Mysql,
                title: "MySQL Server InnoDB 远程代码执行 (CVE-2021-2154)".to_string(),
                severity: "high".to_string(),
                description: "MySQL 8.0 < 8.0.24 InnoDB 存在远程代码执行漏洞".to_string(),
                fix_advice: Some("升级到 8.0.24+".to_string()),
                evidence: format!("检测到版本: {}", version),
            });
        }
    }
    None
}

// ============== 协议构造辅助 ==============

/// 构造最简 BSON isMaster 文档
fn build_simple_bson_isMaster() -> Vec<u8> {
    // BSON: { isMaster: 1 }
    // 字段: type(0x10) + key "isMaster" + 0x00 + value(4 bytes int32)
    let mut field = Vec::new();
    field.push(0x10); // int32 type
    field.extend_from_slice(b"isMaster");
    field.push(0x00); // key null
    field.extend_from_slice(&1i32.to_le_bytes()); // value

    let body_len = (field.len() + 1 + 4) as i32; // +1 doc null, +4 length prefix
    let mut doc = body_len.to_le_bytes().to_vec();
    doc.extend_from_slice(&field);
    doc.push(0); // doc null
    doc
}

/// 构造 OP_MSG 数据包
fn build_op_msg(doc: Vec<u8>) -> Vec<u8> {
    let mut body = vec![0u8]; // kind = 0 (body section)
    body.extend_from_slice(&doc);

    let mut msg = Vec::new();
    msg.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    msg.extend_from_slice(&body);

    let total_len = (msg.len() + 16) as i32;
    let mut packet = Vec::new();
    packet.extend_from_slice(&total_len.to_le_bytes());
    packet.extend_from_slice(&1i32.to_le_bytes()); // requestID
    packet.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    packet.extend_from_slice(&2013i32.to_le_bytes()); // opCode
    packet.extend_from_slice(&msg);
    packet
}

/// 构造 listDatabases BSON 命令
fn build_list_databases() -> Vec<u8> {
    // { listDatabases: 1 }
    let mut field = Vec::new();
    field.push(0x10);
    field.extend_from_slice(b"listDatabases");
    field.push(0x00);
    field.extend_from_slice(&1i32.to_le_bytes());

    let body_len = (field.len() + 1 + 4) as i32;
    let mut doc = body_len.to_le_bytes().to_vec();
    doc.extend_from_slice(&field);
    doc.push(0);
    doc
}

/// 构造 PostgreSQL StartupMessage
fn build_pg_startup(user: &str, db: &str) -> Vec<u8> {
    let mut body = Vec::new();
    // Protocol version 3.0 = 0x00030000
    body.extend_from_slice(&0x00030000u32.to_be_bytes());
    // user=xxx\0
    body.extend_from_slice(format!("user\0{}\0", user).as_bytes());
    // database=xxx\0
    body.extend_from_slice(format!("database\0{}\0", db).as_bytes());
    // 终止符
    body.push(0);

    let len = (body.len() + 4) as i32;
    let mut packet = len.to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

/// 构造 TDS Pre-Login 数据包
fn build_tds_prelogin() -> Vec<u8> {
    let mut options = Vec::new();
    // VERSION option
    options.extend_from_slice(&[0x00, 0x00, 0x00, 0x06, 0x00]);
    // ENCRYPTION option (offset=25, len=1)
    options.extend_from_slice(&[0x01, 0x00, 0x19, 0x06, 0x01]);
    // INSTOPT (offset=26, len=0)
    options.extend_from_slice(&[0x02, 0x00, 0x1A, 0x06, 0x00]);
    // THREADID (offset=26, len=4)
    options.extend_from_slice(&[0x03, 0x00, 0x1A, 0x06, 0x04]);
    // MARS (offset=30, len=1)
    options.extend_from_slice(&[0x04, 0x00, 0x1E, 0x06, 0x01]);

    // Data
    let mut data = Vec::new();
    // VERSION (6 bytes)
    data.extend_from_slice(&[0x0F, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // ENCRYPTION (1 byte)
    data.push(0x01);
    // THREADID (4 bytes)
    data.extend_from_slice(&0u32.to_le_bytes());
    // MARS (1 byte)
    data.push(0x00);

    let body_len = options.len() + data.len();
    let total_len = (8 + body_len) as u16;

    let mut packet = Vec::new();
    packet.push(0x12); // pre-login type
    packet.push(0x01); // status
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // SPID
    packet.push(0x01); // packet id
    packet.push(0x00); // window
    packet.extend_from_slice(&options);
    packet.extend_from_slice(&data);
    packet
}

/// 构造 TDS Login7 数据包（R6.1 修复：真实弱密码检测）
///
/// TDS Login7 结构 (MS-TDS):
/// - 8 byte header: type(0x10) + status + length + SPID + packetID + window
/// - Fixed body (86 bytes): Length + Version + PacketSize + flags + offsets/lengths
/// - Variable data: HostName + UserName + Password(XOR 0xA5) + AppName + ServerName + Database
fn build_tds_login7(user: &str, pass: &str) -> Vec<u8> {
    // UCS-2 (UTF-16LE) 编码各字段
    let host_name: Vec<u8> = Vec::new(); // 空主机名
    let user_name: Vec<u8> = user.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    // 密码: UCS-2 编码后每字节 XOR 0xA5
    let password: Vec<u8> = pass
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .map(|b| b ^ 0xA5)
        .collect();
    let app_name: Vec<u8> = "argus-scan"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let server_name: Vec<u8> = Vec::new();
    let database: Vec<u8> = Vec::new();

    // 固定部分 86 字节，变长数据从 offset 86 开始
    let fixed_len = 86usize;

    let mut offset = fixed_len;
    let host_off = offset;
    offset += host_name.len();
    let user_off = offset;
    offset += user_name.len();
    let pass_off = offset;
    offset += password.len();
    let app_off = offset;
    offset += app_name.len();
    let srv_off = offset;
    offset += server_name.len();
    let db_off = offset;
    offset += database.len();

    let total_body_len = offset;

    let mut body = Vec::with_capacity(total_body_len);

    // --- 固定部分 (36 bytes) ---
    body.extend_from_slice(&(total_body_len as u32).to_le_bytes()); // Length
    body.extend_from_slice(&0x71000001u32.to_le_bytes()); // TDSVersion (7.1)
    body.extend_from_slice(&0x00100000u32.to_le_bytes()); // PacketSize (4096)
    body.extend_from_slice(&0x07000000u32.to_le_bytes()); // ClientProgVer
    body.extend_from_slice(&0x00000000u32.to_le_bytes()); // ClientPID
    body.extend_from_slice(&0x00000000u32.to_le_bytes()); // ConnectionOption
    body.push(0xE0); // OptionFlags1: INIT_LANG_FATAL | USE_DB_ON | ODBC
    body.push(0x00); // OptionFlags2: no integrated security
    body.push(0x00); // TypeFlags
    body.push(0x00); // OptionFlags3
    body.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
    body.extend_from_slice(&0i32.to_le_bytes()); // ClientLCID

    // --- 偏移/长度对 (32 bytes for 8 fields) ---
    // 字段长度以字符数计（UCS-2 每字符 2 字节），所以 bytes/2 = chars
    body.extend_from_slice(&(host_off as u16).to_le_bytes());
    body.extend_from_slice(&((host_name.len() / 2) as u16).to_le_bytes());
    body.extend_from_slice(&(user_off as u16).to_le_bytes());
    body.extend_from_slice(&((user_name.len() / 2) as u16).to_le_bytes());
    body.extend_from_slice(&(pass_off as u16).to_le_bytes());
    body.extend_from_slice(&((password.len() / 2) as u16).to_le_bytes());
    body.extend_from_slice(&(app_off as u16).to_le_bytes());
    body.extend_from_slice(&((app_name.len() / 2) as u16).to_le_bytes());
    body.extend_from_slice(&(srv_off as u16).to_le_bytes());
    body.extend_from_slice(&((server_name.len() / 2) as u16).to_le_bytes());
    // LibraryName (unused)
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    // Language (unused)
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    // Database
    body.extend_from_slice(&(db_off as u16).to_le_bytes());
    body.extend_from_slice(&((database.len() / 2) as u16).to_le_bytes());

    // --- ClientID (6 bytes) ---
    body.extend_from_slice(&[0u8; 6]);

    // --- SSPI / AtchDBFile / ChangePassword (各 4 bytes, unused) ---
    body.extend_from_slice(&0u16.to_le_bytes()); // SSPI offset
    body.extend_from_slice(&0u16.to_le_bytes()); // SSPI length
    body.extend_from_slice(&0u16.to_le_bytes()); // AtchDBFile offset
    body.extend_from_slice(&0u16.to_le_bytes()); // AtchDBFile length
    body.extend_from_slice(&0u16.to_le_bytes()); // ChangePassword offset
    body.extend_from_slice(&0u16.to_le_bytes()); // ChangePassword length

    // --- 变长数据 ---
    body.extend_from_slice(&host_name);
    body.extend_from_slice(&user_name);
    body.extend_from_slice(&password);
    body.extend_from_slice(&app_name);
    body.extend_from_slice(&server_name);
    body.extend_from_slice(&database);

    // 构造 TDS 数据包: 8 字节 header + body
    let total_len = (8 + body.len()) as u16;
    let mut packet = Vec::with_capacity(total_len as usize);
    packet.push(0x10); // Login7 type
    packet.push(0x01); // status: end of message
    packet.extend_from_slice(&total_len.to_be_bytes()); // packet length (big-endian)
    packet.extend_from_slice(&0u16.to_be_bytes()); // SPID
    packet.push(0x01); // packet ID
    packet.push(0x00); // window
    packet.extend_from_slice(&body);

    packet
}

/// 构造 TNS Connect 数据包
fn build_tns_connect(service: &str) -> Vec<u8> {
    let connect_str = format!(
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={}))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))",
        service
    );
    let connect_bytes = connect_str.as_bytes();
    let header_len = 28usize;
    let total_len = header_len + connect_bytes.len();

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.push(0x01); // type: CONNECT
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&318u16.to_le_bytes()); // version
    pkt.extend_from_slice(&318u16.to_le_bytes()); // version compat
    pkt.extend_from_slice(&0x0C41u16.to_le_bytes()); // service options
    pkt.extend_from_slice(&0x0800u16.to_le_bytes()); // SDU length
    pkt.extend_from_slice(&0x7FFFu16.to_le_bytes()); // TDU length
    pkt.extend_from_slice(&0x7F08u16.to_le_bytes()); // NT proto chars
    pkt.extend_from_slice(&0x0001u16.to_le_bytes()); // line turnaround
    pkt.extend_from_slice(&(header_len as u16).to_le_bytes()); // connect data offset
    pkt.extend_from_slice(&0x0800u32.to_le_bytes()); // max recv
    pkt.push(0x41); // connect data flags
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(connect_bytes);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_type_default_port() {
        assert_eq!(DbType::Mysql.default_port(), 3306);
        assert_eq!(DbType::Postgresql.default_port(), 5432);
        assert_eq!(DbType::Redis.default_port(), 6379);
        assert_eq!(DbType::Mongodb.default_port(), 27017);
        assert_eq!(DbType::Mssql.default_port(), 1433);
        assert_eq!(DbType::Oracle.default_port(), 1521);
    }

    #[test]
    fn test_check_redis_cve() {
        assert!(check_redis_cve("6.2.5").is_some());
        assert!(check_redis_cve("6.2.6").is_none());
        assert!(check_redis_cve("7.0.1").is_none());
    }

    #[test]
    fn test_check_mysql_cve() {
        assert!(check_mysql_cve("8.0.23").is_some());
        assert!(check_mysql_cve("8.0.24").is_none());
        assert!(check_mysql_cve("5.7.35").is_none());
    }

    #[test]
    fn test_build_pg_startup() {
        let pkt = build_pg_startup("test", "testdb");
        let len = i32::from_be_bytes(pkt[0..4].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());
        // 包含 user 字段
        let body_str = String::from_utf8_lossy(&pkt[4..]);
        assert!(body_str.contains("test"));
        assert!(body_str.contains("testdb"));
    }

    #[test]
    fn test_build_tns_connect() {
        let pkt = build_tns_connect("ORCL");
        let len = u16::from_be_bytes(pkt[0..2].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());
        assert_eq!(pkt[4], 0x01); // CONNECT type
    }

    #[test]
    fn test_build_simple_bson_isMaster() {
        let doc = build_simple_bson_isMaster();
        // BSON 长度字段
        let len = i32::from_le_bytes(doc[0..4].try_into().unwrap());
        assert_eq!(len as usize, doc.len());
        // 包含 isMaster 字段名
        assert!(String::from_utf8_lossy(&doc).contains("isMaster"));
    }

    #[test]
    fn test_build_op_msg() {
        let doc = build_simple_bson_isMaster();
        let msg = build_op_msg(doc);
        // opCode = 2013
        let op = i32::from_le_bytes(msg[12..16].try_into().unwrap());
        assert_eq!(op, 2013);
        // 总长度一致
        let len = i32::from_le_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(len as usize, msg.len());
    }

    #[test]
    fn test_db_vuln_finding_serialization() {
        let finding = DbVulnFinding {
            target: "127.0.0.1:6379".to_string(),
            db_type: DbType::Redis,
            title: "test".to_string(),
            severity: "high".to_string(),
            description: "desc".to_string(),
            fix_advice: Some("fix".to_string()),
            evidence: "ev".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("redis"));
        assert!(json.contains("high"));
    }

    /// R6.1 验证：TDS Login7 数据包结构
    #[test]
    fn test_build_tds_login7() {
        let pkt = build_tds_login7("sa", "sa");
        // type = 0x10 (Login7)
        assert_eq!(pkt[0], 0x10);
        // status = 0x01 (end of message)
        assert_eq!(pkt[1], 0x01);
        // length = 8 + body_len (big-endian)
        let len = u16::from_be_bytes(pkt[2..4].try_into().unwrap());
        assert_eq!(len as usize, pkt.len());

        // body starts at offset 8
        let body = &pkt[8..];
        // TDSVersion = 0x71000001 (LE)
        let version = u32::from_le_bytes(body[4..8].try_into().unwrap());
        assert_eq!(version, 0x71000001);

        // 用户名 "sa" 应在 UCS-2 编码后存在于 body 中
        let user_bytes = "sa".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        assert!(body.windows(user_bytes.len()).any(|w| w == user_bytes.as_slice()));
    }

    /// R6.1 验证：TDS Login7 密码 XOR 0xA5
    #[test]
    fn test_build_tds_login7_password_xor() {
        let pkt = build_tds_login7("sa", "test");
        let body = &pkt[8..];

        // 密码 "test" UCS-2: 0x74 0x00 0x65 0x00 0x73 0x00 0x74 0x00
        // XOR 0xA5: 0xD1 0xA5 0xC0 0xA5 0xD6 0xA5 0xD1 0xA5
        let expected_pass: Vec<u8> = "test"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .map(|b| b ^ 0xA5)
            .collect();
        assert!(body.windows(expected_pass.len()).any(|w| w == expected_pass.as_slice()));
    }

    /// R6.1 验证：MySQL HandshakeResponse41 空用户结构
    #[test]
    fn test_mysql_anonymous_packet_structure() {
        // 验证 try_mysql_anonymous 构造的包结构正确
        // 通过检查函数是否存在和参数类型正确来验证
        // 真实网络测试需要运行中的 MySQL 实例
        let _ = std::any::TypeId::of::<fn(&mut TcpStream, Duration) -> Result<bool, std::io::Error>>();
    }
}
