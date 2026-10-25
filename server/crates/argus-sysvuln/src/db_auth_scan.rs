//! G6.5 数据库登录扫描（认证后执行审计 SQL 查询）
//!
//! 6.5 数据库扫描中的"登录扫描"模式。
//! 与 db_vuln.rs 的未授权检测互补：当提供凭证时，连接数据库执行审计查询，
//! 检查匿名用户、root 远程登录、空口令、弱密码策略、默认库等配置类风险。
//!
//! 支持的数据库：
//! - MySQL（mysql crate，同步库，用 spawn_blocking 调用）
//! - PostgreSQL（tokio-postgres crate，原生异步）
//! - 其他（Redis/MongoDB/MSSQL/Oracle）：返回"暂不支持"提示

use std::time::Duration;

use argus_scanner::Credentials;

use crate::db_vuln::{DbVulnFinding, DbType};

/// 执行认证后的数据库审计扫描
///
/// 入参：
/// - `host`/`port`：数据库地址
/// - `db_type`：数据库类型
/// - `creds`：凭证（username/password）
/// - `timeout_ms`：连接超时
///
/// 返回：配置类漏洞列表（空列表 = 连接失败或无配置问题）
pub async fn scan_authenticated(
    host: &str,
    port: u16,
    db_type: DbType,
    creds: &Credentials,
    timeout_ms: u64,
) -> Vec<DbVulnFinding> {
    let target = format!("{}:{}", host, port);
    match db_type {
        DbType::Mysql => {
            // mysql crate 是同步库，用 spawn_blocking 调用
            let host_owned = host.to_string();
            let user = creds.username.clone();
            let pass = creds.password.clone();
            tokio::task::spawn_blocking(move || {
                scan_mysql_authenticated(&host_owned, port, &user, &pass, timeout_ms, &target)
            })
            .await
            .unwrap_or_default()
        }
        DbType::Postgresql => {
            scan_postgresql_authenticated(host, port, creds, timeout_ms, &target).await
        }
        DbType::Redis | DbType::Mongodb | DbType::Mssql | DbType::Oracle => {
            // 这些库的认证扫描需要额外的协议驱动，暂不支持登录扫描
            vec![DbVulnFinding {
                target: target.clone(),
                db_type: db_type.clone(),
                title: "登录扫描暂不支持此数据库类型".to_string(),
                severity: "info".to_string(),
                description: format!(
                    "{} 的登录扫描（认证后审计）暂不支持，仅执行未授权检测",
                    db_type.as_str()
                ),
                evidence: format!("db_type={}", db_type.as_str()),
                fix_advice: Some("如需此库的登录扫描，请升级到后续版本".to_string()),
            }]
        }
    }
}

// ==================== MySQL 认证扫描 ====================

/// MySQL 登录扫描：连接后执行审计 SQL 查询
fn scan_mysql_authenticated(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    timeout_ms: u64,
    target: &str,
) -> Vec<DbVulnFinding> {
    use mysql::prelude::Queryable;
    use mysql::OptsBuilder;

    let opts = OptsBuilder::default()
        .ip_or_hostname(Some(host))
        .tcp_port(port)
        .user(Some(user))
        .pass(Some(pass))
        .db_name(Some("mysql")) // 连接到 mysql 系统库以查询用户表
        .tcp_connect_timeout(Some(Duration::from_millis(timeout_ms)))
        .read_timeout(Some(Duration::from_millis(timeout_ms)));

    let pool = match mysql::Pool::new(opts) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("MySQL 认证连接失败 {}: {}", target, e);
            return vec![];
        }
    };

    let mut conn = match pool.get_conn() {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("MySQL 获取连接失败 {}: {}", target, e);
            return vec![];
        }
    };

    let mut findings = Vec::new();
    let db_type = DbType::Mysql;

    // 1. 检查匿名用户（user=''）
    if let Ok(rows) = conn.query::<(String, String), _>(
        "SELECT user, host FROM mysql.user WHERE user = ''"
    ) {
        if !rows.is_empty() {
            let hosts: Vec<String> = rows.iter().map(|(_, h)| h.clone()).collect();
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "存在匿名用户".to_string(),
                severity: "high".to_string(),
                description: format!("数据库允许无用户名登录，hosts: {}", hosts.join(",")),
                evidence: format!("mysql.user WHERE user='' 返回 {} 行", rows.len()),
                fix_advice: Some("删除匿名用户：DROP USER ''@'host';".to_string()),
            });
        }
    }

    // 2. 检查 root 远程登录（user='root' AND host='%'）
    if let Ok(rows) = conn.query::<(String, String), _>(
        "SELECT user, host FROM mysql.user WHERE user = 'root' AND host = '%'"
    ) {
        if !rows.is_empty() {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "root 允许远程登录".to_string(),
                severity: "high".to_string(),
                description: "root 用户允许从任意主机（%）登录，增加暴力破解风险".to_string(),
                evidence: "mysql.user 中 root@% 存在".to_string(),
                fix_advice: Some("限制 root 仅本地登录：将 host='%' 改为 'localhost' 或具体 IP".to_string()),
            });
        }
    }

    // 3. 检查空口令用户（authentication_string=''）
    if let Ok(rows) = conn.query::<(String, String), _>(
        "SELECT user, host FROM mysql.user WHERE authentication_string = ''"
    ) {
        if !rows.is_empty() {
            let users: Vec<String> = rows.iter().map(|(u, h)| format!("{}@{}", u, h)).collect();
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "存在空口令用户".to_string(),
                severity: "high".to_string(),
                description: format!("以下用户无密码：{}", users.join(", ")),
                evidence: format!("authentication_string 为空的用户 {} 个", rows.len()),
                fix_advice: Some("为所有用户设置强密码：ALTER USER ... IDENTIFIED BY '...'".to_string()),
            });
        }
    }

    // 4. 检查默认 test 库
    if let Ok(rows) = conn.query::<String, _>("SHOW DATABASES LIKE 'test'") {
        if !rows.is_empty() {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "存在默认 test 数据库".to_string(),
                severity: "low".to_string(),
                description: "test 库默认对所有用户开放，可能被用于存放测试数据或恶意代码".to_string(),
                evidence: "SHOW DATABASES LIKE 'test' 返回 1 行".to_string(),
                fix_advice: Some("删除 test 库：DROP DATABASE test;".to_string()),
            });
        }
    }

    // 5. 检查 validate_password 插件（密码策略）
    if let Ok(rows) = conn.query::<(String, String), _>(
        "SHOW VARIABLES LIKE 'validate_password%'"
    ) {
        if rows.is_empty() {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "未启用密码复杂度策略".to_string(),
                severity: "medium".to_string(),
                description: "MySQL 未安装 validate_password 插件，无密码复杂度校验".to_string(),
                evidence: "SHOW VARIABLES LIKE 'validate_password%' 返回 0 行".to_string(),
                fix_advice: Some("安装 validate_password 插件并配置密码长度/复杂度".to_string()),
            });
        }
    }

    // 6. 检查 skip_show_database（信息泄露）
    if let Ok(rows) = conn.query::<(String, String), _>(
        "SHOW VARIABLES LIKE 'skip_show_database'"
    ) {
        let enabled = rows.iter().any(|(_, v)| v == "ON");
        if !enabled {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type,
                title: "未启用 skip_show_database".to_string(),
                severity: "low".to_string(),
                description: "普通用户可 SHOW DATABASES 看到无权限的数据库名，存在信息泄露".to_string(),
                evidence: "skip_show_database = OFF 或未设置".to_string(),
                fix_advice: Some("在 my.cnf 中设置 skip_show_database".to_string()),
            });
        }
    }

    findings
}

// ==================== PostgreSQL 认证扫描 ====================

/// PostgreSQL 登录扫描：连接后执行审计 SQL 查询
async fn scan_postgresql_authenticated(
    host: &str,
    port: u16,
    creds: &Credentials,
    timeout_ms: u64,
    target: &str,
) -> Vec<DbVulnFinding> {
    use tokio_postgres::NoTls;

    let conn_str = format!(
        "host={} port={} user={} password={} dbname=postgres connect_timeout={}",
        host, port, creds.username, creds.password, timeout_ms / 1000
    );

    let (client, connection) = match tokio_postgres::connect(&conn_str, NoTls).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("PostgreSQL 认证连接失败 {}: {}", target, e);
            return vec![];
        }
    };

    // 连接需要在后台驱动
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut findings = Vec::new();
    let db_type = DbType::Postgresql;

    // 1. 检查超级用户
    if let Ok(rows) = client.query("SELECT rolname FROM pg_roles WHERE rolsuper", &[]).await {
        if !rows.is_empty() {
            let supers: Vec<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "存在超级用户".to_string(),
                severity: "medium".to_string(),
                description: format!("以下用户具有超级权限：{}", supers.join(", ")),
                evidence: format!("pg_roles WHERE rolsuper 返回 {} 行", rows.len()),
                fix_advice: Some("最小权限原则：为应用创建普通用户，仅必要时授予 SUPERUSER".to_string()),
            });
        }
    }

    // 2. 检查密码加密方式
    if let Ok(rows) = client.query("SHOW password_encryption", &[]).await {
        if let Some(row) = rows.first() {
            let val: String = row.get(0);
            if val == "off" || val == "scram-sha-256" {
                // scram-sha-256 是推荐配置，off 是不安全的
                if val == "off" {
                    findings.push(DbVulnFinding {
                        target: target.to_string(),
                        db_type: db_type.clone(),
                        title: "密码未加密存储".to_string(),
                        severity: "high".to_string(),
                        description: "PostgreSQL password_encryption = off，口令以明文存储".to_string(),
                        evidence: format!("password_encryption = {}", val),
                        fix_advice: Some("设置 password_encryption = scram-sha-256 并重置所有密码".to_string()),
                    });
                }
            } else {
                // md5 或其他
                findings.push(DbVulnFinding {
                    target: target.to_string(),
                    db_type: db_type.clone(),
                    title: "密码加密方式为旧版".to_string(),
                    severity: "low".to_string(),
                    description: format!("password_encryption = {}，建议使用 scram-sha-256", val),
                    evidence: format!("password_encryption = {}", val),
                    fix_advice: Some("升级到 scram-sha-256 并重置密码".to_string()),
                });
            }
        }
    }

    // 3. 检查默认模板库权限
    if let Ok(rows) = client
        .query("SELECT datname FROM pg_database WHERE datistemplate = true AND datname NOT IN ('template0', 'template1')", &[])
        .await
    {
        if !rows.is_empty() {
            let dbs: Vec<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type: db_type.clone(),
                title: "存在非标准模板库".to_string(),
                severity: "low".to_string(),
                description: format!("以下模板库可能被滥用：{}", dbs.join(", ")),
                evidence: format!("pg_database WHERE datistemplate 返回 {} 行", rows.len()),
                fix_advice: Some("清理非标准模板库：UPDATE pg_database SET datistemplate = false WHERE datname = '...'".to_string()),
            });
        }
    }

    // 4. 检查 public schema 默认权限
    if let Ok(rows) = client
        .query(
            "SELECT nspname FROM pg_namespace WHERE nspname = 'public' AND nspacl IS NOT NULL",
            &[],
        )
        .await
    {
        if !rows.is_empty() {
            findings.push(DbVulnFinding {
                target: target.to_string(),
                db_type,
                title: "public schema 存在默认 ACL".to_string(),
                severity: "medium".to_string(),
                description: "public schema 保留了默认权限，普通用户可创建对象".to_string(),
                evidence: "pg_namespace public 行有 nspacl".to_string(),
                fix_advice: Some("REVOKE ALL ON SCHEMA public FROM public;".to_string()),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_authenticated_mysql_unreachable() {
        // 连不上的 MySQL，应返回空（不报错）
        let creds = Credentials {
            username: "root".to_string(),
            password: "wrong".to_string(),
            auth_type: None,
        };
        let r = scan_authenticated(
            "127.0.0.1",
            13306,
            DbType::Mysql,
            &creds,
            500,
        )
        .await;
        assert!(r.is_empty(), "连接失败应返回空结果");
    }

    #[tokio::test]
    async fn test_scan_authenticated_pg_unreachable() {
        // 连不上的 PostgreSQL，应返回空（不报错）
        let creds = Credentials {
            username: "postgres".to_string(),
            password: "wrong".to_string(),
            auth_type: None,
        };
        let r = scan_authenticated(
            "127.0.0.1",
            15432,
            DbType::Postgresql,
            &creds,
            500,
        )
        .await;
        assert!(r.is_empty(), "连接失败应返回空结果");
    }

    #[tokio::test]
    async fn test_scan_authenticated_redis_unsupported() {
        let creds = Credentials {
            username: "default".to_string(),
            password: "".to_string(),
            auth_type: None,
        };
        let r = scan_authenticated("127.0.0.1", 6379, DbType::Redis, &creds, 500).await;
        assert_eq!(r.len(), 1);
        assert!(r[0].title.contains("暂不支持"));
        assert_eq!(r[0].db_type, DbType::Redis);
    }

    #[tokio::test]
    async fn test_scan_authenticated_oracle_unsupported() {
        let creds = Credentials {
            username: "sys".to_string(),
            password: "wrong".to_string(),
            auth_type: None,
        };
        let r = scan_authenticated("127.0.0.1", 1521, DbType::Oracle, &creds, 500).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, "info");
    }
}
