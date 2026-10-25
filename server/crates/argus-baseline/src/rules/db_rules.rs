//! 数据库基线合规核查规则集
//!
//! 对标 GB/T 22239 等保三级要求，覆盖 MySQL/PostgreSQL/Redis/MongoDB 配置基线
//! 规则通过 SQL 查询 / 配置命令采集，用 Rhai 脚本判定合规性

use crate::types::{CollectItem, CollectMethod, ComplianceRule};
use super::RuleSet;

/// MySQL 基线规则集
pub fn mysql_baseline() -> RuleSet {
    RuleSet {
        name: "mysql_baseline".to_string(),
        description: "MySQL 数据库等保三级基线核查（身份鉴别/访问控制/安全审计/入侵防范）".to_string(),
        collect_items: vec![
            CollectItem {
                id: "mysql_user_list".to_string(),
                name: "MySQL 用户列表".to_string(),
                method: CollectMethod::Ssh, // 复用 SSH 通道执行 mysql 命令
                command: "mysql -u$USER -p$PASS -e 'SELECT user, host, authentication_string != \"\" AS has_password FROM mysql.user;' 2>/dev/null".to_string(),
                description: Some("查询 MySQL 用户及密码设置状态".to_string()),
            },
            CollectItem {
                id: "mysql_anonymous".to_string(),
                name: "匿名用户检测".to_string(),
                method: CollectMethod::Ssh,
                command: "mysql -u$USER -p$PASS -e 'SELECT user, host FROM mysql.user WHERE user = \"\";' 2>/dev/null".to_string(),
                description: Some("检查是否存在匿名用户".to_string()),
            },
            CollectItem {
                id: "mysql_root_remote".to_string(),
                name: "root 远程登录检测".to_string(),
                method: CollectMethod::Ssh,
                command: "mysql -u$USER -p$PASS -e 'SELECT user, host FROM mysql.user WHERE user = \"root\" AND host != \"localhost\";' 2>/dev/null".to_string(),
                description: Some("检查 root 是否允许远程登录".to_string()),
            },
            CollectItem {
                id: "mysql_ssl".to_string(),
                name: "SSL/TLS 配置".to_string(),
                method: CollectMethod::Ssh,
                command: "mysql -u$USER -p$PASS -e 'SHOW VARIABLES LIKE \"%ssl%\";' 2>/dev/null".to_string(),
                description: Some("检查 SSL/TLS 配置状态".to_string()),
            },
            CollectItem {
                id: "mysql_version".to_string(),
                name: "MySQL 版本信息".to_string(),
                method: CollectMethod::Ssh,
                command: "mysql -u$USER -p$PASS -e 'SELECT VERSION();' 2>/dev/null".to_string(),
                description: Some("获取 MySQL 版本号".to_string()),
            },
            CollectItem {
                id: "mysql_skip_grant".to_string(),
                name: "skip-grant-tables 检测".to_string(),
                method: CollectMethod::Ssh,
                command: "mysql -u$USER -p$PASS -e 'SHOW VARIABLES LIKE \"skip_grant_tables\";' 2>/dev/null".to_string(),
                description: Some("检查是否禁用了权限验证".to_string()),
            },
        ],
        rules: vec![
            ComplianceRule {
                id: "mysql_no_anonymous".to_string(),
                name: "禁止匿名用户".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "high".to_string(),
                collect_item_id: "mysql_anonymous".to_string(),
                check_script: "is_empty(output)".to_string(),
                expected: Some("无匿名用户".to_string()),
                fix_advice: Some("执行: DELETE FROM mysql.user WHERE user = ''; FLUSH PRIVILEGES;".to_string()),
            },
            ComplianceRule {
                id: "mysql_no_remote_root".to_string(),
                name: "禁止 root 远程登录".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "high".to_string(),
                collect_item_id: "mysql_root_remote".to_string(),
                check_script: "is_empty(output)".to_string(),
                expected: Some("root 仅允许本地登录".to_string()),
                fix_advice: Some("执行: DELETE FROM mysql.user WHERE user='root' AND host != 'localhost'; FLUSH PRIVILEGES;".to_string()),
            },
            ComplianceRule {
                id: "mysql_ssl_enabled".to_string(),
                name: "启用 SSL/TLS 加密".to_string(),
                category: "通信安全".to_string(),
                requirement_id: "8.1.4".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "mysql_ssl".to_string(),
                check_script: "output.contains(\"have_ssl\") && output.contains(\"YES\")".to_string(),
                expected: Some("have_ssl = YES".to_string()),
                fix_advice: Some("在 my.cnf 中配置 SSL 证书，启用 have_ssl".to_string()),
            },
            ComplianceRule {
                id: "mysql_no_skip_grant".to_string(),
                name: "禁止 skip-grant-tables".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "critical".to_string(),
                collect_item_id: "mysql_skip_grant".to_string(),
                check_script: "output.contains(\"skip_grant_tables\") && output.contains(\"OFF\")".to_string(),
                expected: Some("skip_grant_tables = OFF".to_string()),
                fix_advice: Some("从 my.cnf 中移除 skip-grant-tables 配置项".to_string()),
            },
            ComplianceRule {
                id: "mysql_all_users_have_password".to_string(),
                name: "所有用户必须设置密码".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "critical".to_string(),
                collect_item_id: "mysql_user_list".to_string(),
                check_script: "!contains(output, \"0\")".to_string(),
                expected: Some("所有用户 has_password = 1".to_string()),
                fix_advice: Some("为无密码用户设置密码: ALTER USER 'xxx'@'xxx' IDENTIFIED BY 'strong_password';".to_string()),
            },
        ],
    }
}

/// PostgreSQL 基线规则集
pub fn postgresql_baseline() -> RuleSet {
    RuleSet {
        name: "postgresql_baseline".to_string(),
        description: "PostgreSQL 数据库等保三级基线核查".to_string(),
        collect_items: vec![
            CollectItem {
                id: "pg_hba".to_string(),
                name: "pg_hba.conf 认证配置".to_string(),
                method: CollectMethod::Ssh,
                command: "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null || cat /var/lib/pgsql/data/pg_hba.conf 2>/dev/null || find / -name pg_hba.conf -exec cat {} \\; 2>/dev/null | head -50".to_string(),
                description: Some("检查 pg_hba.conf 认证方式".to_string()),
            },
            CollectItem {
                id: "pg_ssl".to_string(),
                name: "SSL 配置".to_string(),
                method: CollectMethod::Ssh,
                command: "sudo -u postgres psql -c 'SHOW ssl;' 2>/dev/null".to_string(),
                description: Some("检查 SSL 是否启用".to_string()),
            },
            CollectItem {
                id: "pg_listen".to_string(),
                name: "监听地址配置".to_string(),
                method: CollectMethod::Ssh,
                command: "sudo -u postgres psql -c 'SHOW listen_addresses;' 2>/dev/null".to_string(),
                description: Some("检查监听地址是否限制".to_string()),
            },
            CollectItem {
                id: "pg_log_connections".to_string(),
                name: "连接日志配置".to_string(),
                method: CollectMethod::Ssh,
                command: "sudo -u postgres psql -c 'SHOW log_connections;' 2>/dev/null".to_string(),
                description: Some("检查是否记录连接日志".to_string()),
            },
            CollectItem {
                id: "pg_version".to_string(),
                name: "PostgreSQL 版本".to_string(),
                method: CollectMethod::Ssh,
                command: "sudo -u postgres psql -c 'SHOW server_version;' 2>/dev/null".to_string(),
                description: Some("获取 PostgreSQL 版本".to_string()),
            },
        ],
        rules: vec![
            ComplianceRule {
                id: "pg_no_trust_auth".to_string(),
                name: "禁止 trust 认证".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "critical".to_string(),
                collect_item_id: "pg_hba".to_string(),
                check_script: "!output.contains(\"trust\")".to_string(),
                expected: Some("pg_hba.conf 无 trust 条目".to_string()),
                fix_advice: Some("将 pg_hba.conf 中的 trust 改为 scram-sha-256".to_string()),
            },
            ComplianceRule {
                id: "pg_ssl_enabled".to_string(),
                name: "启用 SSL 加密".to_string(),
                category: "通信安全".to_string(),
                requirement_id: "8.1.4".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "pg_ssl".to_string(),
                check_script: "output.contains(\"on\")".to_string(),
                expected: Some("ssl = on".to_string()),
                fix_advice: Some("在 postgresql.conf 中设置 ssl = on 并配置证书".to_string()),
            },
            ComplianceRule {
                id: "pg_listen_restricted".to_string(),
                name: "限制监听地址".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "high".to_string(),
                collect_item_id: "pg_listen".to_string(),
                check_script: "!output.contains(\"*\") && (output.contains(\"localhost\") || output.contains(\"127.0.0.1\"))".to_string(),
                expected: Some("listen_addresses = localhost".to_string()),
                fix_advice: Some("在 postgresql.conf 中设置 listen_addresses = 'localhost'".to_string()),
            },
            ComplianceRule {
                id: "pg_log_connections_enabled".to_string(),
                name: "启用连接日志".to_string(),
                category: "安全审计".to_string(),
                requirement_id: "8.1.5".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "pg_log_connections".to_string(),
                check_script: "output.contains(\"on\")".to_string(),
                expected: Some("log_connections = on".to_string()),
                fix_advice: Some("在 postgresql.conf 中设置 log_connections = on".to_string()),
            },
        ],
    }
}

/// Redis 基线规则集
pub fn redis_baseline() -> RuleSet {
    RuleSet {
        name: "redis_baseline".to_string(),
        description: "Redis 数据库等保三级基线核查".to_string(),
        collect_items: vec![
            CollectItem {
                id: "redis_config".to_string(),
                name: "Redis 配置文件".to_string(),
                method: CollectMethod::Ssh,
                command: "cat /etc/redis/redis.conf 2>/dev/null || cat /etc/redis.conf 2>/dev/null || find / -name 'redis.conf' -exec cat {} \\; 2>/dev/null | head -100".to_string(),
                description: Some("读取 Redis 配置文件".to_string()),
            },
            CollectItem {
                id: "redis_info".to_string(),
                name: "Redis INFO 命令输出".to_string(),
                method: CollectMethod::Ssh,
                command: "redis-cli -a $PASS INFO 2>/dev/null | head -50".to_string(),
                description: Some("执行 INFO 命令获取运行状态".to_string()),
            },
        ],
        rules: vec![
            ComplianceRule {
                id: "redis_auth_enabled".to_string(),
                name: "启用认证密码".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "critical".to_string(),
                collect_item_id: "redis_config".to_string(),
                check_script: "contains(output, \"requirepass\")".to_string(),
                expected: Some("requirepass 设置了非空密码".to_string()),
                fix_advice: Some("在 redis.conf 中设置 requirepass <strong_password>".to_string()),
            },
            ComplianceRule {
                id: "redis_bind_local".to_string(),
                name: "限制监听地址".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "high".to_string(),
                collect_item_id: "redis_config".to_string(),
                check_script: "output.contains(\"bind 127.0.0.1\") || output.contains(\"bind ::1\")".to_string(),
                expected: Some("bind 127.0.0.1".to_string()),
                fix_advice: Some("在 redis.conf 中设置 bind 127.0.0.1".to_string()),
            },
            ComplianceRule {
                id: "redis_protected_mode".to_string(),
                name: "启用保护模式".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "redis_config".to_string(),
                check_script: "output.contains(\"protected-mode yes\")".to_string(),
                expected: Some("protected-mode yes".to_string()),
                fix_advice: Some("在 redis.conf 中设置 protected-mode yes".to_string()),
            },
            ComplianceRule {
                id: "redis_no_rename_command".to_string(),
                name: "危险命令重命名/禁用".to_string(),
                category: "入侵防范".to_string(),
                requirement_id: "8.1.6".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "redis_config".to_string(),
                check_script: "output.contains(\"rename-command FLUSHALL\") || output.contains(\"rename-command CONFIG\") || output.contains(\"rename-command FLUSHDB\")".to_string(),
                expected: Some("FLUSHALL/CONFIG/FLUSHDB 已重命名".to_string()),
                fix_advice: Some("在 redis.conf 中: rename-command FLUSHALL \"\", rename-command CONFIG \"\"".to_string()),
            },
        ],
    }
}

/// MongoDB 基线规则集
pub fn mongodb_baseline() -> RuleSet {
    RuleSet {
        name: "mongodb_baseline".to_string(),
        description: "MongoDB 数据库等保三级基线核查".to_string(),
        collect_items: vec![
            CollectItem {
                id: "mongo_config".to_string(),
                name: "MongoDB 配置文件".to_string(),
                method: CollectMethod::Ssh,
                command: "cat /etc/mongod.conf 2>/dev/null || cat /etc/mongodb.conf 2>/dev/null || find / -name 'mongod.conf' -exec cat {} \\; 2>/dev/null | head -50".to_string(),
                description: Some("读取 MongoDB 配置文件".to_string()),
            },
            CollectItem {
                id: "mongo_cmdline".to_string(),
                name: "MongoDB 启动参数".to_string(),
                method: CollectMethod::Ssh,
                command: "ps aux | grep mongod | grep -v grep".to_string(),
                description: Some("检查 mongod 启动参数".to_string()),
            },
        ],
        rules: vec![
            ComplianceRule {
                id: "mongo_auth_enabled".to_string(),
                name: "启用认证".to_string(),
                category: "身份鉴别".to_string(),
                requirement_id: "8.1.1".to_string(),
                severity: "critical".to_string(),
                collect_item_id: "mongo_config".to_string(),
                check_script: "output.contains(\"authorization: enabled\") || output.contains(\"auth=true\")".to_string(),
                expected: Some("security.authorization: enabled".to_string()),
                fix_advice: Some("在 mongod.conf 中设置 security.authorization: enabled".to_string()),
            },
            ComplianceRule {
                id: "mongo_bind_local".to_string(),
                name: "限制监听地址".to_string(),
                category: "访问控制".to_string(),
                requirement_id: "8.1.3".to_string(),
                severity: "high".to_string(),
                collect_item_id: "mongo_config".to_string(),
                check_script: "output.contains(\"bindIp: 127.0.0.1\") || output.contains(\"bindIp: localhost\")".to_string(),
                expected: Some("net.bindIp: 127.0.0.1".to_string()),
                fix_advice: Some("在 mongod.conf 中设置 net.bindIp: 127.0.0.1".to_string()),
            },
            ComplianceRule {
                id: "mongo_tls_enabled".to_string(),
                name: "启用 TLS 加密".to_string(),
                category: "通信安全".to_string(),
                requirement_id: "8.1.4".to_string(),
                severity: "medium".to_string(),
                collect_item_id: "mongo_config".to_string(),
                check_script: "output.contains(\"tls:\") && output.contains(\"mode\")".to_string(),
                expected: Some("net.tls.mode: requireTLS".to_string()),
                fix_advice: Some("在 mongod.conf 中配置 net.tls 设置".to_string()),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_baseline_rules() {
        let rs = mysql_baseline();
        assert_eq!(rs.name, "mysql_baseline");
        assert!(rs.collect_items.len() >= 5);
        assert!(rs.rules.len() >= 5);
        // 所有规则的 collect_item_id 都有对应的采集项
        for rule in &rs.rules {
            assert!(rs.find_collect_item(&rule.collect_item_id).is_some());
        }
    }

    #[test]
    fn test_postgresql_baseline_rules() {
        let rs = postgresql_baseline();
        assert_eq!(rs.name, "postgresql_baseline");
        assert!(rs.collect_items.len() >= 4);
        assert!(rs.rules.len() >= 4);
    }

    #[test]
    fn test_redis_baseline_rules() {
        let rs = redis_baseline();
        assert_eq!(rs.name, "redis_baseline");
        assert!(rs.rules.len() >= 4);
        // 检查关键规则存在
        assert!(rs.rules.iter().any(|r| r.id == "redis_auth_enabled"));
        assert!(rs.rules.iter().any(|r| r.id == "redis_bind_local"));
    }

    #[test]
    fn test_mongodb_baseline_rules() {
        let rs = mongodb_baseline();
        assert_eq!(rs.name, "mongodb_baseline");
        assert!(rs.rules.len() >= 3);
        assert!(rs.rules.iter().any(|r| r.id == "mongo_auth_enabled"));
    }

    #[test]
    fn test_all_rules_have_fix_advice() {
        for rule_set_fn in [mysql_baseline, postgresql_baseline, redis_baseline, mongodb_baseline] {
            let rs = rule_set_fn();
            for rule in &rs.rules {
                assert!(rule.fix_advice.is_some(), "规则 {} 缺少修复建议", rule.id);
            }
        }
    }
}
