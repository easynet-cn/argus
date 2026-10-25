//! 数据库漏洞扫描器 Scanner trait 适配器
//!
//! 包装 DbVulnScanner 实现 argus_scanner::Scanner trait
//! 对每个 target 的 host:port 检测未授权访问/默认库/危险配置等数据库漏洞
//! 数据库类型通过 extra_params.db_type 指定，或从端口号推断

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError, Target};

use crate::db_vuln::{DbVulnFinding, DbVulnScanner, DbType};

/// 数据库漏洞扫描引擎（实现 Scanner trait，注册名 `db_scanner`）
pub struct DbScanner {
    inner: DbVulnScanner,
    progress: Arc<RwLock<HashMap<String, f32>>>,
}

impl DbScanner {
    pub fn new() -> Self {
        Self {
            inner: DbVulnScanner::new(),
            progress: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 从端口号推断数据库类型（覆盖 6 种主流数据库默认端口）
    fn infer_db_type(port: u16) -> Option<DbType> {
        match port {
            3306 => Some(DbType::Mysql),
            5432 => Some(DbType::Postgresql),
            6379 => Some(DbType::Redis),
            27017 => Some(DbType::Mongodb),
            1433 => Some(DbType::Mssql),
            1521 => Some(DbType::Oracle),
            _ => None,
        }
    }

    /// 从字符串解析 DbType（支持常见别名）
    fn parse_db_type(s: &str) -> Option<DbType> {
        match s.to_lowercase().as_str() {
            "mysql" => Some(DbType::Mysql),
            "postgresql" | "postgres" | "pgsql" => Some(DbType::Postgresql),
            "redis" => Some(DbType::Redis),
            "mongodb" | "mongo" => Some(DbType::Mongodb),
            "mssql" | "sqlserver" | "sql-server" => Some(DbType::Mssql),
            "oracle" => Some(DbType::Oracle),
            _ => None,
        }
    }

    /// 解析目标 host:port
    /// 优先取 target.ports[0]；其次解析 host:port 字符串；最后回退 3306（MySQL 默认）
    fn parse_host_port(target: &Target) -> (String, u16) {
        // 优先使用 target.ports 的第一个端口
        if let Some(ports) = &target.ports {
            if let Some(&port) = ports.first() {
                let host = target.host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target.host).to_string();
                return (host, port);
            }
        }
        // 尝试解析 host:port 格式
        if let Some((h, p)) = target.host.rsplit_once(':') {
            if let Ok(p) = p.parse::<u16>() {
                return (h.to_string(), p);
            }
        }
        // 默认 MySQL 端口
        (target.host.clone(), 3306)
    }

    /// DbVulnFinding → PluginResult
    fn to_plugin_result(f: DbVulnFinding) -> PluginResult {
        let mut pr = PluginResult::new(
            f.target.clone(),
            f.title,
            f.severity,
        );
        pr.evidence = format!("{} | 证据: {}", f.description, f.evidence);
        pr.fix_advice = f.fix_advice;
        pr.service = Some(f.db_type.as_str().to_string());
        pr.timestamp = chrono::Utc::now();
        pr
    }
}

impl Default for DbScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for DbScanner {
    fn name(&self) -> &str {
        "db_scanner"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        let task_id = config.task_id.clone();
        let start = std::time::Instant::now();
        let total = config.targets.len();
        if total == 0 {
            return Err(ScannerError::Config("没有扫描目标".to_string()));
        }

        // 从 extra_params.db_type 读取数据库类型（可选）
        let db_type_str = config
            .extra_params
            .get("db_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut all_vulns: Vec<PluginResult> = Vec::new();
        let timeout_ms = config.timeout_secs.saturating_mul(1000).max(1000);

        for (i, target) in config.targets.iter().enumerate() {
            let (host, port) = Self::parse_host_port(target);
            // 优先用 extra_params.db_type，否则按端口推断，最后回退 MySQL
            let db_type = Self::parse_db_type(db_type_str)
                .or_else(|| Self::infer_db_type(port))
                .unwrap_or(DbType::Mysql);

            // G6.5 登录扫描：提供凭证时执行认证后审计查询（与未授权检测互补）
            let mut findings = self.inner.scan(&host, port, db_type.clone(), timeout_ms).await;
            if let Some(creds) = &target.credentials {
                tracing::info!(
                    "MySQL/PostgreSQL 登录扫描: {}:{} (用户={})",
                    host, port, creds.username
                );
                let auth_findings =
                    crate::db_auth_scan::scan_authenticated(&host, port, db_type.clone(), creds, timeout_ms)
                        .await;
                findings.extend(auth_findings);
            }
            for f in findings {
                all_vulns.push(Self::to_plugin_result(f));
            }

            let progress = ((i + 1) as f32) / total as f32 * 0.9;
            if let Ok(mut map) = self.progress.write() {
                map.insert(task_id.clone(), progress);
            }
        }

        let duration = start.elapsed().as_secs_f64();
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.clone(), 1.0);
        }

        Ok(ScanResult {
            task_id,
            status: TaskStatus::Completed,
            hosts_scanned: total,
            vulnerabilities: all_vulns,
            duration_secs: duration,
            raw_data: None,
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        if let Ok(map) = self.progress.read() {
            Ok(map.get(task_id).copied().unwrap_or(0.0))
        } else {
            Ok(0.0)
        }
    }

    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError> {
        if let Ok(mut map) = self.progress.write() {
            map.insert(task_id.to_string(), -1.0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_and_version() {
        let s = DbScanner::new();
        assert_eq!(s.name(), "db_scanner");
        assert_eq!(s.version(), "0.1.0");
    }

    #[test]
    fn test_infer_db_type() {
        assert_eq!(DbScanner::infer_db_type(3306), Some(DbType::Mysql));
        assert_eq!(DbScanner::infer_db_type(5432), Some(DbType::Postgresql));
        assert_eq!(DbScanner::infer_db_type(6379), Some(DbType::Redis));
        assert_eq!(DbScanner::infer_db_type(27017), Some(DbType::Mongodb));
        assert_eq!(DbScanner::infer_db_type(1433), Some(DbType::Mssql));
        assert_eq!(DbScanner::infer_db_type(1521), Some(DbType::Oracle));
        assert_eq!(DbScanner::infer_db_type(8080), None);
    }

    #[test]
    fn test_parse_db_type() {
        assert_eq!(DbScanner::parse_db_type("mysql"), Some(DbType::Mysql));
        assert_eq!(DbScanner::parse_db_type("PostgreSQL"), Some(DbType::Postgresql));
        assert_eq!(DbScanner::parse_db_type("postgres"), Some(DbType::Postgresql));
        assert_eq!(DbScanner::parse_db_type("redis"), Some(DbType::Redis));
        assert_eq!(DbScanner::parse_db_type("MongoDB"), Some(DbType::Mongodb));
        assert_eq!(DbScanner::parse_db_type("mssql"), Some(DbType::Mssql));
        assert_eq!(DbScanner::parse_db_type("sqlserver"), Some(DbType::Mssql));
        assert_eq!(DbScanner::parse_db_type("oracle"), Some(DbType::Oracle));
        assert_eq!(DbScanner::parse_db_type("unknown"), None);
    }

    #[test]
    fn test_parse_host_port_from_target_ports() {
        let t = Target {
            host: "192.168.1.1".to_string(),
            ports: Some(vec![6379]),
            credentials: None,
        };
        let (h, p) = DbScanner::parse_host_port(&t);
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, 6379);
    }

    #[test]
    fn test_parse_host_port_from_string() {
        let t = Target {
            host: "192.168.1.2:5432".to_string(),
            ports: None,
            credentials: None,
        };
        let (h, p) = DbScanner::parse_host_port(&t);
        assert_eq!(h, "192.168.1.2");
        assert_eq!(p, 5432);
    }

    #[test]
    fn test_parse_host_port_default_mysql() {
        let t = Target {
            host: "192.168.1.3".to_string(),
            ports: None,
            credentials: None,
        };
        let (h, p) = DbScanner::parse_host_port(&t);
        assert_eq!(h, "192.168.1.3");
        assert_eq!(p, 3306);
    }

    #[tokio::test]
    async fn test_execute_empty_targets() {
        let s = DbScanner::new();
        let cfg = ScanConfig {
            task_id: "t-empty".to_string(),
            targets: vec![],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_err(), "空目标应返回错误");
    }

    #[tokio::test]
    async fn test_progress_default_zero() {
        let s = DbScanner::new();
        let p = s.progress("nope").await.expect("progress");
        assert_eq!(p, 0.0);
    }

    #[tokio::test]
    async fn test_cancel_sets_minus_one() {
        let s = DbScanner::new();
        s.cancel("task-1").await.expect("cancel");
        let p = s.progress("task-1").await.expect("progress");
        assert_eq!(p, -1.0);
    }

    #[tokio::test]
    async fn test_execute_unreachable_redis_completes() {
        // 6379 端口连不上时，扫描应正常完成（结果为空）
        let s = DbScanner::new();
        let cfg = ScanConfig {
            task_id: "t-redis".to_string(),
            targets: vec![Target {
                host: "127.0.0.1".to_string(),
                ports: Some(vec![16379]), // 非默认端口，无服务
                credentials: None,
            }],
            concurrency: 1,
            timeout_secs: 1,
            extra_params: serde_json::json!({"db_type": "redis"}),
        };
        let r = s.execute(&cfg).await;
        assert!(r.is_ok(), "无法连接时扫描应返回成功（结果为空）");
        let sr = r.unwrap();
        assert_eq!(sr.hosts_scanned, 1);
        assert!(sr.vulnerabilities.is_empty());
    }
}
