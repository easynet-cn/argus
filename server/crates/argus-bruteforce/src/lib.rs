//! Argus 口令猜解引擎
//!
//! 支持在线爆破（SSH/MySQL/Redis/PostgreSQL）、离线 Hash 破解、社工字典生成、弱密码检测

pub mod types;
pub mod protocol;
pub mod dictionary;
pub mod scheduler;
pub mod hash_crack;
pub mod social_engineer;
pub mod weak_password;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use argus_core::entity::task::TaskStatus;
use argus_engine::PluginResult;
use argus_scanner::{ScanConfig, ScanResult, Scanner, ScannerError};
use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use protocol::ProtocolConnector;
use serde_json::Value;
use tokio::sync::RwLock;
use types::{BruteForceParams, BruteForceResult, Protocol};

/// 口令猜解引擎
pub struct BruteForce {
    progress: RwLock<HashMap<String, f32>>,
}

impl BruteForce {
    pub fn new() -> Self {
        Self {
            progress: RwLock::new(HashMap::new()),
        }
    }

    /// 根据协议创建连接器
    fn create_connector(protocol: Protocol) -> Box<dyn ProtocolConnector> {
        match protocol {
            Protocol::Ssh => Box::new(protocol::ssh::SshConnector),
            Protocol::Mysql => Box::new(protocol::mysql::MysqlConnector),
            Protocol::Redis => Box::new(protocol::redis::RedisConnector),
            Protocol::Postgresql => Box::new(protocol::postgresql::PostgresqlConnector),
            Protocol::Mongodb => Box::new(protocol::mongodb::MongodbConnector),
            Protocol::Mssql => Box::new(protocol::mssql::MssqlConnector),
            Protocol::Oracle => Box::new(protocol::oracle::OracleConnector::new()),
            // R2.3 修复：5 个协议真实实现
            Protocol::Ftp => Box::new(protocol::ftp::FtpConnector),
            Protocol::Telnet => Box::new(protocol::telnet::TelnetConnector),
            Protocol::Smb => Box::new(protocol::smb::SmbConnector),
            Protocol::HttpBasic => Box::new(protocol::http_basic::HttpBasicConnector),
            Protocol::HttpForm => Box::new(protocol::http_form::HttpFormConnector),
            // G2.1: 媒体协议爆破
            Protocol::Rtsp => Box::new(protocol::rtsp::RtspConnector),
            Protocol::Onvif => Box::new(protocol::onvif::OnvifConnector),
            // G2.2: 远程桌面 / 邮件 / SNMP 协议爆破
            Protocol::Rdp => Box::new(protocol::rdp::RdpConnector),
            Protocol::Vnc => Box::new(protocol::vnc::VncConnector),
            Protocol::Imap => Box::new(protocol::imap::ImapConnector),
            Protocol::Pop3 => Box::new(protocol::pop3::Pop3Connector),
            Protocol::Smtp => Box::new(protocol::smtp::SmtpConnector),
            Protocol::Snmp => Box::new(protocol::snmp::SnmpConnector),
            // G2.6: LDAP / SFTP 协议爆破
            Protocol::Ldap => Box::new(protocol::ldap::LdapConnector),
            Protocol::Sftp => Box::new(protocol::sftp::SftpConnector),
            // 所有 22 个协议均已实现，此分支保留为安全兜底
            #[allow(unreachable_patterns)]
            other => Box::new(protocol::UnsupportedConnector::new(other)),
        }
    }

    /// 从 ScanConfig 解析爆破参数
    fn parse_params(config: &ScanConfig) -> BruteForceParams {
        tracing::info!("解析爆破参数: {}", config.extra_params);
        let mut params: BruteForceParams = match serde_json::from_value(config.extra_params.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("爆破参数解析失败: {e}");
                BruteForceParams::default()
            }
        };

        // 从第一个 target 取 host
        if !config.targets.is_empty() && params.host.is_empty() {
            params.host = config.targets[0].host.clone();
        }

        // 从 credentials 取用户名密码
        if let Some(creds) = &config.targets.first().and_then(|t| t.credentials.clone()) {
            if params.usernames.is_empty() {
                params.usernames = vec![creds.username.clone()];
            }
            if params.passwords.is_empty() {
                params.passwords = vec![creds.password.clone()];
            }
        }

        params
    }

    /// 执行在线爆破
    async fn run_brute(&self, params: &BruteForceParams) -> Vec<BruteForceResult> {
        let host = params.host.clone();
        let port = params.port.unwrap_or_else(|| params.protocol.default_port());
        let stop_flag = Arc::new(AtomicBool::new(false));

        // G2.3: 组合字典模式 — credential_pairs 非空时优先使用配对文件
        let mut credentials: Vec<types::Credential> = Vec::new();
        if !params.credential_pairs.is_empty() {
            for pair in &params.credential_pairs {
                credentials.push(types::Credential::new(
                    pair.username.clone(),
                    pair.password.clone(),
                ));
            }
        } else {
            // 笛卡尔积模式
            for username in &params.usernames {
                for password in &params.passwords {
                    credentials.push(types::Credential::new(username.clone(), password.clone()));
                }
            }
        }
        if params.max_attempts > 0 && credentials.len() > params.max_attempts {
            credentials.truncate(params.max_attempts);
        }

        let total = credentials.len();
        tracing::info!(
            "开始爆破 {}:{} 协议={}, 共 {} 组凭证",
            host, port, params.protocol.as_str(), total
        );

        let results: Arc<tokio::sync::Mutex<Vec<BruteForceResult>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let protocol = params.protocol;
        let timeout_ms = params.timeout_ms;
        let concurrency = params.concurrency;
        let stop_on_first_success = params.stop_on_first_success;

        stream::iter(credentials)
            .map(|cred| {
                let host = host.clone();
                let stop_flag = stop_flag.clone();
                let results = results.clone();
                async move {
                    if stop_flag.load(Ordering::Relaxed) {
                        return;
                    }
                    let connector = BruteForce::create_connector(protocol);
                    let result = protocol::try_login(
                        connector.as_ref(),
                        &host,
                        port,
                        &cred,
                        timeout_ms,
                    )
                    .await;

                    if result.success {
                        tracing::info!("爆破成功! {}:{} {}:{}", host, port, cred.username, cred.password);
                        if stop_on_first_success {
                            stop_flag.store(true, Ordering::Relaxed);
                        }
                    }
                    results.lock().await.push(result);
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<()>>()
            .await;

        let results = results.lock().await.clone();
        let success_count = results.iter().filter(|r| r.success).count();
        tracing::info!("爆破完成: 成功 {}/{}", success_count, results.len());
        results
    }

    /// 横向撞库：将已爆破成功的凭证复用到其他目标
    ///
    /// 遍历成功凭证列表（host:port:credential 三元组），对每个其他目标
    /// 的同协议端口尝试相同凭证，检测是否存在跨主机口令复用。
    async fn cross_host_stuffing(
        &self,
        successful_creds: &[BruteForceResult],
        other_targets: &[(String, u16)], // (host, port) 列表
        protocol: Protocol,
        timeout_ms: u64,
        concurrency: usize,
    ) -> Vec<BruteForceResult> {
        if successful_creds.is_empty() || other_targets.is_empty() {
            return Vec::new();
        }

        // 去重：收集唯一的成功凭证
        let mut unique_creds: Vec<types::Credential> = Vec::new();
        for r in successful_creds {
            if !unique_creds.iter().any(|c| c.username == r.credential.username && c.password == r.credential.password) {
                unique_creds.push(r.credential.clone());
            }
        }

        tracing::info!(
            "横向撞库: {} 组凭证 × {} 个目标, 协议={}",
            unique_creds.len(), other_targets.len(), protocol.as_str()
        );

        let results: Arc<tokio::sync::Mutex<Vec<BruteForceResult>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // 生成 (target, credential) 组合
        let mut combos: Vec<((String, u16), types::Credential)> = Vec::new();
        for (host, port) in other_targets {
            for cred in &unique_creds {
                combos.push(((host.clone(), *port), cred.clone()));
            }
        }

        stream::iter(combos)
            .map(|((host, port), cred)| {
                let results = results.clone();
                async move {
                    let connector = BruteForce::create_connector(protocol);
                    let result = protocol::try_login(
                        connector.as_ref(),
                        &host,
                        port,
                        &cred,
                        timeout_ms,
                    )
                    .await;

                    if result.success {
                        tracing::info!(
                            "横向撞库成功! {}:{} {}:{}",
                            host, port, cred.username, cred.password
                        );
                    }
                    results.lock().await.push(result);
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<()>>()
            .await;

        let results = results.lock().await.clone();
        let success_count = results.iter().filter(|r| r.success).count();
        tracing::info!(
            "横向撞库完成: 成功 {}/{}",
            success_count, results.len()
        );
        results
    }

    /// G2.4: 弱密码复检 — 对之前爆破成功的凭证再次尝试登录
    ///
    /// 用已扫描到的用户密码再次尝试登录：
    /// - 成功 = 未修复（仍然存在弱口令）
    /// - 失败 = 已修复（密码已修改或账户已禁用）
    ///
    /// 返回 (复检结果列表, 未修复数量)
    pub async fn recheck_weak_passwords(
        &self,
        previous_results: &[BruteForceResult],
        timeout_ms: u64,
        concurrency: usize,
    ) -> (Vec<RecheckResult>, usize) {
        if previous_results.is_empty() {
            return (Vec::new(), 0);
        }

        // 只复检之前成功的凭证
        let success_creds: Vec<&BruteForceResult> =
            previous_results.iter().filter(|r| r.success).collect();

        if success_creds.is_empty() {
            return (Vec::new(), 0);
        }

        tracing::info!(
            "弱密码复检: {} 组成功凭证需要重新验证",
            success_creds.len()
        );

        let results: Arc<tokio::sync::Mutex<Vec<RecheckResult>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));

        stream::iter(success_creds.into_iter())
            .map(|prev| {
                let results = results.clone();
                async move {
                    let connector = BruteForce::create_connector(prev.protocol);
                    let result = protocol::try_login(
                        connector.as_ref(),
                        &prev.host,
                        prev.port,
                        &prev.credential,
                        timeout_ms,
                    )
                    .await;
                    let recheck = RecheckResult {
                        host: prev.host.clone(),
                        port: prev.port,
                        protocol: prev.protocol,
                        username: prev.credential.username.clone(),
                        password: prev.credential.password.clone(),
                        still_vulnerable: result.success,
                        fixed: !result.success,
                        error: result.error,
                    };
                    results.lock().await.push(recheck);
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<()>>()
            .await;

        let results = results.lock().await.clone();
        let unfixed_count = results.iter().filter(|r| r.still_vulnerable).count();
        tracing::info!(
            "弱密码复检完成: 未修复 {}/{}",
            unfixed_count, results.len()
        );
        (results, unfixed_count)
    }
}

/// G2.4: 弱密码复检结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecheckResult {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub username: String,
    pub password: String,
    /// 仍然可登录 = 未修复
    pub still_vulnerable: bool,
    /// 已无法登录 = 已修复
    pub fixed: bool,
    pub error: Option<String>,
}

impl Default for BruteForce {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for BruteForce {
    fn name(&self) -> &str {
        "brute_force"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError> {
        use std::time::Instant;
        let start = Instant::now();
        let task_id = config.task_id.clone();

        // 初始化进度
        self.progress.write().await.insert(task_id.clone(), 0.0);

        let params = Self::parse_params(config);

        if params.host.is_empty() {
            return Err(ScannerError::Config("目标主机不能为空".to_string()));
        }
        if params.usernames.is_empty() || params.passwords.is_empty() {
            return Err(ScannerError::Config("用户名或密码字典不能为空".to_string()));
        }

        self.progress.write().await.insert(task_id.clone(), 0.1);

        let results = self.run_brute(&params).await;

        // 横向撞库：如果有多个目标，将成功凭证复用到其他目标
        let mut all_results = results.clone();
        let success_creds: Vec<BruteForceResult> =
            results.iter().filter(|r| r.success).cloned().collect();

        if !success_creds.is_empty() && config.targets.len() > 1 {
            self.progress.write().await.insert(task_id.clone(), 0.7);

            let protocol = params.protocol;
            let default_port = params.port.unwrap_or_else(|| protocol.default_port());
            let other_targets: Vec<(String, u16)> = config
                .targets
                .iter()
                .skip(1) // 跳过第一个目标（已爆破）
                .filter_map(|t| {
                    // 只对同协议端口的目标尝试
                    let port = t.ports.as_ref()
                        .and_then(|p| p.first().copied())
                        .unwrap_or(default_port);
                    Some((t.host.clone(), port))
                })
                .collect();

            if !other_targets.is_empty() {
                let cross_results = self
                    .cross_host_stuffing(
                        &success_creds,
                        &other_targets,
                        protocol,
                        params.timeout_ms,
                        params.concurrency,
                    )
                    .await;
                all_results.extend(cross_results);
            }
        }

        self.progress.write().await.insert(task_id.clone(), 1.0);

        let success_count = all_results.iter().filter(|r| r.success).count();
        let vulnerabilities: Vec<PluginResult> = all_results
            .iter()
            .filter(|r| r.success)
            .map(|r| {
                let mut vuln = PluginResult::new(
                    r.host.clone(),
                    format!("弱口令: {}:{}", r.host, r.port),
                    "high".to_string(),
                );
                vuln.port = Some(r.port);
                vuln.service = Some(r.protocol.as_str().to_string());
                vuln.evidence = format!(
                    "协议={} 用户名={} 密码={}",
                    r.protocol.as_str(), r.credential.username, r.credential.password
                );
                vuln.fix_advice = Some("建议修改为强密码，启用多因素认证".to_string());
                vuln
            })
            .collect();

        let duration = start.elapsed().as_secs_f64();

        Ok(ScanResult {
            task_id: task_id.clone(),
            status: if success_count > 0 {
                TaskStatus::Completed
            } else {
                TaskStatus::Completed
            },
            hosts_scanned: 1,
            vulnerabilities,
            duration_secs: duration,
            raw_data: Some(serde_json::to_value(&all_results).unwrap_or(Value::Null)),
        })
    }

    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError> {
        Ok(self.progress.read().await.get(task_id).copied().unwrap_or(0.0))
    }

    async fn cancel(&self, _task_id: &str) -> Result<(), ScannerError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::*;
    use crate::hash_crack::*;
    use crate::weak_password::*;
    use crate::social_engineer::*;

    #[test]
    fn test_top10_usernames() {
        let users = get_usernames(&UsernameDict::Top10);
        assert!(users.contains(&"root".to_string()));
        assert!(users.contains(&"admin".to_string()));
    }

    #[test]
    fn test_top10_passwords() {
        let pwds = get_passwords(&PasswordDict::Top10);
        assert!(pwds.contains(&"123456".to_string()));
        assert!(pwds.contains(&"password".to_string()));
    }

    #[test]
    fn test_hash_type_detection() {
        assert!(matches!(HashType::from_hash("5f4dcc3b5aa765d61d8327deb882cf99"), Some(HashType::Md5)));
        assert!(matches!(HashType::from_hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"), Some(HashType::Sha1)));
        assert!(HashType::from_hash("tooshort").is_none());
    }

    #[test]
    fn test_md5_crack() {
        let hash = HashType::Md5.hash("password");
        let result = crack_with_dict(&hash, &["password".to_string()]);
        assert!(result.cracked);
        assert_eq!(result.plaintext, Some("password".to_string()));
    }

    #[test]
    fn test_md5_crack_failed() {
        let hash = HashType::Md5.hash("password");
        let result = crack_with_dict(&hash, &["wrong".to_string()]);
        assert!(!result.cracked);
    }

    #[test]
    fn test_weak_password_detection() {
        let result = WeakPasswordChecker::check("123456");
        assert!(result.is_weak);
        assert!(result.reasons.iter().any(|r| r.contains("弱密码字典")));
    }

    #[test]
    fn test_strong_password() {
        let result = WeakPasswordChecker::check("Str0ng!P@ss2024");
        assert!(!result.is_weak);
    }

    #[test]
    fn test_consecutive_password() {
        let result = WeakPasswordChecker::check("abcdefg");
        assert!(result.is_weak);
        assert!(result.reasons.iter().any(|r| r.contains("连续字符")));
    }

    #[test]
    fn test_social_engineer_passwords() {
        let target = SocialTarget {
            name: Some("张三".to_string()),
            english_name: Some("zhangsan".to_string()),
            company: Some("Acme".to_string()),
            birthday: Some("1990-01-01".to_string()),
            ..Default::default()
        };
        let passwords = SocialEngineer::generate_passwords(&target);
        assert!(!passwords.is_empty());
        assert!(passwords.iter().any(|p| p.contains("zhangsan")));
        assert!(passwords.iter().any(|p| p.contains("1990")));
        assert!(passwords.iter().any(|p| p.contains("Acme")));
    }

    #[test]
    fn test_protocol_default_port() {
        assert_eq!(Protocol::Ssh.default_port(), 22);
        assert_eq!(Protocol::Mysql.default_port(), 3306);
        assert_eq!(Protocol::Redis.default_port(), 6379);
        assert_eq!(Protocol::Postgresql.default_port(), 5432);
    }

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::from_str("ssh"), Some(Protocol::Ssh));
        assert_eq!(Protocol::from_str("MySQL"), Some(Protocol::Mysql));
        assert_eq!(Protocol::from_str("postgres"), Some(Protocol::Postgresql));
        assert!(Protocol::from_str("unknown").is_none());
    }

    // ====== 协议支持性测试 ======

    #[test]
    fn test_protocol_is_supported() {
        // 所有 20 个协议均已实现
        assert!(Protocol::Ssh.is_supported());
        assert!(Protocol::Mysql.is_supported());
        assert!(Protocol::Redis.is_supported());
        assert!(Protocol::Postgresql.is_supported());
        assert!(Protocol::Mongodb.is_supported());
        assert!(Protocol::Mssql.is_supported());
        assert!(Protocol::Oracle.is_supported());
        assert!(Protocol::Ftp.is_supported());
        assert!(Protocol::Telnet.is_supported());
        assert!(Protocol::Smb.is_supported());
        assert!(Protocol::HttpBasic.is_supported());
        assert!(Protocol::HttpForm.is_supported());
        assert!(Protocol::Rtsp.is_supported());
        assert!(Protocol::Onvif.is_supported());
        assert!(Protocol::Rdp.is_supported());
        assert!(Protocol::Vnc.is_supported());
        assert!(Protocol::Imap.is_supported());
        assert!(Protocol::Pop3.is_supported());
        assert!(Protocol::Smtp.is_supported());
        assert!(Protocol::Snmp.is_supported());
        assert!(Protocol::Ldap.is_supported());
        assert!(Protocol::Sftp.is_supported());
    }

    #[test]
    fn test_create_connector_returns_correct_protocol() {
        // 所有 20 个协议的连接器都应返回对应的 Protocol
        let all_protocols = [
            Protocol::Ssh,
            Protocol::Mysql,
            Protocol::Redis,
            Protocol::Postgresql,
            Protocol::Ftp,
            Protocol::Telnet,
            Protocol::Smb,
            Protocol::Mongodb,
            Protocol::Mssql,
            Protocol::Oracle,
            Protocol::HttpBasic,
            Protocol::HttpForm,
            Protocol::Rtsp,
            Protocol::Onvif,
            Protocol::Rdp,
            Protocol::Vnc,
            Protocol::Imap,
            Protocol::Pop3,
            Protocol::Smtp,
            Protocol::Snmp,
            Protocol::Ldap,
            Protocol::Sftp,
        ];
        for proto in all_protocols {
            let connector = BruteForce::create_connector(proto);
            assert_eq!(connector.protocol(), proto, "连接器协议应与请求一致");
        }
    }

    #[tokio::test]
    async fn test_unsupported_connector_login_returns_error() {
        // UnsupportedConnector 的 login 必须返回错误，不产出 success=true
        let connector = protocol::UnsupportedConnector::new(Protocol::Ftp);
        let cred = types::Credential::new("user".to_string(), "pass".to_string());
        let result = connector
            .login("127.0.0.1", 21, &cred, 1000)
            .await;
        assert!(result.is_err(), "未实现协议的 login 应返回错误");
        let err = result.unwrap_err();
        assert!(
            err.contains("暂未实现"),
            "错误信息应说明协议未实现: {err}"
        );
        assert!(
            err.contains("ftp"),
            "错误信息应包含协议名: {err}"
        );
    }

    #[tokio::test]
    async fn test_unsupported_connector_no_misleading_success() {
        // try_login 对 UnsupportedConnector 必须产出 success=false 且带 error，
        // 绝不能产出 success=true 的误导性结果
        let connector = protocol::UnsupportedConnector::new(Protocol::Telnet);
        let cred = types::Credential::new("admin".to_string(), "123456".to_string());
        let result =
            protocol::try_login(&connector, "127.0.0.1", 23, &cred, 1000).await;
        assert!(!result.success, "未实现协议绝不能返回 success=true");
        assert_eq!(result.protocol, Protocol::Telnet);
        assert!(
            result.error.is_some(),
            "未实现协议的结果应携带 error 字段"
        );
    }

    // ====== R2.1: 横向撞库测试 ======

    #[test]
    fn test_cross_host_stuffing_empty_inputs() {
        let bf = BruteForce::new();
        // 空输入应返回空结果
        let rt = tokio::runtime::Runtime::new().unwrap();
        let results = rt.block_on(async {
            bf.cross_host_stuffing(&[], &[], Protocol::Ssh, 1000, 10).await
        });
        assert!(results.is_empty(), "空输入应返回空结果");
    }

    #[test]
    fn test_cross_host_stuffing_no_targets() {
        let bf = BruteForce::new();
        let success_creds = vec![BruteForceResult {
            host: "10.0.0.1".to_string(),
            port: 22,
            protocol: Protocol::Ssh,
            credential: types::Credential::new("root".to_string(), "123456".to_string()),
            success: true,
            response_time_ms: 100,
            error: None,
        }];
        // 有成功凭证但无其他目标 → 返回空
        let rt = tokio::runtime::Runtime::new().unwrap();
        let results = rt.block_on(async {
            bf.cross_host_stuffing(&success_creds, &[], Protocol::Ssh, 1000, 10).await
        });
        assert!(results.is_empty(), "无其他目标应返回空结果");
    }

    #[test]
    fn test_cross_host_stuffing_dedup_credentials() {
        // 验证去重逻辑：相同凭证只保留一份
        let cred = types::Credential::new("root".to_string(), "123456".to_string());
        let _dup_creds = vec![
            BruteForceResult {
                host: "10.0.0.1".to_string(),
                port: 22,
                protocol: Protocol::Ssh,
                credential: cred.clone(),
                success: true,
                response_time_ms: 100,
                error: None,
            },
            BruteForceResult {
                host: "10.0.0.1".to_string(),
                port: 22,
                protocol: Protocol::Ssh,
                credential: cred.clone(),
                success: true,
                response_time_ms: 90,
                error: None,
            },
        ];
        // 函数内部去重后只有 1 组凭证，目标 10.0.0.2 不可达（测试环境），
        // 应返回 1 个 success=false 的结果
        let bf = BruteForce::new();
        let targets = vec![("10.0.0.2".to_string(), 22u16)];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let results = rt.block_on(async {
            bf.cross_host_stuffing(&_dup_creds, &targets, Protocol::Ssh, 500, 1).await
        });
        assert_eq!(results.len(), 1, "去重后 1 组凭证 × 1 目标 = 1 个结果");
        assert!(!results[0].success, "不可达目标应返回 success=false");
    }

    // ====== G2.3: 组合字典模式测试 ======

    #[test]
    fn test_parse_combo_lines_colon() {
        let content = "root:123456\nadmin:password\n";
        let pairs = crate::dictionary::parse_combo_lines(content).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].username, "root");
        assert_eq!(pairs[0].password, "123456");
        assert_eq!(pairs[1].username, "admin");
        assert_eq!(pairs[1].password, "password");
    }

    #[test]
    fn test_parse_combo_lines_space() {
        let content = "root 123456\nadmin password\n";
        let pairs = crate::dictionary::parse_combo_lines(content).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].username, "root");
        assert_eq!(pairs[0].password, "123456");
    }

    #[test]
    fn test_parse_combo_lines_skip_comments() {
        let content = "# 注释行\nroot:123456\n\n# 另一个注释\nadmin:password\n";
        let pairs = crate::dictionary::parse_combo_lines(content).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].username, "root");
        assert_eq!(pairs[1].username, "admin");
    }

    #[test]
    fn test_parse_combo_lines_missing_separator() {
        let content = "nopseparator\n";
        let result = crate::dictionary::parse_combo_lines(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_combo_lines_password_contains_colon() {
        // 密码中可能包含 : 分隔符，但只按第一个分隔符拆分
        let content = "root:pass:word\n";
        let pairs = crate::dictionary::parse_combo_lines(content).unwrap();
        assert_eq!(pairs[0].username, "root");
        assert_eq!(pairs[0].password, "pass:word");
    }

    // ====== G2.4: 弱密码复检测试 ======

    #[test]
    fn test_recheck_empty_input() {
        let bf = BruteForce::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (results, unfixed) = rt.block_on(async {
            bf.recheck_weak_passwords(&[], 1000, 10).await
        });
        assert!(results.is_empty());
        assert_eq!(unfixed, 0);
    }

    #[test]
    fn test_recheck_no_success_creds() {
        let bf = BruteForce::new();
        let failed = vec![BruteForceResult {
            host: "10.0.0.1".to_string(),
            port: 22,
            protocol: Protocol::Ssh,
            credential: types::Credential::new("root".to_string(), "wrong".to_string()),
            success: false,
            response_time_ms: 100,
            error: None,
        }];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (results, unfixed) = rt.block_on(async {
            bf.recheck_weak_passwords(&failed, 1000, 10).await
        });
        assert!(results.is_empty());
        assert_eq!(unfixed, 0);
    }

    #[test]
    fn test_recheck_unreachable_target() {
        // 对不可达目标复检，应返回 fixed=true
        let bf = BruteForce::new();
        let success = vec![BruteForceResult {
            host: "10.0.0.99".to_string(),
            port: 22,
            protocol: Protocol::Ssh,
            credential: types::Credential::new("root".to_string(), "123456".to_string()),
            success: true,
            response_time_ms: 100,
            error: None,
        }];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (results, unfixed) = rt.block_on(async {
            bf.recheck_weak_passwords(&success, 500, 1).await
        });
        assert_eq!(results.len(), 1);
        assert!(!results[0].still_vulnerable, "不可达目标应 still_vulnerable=false");
        assert!(results[0].fixed, "不可达目标应 fixed=true");
        assert_eq!(unfixed, 0);
    }
}
