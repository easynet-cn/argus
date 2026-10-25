//! 在线爆破调度器

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::stream::{self, StreamExt};

use crate::dictionary::CredentialPair;
use crate::protocol::ProtocolConnector;
use crate::types::{BruteForceParams, BruteForceResult, Credential};

/// 爆破调度器
pub struct BruteForceScheduler;

impl BruteForceScheduler {
    /// 执行在线爆破
    pub async fn run<C: ProtocolConnector + Clone>(
        connector: C,
        params: &BruteForceParams,
    ) -> Vec<BruteForceResult> {
        let host = params.host.clone();
        let port = params.port.unwrap_or_else(|| params.protocol.default_port());

        let stop_flag = Arc::new(AtomicBool::new(false));
        let results: Arc<tokio::sync::Mutex<Vec<BruteForceResult>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // G2.3: 组合字典模式 — credential_pairs 非空时优先使用配对文件
        let mut credentials: Vec<Credential> = Vec::new();
        if !params.credential_pairs.is_empty() {
            for pair in &params.credential_pairs {
                credentials.push(Credential::new(
                    pair.username.clone(),
                    pair.password.clone(),
                ));
            }
        } else {
            // 笛卡尔积模式
            for username in &params.usernames {
                for password in &params.passwords {
                    credentials.push(Credential::new(username.clone(), password.clone()));
                }
            }
        }

        // 限制尝试次数
        if params.max_attempts > 0 && credentials.len() > params.max_attempts {
            credentials.truncate(params.max_attempts);
        }

        let total = credentials.len();
        tracing::info!(
            "开始爆破 {}:{} 协议={}, 共 {} 组凭证",
            host, port, params.protocol.as_str(), total
        );

        let connector_arc = Arc::new(connector);

        stream::iter(credentials)
            .map(|cred| {
                let connector = connector_arc.clone();
                let host = host.clone();
                let stop_flag = stop_flag.clone();
                let results = results.clone();
                async move {
                    if stop_flag.load(Ordering::Relaxed) {
                        return;
                    }

                    let mut attempts = 0;
                    loop {
                        attempts += 1;
                        let result = crate::protocol::try_login(
                            connector.as_ref(),
                            &host,
                            port,
                            &cred,
                            params.timeout_ms,
                        )
                        .await;

                        if result.success {
                            tracing::info!(
                                "爆破成功! {}:{} {}:{}",
                                host, port, cred.username, cred.password
                            );
                            if params.stop_on_first_success {
                                stop_flag.store(true, Ordering::Relaxed);
                            }
                            results.lock().await.push(result);
                            break;
                        }

                        if attempts >= params.retries {
                            results.lock().await.push(result);
                            break;
                        }
                        // 重试前短暂等待
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            })
            .buffer_unordered(params.concurrency)
            .collect::<Vec<()>>()
            .await;

        let results = results.lock().await.clone();
        let success_count = results.iter().filter(|r| r.success).count();
        tracing::info!(
            "爆破完成: 成功 {}/{}",
            success_count, results.len()
        );
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Protocol;
    use async_trait::async_trait;
    use std::collections::HashSet;

    /// 可注入的 Mock 连接器：命中 valid 集合返回成功，否则失败。
    /// 实现 Clone 以满足 BruteForceScheduler::run 的约束。
    #[derive(Clone)]
    struct MockConnector {
        protocol: Protocol,
        valid: HashSet<(String, String)>,
    }

    impl MockConnector {
        fn new(protocol: Protocol, valid: &[(&str, &str)]) -> Self {
            Self {
                protocol,
                valid: valid
                    .iter()
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .collect(),
            }
        }
    }

    #[async_trait]
    impl ProtocolConnector for MockConnector {
        fn protocol(&self) -> Protocol {
            self.protocol
        }

        async fn login(
            &self,
            _host: &str,
            _port: u16,
            credential: &Credential,
            _timeout_ms: u64,
        ) -> Result<bool, String> {
            Ok(self
                .valid
                .contains(&(credential.username.clone(), credential.password.clone())))
        }
    }

    fn base_params() -> BruteForceParams {
        BruteForceParams {
            host: "127.0.0.1".to_string(),
            protocol: Protocol::Ssh,
            port: Some(22),
            usernames: vec!["root".to_string(), "admin".to_string()],
            passwords: vec!["123456".to_string(), "wrong".to_string()],
            // concurrency=1 保证顺序执行，使 stop_flag 行为可预测
            concurrency: 1,
            timeout_ms: 1000,
            max_attempts: 0,
            stop_on_first_success: true,
            retries: 1,
            credential_pairs: Vec::new(),
        }
    }

    // ====== G2.5: stop_on_first_success 行为测试 ======

    #[tokio::test]
    async fn test_stop_on_first_success_true_stops_at_first_hit() {
        // root:123456 是第一组凭证（笛卡尔积顺序 root×123456, root×wrong, admin×123456, admin×wrong）
        let connector = MockConnector::new(Protocol::Ssh, &[("root", "123456")]);
        let params = base_params(); // stop_on_first_success = true
        let results = BruteForceScheduler::run(connector, &params).await;

        // 第一个凭证即成功 → 设置 stop_flag → 后续 3 组被跳过
        assert_eq!(results.len(), 1, "发现成功凭证后应立即停止");
        assert!(results[0].success);
        assert_eq!(results[0].credential.username, "root");
        assert_eq!(results[0].credential.password, "123456");
    }

    #[tokio::test]
    async fn test_stop_on_first_success_true_stops_at_later_hit() {
        // 只有 admin:wrong 成功（第 4 组），前 3 组失败后第 4 组成功并停止
        let connector = MockConnector::new(Protocol::Ssh, &[("admin", "wrong")]);
        let params = base_params(); // stop_on_first_success = true
        let results = BruteForceScheduler::run(connector, &params).await;

        assert_eq!(results.len(), 4, "成功出现在第 4 组时，应已尝试前 3 组失败 + 第 4 组成功");
        assert!(results.last().unwrap().success);
    }

    #[tokio::test]
    async fn test_stop_on_first_success_false_scans_all_credentials() {
        // 即使 root:123456 成功，也应继续尝试剩余凭证
        let connector = MockConnector::new(Protocol::Ssh, &[("root", "123456")]);
        let mut params = base_params();
        params.stop_on_first_success = false;
        let results = BruteForceScheduler::run(connector, &params).await;

        // 2 用户 × 2 密码 = 4 组全部尝试
        assert_eq!(results.len(), 4, "stop_on_first_success=false 时应扫描整个字典");
        let success_count = results.iter().filter(|r| r.success).count();
        assert_eq!(success_count, 1);
    }

    #[tokio::test]
    async fn test_stop_on_first_success_false_collects_all_successes() {
        // 多组凭证成功时，false 模式应收集所有成功结果
        let connector = MockConnector::new(
            Protocol::Ssh,
            &[("root", "123456"), ("admin", "wrong")],
        );
        let mut params = base_params();
        params.stop_on_first_success = false;
        let results = BruteForceScheduler::run(connector, &params).await;

        assert_eq!(results.len(), 4);
        let success_count = results.iter().filter(|r| r.success).count();
        assert_eq!(success_count, 2, "应收集所有成功凭证，而非仅第一个");
    }

    #[tokio::test]
    async fn test_stop_on_first_success_true_no_success_scans_all() {
        // 没有任何凭证成功时，两种模式都应扫描完全部字典
        let connector = MockConnector::new(Protocol::Ssh, &[]);
        let params = base_params(); // stop_on_first_success = true
        let results = BruteForceScheduler::run(connector, &params).await;

        assert_eq!(results.len(), 4, "无成功凭证时应扫描整个字典");
        assert!(results.iter().all(|r| !r.success));
    }

    // ====== G2.5 × G2.3: 与组合字典模式（credential_pairs）兼容 ======

    #[tokio::test]
    async fn test_stop_on_first_success_with_credential_pairs_true() {
        let connector = MockConnector::new(Protocol::Ssh, &[("root", "toor")]);
        let mut params = base_params();
        params.usernames.clear();
        params.passwords.clear();
        params.credential_pairs = vec![
            CredentialPair { username: "admin".into(), password: "admin".into() },
            CredentialPair { username: "root".into(), password: "toor".into() },
            CredentialPair { username: "guest".into(), password: "guest".into() },
        ];
        params.stop_on_first_success = true;
        let results = BruteForceScheduler::run(connector, &params).await;

        // 第 2 组成功 → 停止，共 2 个结果
        assert_eq!(results.len(), 2, "credential_pairs 模式下也应遵守 stop_on_first_success");
        assert!(results[1].success);
        assert_eq!(results[1].credential.username, "root");
    }

    #[tokio::test]
    async fn test_stop_on_first_success_with_credential_pairs_false() {
        let connector = MockConnector::new(Protocol::Ssh, &[("root", "toor")]);
        let mut params = base_params();
        params.usernames.clear();
        params.passwords.clear();
        params.credential_pairs = vec![
            CredentialPair { username: "admin".into(), password: "admin".into() },
            CredentialPair { username: "root".into(), password: "toor".into() },
            CredentialPair { username: "guest".into(), password: "guest".into() },
        ];
        params.stop_on_first_success = false;
        let results = BruteForceScheduler::run(connector, &params).await;

        // false 模式下 3 组配对全部尝试
        assert_eq!(results.len(), 3, "credential_pairs + false 应扫描所有配对");
        let success_count = results.iter().filter(|r| r.success).count();
        assert_eq!(success_count, 1);
    }
}
