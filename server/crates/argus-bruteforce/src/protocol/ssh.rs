//! SSH 协议连接器
//!
//! 使用 russh（纯 Rust 实现）替代系统 sshpass 命令
//! 仅做密码认证爆破，不执行远程命令

use async_trait::async_trait;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct SshConnector;

/// 自定义 SSH Handler（实现 client::Handler trait）
///
/// 注意：russh 0.63 的 Handler trait 方法使用 `impl Future` 而非 `async fn`，
/// 因此不通过 #[async_trait] 实现，而是直接手写 trait 实现。
struct ArgusSshHandler;

impl client::Handler for ArgusSshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // 爆破场景：接受任何服务器密钥
        Ok(true)
    }
}

#[async_trait]
impl ProtocolConnector for SshConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Ssh
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let addr = format!("{host}:{port}");
        let dur = Duration::from_millis(timeout_ms);

        let config = Arc::new(client::Config::default());
        let handler = ArgusSshHandler;

        // 建立连接（带超时）
        let mut session = match timeout(dur, client::connect(config, addr, handler)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("SSH 连接失败: {e}")),
            Err(e) => return Err(format!("SSH 连接超时: {e}")),
        };

        // 验证用户名 + 密码
        let auth_result = timeout(dur, async {
            session
                .authenticate_password(&credential.username, &credential.password)
                .await
        })
        .await;

        let success = match auth_result {
            Ok(Ok(auth)) => auth.success(),
            Ok(Err(e)) => {
                tracing::debug!("SSH 鉴权错误: {e}");
                false
            }
            Err(_) => false,
        };

        // 优雅关闭会话
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "argus")
            .await;
        Ok(success)
    }
}
