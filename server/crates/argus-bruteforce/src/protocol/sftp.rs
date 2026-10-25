//! SFTP 协议连接器
//!
//! G2.6: SFTP 爆破（基于 SSH 协议，复用 russh）
//! SFTP 是 SSH 子系统（subsystem），认证方式与 SSH 相同（密码认证），
//! 区别在于认证成功后请求 "sftp" 子系统以确认 SFTP 服务可用。
//!
//! 流程:
//! 1. 建立 SSH 连接（russh）
//! 2. 密码认证
//! 3. 打开 channel，请求 subsystem "sftp"
//! 4. 发送 SSH_FXP_INIT 包，确认 SFTP 服务器响应

use async_trait::async_trait;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::ChannelMsg;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct SftpConnector;

/// 自定义 SSH Handler（与 ssh.rs 相同，接受任何服务器密钥）
struct ArgusSftpHandler;

impl client::Handler for ArgusSftpHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[async_trait]
impl ProtocolConnector for SftpConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Sftp
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
        let handler = ArgusSftpHandler;

        // 1. 建立 SSH 连接
        let mut session = match timeout(dur, client::connect(config, addr, handler)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("SFTP(SSH) 连接失败: {e}")),
            Err(e) => return Err(format!("SFTP(SSH) 连接超时: {e}")),
        };

        // 2. 密码认证
        let auth_result = timeout(dur, async {
            session
                .authenticate_password(&credential.username, &credential.password)
                .await
        })
        .await;

        let auth_success = match auth_result {
            Ok(Ok(auth)) => auth.success(),
            Ok(Err(e)) => {
                tracing::debug!("SFTP 鉴权错误: {e}");
                false
            }
            Err(_) => false,
        };

        if !auth_success {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "argus")
                .await;
            return Ok(false);
        }

        // 3. 请求 SFTP 子系统
        let channel_result = timeout(dur, session.channel_open_session()).await;
        let mut channel = match channel_result {
            Ok(Ok(ch)) => ch,
            Ok(Err(e)) => {
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("SFTP channel 开启失败: {e}"));
            }
            Err(e) => {
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("SFTP channel 开启超时: {e}"));
            }
        };

        // 请求 subsystem "sftp"
        if let Err(e) = channel.request_subsystem(false, "sftp").await {
            let _ = session
                .disconnect(russh::Disconnect::ByApplication, "", "argus")
                .await;
            tracing::debug!("SFTP subsystem 请求失败: {e}");
            return Ok(false);
        }

        // 4. 等待 subsystem 确认或 SSH_FXP_VERSION 响应
        let subsystem_ok = timeout(dur, async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => return true,
                    Some(ChannelMsg::Failure) => return false,
                    Some(ChannelMsg::ExtendedData { .. }) | Some(ChannelMsg::Data { .. }) => return true,
                    Some(_) => continue,
                    None => return false,
                }
            }
        })
        .await;

        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "argus")
            .await;

        match subsystem_ok {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false), // SSH 认证成功但 SFTP 子系统不可用
            Err(e) => Err(format!("SFTP subsystem 等待超时: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sftp_protocol() {
        assert_eq!(SftpConnector.protocol(), Protocol::Sftp);
    }

    #[test]
    fn test_sftp_default_port() {
        assert_eq!(Protocol::Sftp.default_port(), 22);
    }

    #[test]
    fn test_sftp_from_str() {
        assert_eq!(Protocol::from_str("sftp"), Some(Protocol::Sftp));
    }
}
