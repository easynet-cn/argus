//! SSH 远程登录采集器
//!
//! 复用 argus-bruteforce 的 russh 连接经验，登录目标主机后执行命令采集系统配置
//! 适用场景：Linux/Unix 系统配置采集

use std::sync::Arc;
use tokio::time::{timeout, Duration};
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::Disconnect;

use crate::collector::Collector;
use crate::types::{CollectItem, CollectMethod};
use async_trait::async_trait;

pub struct SshCollector {
    /// 是否忽略服务器主机密钥（爆破/采集场景通常接受）
    accept_any_host_key: bool,
}

impl SshCollector {
    pub fn new() -> Self {
        Self {
            accept_any_host_key: true,
        }
    }
}

/// SSH Handler：接受任何服务器密钥
struct ArgusSshHandler {
    accept_any: bool,
}

impl client::Handler for ArgusSshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(self.accept_any)
    }
}

impl Default for SshCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for SshCollector {
    fn name(&self) -> &str {
        "ssh_collector"
    }

    fn method(&self) -> CollectMethod {
        CollectMethod::Ssh
    }

    /// 采集单条配置项
    ///
    /// 建立 SSH 连接 → 认证 → 执行命令 → 收集输出
    async fn collect_one(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        item: &CollectItem,
        timeout_ms: u64,
    ) -> Result<String, String> {
        let addr = format!("{host}:{port}");
        let dur = Duration::from_millis(timeout_ms);

        // 1. 建立 SSH 连接
        let config = Arc::new(client::Config::default());
        let handler = ArgusSshHandler {
            accept_any: self.accept_any_host_key,
        };

        let mut session = match timeout(dur, client::connect(config, addr, handler)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("SSH 连接失败: {e}")),
            Err(_) => return Err("SSH 连接超时".to_string()),
        };

        // 2. 密码认证
        let auth_ok = match timeout(dur, async {
            session
                .authenticate_password(username, password)
                .await
        })
        .await
        {
            Ok(Ok(auth)) => auth.success(),
            Ok(Err(e)) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("SSH 认证失败: {e}"));
            }
            Err(_) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err("SSH 认证超时".to_string());
            }
        };

        if !auth_ok {
            let _ = session
                .disconnect(Disconnect::ByApplication, "", "argus")
                .await;
            return Err("SSH 认证失败: 用户名或密码错误".to_string());
        }

        // 3. 执行命令采集配置
        let output = match timeout(dur, run_command(&mut session, &item.command)).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("命令执行失败: {e}"));
            }
            Err(_) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("命令执行超时: {}", item.command));
            }
        };

        // 4. 优雅关闭会话
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "argus")
            .await;

        Ok(output)
    }
}

/// 通过 SSH 通道执行单条命令并收集输出
///
/// 复用 russh 的 channel 机制：打开 channel → exec 命令 → 读取 stdout/stderr
async fn run_command(
    session: &mut client::Handle<ArgusSshHandler>,
    command: &str,
) -> Result<String, String> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("打开 SSH channel 失败: {e}"))?;

    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec 命令失败: {e}"))?;

    // 收集 stdout
    let mut output = String::new();
    let mut stderr_output = String::new();

    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { ref data }) => {
                if let Ok(text) = std::str::from_utf8(data) {
                    output.push_str(text);
                }
            }
            Some(russh::ChannelMsg::ExtendedData { ref data, .. }) => {
                if let Ok(text) = std::str::from_utf8(data) {
                    stderr_output.push_str(text);
                }
            }
            Some(russh::ChannelMsg::ExitStatus { .. }) => {
                // 命令执行完成
                break;
            }
            Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => {
                break;
            }
            None => break,
            _ => continue,
        }
    }

    // 如果 stdout 为空但有 stderr 输出，返回 stderr（便于排查）
    if output.trim().is_empty() && !stderr_output.trim().is_empty() {
        return Ok(stderr_output.trim().to_string());
    }

    Ok(output.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_name() {
        let c = SshCollector::new();
        assert_eq!(c.name(), "ssh_collector");
        assert_eq!(c.method(), CollectMethod::Ssh);
    }

    #[test]
    fn test_collector_default() {
        let c = SshCollector::default();
        assert!(c.accept_any_host_key);
    }
}
