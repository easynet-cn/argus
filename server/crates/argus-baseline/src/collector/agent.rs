//! Agent 离线采集器
//!
//! 与 SSH 采集器的区别：维护持久 SSH 会话，避免每个采集项重复建立连接和认证
//! 适用场景：需要采集大量配置项的 Linux/Unix 系统，减少网络往返和连接开销
//!
//! 工作流程：
//! 1. 首次 collect_one 调用时建立 SSH 连接并认证
//! 2. 后续调用复用同一会话执行命令
//! 3. 采集器 Drop 时自动断开连接

use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tokio::sync::Mutex;
use russh::client;
use russh::keys::PublicKeyOrCertificate;
use russh::Disconnect;

use crate::collector::Collector;
use crate::types::{CollectItem, CollectMethod};
use async_trait::async_trait;

pub struct AgentCollector {
    /// 是否忽略服务器主机密钥
    accept_any_host_key: bool,
    /// 持久 SSH 会话（惰性初始化）
    session: Mutex<Option<client::Handle<ArgusSshHandler>>>,
}

impl AgentCollector {
    pub fn new() -> Self {
        Self {
            accept_any_host_key: true,
            session: Mutex::new(None),
        }
    }

    /// 获取或建立 SSH 会话（复用已有连接）
    async fn get_or_connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        timeout_ms: u64,
    ) -> Result<(), String> {
        let mut guard = self.session.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let addr = format!("{host}:{port}");
        let dur = Duration::from_millis(timeout_ms);

        let config = Arc::new(client::Config::default());
        let handler = ArgusSshHandler {
            accept_any: self.accept_any_host_key,
        };

        let mut session = match timeout(dur, client::connect(config, addr, handler)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("Agent SSH 连接失败: {e}")),
            Err(_) => return Err("Agent SSH 连接超时".to_string()),
        };

        let auth_ok = match timeout(dur, async {
            session.authenticate_password(username, password).await
        })
        .await
        {
            Ok(Ok(auth)) => auth.success(),
            Ok(Err(e)) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err(format!("Agent SSH 认证失败: {e}"));
            }
            Err(_) => {
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "argus")
                    .await;
                return Err("Agent SSH 认证超时".to_string());
            }
        };

        if !auth_ok {
            let _ = session
                .disconnect(Disconnect::ByApplication, "", "argus")
                .await;
            return Err("Agent SSH 认证失败: 用户名或密码错误".to_string());
        }

        *guard = Some(session);
        Ok(())
    }
}

impl Default for AgentCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// SSH Handler：接受任何服务器密钥（与 SshCollector 共用逻辑）
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

#[async_trait]
impl Collector for AgentCollector {
    fn name(&self) -> &str {
        "agent_collector"
    }

    fn method(&self) -> CollectMethod {
        CollectMethod::Agent
    }

    /// 采集单条配置项
    ///
    /// 复用持久 SSH 会话执行命令，避免重复连接开销
    async fn collect_one(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        item: &CollectItem,
        timeout_ms: u64,
    ) -> Result<String, String> {
        let dur = Duration::from_millis(timeout_ms);

        // 1. 获取或建立持久会话
        self.get_or_connect(host, port, username, password, timeout_ms)
            .await?;

        let mut guard = self.session.lock().await;
        let session = guard.as_mut().ok_or("Agent 会话不可用")?;

        // 2. 在持久会话上执行命令
        let output = match timeout(dur, run_command(session, &item.command)).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                // 命令执行失败时不断开连接（允许后续重试其他采集项）
                return Err(format!("Agent 命令执行失败: {e}"));
            }
            Err(_) => {
                return Err(format!("Agent 命令执行超时: {}", item.command));
            }
        };

        Ok(output)
    }
}

/// 通过持久 SSH 会话执行单条命令并收集输出
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
            Some(russh::ChannelMsg::ExitStatus { .. }) => break,
            Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => break,
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
        let c = AgentCollector::new();
        assert_eq!(c.name(), "agent_collector");
        assert_eq!(c.method(), CollectMethod::Agent);
    }

    #[test]
    fn test_collector_default() {
        let c = AgentCollector::default();
        assert!(c.accept_any_host_key);
    }

    #[test]
    fn test_session_initially_none() {
        let c = AgentCollector::new();
        // 会话初始为 None（惰性初始化）
        // 用 try_lock 避免阻塞测试
        let guard = c.session.try_lock();
        assert!(guard.is_ok());
        assert!(guard.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_connect_invalid_host_returns_error() {
        let c = AgentCollector::new();
        // 连接不存在的目标应返回明确错误而非 fallback
        let result = c
            .get_or_connect("127.0.0.1", 1, "user", "pass", 1000)
            .await;
        assert!(result.is_err(), "连接无效主机应返回错误");
        let err = result.unwrap_err();
        assert!(
            err.contains("失败") || err.contains("超时"),
            "错误信息应明确说明原因: {err}"
        );
    }
}
