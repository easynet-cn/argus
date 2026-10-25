//! 协议连接器模块

pub mod ssh;
pub mod mysql;
pub mod redis;
pub mod postgresql;
pub mod mongodb;
pub mod mssql;
pub mod oracle;
// R2.3 修复：新增 5 个真实协议连接器
pub mod ftp;
pub mod telnet;
pub mod smb;
pub mod http_basic;
pub mod http_form;
// G2.1: 媒体协议爆破
pub mod rtsp;
pub mod onvif;
// G2.2: 远程桌面 / 邮件 / SNMP 协议爆破
pub mod rdp;
pub mod vnc;
pub mod imap;
pub mod pop3;
pub mod smtp;
pub mod snmp;
// G2.6: LDAP / SFTP 协议爆破
pub mod ldap;
pub mod sftp;

use async_trait::async_trait;
use crate::types::{Credential, BruteForceResult, Protocol};

/// 协议连接器统一接口
#[async_trait]
pub trait ProtocolConnector: Send + Sync {
    /// 协议类型
    fn protocol(&self) -> Protocol;

    /// 尝试登录
    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String>;
}

/// 未实现协议的占位连接器
///
/// 对于尚未实现爆破逻辑的协议（如 FTP/Telnet/SMB/MongoDB/HTTP 等），
/// 返回此连接器而非 fallback 到其他协议。其 login 方法直接返回错误，
/// 不会对目标发起任何网络请求，避免产出误导性的爆破结果。
pub struct UnsupportedConnector {
    protocol: Protocol,
}

impl UnsupportedConnector {
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }
}

#[async_trait]
impl ProtocolConnector for UnsupportedConnector {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    async fn login(
        &self,
        _host: &str,
        _port: u16,
        _credential: &Credential,
        _timeout_ms: u64,
    ) -> Result<bool, String> {
        Err(format!(
            "协议 {} 暂未实现爆破支持，已跳过（避免产出误导性结果）",
            self.protocol.as_str()
        ))
    }
}

/// 执行一次爆破尝试（接受 trait object）
pub async fn try_login(
    connector: &dyn ProtocolConnector,
    host: &str,
    port: u16,
    credential: &Credential,
    timeout_ms: u64,
) -> BruteForceResult {
    use std::time::Instant;
    let start = Instant::now();

    match connector.login(host, port, credential, timeout_ms).await {
        Ok(success) => BruteForceResult {
            host: host.to_string(),
            port,
            protocol: connector.protocol(),
            credential: credential.clone(),
            success,
            response_time_ms: start.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => BruteForceResult {
            host: host.to_string(),
            port,
            protocol: connector.protocol(),
            credential: credential.clone(),
            success: false,
            response_time_ms: start.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}
