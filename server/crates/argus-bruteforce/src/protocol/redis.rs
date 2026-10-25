//! Redis 协议连接器

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct RedisConnector;

#[async_trait]
impl ProtocolConnector for RedisConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Redis
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        let mut stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("连接超时: {e}"))?
            .map_err(|e| format!("连接失败: {e}"))?;

        // 构造 AUTH 命令
        // Redis 6.0+ 支持 ACL: AUTH username password
        // 旧版本: AUTH password
        let cmd = if credential.username.is_empty() {
            format!("AUTH {}\r\n", credential.password)
        } else {
            format!("AUTH {} {}\r\n", credential.username, credential.password)
        };

        timeout(dur, stream.write_all(cmd.as_bytes()))
            .await
            .map_err(|e| format!("发送超时: {e}"))?
            .map_err(|e| format!("发送失败: {e}"))?;

        let mut buf = [0u8; 1024];
        let n = timeout(dur, stream.read(&mut buf))
            .await
            .map_err(|e| format!("读取超时: {e}"))?
            .map_err(|e| format!("读取失败: {e}"))?;

        let response = String::from_utf8_lossy(&buf[..n]);
        // +OK 表示成功
        Ok(response.starts_with("+OK"))
    }
}
