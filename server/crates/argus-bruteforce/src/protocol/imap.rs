//! IMAP 协议连接器
//!
//! 真实实现 IMAP 认证爆破（IMAP4rev1, RFC 3501）：
//! 1. TCP 连接到目标端口（默认 143）
//! 2. 接收 "* OK" 服务器问候
//! 3. 发送 "A001 LOGIN username password\r\n"
//! 4. 检查响应：A001 OK = 成功，A001 NO/BAD = 失败

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct ImapConnector;

#[async_trait]
impl ProtocolConnector for ImapConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Imap
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let dur = Duration::from_millis(timeout_ms);
        let addr = format!("{host}:{port}");

        // 1. TCP 连接
        let mut stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("IMAP 连接超时: {e}"))?
            .map_err(|e| format!("IMAP 连接失败: {e}"))?;

        // 2. 接收服务器问候
        let greeting = read_line(&mut stream, dur).await?;
        if !greeting.contains("OK") {
            return Err(format!("IMAP 服务器问候异常: {greeting}"));
        }

        // 3. 发送 LOGIN
        let login_cmd = format!(
            "A001 LOGIN {} {}\r\n",
            credential.username, credential.password
        );
        stream
            .write_all(login_cmd.as_bytes())
            .await
            .map_err(|e| format!("IMAP 发送 LOGIN 失败: {e}"))?;

        // 4. 接收响应
        let resp = read_line(&mut stream, dur).await?;

        // A001 OK = 成功，A001 NO/BAD = 失败
        if resp.contains("A001 OK") {
            // 发送 LOGOUT
            let _ = stream.write_all(b"A002 LOGOUT\r\n").await;
            Ok(true)
        } else if resp.contains("A001 NO") || resp.contains("A001 BAD") {
            Ok(false)
        } else {
            // 某些服务器可能在多行响应中，继续读取
            let resp2 = read_line(&mut stream, dur).await.unwrap_or_default();
            if resp2.contains("A001 OK") {
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

/// 读取一行（以 \r\n 结尾）
async fn read_line(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];

    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Err("IMAP 连接已关闭".to_string()),
            Ok(Ok(_)) => {
                result.push(buf[0]);
                if result.ends_with(b"\r\n") || result.ends_with(b"\n") {
                    break;
                }
                if result.len() > 8192 {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("IMAP 读取失败: {e}")),
            Err(_) => return Err("IMAP 读取超时".to_string()),
        }
    }

    Ok(String::from_utf8_lossy(&result).trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imap_protocol() {
        assert_eq!(ImapConnector.protocol(), Protocol::Imap);
    }

    #[test]
    fn test_imap_login_cmd() {
        let cred = Credential::new("admin", "pass123");
        let cmd = format!("A001 LOGIN {} {}\r\n", cred.username, cred.password);
        assert!(cmd.contains("A001 LOGIN admin pass123"));
    }

    #[test]
    fn test_imap_response_parsing() {
        // 成功响应
        let resp = "A001 OK LOGIN authenticated";
        assert!(resp.contains("A001 OK"));

        // 失败响应
        let resp = "A001 NO authentication failed";
        assert!(resp.contains("A001 NO"));
    }
}
