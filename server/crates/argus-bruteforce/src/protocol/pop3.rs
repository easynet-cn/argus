//! POP3 协议连接器
//!
//! 真实实现 POP3 认证爆破（RFC 1939）：
//! 1. TCP 连接到目标端口（默认 110）
//! 2. 接收 "+OK" 服务器问候
//! 3. 发送 "USER username\r\n"
//! 4. 接收 "+OK"
//! 5. 发送 "PASS password\r\n"
//! 6. 接收 "+OK" = 成功，"-ERR" = 失败

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct Pop3Connector;

#[async_trait]
impl ProtocolConnector for Pop3Connector {
    fn protocol(&self) -> Protocol {
        Protocol::Pop3
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
            .map_err(|e| format!("POP3 连接超时: {e}"))?
            .map_err(|e| format!("POP3 连接失败: {e}"))?;

        // 2. 接收服务器问候
        let greeting = read_line(&mut stream, dur).await?;
        if !greeting.starts_with("+OK") {
            return Err(format!("POP3 服务器问候异常: {greeting}"));
        }

        // 3. 发送 USER
        let user_cmd = format!("USER {}\r\n", credential.username);
        stream
            .write_all(user_cmd.as_bytes())
            .await
            .map_err(|e| format!("POP3 发送 USER 失败: {e}"))?;

        let resp = read_line(&mut stream, dur).await?;
        if !resp.starts_with("+OK") {
            return Ok(false); // 用户名不存在
        }

        // 4. 发送 PASS
        let pass_cmd = format!("PASS {}\r\n", credential.password);
        stream
            .write_all(pass_cmd.as_bytes())
            .await
            .map_err(|e| format!("POP3 发送 PASS 失败: {e}"))?;

        let resp = read_line(&mut stream, dur).await?;

        // 5. +OK = 成功，-ERR = 失败
        if resp.starts_with("+OK") {
            // 发送 QUIT
            let _ = stream.write_all(b"QUIT\r\n").await;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

async fn read_line(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];

    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Err("POP3 连接已关闭".to_string()),
            Ok(Ok(_)) => {
                result.push(buf[0]);
                if result.ends_with(b"\r\n") || result.ends_with(b"\n") {
                    break;
                }
                if result.len() > 8192 {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("POP3 读取失败: {e}")),
            Err(_) => return Err("POP3 读取超时".to_string()),
        }
    }

    Ok(String::from_utf8_lossy(&result).trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop3_protocol() {
        assert_eq!(Pop3Connector.protocol(), Protocol::Pop3);
    }

    #[test]
    fn test_pop3_user_cmd() {
        let cred = Credential::new("admin", "secret");
        let cmd = format!("USER {}\r\n", cred.username);
        assert_eq!(cmd, "USER admin\r\n");
    }

    #[test]
    fn test_pop3_pass_cmd() {
        let cred = Credential::new("admin", "secret");
        let cmd = format!("PASS {}\r\n", cred.password);
        assert_eq!(cmd, "PASS secret\r\n");
    }

    #[test]
    fn test_pop3_response() {
        assert!("+OK password correct".starts_with("+OK"));
        assert!("-ERR authentication failed".starts_with("-ERR"));
    }
}
