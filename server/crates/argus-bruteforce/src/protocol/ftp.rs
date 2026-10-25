//! FTP 协议连接器
//!
//! 真实实现 FTP 登录爆破：
//! 1. TCP 连接到目标端口（默认 21）
//! 2. 读取 "220" 问候消息
//! 3. 发送 "USER <username>\r\n"
//! 4. 读取 "331" 响应（需要密码）
//! 5. 发送 "PASS <password>\r\n"
//! 6. 读取 "230" 表示登录成功

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct FtpConnector;

#[async_trait]
impl ProtocolConnector for FtpConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Ftp
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
            .map_err(|e| format!("FTP 连接超时: {e}"))?
            .map_err(|e| format!("FTP 连接失败: {e}"))?;

        // 2. 读取 220 问候消息
        let greeting = read_ftp_response(&mut stream, dur).await?;
        if !greeting.starts_with("220") {
            return Err(format!("FTP 问候消息异常: {greeting}"));
        }

        // 3. 发送 USER 命令
        let user_cmd = format!("USER {}\r\n", credential.username);
        stream
            .write_all(user_cmd.as_bytes())
            .await
            .map_err(|e| format!("发送 USER 失败: {e}"))?;

        let user_resp = read_ftp_response(&mut stream, dur).await?;

        // 331 = 需要密码，230 = 直接登录成功（匿名/无密码）
        if user_resp.starts_with("230") {
            return Ok(true);
        }
        if !user_resp.starts_with("331") {
            // 530 = 登录失败，或其他错误
            return Ok(false);
        }

        // 5. 发送 PASS 命令
        let pass_cmd = format!("PASS {}\r\n", credential.password);
        stream
            .write_all(pass_cmd.as_bytes())
            .await
            .map_err(|e| format!("发送 PASS 失败: {e}"))?;

        let pass_resp = read_ftp_response(&mut stream, dur).await?;

        // 230 = 登录成功
        Ok(pass_resp.starts_with("230"))
    }
}

/// 读取 FTP 响应（支持多行响应）
///
/// FTP 多行响应格式:
/// ```text
/// 220-Welcome message line 1
/// 220-Welcome message line 2
/// 220 Final line
/// ```
async fn read_ftp_response(
    stream: &mut TcpStream,
    dur: Duration,
) -> Result<String, String> {
    let mut buf = vec![0u8; 4096];
    let n = timeout(dur, stream.read(&mut buf))
        .await
        .map_err(|e| format!("读取 FTP 响应超时: {e}"))?
        .map_err(|e| format!("读取 FTP 响应失败: {e}"))?;

    if n == 0 {
        return Err("FTP 连接已关闭".to_string());
    }

    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    // 处理多行响应：最后一行的第 4 个字符不是 '-'
    // 简化处理：取最后一行
    let last_line = resp.lines().last().unwrap_or("").trim();
    Ok(last_line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_protocol() {
        assert_eq!(FtpConnector.protocol(), Protocol::Ftp);
    }
}
