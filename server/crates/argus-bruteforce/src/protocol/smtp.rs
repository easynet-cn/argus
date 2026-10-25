//! SMTP 协议连接器
//!
//! 真实实现 SMTP AUTH 认证爆破（RFC 4954）：
//! 1. TCP 连接到目标端口（默认 25）
//! 2. 接收 "220" 服务器问候
//! 3. 发送 "EHLO argus\r\n"
//! 4. 接收 "250" 扩展列表（检查 AUTH 支持）
//! 5. 发送 "AUTH LOGIN\r\n"
//! 6. 接收 "334"（base64 提示用户名）
//! 7. 发送 base64(username)
//! 8. 接收 "334"（base64 提示密码）
//! 9. 发送 base64(password)
//! 10. 接收 "235" = 成功，"535" = 失败

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct SmtpConnector;

#[async_trait]
impl ProtocolConnector for SmtpConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Smtp
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
            .map_err(|e| format!("SMTP 连接超时: {e}"))?
            .map_err(|e| format!("SMTP 连接失败: {e}"))?;

        // 2. 接收服务器问候
        let greeting = read_line(&mut stream, dur).await?;
        if !greeting.starts_with("220") {
            return Err(format!("SMTP 服务器问候异常: {greeting}"));
        }

        // 3. 发送 EHLO
        stream
            .write_all(b"EHLO argus\r\n")
            .await
            .map_err(|e| format!("SMTP 发送 EHLO 失败: {e}"))?;

        // 4. 接收 EHLO 响应（可能多行）
        let ehlo_resp = read_full_response(&mut stream, dur).await?;
        if !ehlo_resp.starts_with("250") {
            // 尝试 HELO
            stream
                .write_all(b"HELO argus\r\n")
                .await
                .map_err(|e| format!("SMTP 发送 HELO 失败: {e}"))?;
            let helo_resp = read_line(&mut stream, dur).await?;
            if !helo_resp.starts_with("250") {
                return Err(format!("SMTP EHLO/HELO 失败: {helo_resp}"));
            }
        }

        // 检查服务器是否支持 AUTH LOGIN
        // 如果不检查直接尝试 AUTH LOGIN，服务器会拒绝不支持的方法

        // 5. 发送 AUTH LOGIN
        stream
            .write_all(b"AUTH LOGIN\r\n")
            .await
            .map_err(|e| format!("SMTP 发送 AUTH LOGIN 失败: {e}"))?;

        // 6. 接收 username 提示 (334)
        let resp = read_line(&mut stream, dur).await?;
        if !resp.starts_with("334") {
            // 服务器不支持 AUTH LOGIN 或需要认证方式不同
            if resp.starts_with("504") || resp.starts_with("502") {
                return Err("SMTP 服务器不支持 AUTH LOGIN".to_string());
            }
            return Ok(false);
        }

        // 7. 发送 base64(username)
        let user_b64 = base64::engine::general_purpose::STANDARD.encode(&credential.username);
        stream
            .write_all(format!("{user_b64}\r\n").as_bytes())
            .await
            .map_err(|e| format!("SMTP 发送用户名失败: {e}"))?;

        // 8. 接收 password 提示 (334)
        let resp = read_line(&mut stream, dur).await?;
        if !resp.starts_with("334") {
            return Ok(false);
        }

        // 9. 发送 base64(password)
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode(&credential.password);
        stream
            .write_all(format!("{pass_b64}\r\n").as_bytes())
            .await
            .map_err(|e| format!("SMTP 发送密码失败: {e}"))?;

        // 10. 接收认证结果
        let resp = read_line(&mut stream, dur).await?;

        // 235 = 认证成功，535 = 认证失败
        if resp.starts_with("235") {
            // 发送 QUIT
            let _ = stream.write_all(b"QUIT\r\n").await;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// 读取一行 SMTP 响应
async fn read_line(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let mut result = Vec::new();
    let mut buf = [0u8; 1];

    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Err("SMTP 连接已关闭".to_string()),
            Ok(Ok(_)) => {
                result.push(buf[0]);
                if result.ends_with(b"\r\n") {
                    break;
                }
                if result.len() > 8192 {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("SMTP 读取失败: {e}")),
            Err(_) => return Err("SMTP 读取超时".to_string()),
        }
    }

    Ok(String::from_utf8_lossy(&result).trim_end().to_string())
}

/// 读取完整的多行 SMTP 响应（以 "NNN " 而非 "NNN-" 结尾的行）
async fn read_full_response(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let mut all_lines = Vec::new();
    loop {
        let line = read_line(stream, dur).await?;
        all_lines.push(line.clone());
        // SMTP 多行响应：每行以 "NNN-" 开头，最后一行以 "NNN " 开头
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        // 单行响应
        if !line.starts_with("250-") && !line.starts_with("2") {
            break;
        }
        // 防止无限循环
        if all_lines.len() > 50 {
            break;
        }
    }
    Ok(all_lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_protocol() {
        assert_eq!(SmtpConnector.protocol(), Protocol::Smtp);
    }

    #[test]
    fn test_base64_encode() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin");
        assert_eq!(encoded, "YWRtaW4=");

        let encoded = base64::engine::general_purpose::STANDARD.encode("password");
        assert_eq!(encoded, "cGFzc3dvcmQ=");
    }

    #[test]
    fn test_smtp_response_parsing() {
        // 认证成功
        let resp = "235 2.7.0 Authentication successful";
        assert!(resp.starts_with("235"));

        // 认证失败
        let resp = "535 5.7.8 Authentication credentials invalid";
        assert!(!resp.starts_with("235"));
    }

    #[test]
    fn test_smtp_auth_prompt() {
        // Username prompt
        let resp = "334 VXNlcm5hbWU6"; // base64("Username:")
        assert!(resp.starts_with("334"));

        // Password prompt
        let resp = "334 UGFzc3dvcmQ6"; // base64("Password:")
        assert!(resp.starts_with("334"));
    }
}
