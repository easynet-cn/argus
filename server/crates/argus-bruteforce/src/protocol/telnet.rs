//! Telnet 协议连接器
//!
//! 真实实现 Telnet 登录爆破：
//! 1. TCP 连接到目标端口（默认 23）
//! 2. 处理 Telnet IAC 协商（拒绝所有选项）
//! 3. 等待 "login:" / "Username:" 提示
//! 4. 发送用户名
//! 5. 等待 "Password:" 提示
//! 6. 发送密码
//! 7. 检查是否登录成功（无 "Login incorrect" / "Login failed"）

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct TelnetConnector;

#[async_trait]
impl ProtocolConnector for TelnetConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Telnet
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
            .map_err(|e| format!("Telnet 连接超时: {e}"))?
            .map_err(|e| format!("Telnet 连接失败: {e}"))?;

        // 2. 读取并处理 IAC 协商，同时等待 login 提示
        let data = read_until_pattern(&mut stream, dur, &["login:", "username:", "Login:"])
            .await?;

        // 3. 发送用户名
        stream
            .write_all(format!("{}\r\n", credential.username).as_bytes())
            .await
            .map_err(|e| format!("发送用户名失败: {e}"))?;

        // 4. 等待 Password 提示
        let _ = read_until_pattern(&mut stream, dur, &["password:", "Password:"]).await?;

        // 5. 发送密码
        stream
            .write_all(format!("{}\r\n", credential.password).as_bytes())
            .await
            .map_err(|e| format!("发送密码失败: {e}"))?;

        // 6. 读取响应，检查是否登录成功
        let resp = read_until_pattern(
            &mut stream,
            dur,
            &["incorrect", "failed", "$", "#", ">", "$ "],
        )
        .await
        .unwrap_or_default();

        let resp_lower = resp.to_lowercase();
        // 登录失败标志
        if resp_lower.contains("incorrect") || resp_lower.contains("failed") {
            return Ok(false);
        }

        // 登录成功标志（shell 提示符）
        if resp.ends_with('$') || resp.ends_with('#') || resp.ends_with('>')
            || resp.ends_with("$ ") || resp.ends_with("# ")
        {
            return Ok(true);
        }

        // 无法判断时返回 false
        Ok(false)
    }
}

/// 读取数据直到匹配指定模式之一
///
/// 同时处理 Telnet IAC（0xFF）协商命令：
/// 对所有 DO/DONT/WILL/WONT 回复 WONT/DONT（拒绝所有选项）
async fn read_until_pattern(
    stream: &mut TcpStream,
    dur: Duration,
    patterns: &[&str],
) -> Result<String, String> {
    let mut result = String::new();
    let mut buf = [0u8; 1];

    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Err("Telnet 连接已关闭".to_string()),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("Telnet 读取失败: {e}")),
            Err(_) => return Err("Telnet 读取超时".to_string()),
        }

        let b = buf[0];

        // Telnet IAC 处理
        if b == 0xFF {
            // 读取下一个字节（命令）
            match timeout(dur, stream.read(&mut buf)).await {
                Ok(Ok(_)) => {}
                _ => return Err("Telnet IAC 读取失败".to_string()),
            }
            let cmd = buf[0];

            match cmd {
                0xFB | 0xFC | 0xFD | 0xFE => {
                    // DO(0xFD), DONT(0xFE), WILL(0xFB), WONT(0xFC)
                    // 读取选项码
                    match timeout(dur, stream.read(&mut buf)).await {
                        Ok(Ok(_)) => {}
                        _ => return Err("Telnet 选项码读取失败".to_string()),
                    }
                    let _option = buf[0];
                    // 拒绝所有选项：对 DO/WILL 回复 WONT/DONT
                    let reply_cmd = match cmd {
                        0xFD => 0xFC, // DO -> WONT
                        0xFB => 0xFE, // WILL -> DONT
                        _ => 0x00,    // 其他不回复
                    };
                    if reply_cmd != 0x00 {
                        let _ = stream
                            .write_all(&[0xFF, reply_cmd, _option])
                            .await;
                    }
                }
                0xF4 => {
                    // Interrupt Process (IP)
                }
                _ => {}
            }
            continue;
        }

        // 普通字符
        if b == b'\r' || b == b'\n' || b == b'\t' || (b >= 0x20 && b < 0x7F) {
            result.push(b as char);
        }

        // 检查是否匹配模式
        let result_lower = result.to_lowercase();
        for pat in patterns {
            let pat_lower = pat.to_lowercase();
            if result_lower.contains(&pat_lower) {
                return Ok(result);
            }
        }

        // 防止无限读取
        if result.len() > 4096 {
            return Ok(result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telnet_protocol() {
        assert_eq!(TelnetConnector.protocol(), Protocol::Telnet);
    }
}
