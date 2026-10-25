//! Telnet 远程登录采集器
//!
//! 用于网络设备（路由器/交换机/防火墙）配置采集
//! 通过 Telnet 协议登录后执行命令采集配置

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::collector::Collector;
use crate::types::{CollectItem, CollectMethod};
use async_trait::async_trait;

pub struct TelnetCollector {
    /// 读取等待间隔（毫秒）
    read_interval_ms: u64,
}

impl TelnetCollector {
    pub fn new() -> Self {
        Self {
            read_interval_ms: 200,
        }
    }
}

impl Default for TelnetCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for TelnetCollector {
    fn name(&self) -> &str {
        "telnet_collector"
    }

    fn method(&self) -> CollectMethod {
        CollectMethod::Telnet
    }

    /// Telnet 采集流程：建立连接 → 等待 login 提示 → 发送用户名 → 等待 Password 提示 → 发送密码
    /// → 等待提示符 → 发送命令 → 收集输出 → 退出
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

        // 建立 TCP 连接
        let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(format!("Telnet 连接失败: {e}")),
            Err(_) => return Err("Telnet 连接超时".to_string()),
        };

        // 1. 等待 login 提示
        let _ = read_until(&mut stream, "ogin:", dur).await?;

        // 2. 发送用户名
        write_line(&mut stream, username).await?;

        // 3. 等待 Password 提示
        let _ = read_until(&mut stream, "assword:", dur).await?;

        // 4. 发送密码
        write_line(&mut stream, password).await?;

        // 5. 等待命令提示符（通常为 #、>、$ 或设备名）
        let prompt = read_until_prompt(&mut stream, dur).await?;

        // 6. 关闭分页（可选，部分设备支持）
        let _ = write_line(&mut stream, "terminal length 0").await;
        let _ = read_until(&mut stream, &prompt, dur).await;

        // 7. 执行采集命令
        write_line(&mut stream, &item.command).await?;

        // 8. 收集输出直到提示符
        let output = read_until(&mut stream, &prompt, dur).await
            .map(|s| {
                // 去掉首尾的命令回显和提示符
                let trimmed = s.trim();
                // 移除开头命令回显行
                let without_cmd = trimmed
                    .lines()
                    .skip_while(|l| l.contains(&item.command))
                    .collect::<Vec<_>>()
                    .join("\n");
                without_cmd.trim().to_string()
            })
            .unwrap_or_default();

        // 9. 退出
        let _ = write_line(&mut stream, "exit").await;

        Ok(output)
    }
}

/// 读取数据直到匹配指定关键词
async fn read_until(
    stream: &mut TcpStream,
    keyword: &str,
    dur: Duration,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + dur;
    let mut buf = vec![0u8; 4096];
    let mut accumulated = String::new();

    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::from_millis(0));
        if remaining.is_zero() {
            return Err(format!("读取超时，未找到关键词: {keyword}"));
        }

        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Err("连接已关闭".to_string()),
            Ok(Ok(n)) => {
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    accumulated.push_str(text);
                    if accumulated.contains(keyword) {
                        return Ok(accumulated);
                    }
                }
            }
            Ok(Err(e)) => return Err(format!("读取失败: {e}")),
            Err(_) => return Err(format!("读取超时，未找到关键词: {keyword}")),
        }
    }
}

/// 读取直到出现命令提示符（#、>、$）
async fn read_until_prompt(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + dur;
    let mut buf = vec![0u8; 4096];
    let mut accumulated = String::new();

    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::from_millis(0));
        if remaining.is_zero() {
            // 超时返回当前累积内容，使用 # 作为默认提示符
            return Ok("#".to_string());
        }

        match timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok("#".to_string()),
            Ok(Ok(n)) => {
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    accumulated.push_str(text);
                    // 检查是否出现常见提示符
                    if accumulated.ends_with('#')
                        || accumulated.ends_with('>')
                        || accumulated.ends_with('$')
                        || accumulated.ends_with("\r\n#")
                        || accumulated.ends_with("\r\n>")
                    {
                        // 提取最后一个提示符
                        if let Some(ch) = accumulated.chars().rev().find(|c| {
                            *c == '#' || *c == '>' || *c == '$'
                        }) {
                            return Ok(ch.to_string());
                        }
                    }
                }
            }
            Ok(Err(_)) => return Ok("#".to_string()),
            Err(_) => return Ok("#".to_string()),
        }
    }
}

/// 发送一行数据（带 CRLF）
async fn write_line(stream: &mut TcpStream, line: &str) -> Result<(), String> {
    let data = format!("{line}\r\n");
    stream
        .write_all(data.as_bytes())
        .await
        .map_err(|e| format!("写入失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_name() {
        let c = TelnetCollector::new();
        assert_eq!(c.name(), "telnet_collector");
        assert_eq!(c.method(), CollectMethod::Telnet);
    }
}
