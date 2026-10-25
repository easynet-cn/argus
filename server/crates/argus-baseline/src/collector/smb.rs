//! SMB/WinRM 远程采集器（Windows 配置采集）
//!
//! 通过 WinRM 协议（HTTP 5985 / HTTPS 5986）远程执行命令采集 Windows 系统配置。
//! WinRM 基于 WS-Management 标准，通过 SOAP over HTTP 交互：
//!   1. Create Shell（创建远程命令外壳）
//!   2. Send Command（发送 cmd /c "命令"）
//!   3. Receive Output（轮询接收 base64 编码的 stdout）
//!   4. Delete Shell（清理）
//!
//! 要求目标 Windows 主机已启用 WinRM 远程管理（Enable-PSRemoting）。

use crate::collector::Collector;
use crate::types::{CollectItem, CollectMethod};
use async_trait::async_trait;
use base64::Engine;
use regex::Regex;

/// WinRM 采集器（Windows 远程命令执行）
pub struct SmbCollector {
    /// 使用 HTTPS（5986）还是 HTTP（5985）
    use_tls: bool,
}

impl SmbCollector {
    pub fn new() -> Self {
        Self { use_tls: false }
    }

    pub fn with_tls(use_tls: bool) -> Self {
        Self { use_tls }
    }

    /// 构建 WinRM 端点 URL
    fn endpoint(&self, host: &str, port: u16) -> String {
        let scheme = if self.use_tls { "https" } else { "http" };
        let default_port = if self.use_tls { 5986 } else { 5985 };
        let p = if port == 0 { default_port } else { port };
        format!("{scheme}://{host}:{p}/wsman")
    }

    /// 生成 SOAP 信封
    fn envelope(header: &str, body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
  xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <env:Header>{header}</env:Header>
  <env:Body>{body}</env:Body>
</env:Envelope>"#
        )
    }

    /// 公共 SOAP 头
    fn common_headers(url: &str, action: &str) -> String {
        let msg_id = format!("uuid:{}", uuid::Uuid::new_v4());
        format!(
            r#"<a:To>{url}</a:To>
<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
<a:Action>{action}</a:Action>
<a:MessageID>{msg_id}</a:MessageID>
<w:OperationTimeout>PT60S</w:OperationTimeout>
<w:Locale xml:lang="en-US"/>
<p:DataLocale xml:lang="en-US"/>
<w:MaxEnvelopeSize>153600</w:MaxEnvelopeSize>"#
        )
    }

    /// SelectorSet（关联 ShellId）
    fn selector_set(shell_id: &str) -> String {
        format!(r#"<w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>"#)
    }

    /// 发送 SOAP 请求并返回响应体
    async fn send_soap(
        client: &reqwest::Client,
        url: &str,
        username: &str,
        password: &str,
        body: String,
    ) -> Result<String, String> {
        let resp = client
            .post(url)
            .header("Content-Type", "application/soap+xml;charset=UTF-8")
            .basic_auth(username, Some(password))
            .body(body)
            .send()
            .await
            .map_err(|e| format!("WinRM 请求失败: {e}"))?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;
        if !status.is_success() {
            // 截取错误原因
            let re = Regex::new(r"<faultstring[^>]*>(.*?)</faultstring>").unwrap();
            let reason = re
                .captures(&text)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_else(|| text.chars().take(200).collect());
            return Err(format!("WinRM 返回 {}: {reason}", status.as_u16()));
        }
        Ok(text)
    }

    /// 1. 创建 Shell
    async fn create_shell(
        &self,
        client: &reqwest::Client,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<String, String> {
        let action = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
        let header = format!(
            "{}\n<w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>",
            Self::common_headers(url, action)
        );
        let body = r#"<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:InputStream>stdin</rsp:InputStream><rsp:OutputStream>stdout stderr</rsp:OutputStream><rsp:IdleTimeout>PT7200S</rsp:IdleTimeout></rsp:Shell>"#;
        let envelope = Self::envelope(&header, body);

        let resp = Self::send_soap(client, url, username, password, envelope).await?;

        // 从响应中提取 ShellId
        let re = Regex::new(r"ShellId[^>]*>([^<]+)<").unwrap();
        re.captures(&resp)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "WinRM Create 未返回 ShellId".to_string())
    }

    /// 2. 发送命令（cmd /c "command"）并返回 CommandId
    async fn send_command(
        &self,
        client: &reqwest::Client,
        url: &str,
        username: &str,
        password: &str,
        shell_id: &str,
        command: &str,
    ) -> Result<String, String> {
        let action = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
        let header = format!(
            "{}\n{}",
            Self::common_headers(url, action),
            Self::selector_set(shell_id)
        );
        // 对命令参数中的 XML 特殊字符转义
        let escaped = command
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let body = format!(
            r#"<rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:Command>cmd</rsp:Command><rsp:Arguments>/c {escaped}</rsp:Arguments></rsp:CommandLine>"#
        );
        let envelope = Self::envelope(&header, &body);

        let resp = Self::send_soap(client, url, username, password, envelope).await?;

        // 提取 CommandId
        let re = Regex::new(r"CommandId[^>]*>([^<]+)<").unwrap();
        re.captures(&resp)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| "WinRM Command 未返回 CommandId".to_string())
    }

    /// 3. 接收命令输出（轮询直到完成，返回解码后的 stdout）
    async fn receive_output(
        &self,
        client: &reqwest::Client,
        url: &str,
        username: &str,
        password: &str,
        shell_id: &str,
        _command_id: &str,
    ) -> Result<String, String> {
        let action = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
        let header = format!(
            "{}\n{}",
            Self::common_headers(url, action),
            Self::selector_set(shell_id)
        );
        let body = r#"<rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:DesiredStream>stdout stderr</rsp:DesiredStream></rsp:Receive>"#;
        let envelope = Self::envelope(&header, body);

        let mut stdout_buf: Vec<u8> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();

        // 轮询接收（最多 30 次，每次由 OperationTimeout 控制）
        let stream_re = Regex::new(r#"<Stream[^>]*Name="stdout"[^>]*>(.*?)</Stream>"#).unwrap();
        let stderr_stream_re = Regex::new(r#"<Stream[^>]*Name="stderr"[^>]*>(.*?)</Stream>"#).unwrap();
        let done_re = Regex::new(r"CommandState/[^>]*Done").unwrap();

        for _ in 0..30 {
            let resp = Self::send_soap(client, url, username, password, envelope.clone()).await?;

            // 解码 stdout base64 片段
            for cap in stream_re.captures_iter(&resp) {
                let b64 = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                if !b64.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        stdout_buf.extend_from_slice(&decoded);
                    }
                }
            }
            // 解码 stderr base64 片段
            for cap in stderr_stream_re.captures_iter(&resp) {
                let b64 = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
                if !b64.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        stderr_buf.extend_from_slice(&decoded);
                    }
                }
            }

            // 命令完成则退出轮询
            if done_re.is_match(&resp) {
                break;
            }
            // 未完成则短暂等待后再次接收
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        let mut output = String::from_utf8_lossy(&stdout_buf).to_string();
        if output.is_empty() && !stderr_buf.is_empty() {
            output = String::from_utf8_lossy(&stderr_buf).to_string();
        }
        Ok(output)
    }

    /// 4. 删除 Shell（清理资源）
    async fn delete_shell(
        &self,
        client: &reqwest::Client,
        url: &str,
        username: &str,
        password: &str,
        shell_id: &str,
    ) -> Result<(), String> {
        let action = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
        let header = format!(
            "{}\n{}",
            Self::common_headers(url, action),
            Self::selector_set(shell_id)
        );
        let envelope = Self::envelope(&header, "");
        Self::send_soap(client, url, username, password, envelope).await?;
        Ok(())
    }
}

impl Default for SmbCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for SmbCollector {
    fn name(&self) -> &str {
        "smb_collector"
    }

    fn method(&self) -> CollectMethod {
        CollectMethod::Smb
    }

    /// 通过 WinRM 远程执行采集命令
    ///
    /// 流程：Create Shell → Send Command → Receive Output → Delete Shell
    /// 要求目标 Windows 主机已启用 WinRM（Enable-PSRemoting）且允许 Basic 认证。
    async fn collect_one(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        item: &CollectItem,
        timeout_ms: u64,
    ) -> Result<String, String> {
        tracing::info!(
            "WinRM 采集: host={}:{}, command={}",
            host,
            port,
            item.command
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms.max(5000)))
            .danger_accept_invalid_certs(true) // 内网自签名证书
            .build()
            .map_err(|e| format!("构建 HTTP 客户端失败: {e}"))?;

        let url = self.endpoint(host, port);

        // 1. 创建 Shell
        let shell_id = self
            .create_shell(&client, &url, username, password)
            .await
            .map_err(|e| format!("WinRM 创建 Shell 失败: {e}"))?;

        // 2. 发送命令
        let command_id = self
            .send_command(&client, &url, username, password, &shell_id, &item.command)
            .await
            .map_err(|e| {
                let _ = self.delete_shell(&client, &url, username, password, &shell_id); // 尽力清理
                format!("WinRM 发送命令失败: {e}")
            })?;

        // 3. 接收输出
        let output = self
            .receive_output(&client, &url, username, password, &shell_id, &command_id)
            .await;

        // 4. 删除 Shell（无论输出是否成功都清理）
        let _ = self.delete_shell(&client, &url, username, password, &shell_id).await;

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_name() {
        let c = SmbCollector::new();
        assert_eq!(c.name(), "smb_collector");
        assert_eq!(c.method(), CollectMethod::Smb);
    }

    #[test]
    fn test_with_tls() {
        let c = SmbCollector::with_tls(true);
        assert!(c.use_tls);
        assert_eq!(c.endpoint("host", 0), "https://host:5986/wsman");
    }

    #[test]
    fn test_endpoint_http() {
        let c = SmbCollector::new();
        assert_eq!(c.endpoint("192.168.1.1", 0), "http://192.168.1.1:5985/wsman");
        assert_eq!(c.endpoint("192.168.1.1", 5985), "http://192.168.1.1:5985/wsman");
    }

    #[test]
    fn test_endpoint_custom_port() {
        let c = SmbCollector::new();
        assert_eq!(c.endpoint("host", 7000), "http://host:7000/wsman");
    }

    #[test]
    fn test_endpoint_https() {
        let c = SmbCollector::with_tls(true);
        assert_eq!(c.endpoint("host", 0), "https://host:5986/wsman");
    }

    #[test]
    fn test_envelope_structure() {
        let env = SmbCollector::envelope("HDR", "BODY");
        assert!(env.contains("<env:Envelope"));
        assert!(env.contains("<env:Header>HDR</env:Header>"));
        assert!(env.contains("<env:Body>BODY</env:Body>"));
        assert!(env.contains("xml version"));
    }

    #[test]
    fn test_selector_set() {
        let s = SmbCollector::selector_set("shell-123");
        assert!(s.contains(r#"Name="ShellId""#));
        assert!(s.contains("shell-123"));
    }

    #[test]
    fn test_common_headers() {
        let h = SmbCollector::common_headers("http://h/wsman", "Create");
        assert!(h.contains("http://h/wsman"));
        assert!(h.contains("Create"));
        assert!(h.contains("uuid:"));
    }
}
