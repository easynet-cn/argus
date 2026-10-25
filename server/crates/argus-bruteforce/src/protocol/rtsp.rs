//! RTSP 协议连接器
//!
//! 真实实现 RTSP 认证爆破（RFC 2326）：
//! 1. TCP 连接到目标端口（默认 554）
//! 2. 发送 DESCRIBE 请求探测认证方式
//! 3. 401 + WWW-Authenticate: Basic → 重发带 Basic 认证头
//! 4. 401 + WWW-Authenticate: Digest → 按 RFC 2069 计算 response 重发
//! 5. 200 OK = 认证成功，401 = 认证失败

use async_trait::async_trait;
use base64::Engine;
use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct RtspConnector;

#[async_trait]
impl ProtocolConnector for RtspConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Rtsp
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
        let url = format!("rtsp://{host}:{port}/");

        // 1. TCP 连接
        let mut stream = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|e| format!("RTSP 连接超时: {e}"))?
            .map_err(|e| format!("RTSP 连接失败: {e}"))?;

        // 2. 发送无认证 DESCRIBE 探测
        let probe = format!(
            "DESCRIBE {url} RTSP/1.0\r\n\
             CSeq: 1\r\n\
             User-Agent: Argus-Scanner/1.0\r\n\
             Accept: application/sdp\r\n\
             \r\n"
        );
        stream
            .write_all(probe.as_bytes())
            .await
            .map_err(|e| format!("RTSP 发送失败: {e}"))?;

        let resp = read_response(&mut stream, dur).await?;

        // 3. 解析状态码
        let status = parse_status_code(&resp).unwrap_or(0);

        // 200 = 无需认证直接成功（不太可能，但处理）
        if status == 200 {
            return Ok(true);
        }

        // 非 401 → 无法认证
        if status != 401 {
            return Ok(false);
        }

        // 4. 解析 WWW-Authenticate 头
        let auth_header = extract_header(&resp, "WWW-Authenticate");

        let auth_header = match auth_header {
            Some(h) => h,
            None => return Ok(false),
        };

        // 5. 构造认证请求
        let auth_value = if auth_header.trim().to_lowercase().starts_with("basic") {
            // Basic 认证
            let credentials = format!("{}:{}", credential.username, credential.password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&credentials);
            format!("Basic {encoded}")
        } else if auth_header.trim().to_lowercase().starts_with("digest") {
            // Digest 认证 (RFC 2069)
            let params = parse_digest_params(&auth_header);
            let realm = params.get("realm").cloned().unwrap_or_default();
            let nonce = params.get("nonce").cloned().unwrap_or_default();

            let ha1 = hex_md5(&format!("{}:{}:{}", credential.username, realm, credential.password));
            let ha2 = hex_md5(&format!("DESCRIBE:{url}"));
            let response = hex_md5(&format!("{ha1}:{nonce}:{ha2}"));
            format!(
                "Digest username=\"{}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{url}\", response=\"{response}\"",
                credential.username
            )
        } else {
            return Ok(false);
        };

        // 6. 发送带认证的 DESCRIBE
        let auth_req = format!(
            "DESCRIBE {url} RTSP/1.0\r\n\
             CSeq: 2\r\n\
             User-Agent: Argus-Scanner/1.0\r\n\
             Accept: application/sdp\r\n\
             Authorization: {auth_value}\r\n\
             \r\n"
        );
        stream
            .write_all(auth_req.as_bytes())
            .await
            .map_err(|e| format!("RTSP 认证请求发送失败: {e}"))?;

        let auth_resp = read_response(&mut stream, dur).await?;
        let auth_status = parse_status_code(&auth_resp).unwrap_or(0);

        // 200 = 认证成功，401/403 = 认证失败
        Ok(auth_status == 200)
    }
}

/// 读取 RTSP 响应（状态行 + 头 + 可选 body）
async fn read_response(stream: &mut TcpStream, dur: Duration) -> Result<String, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1];

    loop {
        match timeout(dur, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                buf.push(tmp[0]);
            }
            Ok(Err(e)) => return Err(format!("RTSP 读取失败: {e}")),
            Err(_) => return Err("RTSP 读取超时".to_string()),
        }

        // 检测 \r\n\r\n 头结束
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// 从响应中解析 HTTP 状态码
fn parse_status_code(resp: &str) -> Option<u16> {
    let first_line = resp.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// 提取指定 header 的值（不区分大小写）
fn extract_header(resp: &str, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    for line in resp.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_lowercase() == name_lower {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// 解析 Digest 认证参数 (key="value" 格式)
fn parse_digest_params(header: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    // 去掉 "Digest " 前缀
    let rest = header
        .trim()
        .strip_prefix("Digest")
        .or_else(|| header.trim().strip_prefix("digest"))
        .unwrap_or(header)
        .trim();

    // 按 , 分割，但注意 value 中可能包含逗号（此处简化处理）
    for part in rest.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim().trim_matches('"').to_string();
            params.insert(key, val);
        }
    }
    params
}

/// 计算 MD5 十六进制摘要
fn hex_md5(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtsp_protocol() {
        assert_eq!(RtspConnector.protocol(), Protocol::Rtsp);
    }

    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code("RTSP/1.0 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_code("RTSP/1.0 401 Unauthorized\r\n"), Some(401));
        assert_eq!(parse_status_code("invalid"), None);
    }

    #[test]
    fn test_extract_header() {
        let resp = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"test\"\r\n\r\n";
        assert_eq!(
            extract_header(resp, "WWW-Authenticate"),
            Some("Basic realm=\"test\"".to_string())
        );
        assert_eq!(extract_header(resp, "cseq"), Some("1".to_string()));
    }

    #[test]
    fn test_parse_digest_params() {
        let header = "Digest realm=\"cam\", nonce=\"abc123\"";
        let params = parse_digest_params(header);
        assert_eq!(params.get("realm"), Some(&"cam".to_string()));
        assert_eq!(params.get("nonce"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_hex_md5() {
        let result = hex_md5("admin:realm:password");
        assert_eq!(result.len(), 32);
    }
}
