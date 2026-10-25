//! ONVIF 协议连接器
//!
//! 真实实现 ONVIF 设备认证爆破（WS-Security UsernameToken）：
//! 1. POST SOAP 请求到 /onvif/device_service
//! 2. SOAP Header 含 wsse:UsernameToken
//!    - Username = 凭证用户名
//!    - Password = base64(sha1(nonce_raw + created + password))  (PasswordDigest)
//!    - Nonce = base64(随机 16 字节)
//!    - Created = UTC ISO8601 时间戳
//! 3. 200 + 非 s:Fault = 认证成功

use async_trait::async_trait;
use base64::Engine;
use rand::RngExt;
use sha1::{Digest, Sha1};
use tokio::time::{timeout, Duration};

use crate::protocol::ProtocolConnector;
use crate::types::{Credential, Protocol};

pub struct OnvifConnector;

#[async_trait]
impl ProtocolConnector for OnvifConnector {
    fn protocol(&self) -> Protocol {
        Protocol::Onvif
    }

    async fn login(
        &self,
        host: &str,
        port: u16,
        credential: &Credential,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let dur = Duration::from_millis(timeout_ms);
        let scheme = if port == 443 { "https" } else { "http" };
        let url = format!("{scheme}://{host}:{port}/onvif/device_service");

        // 生成 UsernameToken
        let token = build_username_token(credential);
        let body = build_soap_body(&token);

        // 构造 HTTP 客户端
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(dur)
            .build()
            .map_err(|e| format!("HTTP 客户端构建失败: {e}"))?;

        let req = client
            .post(&url)
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .header("User-Agent", "Argus-Scanner/1.0")
            .body(body);

        let resp = timeout(dur, req.send())
            .await
            .map_err(|e| format!("ONVIF 请求超时: {e}"))?
            .map_err(|e| format!("ONVIF 请求失败: {e}"))?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();

        // 401/403 = 认证失败
        if status == 401 || status == 403 {
            return Ok(false);
        }

        // 非 200 = 无法判断，返回 false
        if status != 200 {
            return Ok(false);
        }

        // 200 + 含 s:Fault = 认证失败（ONVIF 返回 SOAP Fault 表示认证失败）
        // 200 + 不含 s:Fault = 认证成功
        if text.to_lowercase().contains("fault") {
            return Ok(false);
        }

        Ok(true)
    }
}

/// WS-Security UsernameToken 结构
pub struct UsernameToken {
    pub username: String,
    pub password_digest: String,
    pub nonce_b64: String,
    pub created: String,
}

/// 构造 UsernameToken
///
/// PasswordDigest = base64(sha1(nonce_raw + created + password))
/// Nonce = base64(随机 16 字节)
/// Created = UTC ISO8601
fn build_username_token(credential: &Credential) -> UsernameToken {
    let nonce_raw: [u8; 16] = rand::rng().random();
    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // PasswordDigest = sha1(nonce + created + password) -> base64
    let mut hasher = Sha1::new();
    hasher.update(&nonce_raw);
    hasher.update(created.as_bytes());
    hasher.update(credential.password.as_bytes());
    let digest = hasher.finalize();
    let password_digest = base64::engine::general_purpose::STANDARD.encode(digest);

    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_raw);

    UsernameToken {
        username: credential.username.clone(),
        password_digest,
        nonce_b64,
        created,
    }
}

/// 构造 SOAP 请求体（GetDeviceInformation）
fn build_soap_body(token: &UsernameToken) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>"#,
        username = token.username,
        password_digest = token.password_digest,
        nonce_b64 = token.nonce_b64,
        created = token.created,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onvif_protocol() {
        assert_eq!(OnvifConnector.protocol(), Protocol::Onvif);
    }

    #[test]
    fn test_username_token_digest() {
        let cred = Credential::new("admin", "password");
        let token = build_username_token(&cred);
        // PasswordDigest 是 base64 编码的 20 字节 SHA1 = 28 字符
        assert_eq!(token.password_digest.len(), 28);
        // Nonce 是 base64 编码的 16 字节 = 24 字符
        assert_eq!(token.nonce_b64.len(), 24);
        // Created 包含 UTC 时间
        assert!(token.created.contains("T"));
    }

    #[test]
    fn test_soap_body_contains_username() {
        let cred = Credential::new("admin", "password");
        let token = build_username_token(&cred);
        let body = build_soap_body(&token);
        assert!(body.contains("admin"));
        assert!(body.contains("GetDeviceInformation"));
        assert!(body.contains("UsernameToken"));
    }

    #[test]
    fn test_soap_body_no_cleartext_password() {
        let cred = Credential::new("admin", "supersecret");
        let token = build_username_token(&cred);
        let body = build_soap_body(&token);
        // 明文密码不应出现在 SOAP body 中
        assert!(!body.contains("supersecret"));
    }
}
