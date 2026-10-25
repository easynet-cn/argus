//! 凭证管理 API

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::credential::{
    self, AuthResult, AuthType, Entity as CredentialEntity, Protocol,
};
use argus_bruteforce::protocol::ProtocolConnector;
use crate::state::AppState;

// ==================== 请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub ip: String,
    pub protocol: String,
    pub port: i32,
    pub auth_type: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_username: Option<String>,
    pub enable_password: Option<String>,
    pub web_url: Option<String>,
    pub api_key: Option<String>,
    pub encoding: Option<String>,
    pub asset_id: Option<String>,
    pub asset_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCredentialRequest {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub auth_type: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_username: Option<String>,
    pub enable_password: Option<String>,
    pub web_url: Option<String>,
    pub api_key: Option<String>,
    pub encoding: Option<String>,
    pub asset_id: Option<String>,
    pub asset_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub ip: Option<String>,
    pub protocol: Option<String>,
}

// ==================== 响应结构（密码脱敏）====================

/// 凭证响应（密码字段已脱敏）
#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub protocol: String,
    pub port: i32,
    pub auth_type: String,
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub enable_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_password: Option<String>,
    pub web_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    pub encoding: Option<String>,
    pub auth_result: Option<String>,
    pub last_auth_at: Option<chrono::DateTime<chrono::Utc>>,
    pub asset_id: Option<String>,
    pub asset_type: Option<String>,
    pub error_reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// 将密码字段脱敏：有值则返回 "******"，无值则 None
fn mask_secret(secret: &Option<String>) -> Option<String> {
    match secret {
        Some(_) => Some("******".to_string()),
        None => None,
    }
}

impl From<credential::Model> for CredentialResponse {
    fn from(m: credential::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            ip: m.ip,
            protocol: protocol_to_str(&m.protocol),
            port: m.port,
            auth_type: auth_type_to_str(&m.auth_type),
            username: m.username,
            password: mask_secret(&m.password),
            enable_username: m.enable_username,
            enable_password: mask_secret(&m.enable_password),
            web_url: m.web_url,
            api_key: mask_secret(&m.api_key),
            encoding: m.encoding,
            auth_result: m.auth_result.as_ref().map(auth_result_to_str),
            last_auth_at: m.last_auth_at,
            asset_id: m.asset_id,
            asset_type: m.asset_type,
            error_reason: m.error_reason,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

// ==================== 枚举转换辅助 ====================

fn parse_protocol(s: &str) -> Protocol {
    match s {
        "ssh" => Protocol::Ssh,
        "telnet" => Protocol::Telnet,
        "smb" => Protocol::Smb,
        "rdp" => Protocol::Rdp,
        "http" => Protocol::Http,
        "winrm" => Protocol::Winrm,
        "pop" => Protocol::Pop,
        "ftp" => Protocol::Ftp,
        "snmp" => Protocol::Snmp,
        _ => Protocol::Ssh,
    }
}

fn protocol_to_str(p: &Protocol) -> String {
    match p {
        Protocol::Ssh => "ssh",
        Protocol::Telnet => "telnet",
        Protocol::Smb => "smb",
        Protocol::Rdp => "rdp",
        Protocol::Http => "http",
        Protocol::Winrm => "winrm",
        Protocol::Pop => "pop",
        Protocol::Ftp => "ftp",
        Protocol::Snmp => "snmp",
    }
    .to_string()
}

fn parse_auth_type(s: &str) -> AuthType {
    match s {
        "key" => AuthType::Key,
        _ => AuthType::Password,
    }
}

fn auth_type_to_str(a: &AuthType) -> String {
    match a {
        AuthType::Password => "password",
        AuthType::Key => "key",
    }
    .to_string()
}

fn auth_result_to_str(a: &AuthResult) -> String {
    match a {
        AuthResult::Success => "success",
        AuthResult::Failed => "failed",
        AuthResult::Unknown => "unknown",
    }
    .to_string()
}

// ==================== API 处理函数 ====================

/// 创建凭证 POST /api/v1/credentials
pub async fn create_credential(
    data: web::Data<AppState>,
    body: web::Json<CreateCredentialRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let protocol = parse_protocol(&body.protocol);
    let auth_type = body
        .auth_type
        .as_deref()
        .map(parse_auth_type)
        .unwrap_or(AuthType::Password);

    let new = credential::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        ip: Set(body.ip.clone()),
        protocol: Set(protocol),
        port: Set(body.port),
        auth_type: Set(auth_type),
        username: Set(body.username.clone()),
        password: Set(argus_core::crypto::encrypt_opt(body.password.clone())),
        enable_username: Set(body.enable_username.clone()),
        enable_password: Set(argus_core::crypto::encrypt_opt(body.enable_password.clone())),
        web_url: Set(body.web_url.clone()),
        api_key: Set(argus_core::crypto::encrypt_opt(body.api_key.clone())),
        encoding: Set(body.encoding.clone().or_else(|| Some("UTF-8".to_string()))),
        auth_result: Set(None),
        last_auth_at: Set(None),
        asset_id: Set(body.asset_id.clone()),
        asset_type: Set(body.asset_type.clone()),
        error_reason: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(c) => HttpResponse::Created().json(CredentialResponse::from(c)),
        Err(e) => {
            tracing::error!("创建凭证失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 凭证列表 GET /api/v1/credentials
pub async fn list_credentials(
    data: web::Data<AppState>,
    query: web::Query<CredentialListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = CredentialEntity::find();
    if let Some(ip) = &query.ip {
        q = q.filter(credential::Column::Ip.contains(ip.as_str()));
    }
    if let Some(p) = &query.protocol {
        q = q.filter(credential::Column::Protocol.eq(parse_protocol(p)));
    }

    match q
        .order_by_desc(credential::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let resp: Vec<CredentialResponse> =
                items.into_iter().map(CredentialResponse::from).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "items": resp,
                "page": page,
                "page_size": page_size,
            }))
        }
        Err(e) => {
            tracing::error!("查询凭证列表失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 凭证详情 GET /api/v1/credentials/{id}
pub async fn get_credential(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match CredentialEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(c)) => HttpResponse::Ok().json(CredentialResponse::from(c)),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "凭证未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新凭证 PUT /api/v1/credentials/{id}
pub async fn update_credential(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateCredentialRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let c = match CredentialEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "凭证未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: credential::ActiveModel = c.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.ip { active.ip = Set(v.clone()); }
    if let Some(v) = &body.protocol { active.protocol = Set(parse_protocol(v)); }
    if let Some(v) = body.port { active.port = Set(v); }
    if let Some(v) = &body.auth_type { active.auth_type = Set(parse_auth_type(v)); }
    if let Some(v) = &body.username { active.username = Set(Some(v.clone())); }
    if let Some(v) = &body.password { active.password = Set(argus_core::crypto::encrypt_opt(Some(v.clone()))); }
    if let Some(v) = &body.enable_username { active.enable_username = Set(Some(v.clone())); }
    if let Some(v) = &body.enable_password { active.enable_password = Set(argus_core::crypto::encrypt_opt(Some(v.clone()))); }
    if let Some(v) = &body.web_url { active.web_url = Set(Some(v.clone())); }
    if let Some(v) = &body.api_key { active.api_key = Set(argus_core::crypto::encrypt_opt(Some(v.clone()))); }
    if let Some(v) = &body.encoding { active.encoding = Set(Some(v.clone())); }
    if let Some(v) = &body.asset_id { active.asset_id = Set(Some(v.clone())); }
    if let Some(v) = &body.asset_type { active.asset_type = Set(Some(v.clone())); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(CredentialResponse::from(updated)),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除凭证 DELETE /api/v1/credentials/{id}
pub async fn delete_credential(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match CredentialEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "凭证未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 批量删除凭证 POST /api/v1/credentials/batch-delete
#[derive(Debug, Deserialize)]
pub struct CredentialBatchDeleteRequest {
    pub ids: Vec<String>,
}

pub async fn batch_delete_credentials(
    data: web::Data<AppState>,
    body: web::Json<CredentialBatchDeleteRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let mut deleted = 0usize;
    for id in &body.ids {
        if let Ok(res) = CredentialEntity::delete_by_id(id.clone()).exec(&data.db).await {
            if res.rows_affected > 0 { deleted += 1; }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted }))
}

/// 验证凭证 POST /api/v1/credentials/{id}/verify
///
/// 调用对应协议连接器进行登录验证，返回验证结果并更新凭证状态。
pub async fn verify_credential(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let cred = match CredentialEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "凭证未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let (success, message) = verify_with_protocol(&cred).await;

    // 更新认证结果
    let mut active: credential::ActiveModel = cred.clone().into();
    let result = if success { AuthResult::Success } else { AuthResult::Failed };
    active.auth_result = Set(Some(result));
    active.last_auth_at = Set(Some(chrono::Utc::now()));
    active.updated_at = Set(chrono::Utc::now());
    let _ = active.update(&data.db).await;

    HttpResponse::Ok().json(serde_json::json!({
        "id": cred.id,
        "success": success,
        "result": if success { "success" } else { "failed" },
        "message": message,
    }))
}

/// 使用对应协议连接器执行验证
pub(crate) async fn verify_with_protocol(cred: &credential::Model) -> (bool, String) {
    use argus_bruteforce::types::{Credential as BfCredential, Protocol as BfProtocol};

    // 映射凭证协议到爆破协议
    let bf_protocol = match cred.protocol {
        Protocol::Ssh => Some(BfProtocol::Ssh),
        Protocol::Telnet => Some(BfProtocol::Telnet),
        Protocol::Smb => Some(BfProtocol::Smb),
        Protocol::Rdp => Some(BfProtocol::Rdp),
        Protocol::Http => Some(BfProtocol::HttpBasic),
        Protocol::Ftp => Some(BfProtocol::Ftp),
        Protocol::Pop => Some(BfProtocol::Pop3),
        Protocol::Snmp => Some(BfProtocol::Snmp),
        Protocol::Winrm => None, // 暂无 winrm 连接器
    };

    let username = cred.username.clone().unwrap_or_default();
    let password = argus_core::crypto::decrypt_opt(cred.password.clone()).unwrap_or_default();
    let bf_cred = BfCredential::new(username, password);

    match bf_protocol {
        Some(protocol) => {
            let connector = create_bf_connector(protocol);
            let port = cred.port as u16;
            match connector.login(&cred.ip, port, &bf_cred, 5000).await {
                Ok(success) => {
                    if success {
                        (true, "认证成功".to_string())
                    } else {
                        (false, "认证失败：用户名或密码错误".to_string())
                    }
                }
                Err(e) => (false, format!("验证失败: {e}")),
            }
        }
        None => {
            // 无专用连接器时，降级为 TCP 连通性检测
            tcp_connectivity_check(&cred.ip, cred.port as u16).await
        }
    }
}

/// 创建爆破协议连接器
fn create_bf_connector(protocol: argus_bruteforce::types::Protocol) -> Box<dyn ProtocolConnector> {
    use argus_bruteforce::protocol::*;
    use argus_bruteforce::types::Protocol as P;
    match protocol {
        P::Ssh => Box::new(ssh::SshConnector),
        P::Telnet => Box::new(telnet::TelnetConnector),
        P::Smb => Box::new(smb::SmbConnector),
        P::Rdp => Box::new(rdp::RdpConnector),
        P::HttpBasic => Box::new(http_basic::HttpBasicConnector),
        P::Ftp => Box::new(ftp::FtpConnector),
        P::Pop3 => Box::new(pop3::Pop3Connector),
        P::Snmp => Box::new(snmp::SnmpConnector),
        other => Box::new(UnsupportedConnector::new(other)),
    }
}

/// TCP 连通性检测（降级方案）
async fn tcp_connectivity_check(ip: &str, port: u16) -> (bool, String) {
    use tokio::time::{timeout, Duration};
    let addr = format!("{ip}:{port}");
    match timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => (true, "TCP 连接成功（协议认证未实现，仅连通性验证）".to_string()),
        Ok(Err(e)) => (false, format!("TCP 连接失败: {e}")),
        Err(_) => (false, "TCP 连接超时".to_string()),
    }
}
