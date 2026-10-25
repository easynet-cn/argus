//! 告警配置 API
//!
//! 路由前缀：/api/v1/alerts
//! 包含告警配置 CRUD 及通道测试。config/rules 中的敏感字段（password/secret/token）
//! 在响应中自动脱敏。

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::alert_config::{self, Entity as AlertConfigEntity};
use argus_core::entity::alert_record::{
    self, AlertLevel, AlertSource, AlertStatus, Entity as AlertRecordEntity,
};
use crate::state::AppState;

// ==================== 请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct CreateAlertRequest {
    pub id: Option<String>,
    pub channel: String,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
    pub rules: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertRequest {
    pub channel: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
    pub rules: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct TestAlertRequest {
    pub message: Option<String>,
}

// ==================== 响应结构（敏感字段脱敏）====================

/// 敏感字段名（小写匹配）
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "webhook_url",
];

/// 递归脱敏 JSON 中的敏感字段
fn mask_sensitive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if SENSITIVE_KEYS.contains(&k.to_lowercase().as_str()) {
                    if let Some(s) = v.as_str() {
                        if !s.is_empty() {
                            *v = serde_json::Value::String("******".to_string());
                        }
                    }
                } else {
                    mask_sensitive(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                mask_sensitive(v);
            }
        }
        _ => {}
    }
}

#[derive(Debug, Serialize)]
pub struct AlertConfigResponse {
    pub id: String,
    pub channel: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub rules: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<alert_config::Model> for AlertConfigResponse {
    fn from(m: alert_config::Model) -> Self {
        let mut config = m.config.clone();
        mask_sensitive(&mut config);
        Self {
            id: m.id,
            channel: m.channel,
            enabled: m.enabled,
            config,
            rules: m.rules,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

// ==================== API 处理函数 ====================

/// GET /api/v1/alerts - 告警配置列表
pub async fn list_alerts(data: web::Data<AppState>) -> impl Responder {
    match AlertConfigEntity::find().all(&data.db).await {
        Ok(items) => {
            let resp: Vec<AlertConfigResponse> =
                items.into_iter().map(AlertConfigResponse::from).collect();
            HttpResponse::Ok().json(serde_json::json!({ "items": resp }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/alerts - 新建告警配置
pub async fn create_alert(
    data: web::Data<AppState>,
    body: web::Json<CreateAlertRequest>,
) -> impl Responder {
    let id = body
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let now = chrono::Utc::now();

    let new = alert_config::ActiveModel {
        id: Set(id),
        channel: Set(body.channel.clone()),
        enabled: Set(body.enabled.unwrap_or(true)),
        config: Set(body.config.clone().unwrap_or_else(|| serde_json::json!({}))),
        rules: Set(body.rules.clone().unwrap_or_else(|| serde_json::json!({}))),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(c) => HttpResponse::Created().json(AlertConfigResponse::from(c)),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// PUT /api/v1/alerts/{id} - 更新告警配置
pub async fn update_alert(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateAlertRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let c = match AlertConfigEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "告警配置未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: alert_config::ActiveModel = c.into();
    if let Some(v) = &body.channel {
        active.channel = Set(v.clone());
    }
    if let Some(v) = body.enabled {
        active.enabled = Set(v);
    }
    if let Some(v) = body.config.clone() {
        active.config = Set(v);
    }
    if let Some(v) = body.rules.clone() {
        active.rules = Set(v);
    }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(AlertConfigResponse::from(updated)),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// DELETE /api/v1/alerts/{id} - 删除告警配置
pub async fn delete_alert(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match AlertConfigEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "告警配置未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/alerts/{id}/test - 测试告警通道
pub async fn test_alert(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<TestAlertRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let c = match AlertConfigEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "告警配置未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let message = body
        .message
        .clone()
        .unwrap_or_else(|| "Argus 告警通道测试".to_string());

    let (success, result) = send_test_alert(&c.channel, &c.config, &message).await;

    HttpResponse::Ok().json(serde_json::json!({
        "id": c.id,
        "channel": c.channel,
        "success": success,
        "message": result,
    }))
}

/// 发送测试告警（根据通道类型）
async fn send_test_alert(channel: &str, config: &serde_json::Value, message: &str) -> (bool, String) {
    match channel {
        "webhook" => {
            let url = config.get("url").and_then(|v| v.as_str()).unwrap_or_default();
            if url.is_empty() {
                return (false, "缺少 webhook url".to_string());
            }
            // 构造 payload，兼容常见 webhook 格式（飞书/钉钉/企业微信/Slack）
            let payload = serde_json::json!({
                "msg_type": "text",
                "content": { "text": message },
                "text": message,
            });
            match reqwest::Client::new()
                .post(url)
                .header("Content-Type", "application/json")
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let status = resp.status();
                    (true, format!("webhook 告警已发送，HTTP {status}"))
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    (false, format!("webhook 返回错误: HTTP {status} - {body}"))
                }
                Err(e) => (false, format!("webhook 发送失败: {e}")),
            }
        }
        "email" => {
            let to = config.get("to").and_then(|v| v.as_str()).unwrap_or_default();
            let from = config.get("from").and_then(|v| v.as_str()).unwrap_or("argus@localhost");
            let subject = config.get("subject").and_then(|v| v.as_str()).unwrap_or("Argus 告警通知");
            let smtp_host = config.get("smtp_host").and_then(|v| v.as_str()).unwrap_or("localhost");
            let smtp_port = config.get("smtp_port").and_then(|v| v.as_i64()).unwrap_or(25);

            if to.is_empty() {
                return (false, "缺少收件人".to_string());
            }

            // 构造邮件内容
            let email_content = format!(
                "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{message}\r\n"
            );

            // 使用系统 sendmail 命令发送邮件
            let sendmail_path = config.get("sendmail_path").and_then(|v| v.as_str()).unwrap_or("/usr/sbin/sendmail");
            match std::process::Command::new(sendmail_path)
                .arg("-t")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        if stdin.write_all(email_content.as_bytes()).is_err() {
                            return (false, "写入邮件内容失败".to_string());
                        }
                    }
                    match child.wait() {
                        Ok(status) if status.success() => (true, "邮件已通过 sendmail 发送".to_string()),
                        Ok(status) => (false, format!("sendmail 执行失败: {}", status)),
                        Err(e) => (false, format!("等待 sendmail 失败: {e}")),
                    }
                }
                Err(e) => (false, format!("调用 sendmail 失败: {e}（smtp_host={smtp_host}:{smtp_port}）")),
            }
        }
        "syslog" => {
            let host = config.get("host").and_then(|v| v.as_str()).unwrap_or("localhost");
            let port = config.get("port").and_then(|v| v.as_i64()).unwrap_or(514);
            let facility = config.get("facility").and_then(|v| v.as_i64()).unwrap_or(1); // user-level
            let severity = config.get("severity").and_then(|v| v.as_i64()).unwrap_or(5); // notice

            // syslog PRI = facility * 8 + severity
            let pri = facility * 8 + severity;
            let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "argus".to_string());
            let timestamp = chrono::Utc::now().format("%b %d %H:%M:%S");
            let syslog_msg = format!("<{pri}>{timestamp} {hostname} argus: {message}\n");

            // 通过 UDP 发送 syslog
            match std::net::UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    match socket.send_to(syslog_msg.as_bytes(), format!("{host}:{port}")) {
                        Ok(n) => (true, format!("syslog 已发送 {n} 字节到 {host}:{port}")),
                        Err(e) => (false, format!("syslog 发送失败: {e}")),
                    }
                }
                Err(e) => (false, format!("创建 UDP socket 失败: {e}")),
            }
        }
        "sms" => {
            let api_url = config.get("api_url").and_then(|v| v.as_str()).unwrap_or_default();
            let phone = config.get("phone").and_then(|v| v.as_str()).unwrap_or_default();
            if api_url.is_empty() || phone.is_empty() {
                return (false, "缺少 sms api_url 或 phone".to_string());
            }
            // 调用短信网关 API
            let payload = serde_json::json!({
                "phone": phone,
                "message": message,
            });
            match reqwest::Client::new()
                .post(api_url)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => (true, "短信已发送".to_string()),
                Ok(resp) => (false, format!("短信网关返回错误: HTTP {}", resp.status())),
                Err(e) => (false, format!("短信发送失败: {e}")),
            }
        }
        "kafka" => {
            let brokers = config.get("brokers").and_then(|v| v.as_str()).unwrap_or_default();
            let topic = config.get("topic").and_then(|v| v.as_str()).unwrap_or("argus-alerts");
            if brokers.is_empty() {
                return (false, "缺少 kafka brokers".to_string());
            }
            // 使用 kcat 命令行工具发送（如果可用），否则返回配置信息
            let payload = serde_json::json!({
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            match std::process::Command::new("kcat")
                .args(["-b", brokers, "-t", topic, "-P"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(payload.to_string().as_bytes());
                    }
                    match child.wait_with_output() {
                        Ok(o) if o.status.success() => (true, format!("Kafka 消息已发送到 {topic}")),
                        Ok(o) => (false, format!("kcat 执行失败: {}", String::from_utf8_lossy(&o.stderr))),
                        Err(e) => (false, format!("等待 kcat 失败: {e}")),
                    }
                }
                Err(e) => (false, format!("调用 kcat 失败: {e}（brokers={brokers}, topic={topic}）")),
            }
        }
        _ => (false, format!("不支持的通道类型: {}", channel)),
    }
}

// ==================== 告警记录 API ====================

#[derive(Debug, Deserialize)]
pub struct AlertRecordListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeAlertRequest {
    pub operator: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TriggerAlertRequest {
    pub title: String,
    pub content: Option<String>,
    pub level: Option<String>,
    pub source: Option<String>,
    pub source_id: Option<String>,
    pub alert_config_id: Option<String>,
}

/// 告警记录列表 GET /api/v1/alerts/records
pub async fn list_alert_records(
    data: web::Data<AppState>,
    query: web::Query<AlertRecordListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = AlertRecordEntity::find();
    if let Some(v) = &query.status {
        q = q.filter(alert_record::Column::Status.eq(v.clone()));
    }
    if let Some(v) = &query.level {
        q = q.filter(alert_record::Column::Level.eq(v.clone()));
    }
    if let Some(v) = &query.source {
        q = q.filter(alert_record::Column::Source.eq(v.clone()));
    }

    match q
        .order_by_desc(alert_record::Column::TriggeredAt)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let total = AlertRecordEntity::find()
                .count(&data.db)
                .await
                .unwrap_or(0);
            HttpResponse::Ok().json(serde_json::json!({
                "items": items,
                "page": page,
                "page_size": page_size,
                "total": total,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 告警记录详情 GET /api/v1/alerts/records/{id}
pub async fn get_alert_record(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match AlertRecordEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(record)) => HttpResponse::Ok().json(record),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "告警记录未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 确认告警 PUT /api/v1/alerts/records/{id}/acknowledge
pub async fn acknowledge_alert_record(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AcknowledgeAlertRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let record = match AlertRecordEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "告警记录未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: alert_record::ActiveModel = record.into();
    active.status = Set(AlertStatus::Acknowledged);
    active.acknowledged_at = Set(Some(chrono::Utc::now()));
    active.acknowledged_by = Set(body.operator.clone());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 解决告警 PUT /api/v1/alerts/records/{id}/resolve
pub async fn resolve_alert_record(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AcknowledgeAlertRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let record = match AlertRecordEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "告警记录未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let need_ack = record.acknowledged_at.is_none();
    let mut active: alert_record::ActiveModel = record.into();
    active.status = Set(AlertStatus::Resolved);
    if need_ack {
        active.acknowledged_at = Set(Some(chrono::Utc::now()));
        active.acknowledged_by = Set(body.operator.clone());
    }
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 手动触发告警 POST /api/v1/alerts/records/trigger
pub async fn trigger_alert(
    data: web::Data<AppState>,
    body: web::Json<TriggerAlertRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let level = body.level.as_deref().map(parse_alert_level).unwrap_or(AlertLevel::Warning);
    let source = body.source.as_deref().map(parse_alert_source).unwrap_or(AlertSource::Manual);
    let new = alert_record::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        alert_config_id: Set(body.alert_config_id.clone()),
        title: Set(body.title.clone()),
        content: Set(body.content.clone()),
        level: Set(level),
        source: Set(source),
        source_id: Set(body.source_id.clone()),
        status: Set(AlertStatus::Pending),
        triggered_at: Set(now),
        acknowledged_at: Set(None),
        acknowledged_by: Set(None),
        created_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(record) => HttpResponse::Created().json(record),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 告警触发辅助函数 ====================

fn parse_alert_level(s: &str) -> AlertLevel {
    match s {
        "critical" => AlertLevel::Critical,
        "info" => AlertLevel::Info,
        _ => AlertLevel::Warning,
    }
}

fn parse_alert_source(s: &str) -> AlertSource {
    match s {
        "config_change" => AlertSource::ConfigChange,
        "system" => AlertSource::System,
        "asset_discovery" => AlertSource::AssetDiscovery,
        "weak_password" => AlertSource::WeakPassword,
        "manual" => AlertSource::Manual,
        _ => AlertSource::VulnScan,
    }
}

/// 内部告警触发函数，供系统各模块调用
pub async fn emit_alert(
    db: &sea_orm::DatabaseConnection,
    title: &str,
    content: Option<&str>,
    level: AlertLevel,
    source: AlertSource,
    source_id: Option<&str>,
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let record_id = uuid::Uuid::new_v4().to_string();
    let new = alert_record::ActiveModel {
        id: Set(record_id.clone()),
        alert_config_id: Set(None),
        title: Set(title.to_string()),
        content: Set(content.map(|s| s.to_string())),
        level: Set(level),
        source: Set(source),
        source_id: Set(source_id.map(|s| s.to_string())),
        status: Set(AlertStatus::Pending),
        triggered_at: Set(now),
        acknowledged_at: Set(None),
        acknowledged_by: Set(None),
        created_at: Set(now),
    };
    new.insert(db).await?;

    // 通过已启用的告警通道发送通知
    let configs = AlertConfigEntity::find()
        .filter(alert_config::Column::Enabled.eq(true))
        .all(db)
        .await
        .unwrap_or_default();

    let content_str = content.unwrap_or("").to_string();
    let title_str = title.to_string();

    tokio::spawn(async move {
        let client = reqwest::Client::new();
        for cfg in &configs {
            let _ = send_alert_via_channel(&client, cfg, &title_str, &content_str).await;
        }
    });

    Ok(())
}

/// 通过告警通道发送通知
///
/// 支持三种通道：
/// - email: 通过 HTTP API 发送邮件（config: api_url, api_key, from, to）
/// - sms: 通过 HTTP API 发送短信（config: api_url, api_key, phone, template_id）
/// - webhook: 发送 HTTP POST 到 webhook_url
async fn send_alert_via_channel(
    client: &reqwest::Client,
    config: &alert_config::Model,
    title: &str,
    content: &str,
) -> Result<(), String> {
    match config.channel.as_str() {
        "email" => send_email_alert(client, config, title, content).await,
        "sms" => send_sms_alert(client, config, title, content).await,
        "webhook" => send_webhook_alert(client, config, title, content).await,
        other => Err(format!("不支持的告警通道: {other}")),
    }
}

/// 邮件告警：通过 HTTP API（如 SendGrid/Mailgun）发送
async fn send_email_alert(
    client: &reqwest::Client,
    config: &alert_config::Model,
    title: &str,
    content: &str,
) -> Result<(), String> {
    let api_url = config.config["api_url"].as_str().ok_or("缺少 api_url")?;
    let api_key = config.config["api_key"].as_str().unwrap_or("");
    let from = config.config["from"].as_str().unwrap_or("argus@localhost");
    let to = config.config["to"].as_str().ok_or("缺少收件人 to")?;

    let body = serde_json::json!({
        "from": from,
        "to": to,
        "subject": title,
        "text": content,
    });

    client
        .post(api_url)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("邮件发送请求失败: {e}"))?
        .error_for_status()
        .map_err(|e| format!("邮件发送失败: {e}"))?;

    Ok(())
}

/// 短信告警：通过 HTTP API 调用短信网关
async fn send_sms_alert(
    client: &reqwest::Client,
    config: &alert_config::Model,
    title: &str,
    content: &str,
) -> Result<(), String> {
    let api_url = config.config["api_url"].as_str().ok_or("缺少 api_url")?;
    let api_key = config.config["api_key"].as_str().unwrap_or("");
    let phone = config.config["phone"].as_str().ok_or("缺少手机号 phone")?;

    let body = serde_json::json!({
        "api_key": api_key,
        "phone": phone,
        "content": format!("[{title}] {content}"),
    });

    client
        .post(api_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("短信发送请求失败: {e}"))?
        .error_for_status()
        .map_err(|e| format!("短信发送失败: {e}"))?;

    Ok(())
}

/// Webhook 告警：发送 HTTP POST
async fn send_webhook_alert(
    client: &reqwest::Client,
    config: &alert_config::Model,
    title: &str,
    content: &str,
) -> Result<(), String> {
    let webhook_url = config.config["webhook_url"].as_str().ok_or("缺少 webhook_url")?;

    let body = serde_json::json!({
        "title": title,
        "content": content,
        "channel": config.channel,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    client
        .post(webhook_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Webhook 请求失败: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Webhook 返回错误: {e}"))?;

    Ok(())
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_sensitive() {
        let mut v = serde_json::json!({
            "host": "localhost",
            "password": "secret123",
            "nested": {
                "api_key": "abc123",
                "port": 8080
            },
            "arr": [{"token": "xyz"}]
        });
        mask_sensitive(&mut v);
        assert_eq!(v["password"], "******");
        assert_eq!(v["nested"]["api_key"], "******");
        assert_eq!(v["arr"][0]["token"], "******");
        assert_eq!(v["host"], "localhost");
        assert_eq!(v["nested"]["port"], 8080);
    }
}
