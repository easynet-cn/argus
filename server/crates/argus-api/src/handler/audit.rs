//! 审计日志 API
//!
//! 路由前缀：/api/v1/audit
//! 包含：日志列表、导出 CSV、按时间范围删除、清空日志。

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Statement,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::audit_log::{self, Entity as AuditLogEntity};
use argus_core::entity::system_setting::{self, Entity as SystemSettingEntity};
use crate::state::AppState;

// ==================== 请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub username: Option<String>,
    pub login_ip: Option<String>,
    pub log_type: Option<String>,
    pub status: Option<String>,
    /// 描述关键词搜索
    pub description: Option<String>,
    /// 起始时间（ISO 8601）
    pub start_time: Option<String>,
    /// 结束时间（ISO 8601）
    pub end_time: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

/// 日志类型枚举（分类：登录/系统/安全/操作）
pub const LOG_TYPES: &[&str] = &["login", "system", "security", "operation"];

#[derive(Debug, Deserialize)]
pub struct DeleteLogsRequest {
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

// ==================== 响应结构 ====================

#[derive(Debug, Serialize)]
pub struct AuditLogItem {
    pub id: uuid::Uuid,
    pub username: String,
    pub login_ip: Option<String>,
    pub log_type: String,
    pub description: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<audit_log::Model> for AuditLogItem {
    fn from(m: audit_log::Model) -> Self {
        Self {
            id: m.id,
            username: m.username,
            login_ip: m.login_ip,
            log_type: m.log_type,
            description: m.description,
            status: m.status,
            created_at: m.created_at,
        }
    }
}

// ==================== 工具 ====================

fn parse_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            s.parse::<chrono::NaiveDateTime>()
                .ok()
                .map(|nd| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(nd, chrono::Utc))
        })
}

/// 构建带筛选条件的查询
fn build_query(query: &AuditLogQuery) -> sea_orm::Select<AuditLogEntity> {
    let mut q = AuditLogEntity::find();
    if let Some(v) = &query.username {
        q = q.filter(audit_log::Column::Username.contains(v.as_str()));
    }
    if let Some(v) = &query.login_ip {
        q = q.filter(audit_log::Column::LoginIp.contains(v.as_str()));
    }
    if let Some(v) = &query.log_type {
        q = q.filter(audit_log::Column::LogType.eq(v.clone()));
    }
    if let Some(v) = &query.status {
        q = q.filter(audit_log::Column::Status.eq(v.clone()));
    }
    if let Some(v) = &query.description {
        q = q.filter(audit_log::Column::Description.contains(v.clone()));
    }
    if let Some(v) = &query.start_time {
        if let Some(t) = parse_time(v) {
            q = q.filter(audit_log::Column::CreatedAt.gte(t));
        }
    }
    if let Some(v) = &query.end_time {
        if let Some(t) = parse_time(v) {
            q = q.filter(audit_log::Column::CreatedAt.lte(t));
        }
    }
    q
}

// ==================== API 处理函数 ====================

/// GET /api/v1/audit/logs - 审计日志列表
pub async fn list_logs(
    data: web::Data<AppState>,
    query: web::Query<AuditLogQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 500);

    let q = build_query(&query);
    let count_q = q.clone();

    match q
        .order_by_desc(audit_log::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let total = match count_q.count(&data.db).await {
                Ok(c) => c,
                Err(_) => 0,
            };
            let resp: Vec<AuditLogItem> = items.into_iter().map(AuditLogItem::from).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "items": resp,
                "page": page,
                "page_size": page_size,
                "total": total,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /api/v1/audit/logs/export - 导出审计日志为 CSV
pub async fn export_logs(
    data: web::Data<AppState>,
    query: web::Query<AuditLogQuery>,
) -> impl Responder {
    let q = build_query(&query);
    let items = match q
        .order_by_desc(audit_log::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}))
        }
    };

    // 生成 CSV
    let mut csv = String::from("id,username,login_ip,log_type,description,status,created_at\n");
    for m in items {
        let desc = m.description.replace('"', "\"\"");
        csv.push_str(&format!(
            "{},{},{},{},\"{}\",{},{}\n",
            m.id,
            m.username,
            m.login_ip.unwrap_or_default(),
            m.log_type,
            desc,
            m.status,
            m.created_at
        ));
    }

    HttpResponse::Ok()
        .content_type("text/csv; charset=utf-8")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"audit_logs.csv\"",
        ))
        .body(csv)
}

/// GET /api/v1/audit/logs/export-xlsx - 导出审计日志为 XLSX
pub async fn export_logs_xlsx(
    data: web::Data<AppState>,
    query: web::Query<AuditLogQuery>,
) -> impl Responder {
    use rust_xlsxwriter::Workbook;

    let q = build_query(&query);
    let items = match q
        .order_by_desc(audit_log::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}))
        }
    };

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let headers = ["ID", "用户名", "登录IP", "日志类型", "描述", "状态", "创建时间"];
    for (i, h) in headers.iter().enumerate() {
        ws.write_string(0, i as u16, *h).ok();
    }
    for (row, m) in items.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, m.id.to_string()).ok();
        ws.write_string(r, 1, &m.username).ok();
        ws.write_string(r, 2, m.login_ip.clone().unwrap_or_default()).ok();
        ws.write_string(r, 3, &m.log_type).ok();
        ws.write_string(r, 4, &m.description).ok();
        ws.write_string(r, 5, &m.status).ok();
        ws.write_string(r, 6, m.created_at.to_rfc3339()).ok();
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header((
                "Content-Disposition",
                "attachment; filename=audit_logs.xlsx",
            ))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// DELETE /api/v1/audit/logs - 删除指定时间范围的日志
pub async fn delete_logs(
    data: web::Data<AppState>,
    body: web::Json<DeleteLogsRequest>,
) -> impl Responder {
    let start = body
        .start_time
        .as_deref()
        .and_then(parse_time);
    let end = body
        .end_time
        .as_deref()
        .and_then(parse_time);

    if start.is_none() && end.is_none() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "至少提供 start_time 或 end_time"}));
    }

    let mut sql = "DELETE FROM audit_logs WHERE 1=1".to_string();
    let mut params: Vec<sea_orm::Value> = Vec::new();
    if let Some(s) = start {
        sql.push_str(" AND created_at >= $1");
        params.push(sea_orm::Value::ChronoDateTimeUtc(Some(s)));
    }
    if let Some(e) = end {
        sql.push_str(&format!(" AND created_at <= ${}", params.len() + 1));
        params.push(sea_orm::Value::ChronoDateTimeUtc(Some(e)));
    }

    let stmt = Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, params);
    match data.db.execute_raw(stmt).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": res.rows_affected(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/audit/logs/clean - 清空所有审计日志
pub async fn clean_logs(data: web::Data<AppState>) -> impl Responder {
    match data
        .db
        .execute_unprepared("DELETE FROM audit_logs;")
        .await
    {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": res.rows_affected(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 日志类型 ====================

/// GET /api/v1/audit/logs/types - 获取支持的日志类型
pub async fn get_log_types() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "types": LOG_TYPES,
    }))
}

// ==================== 日志备份策略 ====================

const LOG_BACKUP_POLICY_KEY: &str = "log_backup_policy";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogBackupPolicy {
    /// 是否启用自动备份
    pub enabled: bool,
    /// 日志保留天数（超过则备份后删除）
    pub retention_days: i32,
    /// 最多保留备份文件数
    pub max_backup_files: i32,
    /// 邮件推送配置（可选）
    #[serde(default)]
    pub email_push: Option<EmailPushConfig>,
    /// FTP 推送配置（可选）
    #[serde(default)]
    pub ftp_push: Option<FtpPushConfig>,
}

/// 邮件推送配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EmailPushConfig {
    /// 收件人（逗号分隔多个地址）
    pub to: String,
    /// 发件人
    pub from: String,
    /// sendmail 路径（默认 /usr/sbin/sendmail）
    pub sendmail_path: Option<String>,
}

/// FTP 推送配置
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FtpPushConfig {
    /// FTP 服务器地址
    pub host: String,
    /// FTP 端口（默认 21）
    pub port: Option<u16>,
    /// 用户名
    pub username: String,
    /// 密码
    pub password: String,
    /// 远程目录（默认 /）
    pub remote_dir: Option<String>,
}

impl Default for LogBackupPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 90,
            max_backup_files: 12,
            email_push: None,
            ftp_push: None,
        }
    }
}

/// 读取备份策略，不存在则返回默认值
async fn load_backup_policy(db: &impl ConnectionTrait) -> LogBackupPolicy {
    match SystemSettingEntity::find_by_id(LOG_BACKUP_POLICY_KEY.to_string())
        .one(db)
        .await
    {
        Ok(Some(s)) => serde_json::from_value(s.value).unwrap_or_default(),
        _ => LogBackupPolicy::default(),
    }
}

/// GET /api/v1/audit/logs/backup-policy
pub async fn get_backup_policy(data: web::Data<AppState>) -> impl Responder {
    let policy = load_backup_policy(&data.db).await;
    HttpResponse::Ok().json(policy)
}

/// PUT /api/v1/audit/logs/backup-policy
pub async fn update_backup_policy(
    data: web::Data<AppState>,
    body: web::Json<LogBackupPolicy>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let value = serde_json::to_value(body.into_inner()).unwrap_or(serde_json::json!({}));
    let active = system_setting::ActiveModel {
        key: Set(LOG_BACKUP_POLICY_KEY.to_string()),
        value: Set(value),
        updated_at: Set(now),
    };
    match SystemSettingEntity::insert(active)
        .on_conflict(
            sea_orm::sea_query::OnConflict::column(system_setting::Column::Key)
                .update_column(system_setting::Column::Value)
                .update_column(system_setting::Column::UpdatedAt)
                .to_owned(),
        )
        .exec(&data.db)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "备份策略已更新"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/audit/logs/backup - 执行日志备份
/// 导出超过保留期的日志为 XLSX 文件，并从数据库中删除
pub async fn execute_backup(data: web::Data<AppState>) -> impl Responder {
    use rust_xlsxwriter::Workbook;

    let policy = load_backup_policy(&data.db).await;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(policy.retention_days as i64);

    let items = match AuditLogEntity::find()
        .filter(audit_log::Column::CreatedAt.lt(cutoff))
        .order_by_desc(audit_log::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(i) => i,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    if items.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "message": "无超过保留期的日志",
            "backed_up": 0,
        }));
    }

    // 生成 XLSX
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let headers = ["ID", "用户名", "登录IP", "日志类型", "描述", "状态", "创建时间"];
    for (i, h) in headers.iter().enumerate() {
        ws.write_string(0, i as u16, *h).ok();
    }
    for (row, m) in items.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, m.id.to_string()).ok();
        ws.write_string(r, 1, &m.username).ok();
        ws.write_string(r, 2, m.login_ip.clone().unwrap_or_default()).ok();
        ws.write_string(r, 3, &m.log_type).ok();
        ws.write_string(r, 4, &m.description).ok();
        ws.write_string(r, 5, &m.status).ok();
        ws.write_string(r, 6, m.created_at.to_rfc3339()).ok();
    }
    let buf = match wb.save_to_buffer() {
        Ok(b) => b,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 写入备份文件到 data/logs/backup 目录
    let backup_dir = std::path::Path::new("data").join("logs").join("backup");
    if let Err(e) = std::fs::create_dir_all(&backup_dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("创建备份目录失败: {e}")}));
    }
    let fname = format!("audit_logs_{}.xlsx", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    let fpath = backup_dir.join(&fname);
    if let Err(e) = std::fs::write(&fpath, &buf) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("写入备份文件失败: {e}")}));
    }

    // 邮件推送（如果配置）
    let mut push_results = Vec::new();
    if let Some(email_cfg) = &policy.email_push {
        match push_backup_email(email_cfg, &fpath, &fname) {
            Ok(msg) => push_results.push(serde_json::json!({"channel": "email", "status": "success", "message": msg})),
            Err(e) => push_results.push(serde_json::json!({"channel": "email", "status": "failed", "error": e})),
        }
    }

    // FTP 推送（如果配置）
    if let Some(ftp_cfg) = &policy.ftp_push {
        match push_backup_ftp(ftp_cfg, &fpath, &fname) {
            Ok(msg) => push_results.push(serde_json::json!({"channel": "ftp", "status": "success", "message": msg})),
            Err(e) => push_results.push(serde_json::json!({"channel": "ftp", "status": "failed", "error": e})),
        }
    }

    // 删除已备份的日志
    let sql = "DELETE FROM audit_logs WHERE created_at < $1";
    let stmt = Statement::from_sql_and_values(
        DatabaseBackend::Postgres,
        sql,
        vec![sea_orm::Value::ChronoDateTimeUtc(Some(cutoff))],
    );
    let deleted = match data.db.execute_raw(stmt).await {
        Ok(res) => res.rows_affected(),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 清理超过 max_backup_files 的旧备份
    if policy.max_backup_files > 0 {
        if let Ok(mut entries) = std::fs::read_dir(&backup_dir) {
            let mut files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|ext| ext == "xlsx").unwrap_or(false))
                .collect();
            files.sort_by_key(|e| std::cmp::Reverse(e.metadata().and_then(|m| m.modified()).ok()));
            for old in files.iter().skip(policy.max_backup_files as usize) {
                let _ = std::fs::remove_file(old.path());
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "备份完成",
        "backed_up": items.len(),
        "deleted": deleted,
        "file": fpath.to_string_lossy(),
        "push_results": push_results,
    }))
}

/// 通过 sendmail 发送备份文件附件邮件
fn push_backup_email(cfg: &EmailPushConfig, fpath: &std::path::Path, fname: &str) -> Result<String, String> {
    let sendmail_path = cfg.sendmail_path.as_deref().unwrap_or("/usr/sbin/sendmail");
    let subject = format!("Argus 日志备份 - {}", fname);

    // 读取文件内容并 Base64 编码
    let content = std::fs::read(fpath).map_err(|e| format!("读取备份文件失败: {e}"))?;
    let b64 = {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&content)
    };
    let boundary = "ARGUS_BACKUP_BOUNDARY";

    // 构造 MIME multipart 邮件（含附件）
    let email = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Argus 审计日志备份文件: {fname}\r\n\
         备份时间: {time}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"{fname}\"\r\n\
         \r\n\
         {b64}\r\n\
         --{boundary}--\r\n",
        from = cfg.from,
        to = cfg.to,
        subject = subject,
        boundary = boundary,
        fname = fname,
        time = chrono::Utc::now().to_rfc3339(),
        b64 = b64
    );

    // 使用系统 sendmail 命令发送邮件
    match std::process::Command::new(sendmail_path)
        .arg("-t")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                if stdin.write_all(email.as_bytes()).is_err() {
                    return Err("写入邮件内容失败".to_string());
                }
            }
            match child.wait() {
                Ok(status) if status.success() => Ok(format!("邮件已发送至 {}", cfg.to)),
                Ok(status) => Err(format!("sendmail 执行失败: {}", status)),
                Err(e) => Err(format!("等待 sendmail 失败: {e}")),
            }
        }
        Err(e) => Err(format!("调用 sendmail 失败: {e}")),
    }
}

/// 通过 FTP 上传备份文件
fn push_backup_ftp(cfg: &FtpPushConfig, fpath: &std::path::Path, fname: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let port = cfg.port.unwrap_or(21);
    let remote_dir = cfg.remote_dir.as_deref().unwrap_or("/");

    // 连接 FTP 控制端口
    let mut ctrl = TcpStream::connect((cfg.host.as_str(), port))
        .map_err(|e| format!("连接 FTP 服务器失败: {e}"))?;
    ctrl.set_read_timeout(Some(Duration::from_secs(30))).ok();
    ctrl.set_write_timeout(Some(Duration::from_secs(30))).ok();

    // 读取 FTP 响应的工具函数
    fn read_reply(stream: &mut TcpStream) -> Result<String, String> {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).map_err(|e| format!("读取 FTP 响应失败: {e}"))?;
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        if !reply.starts_with('2') && !reply.starts_with('3') {
            return Err(format!("FTP 错误: {reply}"));
        }
        Ok(reply)
    }

    fn send_cmd(stream: &mut TcpStream, cmd: &str) -> Result<(), String> {
        stream.write_all(cmd.as_bytes()).map_err(|e| format!("发送 FTP 命令失败: {e}"))?;
        stream.write_all(b"\r\n").map_err(|e| format!("发送 FTP 命令失败: {e}"))
    }

    // 等待服务器欢迎信息
    read_reply(&mut ctrl).map_err(|e| format!("FTP 欢迎信息: {e}"))?;

    // 登录
    send_cmd(&mut ctrl, &format!("USER {}", cfg.username))?;
    let _ = read_reply(&mut ctrl);
    send_cmd(&mut ctrl, &format!("PASS {}", cfg.password))?;
    read_reply(&mut ctrl)?;

    // 切换到二进制模式
    send_cmd(&mut ctrl, "TYPE I")?;
    read_reply(&mut ctrl)?;

    // 切换到目标目录
    if remote_dir != "/" && !remote_dir.is_empty() {
        send_cmd(&mut ctrl, &format!("CWD {}", remote_dir))?;
        read_reply(&mut ctrl)?;
    }

    // 进入被动模式获取数据端口
    send_cmd(&mut ctrl, "PASV")?;
    let pasv_reply = {
        let mut buf = [0u8; 1024];
        let n = ctrl.read(&mut buf).map_err(|e| format!("读取 PASV 响应失败: {e}"))?;
        String::from_utf8_lossy(&buf[..n]).to_string()
    };
    if !pasv_reply.starts_with('2') {
        return Err(format!("PASV 失败: {pasv_reply}"));
    }

    // 解析 PASV 响应中的 IP 和端口 (h1,h2,h3,h4,p1,p2)
    let pasv_start = pasv_reply.rfind('(').ok_or("PASV 响应格式错误")?;
    let pasv_end = pasv_reply.rfind(')').ok_or("PASV 响应格式错误")?;
    let nums: Vec<u16> = pasv_reply[pasv_start+1..pasv_end]
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    if nums.len() != 6 {
        return Err(format!("PASV 端口解析失败: {pasv_reply}"));
    }
    let data_port = nums[4] * 256 + nums[5];

    // 连接数据端口
    let mut data_conn = TcpStream::connect((cfg.host.as_str(), data_port))
        .map_err(|e| format!("连接 FTP 数据端口失败: {e}"))?;
    data_conn.set_read_timeout(Some(Duration::from_secs(60))).ok();
    data_conn.set_write_timeout(Some(Duration::from_secs(60))).ok();

    // 发送 STOR 命令
    send_cmd(&mut ctrl, &format!("STOR {}", fname))?;

    // 读取文件并上传
    let content = std::fs::read(fpath).map_err(|e| format!("读取备份文件失败: {e}"))?;
    data_conn.write_all(&content).map_err(|e| format!("上传数据失败: {e}"))?;
    drop(data_conn); // 关闭数据连接

    // 读取传输完成响应
    let _ = read_reply(&mut ctrl);

    // 退出
    send_cmd(&mut ctrl, "QUIT")?;
    let _ = read_reply(&mut ctrl);

    Ok(format!("已上传至 {}/{}", remote_dir, fname))
}
