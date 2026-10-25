//! 认证处理函数：登录、当前用户、初始化管理员、双因素认证（TOTP）

use actix_web::{web, HttpMessage, HttpResponse, Responder};
// HttpMessage trait is needed for req.extensions()
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, ActiveValue::Set, ActiveModelTrait};
use serde::{Deserialize, Serialize};
use argus_core::auth::{generate_token, hash_password, verify_password};
use argus_core::config::AppConfig;
use argus_core::entity::{user, UserEntity, User as UserModel};
use argus_core::entity::user::{UserRole, UserStatus};
use argus_core::entity::system_setting::Entity as SystemSettingEntity;
use argus_core::entity::user_session::{Entity as UserSessionEntity, ActiveModel as UserSessionActiveModel};
use argus_core::entity::ip_lockout::{self, Entity as IpLockoutEntity, ActiveModel as IpLockoutActiveModel};
use crate::middleware::{audit_log, client_ip};
use crate::state::AppState;

/// 登录请求
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// 双因素认证验证码（启用 2FA 时必填）
    pub totp_code: Option<String>,
}

/// 登录响应
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
    /// 是否必须修改密码（first_login_change 为 true 时）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
}

/// 用户信息
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub status: String,
    pub totp_enabled: bool,
}

impl From<&UserModel> for UserInfo {
    fn from(u: &UserModel) -> Self {
        Self {
            id: u.id.clone(),
            username: u.username.clone(),
            email: u.email.clone(),
            role: format!("{:?}", u.role).to_lowercase(),
            status: format!("{:?}", u.status).to_lowercase(),
            totp_enabled: u.totp_enabled,
        }
    }
}

// ==================== 系统配置辅助 ====================

/// 获取系统配置的整型值
async fn get_setting_i64(db: &sea_orm::DatabaseConnection, key: &str, default: i64) -> i64 {
    match SystemSettingEntity::find_by_id(key).one(db).await {
        Ok(Some(s)) => s.value.as_i64().unwrap_or(default),
        _ => default,
    }
}

// ==================== IP 锁定辅助 ====================

/// 检查 IP 是否被锁定
async fn check_ip_lockout(db: &sea_orm::DatabaseConnection, ip: &str) -> bool {
    if let Ok(Some(record)) = IpLockoutEntity::find()
        .filter(ip_lockout::Column::Ip.eq(ip))
        .one(db)
        .await
    {
        if let Some(until) = record.locked_until {
            if until > chrono::Utc::now() {
                return true;
            }
        }
    }
    false
}

/// 记录 IP 登录失败，达到阈值则锁定
async fn record_ip_failure(
    db: &sea_orm::DatabaseConnection,
    ip: &str,
    max_attempts: i32,
    lock_duration: i64,
) {
    let now = chrono::Utc::now();
    let existing = IpLockoutEntity::find()
        .filter(ip_lockout::Column::Ip.eq(ip))
        .one(db)
        .await
        .ok()
        .flatten();

    match existing {
        Some(record) => {
            let mut active: ip_lockout::ActiveModel = record.clone().into();
            let new_attempts = record.failed_attempts + 1;
            active.failed_attempts = Set(new_attempts);
            active.last_failed_at = Set(Some(now));
            if new_attempts >= max_attempts {
                let until = now + chrono::Duration::seconds(lock_duration);
                active.locked_until = Set(Some(until));
            }
            active.updated_at = Set(now);
            let _ = active.update(db).await;
        }
        None => {
            let locked_until = if 1 >= max_attempts {
                Some(now + chrono::Duration::seconds(lock_duration))
            } else {
                None
            };
            let new = IpLockoutActiveModel {
                ip: Set(ip.to_string()),
                failed_attempts: Set(1),
                locked_until: Set(locked_until),
                last_failed_at: Set(Some(now)),
                created_at: Set(now),
                updated_at: Set(now),
                ..Default::default()
            };
            let _ = new.insert(db).await;
        }
    }
}

/// 重置 IP 失败计数（登录成功时调用）
async fn reset_ip_failures(db: &sea_orm::DatabaseConnection, ip: &str) {
    if let Ok(Some(record)) = IpLockoutEntity::find()
        .filter(ip_lockout::Column::Ip.eq(ip))
        .one(db)
        .await
    {
        let mut active: ip_lockout::ActiveModel = record.into();
        active.failed_attempts = Set(0);
        active.locked_until = Set(None);
        active.updated_at = Set(chrono::Utc::now());
        let _ = active.update(db).await;
    }
}

// ==================== 登录 ====================

/// 登录（POST /api/v1/auth/login）
pub async fn login(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
    config: web::Data<AppConfig>,
    body: web::Json<LoginRequest>,
) -> impl Responder {
    let ip = client_ip(&req);
    let ip_str = ip.as_deref().unwrap_or("unknown");

    // IP 锁定检查
    if check_ip_lockout(&data.db, ip_str).await {
        audit_log(&data.db, body.username.as_str(), Some(ip_str), "login", "IP 被锁定", "failed").await;
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "该 IP 已被锁定，请稍后重试"
        }));
    }

    // 查询用户
    let user = UserEntity::find()
        .filter(user::Column::Username.eq(body.username.as_str()))
        .one(&data.db)
        .await;

    match user {
        Ok(Some(user)) => {
            // 检查是否被锁定
            if let Some(locked_until) = user.locked_until {
                if locked_until > chrono::Utc::now() {
                    audit_log(&data.db, &user.username, Some(ip_str), "login", "账户被临时锁定", "failed").await;
                    return HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "账户已被锁定，请稍后重试"
                    }));
                }
            }
            if user.status != UserStatus::Active {
                audit_log(&data.db, &user.username, Some(ip_str), "login", "用户已禁用", "failed").await;
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "用户已被禁用"
                }));
            }

            // 验证密码
            match verify_password(&body.password, &user.password_hash) {
                Ok(true) => {
                    // 2FA 校验
                    if user.totp_enabled {
                        match &body.totp_code {
                            Some(code) => {
                                if !verify_totp_for_user(&user, code) {
                                    audit_log(&data.db, &user.username, Some(ip_str), "login", "2FA 验证码错误", "failed").await;
                                    return HttpResponse::Unauthorized().json(serde_json::json!({
                                        "error": "双因素认证验证码错误"
                                    }));
                                }
                            }
                            None => {
                                return HttpResponse::Unauthorized().json(serde_json::json!({
                                    "error": "需要双因素认证验证码"
                                }));
                            }
                        }
                    }

                    let role = format!("{:?}", user.role).to_lowercase();
                    let token = match generate_token(
                        &user.id,
                        &user.username,
                        &role,
                        &config.jwt.secret,
                        config.jwt.expiration_hours,
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!("生成 token 失败: {e}");
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "生成 token 失败"
                            }));
                        }
                    };

                    // 登录成功：重置失败计数
                    let mut active: user::ActiveModel = user.clone().into();
                    active.failed_attempts = Set(0);
                    active.locked_until = Set(None);
                    let _ = active.update(&data.db).await;

                    // 重置 IP 失败计数
                    reset_ip_failures(&data.db, ip_str).await;

                    // 创建会话记录
                    let now = chrono::Utc::now();
                    let expires_at = now + chrono::Duration::hours(config.jwt.expiration_hours);
                    let user_agent = req
                        .headers()
                        .get("User-Agent")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string());

                    // 从 token 中解码 jti
                    let claims = argus_core::auth::verify_token(&token, &config.jwt.secret).ok();
                    if let Some(ref claims) = claims {
                        let session = UserSessionActiveModel {
                            id: Set(claims.jti.clone()),
                            user_id: Set(user.id.clone()),
                            username: Set(user.username.clone()),
                            jti: Set(claims.jti.clone()),
                            login_ip: Set(ip.clone()),
                            user_agent: Set(user_agent),
                            login_at: Set(now),
                            last_active_at: Set(now),
                            expires_at: Set(expires_at),
                            is_active: Set(true),
                        };
                        let _ = session.insert(&data.db).await;
                    }

                    let user_info = UserInfo::from(&user);
                    audit_log(&data.db, &user.username, Some(ip_str), "login", "登录成功", "success").await;
                    // 首次登录强制改密
                    let must_change = if user.first_login_change { Some(true) } else { None };
                    HttpResponse::Ok().json(LoginResponse {
                        token,
                        user: user_info,
                        must_change_password: must_change,
                    })
                }
                Ok(false) => {
                    // 登录失败：增加失败计数，达到阈值则锁定（按密码策略）
                    let policy = crate::handler::admin::get_password_policy(&data.db).await;
                    let max_attempts = policy.lockout_threshold as i32;
                    let lock_duration_secs = (policy.lockout_duration_minutes as i64) * 60;
                    let new_attempts = user.failed_attempts + 1;
                    let mut active: user::ActiveModel = user.clone().into();
                    active.failed_attempts = Set(new_attempts);
                    if new_attempts >= max_attempts {
                        let until = chrono::Utc::now() + chrono::Duration::seconds(lock_duration_secs);
                        active.locked_until = Set(Some(until));
                        let _ = active.update(&data.db).await;
                        audit_log(&data.db, &user.username, Some(ip_str), "login", &format!("登录失败次数超限，账户锁定 {} 分钟", policy.lockout_duration_minutes), "failed").await;
                        return HttpResponse::Unauthorized().json(serde_json::json!({
                            "error": format!("登录失败次数过多，账户已锁定 {} 分钟", policy.lockout_duration_minutes)
                        }));
                    }
                    let _ = active.update(&data.db).await;

                    // IP 维度失败计数
                    record_ip_failure(&data.db, ip_str, max_attempts, lock_duration_secs).await;

                    audit_log(&data.db, &user.username, Some(ip_str), "login", &format!("密码错误（第 {} 次）", new_attempts), "failed").await;
                    HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "用户名或密码错误"
                    }))
                }
                Err(e) => {
                    tracing::error!("密码验证失败: {e}");
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "内部错误"
                    }))
                }
            }
        }
        Ok(Some(_)) => HttpResponse::Forbidden().json(serde_json::json!({
            "error": "用户已被禁用"
        })),
        Ok(None) => {
            // 用户不存在也记录 IP 失败（按密码策略的锁定阈值）
            let policy = crate::handler::admin::get_password_policy(&data.db).await;
            let max_attempts = policy.lockout_threshold as i32;
            let lock_duration_secs = (policy.lockout_duration_minutes as i64) * 60;
            record_ip_failure(&data.db, ip_str, max_attempts, lock_duration_secs).await;

            audit_log(&data.db, body.username.as_str(), Some(ip_str), "login", "用户不存在", "failed").await;
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "用户名或密码错误"
            }))
        }
        Err(e) => {
            tracing::error!("数据库查询失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "内部错误"
            }))
        }
    }
}

/// 退出登录（POST /api/v1/auth/logout）
pub async fn logout(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
    config: web::Data<AppConfig>,
) -> impl Responder {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    if let Ok(claims) = argus_core::auth::verify_token(token, &config.jwt.secret) {
        // 标记会话为非活跃
        use sea_orm::QueryFilter;
        if let Ok(Some(session)) = UserSessionEntity::find()
            .filter(argus_core::entity::user_session::Column::Jti.eq(&claims.jti))
            .one(&data.db)
            .await
        {
            let mut active: argus_core::entity::user_session::ActiveModel = session.into();
            active.is_active = Set(false);
            let _ = active.update(&data.db).await;
        }
        // 加入撤销列表
        if let Ok(mut set) = data.revoked_sessions.lock() {
            set.insert(claims.jti.clone());
        }
        audit_log(&data.db, &claims.username, None, "login", "退出登录", "success").await;
    }
    HttpResponse::Ok().json(serde_json::json!({"message": "已退出登录"}))
}

/// 当前用户信息（GET /api/v1/auth/me）
pub async fn me(req: actix_web::HttpRequest) -> impl Responder {
    match req.extensions().get::<argus_core::auth::Claims>() {
        Some(claims) => HttpResponse::Ok().json(serde_json::json!({
            "id": claims.sub,
            "username": claims.username,
            "role": claims.role,
        })),
        None => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "未认证"
        })),
    }
}

/// 修改密码请求（POST /api/v1/auth/change-password）
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// 旧密码
    pub old_password: String,
    /// 新密码
    pub new_password: String,
}

/// 修改当前用户密码（POST /api/v1/auth/change-password）
///
/// 强制校验：旧密码正确 + 新密码符合 PasswordPolicy + 新旧不同。
/// 成功后清除 first_login_change 标志（首次登录强制改密完成后清除）。
pub async fn change_password(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
    body: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    let claims = match req.extensions().get::<argus_core::auth::Claims>() {
        Some(c) => c.clone(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "未认证"})),
    };

    // 加载密码策略
    let policy = crate::handler::admin::get_password_policy(&data.db).await;
    if let Err(e) = crate::handler::admin::validate_password(&body.new_password, &policy) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }

    if body.old_password == body.new_password {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "新密码不能与旧密码相同"
        }));
    }

    // 查询用户
    let user = match UserEntity::find()
        .filter(user::Column::Id.eq(claims.sub.clone()))
        .one(&data.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 校验旧密码
    match verify_password(&body.old_password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "旧密码错误"}));
        }
    }

    // 哈希新密码并更新
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("密码哈希失败: {e}")}))
        }
    };
    let mut active: user::ActiveModel = user.clone().into();
    active.password_hash = Set(new_hash);
    active.first_login_change = Set(false);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => {
            audit_log(
                &data.db,
                &user.username,
                None,
                "change_password",
                "用户修改密码成功",
                "success",
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"message": "密码修改成功"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建管理员账号（仅用于初始化，POST /api/v1/auth/setup）
#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

pub async fn setup(
    data: web::Data<AppState>,
    body: web::Json<SetupRequest>,
) -> impl Responder {
    use argus_core::entity::user::ActiveModel;

    // 检查是否已有用户
    let existing_count = UserEntity::find().count(&data.db).await;
    match existing_count {
        Ok(count) if count > 0 => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "系统已初始化，不允许重复创建"
            }));
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!("查询用户失败: {e}");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "内部错误"
            }));
        }
    }

    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("密码哈希失败: {e}");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "内部错误"
            }));
        }
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let new_user = ActiveModel {
        id: Set(user_id.clone()),
        username: Set(body.username.clone()),
        password_hash: Set(hash),
        email: Set(body.email.clone()),
        role: Set(UserRole::Admin),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        role_id: Set(Some("admin".to_string())),
        organization: Set(None),
        phone: Set(None),
        real_name: Set(None),
        source: Set("local".to_string()),
        expire_at: Set(None),
        first_login_change: Set(false),
        scan_target_whitelist: Set(serde_json::json!([])),
        scan_target_blacklist: Set(serde_json::json!([])),
        max_scan_ips: Set(0),
        max_scan_domains: Set(0),
        login_ip_whitelist: Set(serde_json::json!([])),
        login_ip_blacklist: Set(serde_json::json!([])),
        failed_attempts: Set(0),
        locked_until: Set(None),
        totp_secret: Set(None),
        totp_enabled: Set(false),
    };

    match UserEntity::insert(new_user).exec(&data.db).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "message": "管理员账号创建成功",
            "username": body.username,
        })),
        Err(e) => {
            tracing::error!("创建用户失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "创建用户失败"
            }))
        }
    }
}

// ==================== 双因素认证（TOTP）====================

/// TOTP 密钥的简单编码：base64 编码后存储
fn encode_secret(secret: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(secret)
}

fn decode_secret(encoded: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64 解码失败: {e}"))
}

/// 为指定用户验证 TOTP 验证码
fn verify_totp_for_user(user: &UserModel, code: &str) -> bool {
    let secret_encoded = match &user.totp_secret {
        Some(s) => s,
        None => return false,
    };
    let secret_bytes = match decode_secret(secret_encoded) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        user.username.clone(),
    );
    match totp {
        Ok(t) => t.check_current(code).unwrap_or(false),
        Err(_) => false,
    }
}

#[derive(Debug, Serialize)]
pub struct Enroll2faResponse {
    pub secret: String,
    pub otpauth_url: String,
}

/// POST /api/v1/auth/2fa/enroll - 生成 TOTP 密钥和二维码 URL
pub async fn enroll_2fa(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
) -> impl Responder {
    let ext = req.extensions();
    let claims = match ext.get::<argus_core::auth::Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "未认证"})),
    };

    let user = match UserEntity::find_by_id(claims.sub.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 生成 TOTP 密钥
    let secret = match totp_rs::Secret::generate_secret().to_bytes() {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("密钥生成失败: {e}")})),
    };
    let secret_encoded = encode_secret(&secret);

    // 构建 TOTP 实例以生成 otpauth URL
    let totp = match totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret.clone(),
        Some("Argus".to_string()),
        user.username.clone(),
    ) {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("TOTP 生成失败: {e}")})),
    };
    let otpauth_url = totp.get_url();

    // 暂存密钥（未启用），待 verify 成功后启用
    let mut active: user::ActiveModel = user.into();
    active.totp_secret = Set(Some(secret_encoded));
    active.totp_enabled = Set(false);
    active.updated_at = Set(chrono::Utc::now());
    if let Err(e) = active.update(&data.db).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(Enroll2faResponse {
        secret: encode_secret(&secret),
        otpauth_url,
    })
}

#[derive(Debug, Deserialize)]
pub struct Verify2faRequest {
    pub code: String,
}

/// POST /api/v1/auth/2fa/verify - 验证 TOTP 码并启用 2FA
pub async fn verify_2fa(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
    body: web::Json<Verify2faRequest>,
) -> impl Responder {
    let ext = req.extensions();
    let claims = match ext.get::<argus_core::auth::Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "未认证"})),
    };

    let user = match UserEntity::find_by_id(claims.sub.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    if user.totp_secret.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "请先调用 enroll 接口生成密钥"}));
    }

    if !verify_totp_for_user(&user, &body.code) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "验证码错误"}));
    }

    // 验证成功，启用 2FA
    let mut active: user::ActiveModel = user.into();
    active.totp_enabled = Set(true);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "双因素认证已启用"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/auth/2fa/disable - 禁用 2FA
pub async fn disable_2fa(
    req: actix_web::HttpRequest,
    data: web::Data<AppState>,
) -> impl Responder {
    let ext = req.extensions();
    let claims = match ext.get::<argus_core::auth::Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "未认证"})),
    };

    let user = match UserEntity::find_by_id(claims.sub.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: user::ActiveModel = user.into();
    active.totp_secret = Set(None);
    active.totp_enabled = Set(false);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "双因素认证已禁用"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== LDAP 认证 ====================

/// LDAP 配置
#[derive(Debug, Deserialize, Serialize)]
pub struct LdapConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub base_dn: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub user_filter: String,
    pub use_tls: bool,
}

/// 获取 LDAP 配置 GET /api/v1/auth/ldap/config
pub async fn get_ldap_config(data: web::Data<AppState>) -> impl Responder {
    match SystemSettingEntity::find_by_id("ldap_config").one(&data.db).await {
        Ok(Some(s)) => HttpResponse::Ok().json(s.value),
        _ => HttpResponse::Ok().json(serde_json::json!({
            "enabled": false,
            "host": "",
            "port": 389,
            "base_dn": "",
            "bind_dn": "",
            "bind_password": "",
            "user_filter": "(uid={username})",
            "use_tls": false,
        })),
    }
}

/// 设置 LDAP 配置 PUT /api/v1/auth/ldap/config
pub async fn set_ldap_config(
    data: web::Data<AppState>,
    body: web::Json<LdapConfig>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let active = argus_core::entity::system_setting::ActiveModel {
        key: Set("ldap_config".to_string()),
        value: Set(serde_json::to_value(&body).unwrap_or_default()),
        updated_at: Set(now),
    };
    match active.save(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "LDAP 配置已保存"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// LDAP 登录请求
#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

/// LDAP 登录 POST /api/v1/auth/ldap/login
pub async fn ldap_login(
    data: web::Data<AppState>,
    config: web::Data<AppConfig>,
    body: web::Json<LdapLoginRequest>,
) -> impl Responder {
    use argus_core::entity::system_setting::Entity as SettingEntity;

    let ldap_cfg = match SettingEntity::find_by_id("ldap_config").one(&data.db).await {
        Ok(Some(s)) => match serde_json::from_value::<LdapConfig>(s.value) {
            Ok(c) => c,
            Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "LDAP 配置格式错误"})),
        },
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "LDAP 未配置"})),
    };

    if !ldap_cfg.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "LDAP 认证未启用"}));
    }

    // 构造用户 DN
    let user_dn = ldap_cfg.user_filter.replace("{username}", &body.username);
    let full_dn = format!("{},{}", user_dn, ldap_cfg.base_dn);

    let ldap_url = format!("{}://{}:{}", if ldap_cfg.use_tls { "ldaps" } else { "ldap" }, ldap_cfg.host, ldap_cfg.port);

    // 使用 ldap3 进行认证
    let auth_result = tokio::task::spawn_blocking({
        let password = body.password.clone();
        move || -> Result<(), String> {
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(async {
                use ldap3::{LdapConnAsync, LdapConnSettings};
                let settings = if ldap_cfg.use_tls {
                    LdapConnSettings::new().set_starttls(false)
                } else {
                    LdapConnSettings::new()
                };
                let (conn, mut ldap) = LdapConnAsync::with_settings(settings, ldap_url.as_str())
                    .await
                    .map_err(|e| format!("LDAP 连接失败: {e}"))?;
                ldap3::drive!(conn);
                ldap.simple_bind(&full_dn, &password)
                    .await
                    .map_err(|e| format!("LDAP 绑定失败: {e}"))?
                    .success()
                    .map_err(|e| format!("LDAP 认证失败: {e}"))?;
                Ok(())
            })
        }
    })
    .await
    .map_err(|e| format!("任务执行失败: {e}"))
    .unwrap_or_else(|e| Err(e));

    match auth_result {
        Ok(()) => {
            // 认证成功，查找或创建本地用户
            let username = body.username.clone();
            let user = match UserEntity::find()
                .filter(user::Column::Username.eq(&username))
                .one(&data.db)
                .await
            {
                Ok(Some(u)) => u,
                Ok(None) => {
                    // 自动创建本地用户
                    let now = chrono::Utc::now();
                    let new_user = user::ActiveModel {
                        id: Set(uuid::Uuid::new_v4().to_string()),
                        username: Set(username.clone()),
                        password_hash: Set(hash_password("!ldap_user_no_password").unwrap_or_default()),
                        email: Set(None),
                        role: Set(UserRole::Viewer),
                        status: Set(UserStatus::Active),
                        created_at: Set(now),
                        updated_at: Set(now),
                        role_id: Set(None),
                        organization: Set(None),
                        phone: Set(None),
                        real_name: Set(None),
                        source: Set("ldap".to_string()),
                        expire_at: Set(None),
                        first_login_change: Set(false),
                        scan_target_whitelist: Set(serde_json::json!([])),
                        scan_target_blacklist: Set(serde_json::json!([])),
                        max_scan_ips: Set(0),
                        max_scan_domains: Set(0),
                        login_ip_whitelist: Set(serde_json::json!([])),
                        login_ip_blacklist: Set(serde_json::json!([])),
                        failed_attempts: Set(0),
                        locked_until: Set(None),
                        totp_secret: Set(None),
                        totp_enabled: Set(false),
                    };
                    match new_user.insert(&data.db).await {
                        Ok(u) => u,
                        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("创建用户失败: {e}")})),
                    }
                }
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            };

            let role = format!("{:?}", user.role).to_lowercase();
            let token = generate_token(
                &user.id,
                &user.username,
                &role,
                &config.jwt.secret,
                config.jwt.expiration_hours,
            ).unwrap_or_default();
            HttpResponse::Ok().json(LoginResponse {
                token,
                user: UserInfo::from(&user),
                must_change_password: None,
            })
        }
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({"error": e})),
    }
}

// ==================== OAuth SSO ====================

/// OAuth 配置
#[derive(Debug, Deserialize, Serialize)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub provider: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub redirect_uri: String,
    pub scope: String,
}

/// 获取 OAuth 配置 GET /api/v1/auth/oauth/config
pub async fn get_oauth_config(data: web::Data<AppState>) -> impl Responder {
    match SystemSettingEntity::find_by_id("oauth_config").one(&data.db).await {
        Ok(Some(s)) => {
            let mut v = s.value;
            // 脱敏 client_secret
            if let Some(obj) = v.as_object_mut() {
                if let Some(secret) = obj.get("client_secret").and_then(|s| s.as_str()) {
                    if !secret.is_empty() {
                        obj.insert("client_secret".to_string(), serde_json::Value::String("******".to_string()));
                    }
                }
            }
            HttpResponse::Ok().json(v)
        }
        _ => HttpResponse::Ok().json(serde_json::json!({
            "enabled": false,
            "provider": "",
            "client_id": "",
            "client_secret": "",
            "auth_url": "",
            "token_url": "",
            "userinfo_url": "",
            "redirect_uri": "",
            "scope": "openid profile email",
        })),
    }
}

/// 设置 OAuth 配置 PUT /api/v1/auth/oauth/config
pub async fn set_oauth_config(
    data: web::Data<AppState>,
    body: web::Json<OAuthConfig>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let active = argus_core::entity::system_setting::ActiveModel {
        key: Set("oauth_config".to_string()),
        value: Set(serde_json::to_value(&body).unwrap_or_default()),
        updated_at: Set(now),
    };
    match active.save(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "OAuth 配置已保存"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// OAuth 登录重定向 GET /api/v1/auth/oauth/login
pub async fn oauth_login_redirect(data: web::Data<AppState>) -> impl Responder {
    use argus_core::entity::system_setting::Entity as SettingEntity;

    let oauth_cfg = match SettingEntity::find_by_id("oauth_config").one(&data.db).await {
        Ok(Some(s)) => match serde_json::from_value::<OAuthConfig>(s.value) {
            Ok(c) => c,
            Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "OAuth 配置格式错误"})),
        },
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "OAuth 未配置"})),
    };

    if !oauth_cfg.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "OAuth 未启用"}));
    }

    let state = uuid::Uuid::new_v4().to_string();
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        oauth_cfg.auth_url,
        urlencoding::encode(&oauth_cfg.client_id),
        urlencoding::encode(&oauth_cfg.redirect_uri),
        urlencoding::encode(&oauth_cfg.scope),
        state
    );

    HttpResponse::Ok().json(serde_json::json!({
        "auth_url": auth_url,
        "state": state,
    }))
}

/// OAuth 回调 GET /api/v1/auth/oauth/callback
pub async fn oauth_callback(
    data: web::Data<AppState>,
    config: web::Data<AppConfig>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    use argus_core::entity::system_setting::Entity as SettingEntity;

    let code = match query.get("code") {
        Some(c) => c.clone(),
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "缺少 code 参数"})),
    };

    let oauth_cfg = match SettingEntity::find_by_id("oauth_config").one(&data.db).await {
        Ok(Some(s)) => match serde_json::from_value::<OAuthConfig>(s.value) {
            Ok(c) => c,
            Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "OAuth 配置格式错误"})),
        },
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "OAuth 未配置"})),
    };

    // 用 code 换取 token
    let token_resp = match reqwest::Client::new()
        .post(&oauth_cfg.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", oauth_cfg.redirect_uri.as_str()),
            ("client_id", oauth_cfg.client_id.as_str()),
            ("client_secret", oauth_cfg.client_secret.as_str()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("获取 token 失败: {e}")})),
    };

    let token_json: serde_json::Value = match token_resp.json().await {
        Ok(j) => j,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("解析 token 失败: {e}")})),
    };

    let access_token = match token_json["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "获取 access_token 失败"})),
    };

    // 获取用户信息
    let userinfo_resp = match reqwest::Client::new()
        .get(&oauth_cfg.userinfo_url)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("获取用户信息失败: {e}")})),
    };

    let userinfo: serde_json::Value = match userinfo_resp.json().await {
        Ok(j) => j,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("解析用户信息失败: {e}")})),
    };

    let username = userinfo["preferred_username"]
        .as_str()
        .or_else(|| userinfo["username"].as_str())
        .or_else(|| userinfo["email"].as_str())
        .unwrap_or("oauth_user")
        .to_string();

    // 查找或创建本地用户
    let user = match UserEntity::find()
        .filter(user::Column::Username.eq(&username))
        .one(&data.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            let now = chrono::Utc::now();
            let new_user = user::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                username: Set(username.clone()),
                password_hash: Set(hash_password("!oauth_user_no_password").unwrap_or_default()),
                email: Set(userinfo["email"].as_str().map(|s| s.to_string())),
                role: Set(UserRole::Viewer),
                status: Set(UserStatus::Active),
                created_at: Set(now),
                updated_at: Set(now),
                role_id: Set(None),
                organization: Set(None),
                phone: Set(None),
                real_name: Set(userinfo["name"].as_str().map(|s| s.to_string())),
                source: Set("oauth".to_string()),
                expire_at: Set(None),
                first_login_change: Set(false),
                scan_target_whitelist: Set(serde_json::json!([])),
                scan_target_blacklist: Set(serde_json::json!([])),
                max_scan_ips: Set(0),
                max_scan_domains: Set(0),
                login_ip_whitelist: Set(serde_json::json!([])),
                login_ip_blacklist: Set(serde_json::json!([])),
                failed_attempts: Set(0),
                locked_until: Set(None),
                totp_secret: Set(None),
                totp_enabled: Set(false),
            };
            match new_user.insert(&data.db).await {
                Ok(u) => u,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("创建用户失败: {e}")})),
            }
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let role = format!("{:?}", user.role).to_lowercase();
    let token = generate_token(
        &user.id,
        &user.username,
        &role,
        &config.jwt.secret,
        config.jwt.expiration_hours,
    ).unwrap_or_default();
    HttpResponse::Ok().json(LoginResponse {
        token,
        user: UserInfo::from(&user),
        must_change_password: None,
    })
}
