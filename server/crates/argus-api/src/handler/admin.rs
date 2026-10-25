//! 系统管理 API：角色管理 + 用户管理
//!
//! 路由前缀：/api/v1/admin
//! 包含角色 CRUD、用户 CRUD、锁定/解锁、重置 2FA，以及密码策略校验。

use actix_web::{web, HttpResponse, Responder};
use actix_web::HttpMessage;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::auth::hash_password;
use argus_core::entity::role::{self, Entity as RoleEntity};
use argus_core::entity::user::{self, Entity as UserEntity, UserRole, UserStatus};
use argus_core::entity::system_setting::Entity as SystemSettingEntity;
use crate::middleware::audit_log;
use crate::state::AppState;

// ==================== 密码策略 ====================

/// 密码策略配置（持久化于 system_settings 表，key = "password_policy"）
///
/// 10.9 系统设置中的密码策略项。所有字段在创建/修改用户密码时强制生效。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// 密码最小长度
    #[serde(default = "default_min_length")]
    pub min_length: u8,
    /// 是否要求复杂度（数字/大写/小写/特殊字符至少 3 种）
    #[serde(default = "default_true")]
    pub require_complexity: bool,
    /// 是否必须包含特殊字符
    #[serde(default = "default_false")]
    pub require_special_char: bool,
    /// 密码过期天数（0 = 不过期）
    #[serde(default = "default_expiry_days")]
    pub expiry_days: u32,
    /// 历史密码记录数（0 = 不校验历史）
    #[serde(default = "default_history_count")]
    pub history_count: u32,
    /// 连续失败 N 次后锁定
    #[serde(default = "default_lockout_threshold")]
    pub lockout_threshold: u32,
    /// 锁定时长（分钟）
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration_minutes: u32,
}

fn default_min_length() -> u8 { 8 }
fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_expiry_days() -> u32 { 90 }
fn default_history_count() -> u32 { 5 }
fn default_lockout_threshold() -> u32 { 5 }
fn default_lockout_duration() -> u32 { 30 }

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            min_length: default_min_length(),
            require_complexity: default_true(),
            require_special_char: default_false(),
            expiry_days: default_expiry_days(),
            history_count: default_history_count(),
            lockout_threshold: default_lockout_threshold(),
            lockout_duration_minutes: default_lockout_duration(),
        }
    }
}

/// system_settings 表中存储密码策略的 key
pub const PASSWORD_POLICY_KEY: &str = "password_policy";

/// 从数据库读取密码策略，失败或不存在时返回默认策略
pub async fn get_password_policy(db: &sea_orm::DatabaseConnection) -> PasswordPolicy {
    match SystemSettingEntity::find_by_id(PASSWORD_POLICY_KEY.to_string())
        .one(db)
        .await
    {
        Ok(Some(s)) => serde_json::from_value::<PasswordPolicy>(s.value).unwrap_or_default(),
        _ => PasswordPolicy::default(),
    }
}

/// 校验密码复杂度：数字/大写/小写/特殊字符至少 3 种
fn check_complexity(password: &str) -> bool {
    let mut digit = false;
    let mut upper = false;
    let mut lower = false;
    let mut special = false;
    for c in password.chars() {
        if c.is_ascii_digit() {
            digit = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_lowercase() {
            lower = true;
        } else {
            special = true;
        }
    }
    let count = [digit, upper, lower, special].iter().filter(|&&x| x).count();
    count >= 3
}

/// 校验密码是否符合策略
///
/// 检查项：最小长度、复杂度、是否必须包含特殊字符。
/// 历史密码校验由调用方在哈希后单独比对（此处仅做静态规则校验）。
pub fn validate_password(password: &str, policy: &PasswordPolicy) -> Result<(), String> {
    if password.len() < policy.min_length as usize {
        return Err(format!("密码长度不能少于 {} 位", policy.min_length));
    }
    if policy.require_complexity && !check_complexity(password) {
        return Err("密码必须包含数字、大写字母、小写字母、特殊字符中的至少 3 种".to_string());
    }
    if policy.require_special_char && !has_special_char(password) {
        return Err("密码必须包含至少一个特殊字符".to_string());
    }
    Ok(())
}

/// 是否包含特殊字符
fn has_special_char(password: &str) -> bool {
    password.chars().any(|c| !c.is_ascii_alphanumeric())
}

// ==================== 角色管理 ====================

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<serde_json::Value>,
    pub is_builtin: Option<bool>,
}

/// GET /api/v1/admin/roles - 角色列表
pub async fn list_roles(data: web::Data<AppState>) -> impl Responder {
    match RoleEntity::find()
        .order_by_asc(role::Column::Name)
        .all(&data.db)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({ "items": items })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/admin/roles - 新建角色
pub async fn create_role(
    data: web::Data<AppState>,
    body: web::Json<CreateRoleRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let permissions = body
        .permissions
        .clone()
        .unwrap_or_else(|| serde_json::json!([]));

    let new = role::ActiveModel {
        id: Set(body.id.clone()),
        name: Set(body.name.clone()),
        description: Set(body.description.clone()),
        permissions: Set(permissions),
        is_builtin: Set(false),
        created_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(r) => {
            audit_log(
                &data.db,
                "system",
                None,
                "system",
                &format!("创建角色: {}", r.name),
                "success",
            )
            .await;
            HttpResponse::Created().json(r)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// PUT /api/v1/admin/roles/{id} - 编辑角色
pub async fn update_role(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateRoleRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let r = match RoleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "角色未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: role::ActiveModel = r.into();
    if let Some(v) = &body.name {
        active.name = Set(v.clone());
    }
    if body.description.is_some() {
        active.description = Set(body.description.clone());
    }
    if let Some(v) = body.permissions.clone() {
        active.permissions = Set(v);
    }
    if let Some(v) = body.is_builtin {
        active.is_builtin = Set(v);
    }
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// DELETE /api/v1/admin/roles/{id} - 删除角色（builtin 不可删）
pub async fn delete_role(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let r = match RoleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "角色未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    if r.is_builtin {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "内置角色不可删除"}));
    }
    match RoleEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "角色未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 用户管理 ====================

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub role: Option<String>,
    pub role_id: Option<String>,
    pub organization: Option<String>,
    pub phone: Option<String>,
    pub real_name: Option<String>,
    pub expire_at: Option<String>,
    pub max_scan_ips: Option<i32>,
    pub max_scan_domains: Option<i32>,
    pub first_login_change: Option<bool>,
    pub scan_target_whitelist: Option<Vec<String>>,
    pub scan_target_blacklist: Option<Vec<String>>,
    pub login_ip_whitelist: Option<Vec<String>>,
    pub login_ip_blacklist: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub role: Option<String>,
    pub role_id: Option<String>,
    pub organization: Option<String>,
    pub phone: Option<String>,
    pub real_name: Option<String>,
    pub status: Option<String>,
    pub expire_at: Option<String>,
    pub password: Option<String>,
    pub max_scan_ips: Option<i32>,
    pub max_scan_domains: Option<i32>,
    pub first_login_change: Option<bool>,
    pub scan_target_whitelist: Option<Vec<String>>,
    pub scan_target_blacklist: Option<Vec<String>>,
    pub login_ip_whitelist: Option<Vec<String>>,
    pub login_ip_blacklist: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UserListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub username: Option<String>,
    pub status: Option<String>,
}

fn parse_user_role(s: &str) -> UserRole {
    match s {
        "admin" => UserRole::Admin,
        "auditor" => UserRole::Auditor,
        _ => UserRole::Viewer,
    }
}

fn parse_user_status(s: &str) -> UserStatus {
    match s {
        "disabled" => UserStatus::Disabled,
        _ => UserStatus::Active,
    }
}

/// GET /api/v1/admin/users - 用户列表
pub async fn list_users(
    data: web::Data<AppState>,
    query: web::Query<UserListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = UserEntity::find();
    if let Some(v) = &query.username {
        q = q.filter(user::Column::Username.contains(v.as_str()));
    }
    if let Some(v) = &query.status {
        q = q.filter(user::Column::Status.eq(parse_user_status(v)));
    }
    let count_q = q.clone();

    match q
        .order_by_asc(user::Column::Username)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let total = match count_q.count(&data.db).await {
                Ok(c) => c,
                Err(_) => 0,
            };
            let resp: Vec<serde_json::Value> = items
                .into_iter()
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "email": u.email,
                        "role": format!("{:?}", u.role).to_lowercase(),
                        "role_id": u.role_id,
                        "status": format!("{:?}", u.status).to_lowercase(),
                        "organization": u.organization,
                        "phone": u.phone,
                        "real_name": u.real_name,
                        "source": u.source,
                        "expire_at": u.expire_at,
                        "first_login_change": u.first_login_change,
                        "max_scan_ips": u.max_scan_ips,
                        "max_scan_domains": u.max_scan_domains,
                        "scan_target_whitelist": u.scan_target_whitelist,
                        "scan_target_blacklist": u.scan_target_blacklist,
                        "login_ip_whitelist": u.login_ip_whitelist,
                        "login_ip_blacklist": u.login_ip_blacklist,
                        "failed_attempts": u.failed_attempts,
                        "locked_until": u.locked_until,
                        "totp_enabled": u.totp_enabled,
                        "created_at": u.created_at,
                        "updated_at": u.updated_at,
                    })
                })
                .collect();
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

/// POST /api/v1/admin/users - 新建用户
pub async fn create_user(
    data: web::Data<AppState>,
    body: web::Json<CreateUserRequest>,
) -> impl Responder {
    // 密码策略校验（从数据库加载生效策略）
    let policy = get_password_policy(&data.db).await;
    if let Err(e) = validate_password(&body.password, &policy) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }

    // 检查用户名是否已存在
    if UserEntity::find()
        .filter(user::Column::Username.eq(body.username.as_str()))
        .one(&data.db)
        .await
        .map(|opt| opt.is_some())
        .unwrap_or(false)
    {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "用户名已存在"}));
    }

    let hash = match hash_password(&body.password) {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": format!("密码哈希失败: {e}")}))
        }
    };

    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let expire_at = body
        .expire_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let new = user::ActiveModel {
        id: Set(user_id.clone()),
        username: Set(body.username.clone()),
        password_hash: Set(hash),
        email: Set(body.email.clone()),
        role: Set(body
            .role
            .as_deref()
            .map(parse_user_role)
            .unwrap_or(UserRole::Viewer)),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        role_id: Set(body.role_id.clone()),
        organization: Set(body.organization.clone()),
        phone: Set(body.phone.clone()),
        real_name: Set(body.real_name.clone()),
        source: Set("local".to_string()),
        expire_at: Set(expire_at),
        first_login_change: Set(body.first_login_change.unwrap_or(false)),
        scan_target_whitelist: Set(serde_json::to_value(body.scan_target_whitelist.clone().unwrap_or_default()).unwrap_or(serde_json::json!([]))),
        scan_target_blacklist: Set(serde_json::to_value(body.scan_target_blacklist.clone().unwrap_or_default()).unwrap_or(serde_json::json!([]))),
        max_scan_ips: Set(body.max_scan_ips.unwrap_or(0)),
        max_scan_domains: Set(body.max_scan_domains.unwrap_or(0)),
        login_ip_whitelist: Set(serde_json::to_value(body.login_ip_whitelist.clone().unwrap_or_default()).unwrap_or(serde_json::json!([]))),
        login_ip_blacklist: Set(serde_json::to_value(body.login_ip_blacklist.clone().unwrap_or_default()).unwrap_or(serde_json::json!([]))),
        failed_attempts: Set(0),
        locked_until: Set(None),
        totp_secret: Set(None),
        totp_enabled: Set(false),
    };

    match new.insert(&data.db).await {
        Ok(u) => {
            audit_log(
                &data.db,
                "system",
                None,
                "system",
                &format!("创建用户: {}", u.username),
                "success",
            )
            .await;
            HttpResponse::Created().json(serde_json::json!({
                "id": u.id,
                "username": u.username,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// PUT /api/v1/admin/users/{id} - 编辑用户
pub async fn update_user(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateUserRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let u = match UserEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: user::ActiveModel = u.clone().into();
    if body.email.is_some() {
        active.email = Set(body.email.clone());
    }
    if let Some(v) = &body.role {
        active.role = Set(parse_user_role(v));
    }
    if body.role_id.is_some() {
        active.role_id = Set(body.role_id.clone());
    }
    if body.organization.is_some() {
        active.organization = Set(body.organization.clone());
    }
    if body.phone.is_some() {
        active.phone = Set(body.phone.clone());
    }
    if body.real_name.is_some() {
        active.real_name = Set(body.real_name.clone());
    }
    if let Some(v) = &body.status {
        active.status = Set(parse_user_status(v));
    }
    if let Some(v) = &body.password {
        // 从数据库加载生效的密码策略
        let policy = get_password_policy(&data.db).await;
        if let Err(e) = validate_password(v, &policy) {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
        }
        let hash = match hash_password(v) {
            Ok(h) => h,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("密码哈希失败: {e}")}))
            }
        };
        active.password_hash = Set(hash);
    }
    if let Some(v) = body.max_scan_ips {
        active.max_scan_ips = Set(v);
    }
    if let Some(v) = body.max_scan_domains {
        active.max_scan_domains = Set(v);
    }
    if let Some(v) = body.first_login_change {
        active.first_login_change = Set(v);
    }
    if let Some(v) = body.scan_target_whitelist.clone() {
        active.scan_target_whitelist = Set(serde_json::to_value(v).unwrap_or(serde_json::json!([])));
    }
    if let Some(v) = body.scan_target_blacklist.clone() {
        active.scan_target_blacklist = Set(serde_json::to_value(v).unwrap_or(serde_json::json!([])));
    }
    if let Some(v) = body.login_ip_whitelist.clone() {
        active.login_ip_whitelist = Set(serde_json::to_value(v).unwrap_or(serde_json::json!([])));
    }
    if let Some(v) = body.login_ip_blacklist.clone() {
        active.login_ip_blacklist = Set(serde_json::to_value(v).unwrap_or(serde_json::json!([])));
    }
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "用户更新成功"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// DELETE /api/v1/admin/users/{id} - 删除用户
pub async fn delete_user(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match UserEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/admin/users/{id}/lock - 锁定用户
pub async fn lock_user(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let u = match UserEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: user::ActiveModel = u.clone().into();
    active.status = Set(UserStatus::Disabled);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => {
            audit_log(&data.db, "system", None, "system", &format!("锁定用户: {}", u.username), "success").await;
            HttpResponse::Ok().json(serde_json::json!({"message": "用户已锁定"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/admin/users/{id}/unlock - 解锁用户
pub async fn unlock_user(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let u = match UserEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: user::ActiveModel = u.clone().into();
    active.status = Set(UserStatus::Active);
    active.failed_attempts = Set(0);
    active.locked_until = Set(None);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => {
            audit_log(&data.db, "system", None, "system", &format!("解锁用户: {}", u.username), "success").await;
            HttpResponse::Ok().json(serde_json::json!({"message": "用户已解锁"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /api/v1/admin/users/{id}/reset-2fa - 重置双因素认证
pub async fn reset_user_2fa(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let u = match UserEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "用户未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: user::ActiveModel = u.clone().into();
    active.totp_secret = Set(None);
    active.totp_enabled = Set(false);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => {
            audit_log(&data.db, "system", None, "system", &format!("重置用户 2FA: {}", u.username), "success").await;
            HttpResponse::Ok().json(serde_json::json!({"message": "双因素认证已重置"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 会话管理 ====================

use argus_core::entity::user_session::{self, Entity as UserSessionEntity};
use argus_core::entity::ip_lockout::{self, Entity as IpLockoutEntity};

/// GET /api/v1/admin/sessions - 活跃会话列表
pub async fn list_sessions(
    data: web::Data<AppState>,
    query: web::Query<SessionQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = UserSessionEntity::find().filter(user_session::Column::IsActive.eq(true));
    if let Some(v) = &query.username {
        q = q.filter(user_session::Column::Username.contains(v.as_str()));
    }
    let count_q = q.clone();

    match q
        .order_by_desc(user_session::Column::LoginAt)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let total = count_q.count(&data.db).await.unwrap_or(0);
            let resp: Vec<serde_json::Value> = items
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id,
                        "user_id": s.user_id,
                        "username": s.username,
                        "login_ip": s.login_ip,
                        "user_agent": s.user_agent,
                        "login_at": s.login_at,
                        "last_active_at": s.last_active_at,
                        "expires_at": s.expires_at,
                        "is_active": s.is_active,
                    })
                })
                .collect();
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

#[derive(Debug, Deserialize)]
pub struct SessionQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub username: Option<String>,
}

/// POST /api/v1/admin/sessions/{id}/revoke - 强制下线（撤销会话）
pub async fn revoke_session(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let session_id = path.into_inner();
    let session = match UserSessionEntity::find_by_id(session_id.clone())
        .one(&data.db)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "会话未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 标记会话为非活跃
    let mut active: user_session::ActiveModel = session.clone().into();
    active.is_active = Set(false);
    if let Err(e) = active.update(&data.db).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    // 加入内存撤销列表
    if let Ok(mut set) = data.revoked_sessions.lock() {
        set.insert(session.jti.clone());
    }

    audit_log(
        &data.db,
        "system",
        None,
        "system",
        &format!("强制下线会话: {} (用户: {})", session.id, session.username),
        "success",
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "会话已撤销"}))
}

// ==================== IP 锁定管理 ====================

/// GET /api/v1/admin/ip-lockouts - IP 锁定列表
pub async fn list_ip_lockouts(
    data: web::Data<AppState>,
    query: web::Query<IpLockoutQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);

    let mut q = IpLockoutEntity::find();
    if let Some(v) = &query.ip {
        q = q.filter(ip_lockout::Column::Ip.contains(v.as_str()));
    }
    if query.locked == Some(true) {
        q = q.filter(ip_lockout::Column::LockedUntil.gt(chrono::Utc::now()));
    }
    let count_q = q.clone();

    match q
        .order_by_desc(ip_lockout::Column::UpdatedAt)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            let total = count_q.count(&data.db).await.unwrap_or(0);
            let now = chrono::Utc::now();
            let resp: Vec<serde_json::Value> = items
                .iter()
                .map(|r| {
                    let is_locked = r.locked_until.is_some_and(|u| u > now);
                    serde_json::json!({
                        "id": r.id,
                        "ip": r.ip,
                        "failed_attempts": r.failed_attempts,
                        "locked_until": r.locked_until,
                        "last_failed_at": r.last_failed_at,
                        "is_locked": is_locked,
                        "created_at": r.created_at,
                        "updated_at": r.updated_at,
                    })
                })
                .collect();
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

#[derive(Debug, Deserialize)]
pub struct IpLockoutQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub ip: Option<String>,
    pub locked: Option<bool>,
}

/// POST /api/v1/admin/ip-lockouts/{id}/unlock - 解锁 IP
pub async fn unlock_ip(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let id_uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无效的 ID"})),
    };

    let record = match IpLockoutEntity::find_by_id(id_uuid).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "锁定记录未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: ip_lockout::ActiveModel = record.clone().into();
    active.failed_attempts = Set(0);
    active.locked_until = Set(None);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(_) => {
            audit_log(
                &data.db,
                "system",
                None,
                "system",
                &format!("解锁 IP: {}", record.ip),
                "success",
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"message": "IP 已解锁"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 角色权限结构化 ====================

/// GET /api/v1/admin/roles/{id}/permissions - 获取角色结构化权限
pub async fn get_role_permissions(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match RoleEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(r)) => {
            // 如果 permissions 为空或非结构化，返回默认结构
            let perms = &r.permissions;
            let structured = if perms.is_array() {
                // 扁平数组 → 转为结构化
                serde_json::json!({
                    "permissions": perms,
                    "menus": [],
                })
            } else if perms.is_object() {
                perms.clone()
            } else {
                serde_json::json!({
                    "permissions": [],
                    "menus": [],
                })
            };
            HttpResponse::Ok().json(serde_json::json!({
                "role_id": r.id,
                "role_name": r.name,
                "permissions": structured,
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "角色未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// PUT /api/v1/admin/roles/{id}/permissions - 更新角色结构化权限
pub async fn update_role_permissions(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let id = path.into_inner();
    let r = match RoleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "角色未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: role::ActiveModel = r.into();
    active.permissions = Set(body.into_inner());
    match active.update(&data.db).await {
        Ok(updated) => {
            audit_log(
                &data.db,
                "system",
                None,
                "system",
                &format!("更新角色权限: {}", updated.name),
                "success",
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({"message": "权限已更新"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /api/v1/admin/menus - 获取菜单树（基于角色权限）
pub async fn get_menu_tree(req: actix_web::HttpRequest) -> impl Responder {
    use argus_core::auth::has_permission;
    let ext = req.extensions();
    let claims = match ext.get::<argus_core::auth::Claims>() {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "未认证"})),
    };

    // 菜单定义（一级菜单 + 子菜单 + 所需权限）
    let all_menus = serde_json::json!([
        {
            "id": "dashboard",
            "name": "仪表盘",
            "icon": "dashboard",
            "permissions": ["dashboard:read"],
            "submenus": []
        },
        {
            "id": "asset",
            "name": "资产管理",
            "icon": "asset",
            "permissions": ["asset:read"],
            "submenus": [
                { "id": "asset-group", "name": "资产组", "permissions": ["asset:read"] },
                { "id": "network-asset", "name": "网络资产", "permissions": ["asset:read"] },
                { "id": "application-asset", "name": "应用资产", "permissions": ["asset:read"] },
                { "id": "database-asset", "name": "数据库资产", "permissions": ["asset:read"] },
                { "id": "discovery", "name": "资产发现", "permissions": ["asset:read"] },
                { "id": "credential", "name": "凭证管理", "permissions": ["asset:read"] }
            ]
        },
        {
            "id": "scan",
            "name": "扫描管理",
            "icon": "scan",
            "permissions": ["scan:execute"],
            "submenus": [
                { "id": "port-scan", "name": "端口扫描", "permissions": ["scan:execute"] },
                { "id": "vuln-scan", "name": "系统扫描", "permissions": ["scan:execute"] },
                { "id": "web-scan", "name": "应用扫描", "permissions": ["scan:execute"] },
                { "id": "db-scan", "name": "数据库扫描", "permissions": ["scan:execute"] },
                { "id": "baseline", "name": "基线核查", "permissions": ["scan:execute"] },
                { "id": "brute-force", "name": "口令猜解", "permissions": ["scan:execute"] },
                { "id": "ics-scan", "name": "工控扫描", "permissions": ["scan:execute"] },
                { "id": "mobile-scan", "name": "移动扫描", "permissions": ["scan:execute"] }
            ]
        },
        {
            "id": "risk",
            "name": "风险管理",
            "icon": "risk",
            "permissions": ["risk:read"],
            "submenus": [
                { "id": "exposure-port", "name": "暴露端口", "permissions": ["risk:read"] },
                { "id": "vuln", "name": "系统漏洞", "permissions": ["risk:read"] },
                { "id": "app-vuln", "name": "应用漏洞", "permissions": ["risk:read"] },
                { "id": "db-vuln", "name": "数据库漏洞", "permissions": ["risk:read"] },
                { "id": "weak-password", "name": "弱密码", "permissions": ["risk:read"] },
                { "id": "config-change", "name": "配置变更", "permissions": ["risk:read"] },
                { "id": "alert", "name": "告警管理", "permissions": ["risk:read"] }
            ]
        },
        {
            "id": "template",
            "name": "模板管理",
            "icon": "template",
            "permissions": ["template:read"],
            "submenus": [
                { "id": "port-template", "name": "端口模板", "permissions": ["template:read"] },
                { "id": "dictionary", "name": "字典管理", "permissions": ["template:read"] },
                { "id": "certificate", "name": "证书管理", "permissions": ["template:read"] },
                { "id": "param-template", "name": "参数模板", "permissions": ["template:read"] },
                { "id": "config-template", "name": "配置模板", "permissions": ["template:read"] },
                { "id": "vuln-template", "name": "漏洞模板", "permissions": ["template:read"] },
                { "id": "fingerprint", "name": "指纹规则", "permissions": ["template:read"] }
            ]
        },
        {
            "id": "system",
            "name": "系统管理",
            "icon": "system",
            "permissions": ["system:read"],
            "submenus": [
                { "id": "user", "name": "用户管理", "permissions": ["system:read"] },
                { "id": "role", "name": "角色管理", "permissions": ["system:read"] },
                { "id": "session", "name": "会话管理", "permissions": ["system:read"] },
                { "id": "node", "name": "探针管理", "permissions": ["system:read"] },
                { "id": "alert-config", "name": "告警配置", "permissions": ["system:read"] },
                { "id": "device", "name": "设备管理", "permissions": ["system:read"] },
                { "id": "diagnostic", "name": "诊断工具", "permissions": ["system:read"] },
                { "id": "upgrade", "name": "升级管理", "permissions": ["system:read"] },
                { "id": "log", "name": "日志管理", "permissions": ["system:read"] }
            ]
        }
    ]);

    // 按权限过滤菜单
    fn filter_menus(menus: &serde_json::Value, claims: &argus_core::auth::Claims) -> serde_json::Value {
        use argus_core::auth::has_permission;
        let filtered: Vec<serde_json::Value> = menus
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        let perms = m.get("permissions").and_then(|p| p.as_array());
                        let has_access = perms.map_or(true, |ps| {
                            ps.iter().any(|p| {
                                p.as_str().map_or(false, |perm| has_permission(claims, perm))
                            })
                        });
                        if has_access {
                            // 递归过滤子菜单
                            let mut m = m.clone();
                            if let Some(subs) = m.get("submenus").and_then(|s| s.as_array()) {
                                let filtered_subs: Vec<serde_json::Value> = subs
                                    .iter()
                                    .filter_map(|s| {
                                        let s_perms = s.get("permissions").and_then(|p| p.as_array());
                                        let s_access = s_perms.map_or(true, |ps| {
                                            ps.iter().any(|p| {
                                                p.as_str().map_or(false, |perm| has_permission(claims, perm))
                                            })
                                        });
                                        if s_access { Some(s.clone()) } else { None }
                                    })
                                    .collect();
                                m["submenus"] = serde_json::Value::Array(filtered_subs);
                            }
                            Some(m)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        serde_json::Value::Array(filtered)
    }

    let menus = filter_menus(&all_menus, claims);
    HttpResponse::Ok().json(serde_json::json!({
        "menus": menus,
        "role": claims.role,
    }))
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complexity_valid() {
        assert!(check_complexity("Abc12345")); // 数字+大写+小写 = 3
        assert!(check_complexity("Abc!@#$")); // 大写+小写+特殊 = 3
        assert!(check_complexity("ABC123!")); // 大写+数字+特殊 = 3
    }

    #[test]
    fn test_complexity_invalid() {
        assert!(!check_complexity("abcdef")); // 仅小写
        assert!(!check_complexity("abc123")); // 小写+数字 = 2
        assert!(!check_complexity("ABCD123")); // 大写+数字 = 2
    }

    #[test]
    fn test_validate_password() {
        // 默认策略：min_length=8, require_complexity=true, require_special_char=false
        let policy = PasswordPolicy::default();
        assert!(validate_password("Abc12345", &policy).is_ok());
        assert!(validate_password("short", &policy).is_err());
        assert!(validate_password("abcdefgh", &policy).is_err());
    }

    #[test]
    fn test_validate_password_special_char_required() {
        let mut policy = PasswordPolicy::default();
        policy.require_special_char = true;
        // 满足复杂度但无特殊字符 → 失败
        assert!(validate_password("Abc12345", &policy).is_err());
        // 含特殊字符 → 成功
        assert!(validate_password("Abc12345!", &policy).is_ok());
    }

    #[test]
    fn test_validate_password_strict_length() {
        let mut policy = PasswordPolicy::default();
        policy.min_length = 12;
        // 8 位太短
        assert!(validate_password("Abc12345", &policy).is_err());
        // 12 位 OK
        assert!(validate_password("Abc123456789", &policy).is_ok());
    }

    #[test]
    fn test_password_policy_serde_round_trip() {
        let p = PasswordPolicy::default();
        let j = serde_json::to_value(&p).unwrap();
        let back: PasswordPolicy = serde_json::from_value(j).unwrap();
        assert_eq!(back.min_length, 8);
        assert!(back.require_complexity);
        assert_eq!(back.expiry_days, 90);
        assert_eq!(back.history_count, 5);
    }

    #[test]
    fn test_password_policy_default_fields_match() {
        // 10.9 默认密码策略
        let p = PasswordPolicy::default();
        assert_eq!(p.min_length, 8, "默认最小长度 8");
        assert!(p.require_complexity, "默认启用复杂度");
        assert_eq!(p.expiry_days, 90, "默认 90 天过期");
        assert_eq!(p.history_count, 5, "默认 5 次历史");
        assert_eq!(p.lockout_threshold, 5, "默认 5 次锁定");
        assert_eq!(p.lockout_duration_minutes, 30, "默认 30 分钟");
    }

    #[test]
    fn test_password_policy_partial_deserialize_uses_defaults() {
        // 只提供 min_length 字段，其它字段应使用默认值（serde(default=...)）
        let json = serde_json::json!({"min_length": 14});
        let p: PasswordPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(p.min_length, 14);
        assert!(p.require_complexity);
        assert_eq!(p.expiry_days, 90);
    }
}
