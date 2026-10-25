//! 认证模块：JWT Token 生成/验证 + 密码哈希

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// 用户 ID
    pub sub: String,
    /// 用户名
    pub username: String,
    /// 角色
    pub role: String,
    /// 过期时间（unix 时间戳）
    pub exp: usize,
    /// JWT ID（会话标识），用于会话管理和强制下线
    pub jti: String,
}

/// 生成 JWT Token（含 jti 会话标识）
pub fn generate_token(
    user_id: &str,
    username: &str,
    role: &str,
    secret: &str,
    expiration_hours: i64,
) -> Result<String, CoreError> {
    let exp = (Utc::now() + Duration::hours(expiration_hours)).timestamp() as usize;
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp,
        jti,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| CoreError::Internal(format!("JWT 生成失败: {e}")))?;
    Ok(token)
}

/// 验证 JWT Token，返回 Claims
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, CoreError> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| CoreError::BadRequest(format!("JWT 验证失败: {e}")))?;
    Ok(data.claims)
}

/// 密码哈希
pub fn hash_password(password: &str) -> Result<String, CoreError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| CoreError::Internal(format!("密码哈希失败: {e}")))
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> Result<bool, CoreError> {
    bcrypt::verify(password, hash)
        .map_err(|e| CoreError::Internal(format!("密码验证失败: {e}")))
}

/// 权限检查：检查 Claims 的角色是否拥有指定权限。
///
/// 权限模型：
/// - admin 角色拥有所有权限（超级管理员）
/// - 其他角色需在 permissions 中显式声明
/// - permissions 可以是扁平数组 `["asset:read", ...]` 或结构化对象 `{ "permissions": [...] }`
pub fn has_permission(claims: &Claims, permission: &str) -> bool {
    // admin 拥有所有权限
    if claims.role == "admin" {
        return true;
    }
    // auditor 拥有所有读权限（以 :read 结尾的权限）
    if claims.role == "auditor" && permission.ends_with(":read") {
        return true;
    }
    // 其他角色：需要显式权限（由 handler 层从 DB 加载 role.permissions 后传入检查）
    // 此处仅做基础角色判断，详细权限检查由 handler 层的 check_role_permission 完成
    false
}

/// 检查角色 permissions JSON 是否包含指定权限。
///
/// 支持两种格式：
/// - 扁平数组: `["asset:read", "scan:execute"]`
/// - 结构化对象: `{ "permissions": ["asset:read"], "menus": ["asset"] }`
pub fn check_role_permission(perms: &serde_json::Value, permission: &str) -> bool {
    // 扁平数组
    if let Some(arr) = perms.as_array() {
        return arr.iter().any(|v| v.as_str() == Some(permission));
    }
    // 结构化对象
    if let Some(obj) = perms.as_object() {
        if let Some(arr) = obj.get("permissions").and_then(|p| p.as_array()) {
            // 通配符匹配：如 "asset:*" 匹配 "asset:read"
            for v in arr {
                if let Some(s) = v.as_str() {
                    if s == permission {
                        return true;
                    }
                    // 通配符
                    if let Some(prefix) = s.strip_suffix(":*") {
                        if permission.starts_with(&format!("{}:", prefix)) {
                            return true;
                        }
                    }
                    if s == "*" {
                        return true;
                    }
                }
            }
        }
    }
    false
}
