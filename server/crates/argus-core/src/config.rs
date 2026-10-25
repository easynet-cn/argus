//! 系统配置
//! 支持通过环境变量覆盖默认值

use std::env;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_or_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// 解析 JWT 签名密钥。
///
/// 安全约束：JWT 用于签发登录令牌，若使用可预测的默认值，任何人都可伪造令牌。
/// - 显式设置 `JWT_SECRET` 时使用该值；
/// - 未设置且为生产环境（`ARGUS_ENV=production`）时启动失败（fail-fast）；
/// - 未设置且非生产环境（本地开发）时回退到开发默认值并打印告警。
fn resolve_jwt_secret() -> String {
    match env::var("JWT_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            let is_production =
                env::var("ARGUS_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false);
            if is_production {
                panic!(
                    "JWT_SECRET 环境变量未设置。生产环境（ARGUS_ENV=production）启动前必须设置强随机的 JWT_SECRET，\
                     否则任何人都可伪造登录令牌。本地开发可设置 ARGUS_ENV=development 跳过该检查。"
                );
            }
            eprintln!(
                "[warn] JWT_SECRET 未设置，已使用内置开发默认密钥（公开且不安全）。\
                 生产环境请设置 JWT_SECRET 并以 ARGUS_ENV=production 启动。"
            );
            "argus-dev-secret-change-in-production".to_string()
        }
    }
}

/// 解析许可证签名密钥（HMAC-SHA256）。
///
/// 未设置时回退到默认值，但开发/生产环境均打印告警：默认密钥公开，
/// 攻击者可据此伪造许可证签名。生产部署应通过 `ARGUS_LICENSE_SECRET` 设置自有密钥。
pub fn resolve_license_secret() -> String {
    match env::var("ARGUS_LICENSE_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            let is_production =
                env::var("ARGUS_ENV").map(|v| v.eq_ignore_ascii_case("production")).unwrap_or(false);
            if is_production {
                eprintln!(
                    "[error] ARGUS_LICENSE_SECRET 未设置：生产环境下许可证签名校验将使用不安全默认值，\
                     存在被伪造许可证的风险，请尽快设置该变量。"
                );
            } else {
                eprintln!("[warn] ARGUS_LICENSE_SECRET 未设置，使用内置开发默认密钥（仅限本地开发）。");
            }
            "argus-default-secret".to_string()
        }
    }
}

impl AppConfig {
    /// 从环境变量加载配置（未设置则使用默认值）
    pub fn from_env() -> Self {
        Self {
            server: ServerConfig {
                host: env_or("ARGUS_HOST", "0.0.0.0"),
                port: env_or_parse("ARGUS_PORT", 8080),
            },
            database: DatabaseConfig {
                url: env_or("DATABASE_URL", "postgresql://argus:argus@localhost:5432/argus"),
                max_connections: env_or_parse("DATABASE_MAX_CONNECTIONS", 10),
            },
            redis: RedisConfig {
                url: env_or("REDIS_URL", "redis://localhost:6379"),
            },
            jwt: JwtConfig {
                secret: resolve_jwt_secret(),
                expiration_hours: env_or_parse("JWT_EXPIRATION_HOURS", 24),
            },
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
