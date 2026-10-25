//! 中间件：JWT 认证 + 审计日志辅助
//!
//! 使用 actix-web 4 的 Transform/Service 模式

use std::rc::Rc;
use std::sync::Arc;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::{self, LocalBoxFuture, Ready};
use argus_core::auth::verify_token;
use argus_core::config::AppConfig;
use argus_core::entity::audit_log;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection};

/// JWT 认证中间件工厂（Send + Clone，用于 HttpServer::new）
#[derive(Clone)]
pub struct AuthMiddleware {
    config: Arc<AppConfig>,
}

impl AuthMiddleware {
    pub fn new(config: AppConfig) -> Self {
        Self { config: Arc::new(config) }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthMiddlewareService {
            service: Rc::new(service),
            config: Rc::new((*self.config).clone()),
        })
    }
}

/// 中间件服务实例（单线程，使用 Rc）
pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
    config: Rc<AppConfig>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let path = req.path().to_string();

            // 公开路径白名单
            let is_public = path == "/api/v1/health"
                || path == "/api/v1/auth/login"
                || path == "/api/v1/auth/setup"
                || path.starts_with("/api/v1/internal/node/");

            if is_public {
                let res = svc.call(req).await?;
                return Ok(res.map_into_left_body());
            }

            // 提取 Authorization: Bearer <token>
            let token_opt = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "));

            match token_opt {
                Some(token) => match verify_token(token, &config.jwt.secret) {
                    Ok(claims) => {
                        // 检查会话是否已被撤销（强制下线）
                        let is_revoked = req
                            .app_data::<actix_web::web::Data<crate::state::AppState>>()
                            .is_some_and(|state| {
                                if let Ok(set) = state.revoked_sessions.lock() {
                                    set.contains(&claims.jti)
                                } else {
                                    false
                                }
                            });
                        if is_revoked {
                            let (req, _) = req.into_parts();
                            let res = HttpResponse::Unauthorized()
                                .json(serde_json::json!({"error": "会话已被撤销，请重新登录"}))
                                .map_into_boxed_body();
                            return Ok(ServiceResponse::new(req, res).map_into_right_body());
                        }
                        req.extensions_mut().insert(claims);
                        let res = svc.call(req).await?;
                        Ok(res.map_into_left_body())
                    }
                    Err(e) => {
                        let (req, _) = req.into_parts();
                        let res = HttpResponse::Unauthorized()
                            .json(serde_json::json!({"error": e.to_string()}))
                            .map_into_boxed_body();
                        Ok(ServiceResponse::new(req, res).map_into_right_body())
                    }
                },
                None => {
                    let (req, _) = req.into_parts();
                    let res = HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "缺少认证 token"}))
                        .map_into_boxed_body();
                    Ok(ServiceResponse::new(req, res).map_into_right_body())
                }
            }
        })
    }
}

/// 审计日志辅助函数：在各 handler 中调用，记录关键操作日志
///
/// 注意：不要在 description 中记录密码等敏感信息。
///
/// # 参数
/// - `db`: 数据库连接
/// - `username`: 操作用户名（系统操作用 "system"）
/// - `login_ip`: 登录/操作 IP（可空）
/// - `log_type`: 日志类型，如 login/logout/network_asset/task/system 等
/// - `description`: 操作描述（不含敏感信息）
/// - `status`: success / failed
pub async fn audit_log(
    db: &DatabaseConnection,
    username: &str,
    login_ip: Option<&str>,
    log_type: &str,
    description: &str,
    status: &str,
) {
    let record = audit_log::ActiveModel {
        username: Set(username.to_string()),
        login_ip: Set(login_ip.map(|s| s.to_string())),
        log_type: Set(log_type.to_string()),
        description: Set(description.to_string()),
        status: Set(status.to_string()),
        created_at: Set(chrono::Utc::now()),
        ..Default::default()
    };
    if let Err(e) = record.insert(db).await {
        tracing::warn!("写入审计日志失败: {e}");
    }
}

/// 从 HTTP 请求中提取客户端 IP
pub fn client_ip(req: &actix_web::HttpRequest) -> Option<String> {
    // 优先取 X-Forwarded-For
    if let Some(val) = req.headers().get("X-Forwarded-For") {
        if let Ok(s) = val.to_str() {
            if let Some(first) = s.split(',').next() {
                return Some(first.trim().to_string());
            }
        }
    }
    // 其次取 X-Real-IP
    if let Some(val) = req.headers().get("X-Real-IP") {
        if let Ok(s) = val.to_str() {
            return Some(s.trim().to_string());
        }
    }
    // 最后取 peer_addr
    req.peer_addr().map(|addr| addr.ip().to_string())
}
