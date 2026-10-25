//! 许可证管理：激活、查询、校验

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, EntityTrait, ActiveValue::Set, ColumnTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use argus_core::entity::license::{self, Entity as LicenseEntity};
use crate::state::AppState;

/// 许可证激活请求
#[derive(Debug, Deserialize)]
pub struct LicenseActivateRequest {
    pub license_key: String,
}

/// 许可证信息响应
#[derive(Debug, Serialize)]
pub struct LicenseInfo {
    pub id: i32,
    pub customer: String,
    pub product: String,
    pub edition: String,
    pub max_nodes: i32,
    pub max_assets: i32,
    pub features: serde_json::Value,
    pub issued_at: String,
    pub expires_at: String,
    pub status: String,
    pub valid: bool,
    pub days_remaining: i64,
}

/// 激活许可证 POST /api/v1/license/activate
pub async fn activate_license(
    data: web::Data<AppState>,
    body: web::Json<LicenseActivateRequest>,
) -> impl Responder {
    // 解码许可证（base64 JSON）
    use base64::Engine;
    let decoded = match base64::engine::general_purpose::STANDARD.decode(&body.license_key) {
        Ok(b) => b,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "许可证格式错误"})),
    };

    let license_json: serde_json::Value = match serde_json::from_slice(&decoded) {
        Ok(j) => j,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "许可证解析失败"})),
    };

    // 验证签名（HMAC-SHA256，密钥由 AppConfig 统一解析；生产环境缺失会告警）
    let secret = argus_core::config::resolve_license_secret();
    let signature = license_json["signature"].as_str().unwrap_or("");
    let payload = format!(
        "{}{}{}{}{}{}{}",
        license_json["customer"].as_str().unwrap_or(""),
        license_json["product"].as_str().unwrap_or(""),
        license_json["edition"].as_str().unwrap_or(""),
        license_json["max_nodes"].as_i64().unwrap_or(0),
        license_json["max_assets"].as_i64().unwrap_or(0),
        license_json["issued_at"].as_str().unwrap_or(""),
        license_json["expires_at"].as_str().unwrap_or(""),
    );

    let mut hasher = Sha256::new();
    hasher.update(format!("{payload}{secret}"));
    let expected_sig = hex::encode(hasher.finalize());

    if signature != expected_sig {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "许可证签名无效"}));
    }

    // 检查过期
    let expires_at = match chrono::DateTime::parse_from_rfc3339(license_json["expires_at"].as_str().unwrap_or("")) {
        Ok(dt) => dt.with_timezone(&chrono::Utc),
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "过期时间格式错误"})),
    };

    let now = chrono::Utc::now();
    if expires_at < now {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "许可证已过期"}));
    }

    let issued_at = chrono::DateTime::parse_from_rfc3339(
        license_json["issued_at"].as_str().unwrap_or("")
    ).map(|dt| dt.with_timezone(&chrono::Utc)).unwrap_or(now);

    // 保存许可证
    let model = license::ActiveModel {
        license_key: Set(body.license_key.clone()),
        customer: Set(license_json["customer"].as_str().unwrap_or("").to_string()),
        product: Set(license_json["product"].as_str().unwrap_or("").to_string()),
        edition: Set(license_json["edition"].as_str().unwrap_or("").to_string()),
        max_nodes: Set(license_json["max_nodes"].as_i64().unwrap_or(0) as i32),
        max_assets: Set(license_json["max_assets"].as_i64().unwrap_or(0) as i32),
        features: Set(license_json["features"].clone()),
        issued_at: Set(issued_at),
        expires_at: Set(expires_at),
        status: Set("active".to_string()),
        signature: Set(signature.to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    match model.insert(&data.db).await {
        Ok(saved) => HttpResponse::Ok().json(serde_json::json!({
            "message": "许可证激活成功",
            "id": saved.id,
            "customer": saved.customer,
            "edition": saved.edition,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 获取当前许可证 GET /api/v1/license
pub async fn get_license(data: web::Data<AppState>) -> impl Responder {
    match LicenseEntity::find()
        .filter(license::Column::Status.eq("active"))
        .one(&data.db)
        .await
    {
        Ok(Some(lic)) => {
            let now = chrono::Utc::now();
            let valid = lic.expires_at > now && lic.status == "active";
            let days_remaining = (lic.expires_at - now).num_days();

            HttpResponse::Ok().json(LicenseInfo {
                id: lic.id,
                customer: lic.customer,
                product: lic.product,
                edition: lic.edition,
                max_nodes: lic.max_nodes,
                max_assets: lic.max_assets,
                features: lic.features,
                issued_at: lic.issued_at.to_rfc3339(),
                expires_at: lic.expires_at.to_rfc3339(),
                status: lic.status,
                valid,
                days_remaining,
            })
        }
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "valid": false,
            "message": "未激活许可证，使用社区版功能",
            "edition": "community",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 列出所有许可证 GET /api/v1/license/list
pub async fn list_licenses(data: web::Data<AppState>) -> impl Responder {
    match LicenseEntity::find().all(&data.db).await {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({ "licenses": items })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 吊销许可证 DELETE /api/v1/license/{id}
pub async fn revoke_license(
    data: web::Data<AppState>,
    path: web::Path<i32>,
) -> impl Responder {
    let id = path.into_inner();
    match LicenseEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(lic)) => {
            let mut active: license::ActiveModel = lic.into();
            active.status = Set("revoked".to_string());
            active.updated_at = Set(chrono::Utc::now());
            match active.update(&data.db).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "许可证已吊销"})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            }
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "许可证不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
