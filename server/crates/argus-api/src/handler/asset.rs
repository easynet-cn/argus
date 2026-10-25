//! 资产管理 CRUD API

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, ActiveValue::Set};
use serde::Deserialize;
use argus_core::entity::{
    network_asset::{self, AssetStatus, AssetType, Entity as NetworkAssetEntity},
    application_asset::{self, Entity as ApplicationAssetEntity},
    database_asset::{self, Entity as DatabaseAssetEntity},
};
use crate::state::AppState;

/// 批量删除请求
#[derive(Debug, Deserialize)]
pub struct BatchDeleteRequest {
    pub ids: Vec<String>,
}

// ==================== 网络资产 ====================

#[derive(Debug, Deserialize)]
pub struct CreateNetworkAssetRequest {
    pub name: String,
    pub ip: String,
    pub mac: Option<String>,
    pub os: Option<String>,
    pub asset_type: Option<String>,
    pub tags: Option<Vec<String>>,
    // 阶段8 扩展字段
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub network_zone: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub is_industrial: Option<bool>,
    pub industrial_vendor: Option<String>,
    pub industrial_model: Option<String>,
    pub industrial_version: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub trusted_device: Option<bool>,
    pub industrial_device_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNetworkAssetRequest {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
    pub risk_score: Option<f64>,
    pub tags: Option<Vec<String>>,
    // 阶段8 扩展字段
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub network_zone: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub is_industrial: Option<bool>,
    pub industrial_vendor: Option<String>,
    pub industrial_model: Option<String>,
    pub industrial_version: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub trusted_device: Option<bool>,
    pub industrial_device_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

/// 创建网络资产 POST /api/v1/assets/network
pub async fn create_network_asset(
    data: web::Data<AppState>,
    body: web::Json<CreateNetworkAssetRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let asset_type = match body.asset_type.as_deref() {
        Some("application") => AssetType::Application,
        Some("database") => AssetType::Database,
        _ => AssetType::Network,
    };
    let new = network_asset::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        ip: Set(body.ip.clone()),
        mac: Set(body.mac.clone()),
        os: Set(body.os.clone()),
        asset_type: Set(asset_type),
        status: Set(AssetStatus::Unknown),
        risk_score: Set(0.0),
        tags: Set(serde_json::to_value(body.tags.clone().unwrap_or_default()).unwrap_or_default()),
        created_at: Set(now),
        updated_at: Set(now),
        // 阶段8 扩展字段
        device_no: Set(body.device_no.clone()),
        location: Set(body.location.clone()),
        weight: Set(body.weight.clone()),
        asset_group_id: Set(body.asset_group_id.clone()),
        network_zone: Set(body.network_zone.clone()),
        business_system: Set(body.business_system.clone()),
        owner: Set(body.owner.clone()),
        contact: Set(body.contact.clone()),
        email: Set(body.email.clone()),
        is_industrial: Set(body.is_industrial.unwrap_or(false)),
        industrial_vendor: Set(body.industrial_vendor.clone()),
        industrial_model: Set(body.industrial_model.clone()),
        industrial_version: Set(body.industrial_version.clone()),
        protection_level: Set(body.protection_level.clone()),
        confidentiality: Set(body.confidentiality.clone()),
        integrity: Set(body.integrity.clone()),
        availability: Set(body.availability.clone()),
        importance: Set(body.importance.clone()),
        // P0-1 补齐字段
        description: Set(body.description.clone()),
        trusted_device: Set(body.trusted_device.unwrap_or(false)),
        industrial_device_type: Set(body.industrial_device_type.clone()),
    };
    match new.insert(&data.db).await {
        Ok(asset) => HttpResponse::Created().json(asset),
        Err(e) => {
            tracing::error!("创建网络资产失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 列出网络资产 GET /api/v1/assets/network
pub async fn list_network_assets(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match NetworkAssetEntity::find()
        .order_by_desc(network_asset::Column::CreatedAt)
        .paginate(&data.db, page_size as u64)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => {
            tracing::error!("查询网络资产列表失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 获取单个网络资产 GET /api/v1/assets/network/{id}
pub async fn get_network_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match NetworkAssetEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(asset)) => HttpResponse::Ok().json(asset),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新网络资产 PUT /api/v1/assets/network/{id}
pub async fn update_network_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateNetworkAssetRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let asset = match NetworkAssetEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: network_asset::ActiveModel = asset.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.ip { active.ip = Set(v.clone()); }
    if let Some(v) = &body.mac { active.mac = Set(Some(v.clone())); }
    if let Some(v) = &body.os { active.os = Set(Some(v.clone())); }
    if let Some(v) = body.risk_score { active.risk_score = Set(v); }
    if let Some(v) = &body.tags { active.tags = Set(serde_json::to_value(v).unwrap_or_default()); }
    // 阶段8 扩展字段
    if let Some(v) = &body.device_no { active.device_no = Set(Some(v.clone())); }
    if let Some(v) = &body.location { active.location = Set(Some(v.clone())); }
    if let Some(v) = &body.weight { active.weight = Set(Some(v.clone())); }
    if let Some(v) = &body.asset_group_id { active.asset_group_id = Set(Some(v.clone())); }
    if let Some(v) = &body.network_zone { active.network_zone = Set(Some(v.clone())); }
    if let Some(v) = &body.business_system { active.business_system = Set(Some(v.clone())); }
    if let Some(v) = &body.owner { active.owner = Set(Some(v.clone())); }
    if let Some(v) = &body.contact { active.contact = Set(Some(v.clone())); }
    if let Some(v) = &body.email { active.email = Set(Some(v.clone())); }
    if let Some(v) = body.is_industrial { active.is_industrial = Set(v); }
    if let Some(v) = &body.industrial_vendor { active.industrial_vendor = Set(Some(v.clone())); }
    if let Some(v) = &body.industrial_model { active.industrial_model = Set(Some(v.clone())); }
    if let Some(v) = &body.industrial_version { active.industrial_version = Set(Some(v.clone())); }
    if let Some(v) = &body.protection_level { active.protection_level = Set(Some(v.clone())); }
    if let Some(v) = &body.confidentiality { active.confidentiality = Set(Some(v.clone())); }
    if let Some(v) = &body.integrity { active.integrity = Set(Some(v.clone())); }
    if let Some(v) = &body.availability { active.availability = Set(Some(v.clone())); }
    if let Some(v) = &body.importance { active.importance = Set(Some(v.clone())); }
    if let Some(v) = &body.description { active.description = Set(Some(v.clone())); }
    if let Some(v) = body.trusted_device { active.trusted_device = Set(v); }
    if let Some(v) = &body.industrial_device_type { active.industrial_device_type = Set(Some(v.clone())); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除网络资产 DELETE /api/v1/assets/network/{id}
pub async fn delete_network_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match NetworkAssetEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 批量删除网络资产 POST /api/v1/assets/network/batch-delete
pub async fn batch_delete_network_assets(
    data: web::Data<AppState>,
    body: web::Json<BatchDeleteRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let mut deleted = 0usize;
    for id in &body.ids {
        if let Ok(res) = NetworkAssetEntity::delete_by_id(id.clone()).exec(&data.db).await {
            if res.rows_affected > 0 { deleted += 1; }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted }))
}

// ==================== 应用资产 ====================

#[derive(Debug, Deserialize)]
pub struct CreateApplicationAssetRequest {
    pub name: String,
    pub url: String,
    pub title: Option<String>,
    pub server_arch: Option<String>,
    // 阶段8 扩展字段
    pub page_encoding: Option<String>,
    pub os: Option<String>,
    pub cert_type: Option<String>,
    pub cert_id: Option<String>,
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub ip: Option<String>,
    pub tags: Option<Vec<String>>,
    pub trusted_device: Option<bool>,
    pub asset_type: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    pub auto_fetch: Option<bool>,
}

/// 创建应用资产 POST /api/v1/assets/application
pub async fn create_application_asset(
    data: web::Data<AppState>,
    body: web::Json<CreateApplicationAssetRequest>,
) -> impl Responder {
    use argus_core::entity::network_asset::AssetStatus;
    use argus_core::entity::application_asset;
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let new = application_asset::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        url: Set(body.url.clone()),
        title: Set(body.title.clone()),
        server_arch: Set(body.server_arch.clone()),
        status: Set(AssetStatus::Unknown),
        risk_score: Set(0.0),
        created_at: Set(now),
        // 阶段8 扩展字段
        page_encoding: Set(body.page_encoding.clone()),
        os: Set(body.os.clone()),
        cert_type: Set(body.cert_type.clone()),
        cert_id: Set(body.cert_id.clone()),
        device_no: Set(body.device_no.clone()),
        location: Set(body.location.clone()),
        weight: Set(body.weight.clone()),
        asset_group_id: Set(body.asset_group_id.clone()),
        business_system: Set(body.business_system.clone()),
        owner: Set(body.owner.clone()),
        contact: Set(body.contact.clone()),
        email: Set(body.email.clone()),
        updated_at: Set(now),
        // P0-1 补齐字段
        description: Set(body.description.clone()),
        ip: Set(body.ip.clone()),
        tags: Set(serde_json::to_value(body.tags.clone().unwrap_or_default()).ok()),
        trusted_device: Set(body.trusted_device.unwrap_or(false)),
        asset_type: Set(body.asset_type.clone()),
        protection_level: Set(body.protection_level.clone()),
        confidentiality: Set(body.confidentiality.clone()),
        integrity: Set(body.integrity.clone()),
        availability: Set(body.availability.clone()),
        importance: Set(body.importance.clone()),
        auto_fetch: Set(body.auto_fetch.unwrap_or(false)),
    };
    match new.insert(&data.db).await {
        Ok(asset) => HttpResponse::Created().json(asset),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 列出应用资产 GET /api/v1/assets/application
pub async fn list_application_assets(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match ApplicationAssetEntity::find()
        .order_by_desc(application_asset::Column::CreatedAt)
        .paginate(&data.db, page_size as u64)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 获取单个应用资产 GET /api/v1/assets/application/{id}
pub async fn get_application_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ApplicationAssetEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(asset)) => HttpResponse::Ok().json(asset),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateApplicationAssetRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub server_arch: Option<String>,
    pub status: Option<String>,
    pub risk_score: Option<f64>,
    pub page_encoding: Option<String>,
    pub os: Option<String>,
    pub cert_type: Option<String>,
    pub cert_id: Option<String>,
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub ip: Option<String>,
    pub tags: Option<Vec<String>>,
    pub trusted_device: Option<bool>,
    pub asset_type: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
    pub auto_fetch: Option<bool>,
}

/// 更新应用资产 PUT /api/v1/assets/application/{id}
pub async fn update_application_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateApplicationAssetRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let asset = match ApplicationAssetEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: application_asset::ActiveModel = asset.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.url { active.url = Set(v.clone()); }
    if let Some(v) = &body.title { active.title = Set(Some(v.clone())); }
    if let Some(v) = &body.server_arch { active.server_arch = Set(Some(v.clone())); }
    if let Some(v) = body.risk_score { active.risk_score = Set(v); }
    if let Some(v) = &body.page_encoding { active.page_encoding = Set(Some(v.clone())); }
    if let Some(v) = &body.os { active.os = Set(Some(v.clone())); }
    if let Some(v) = &body.cert_type { active.cert_type = Set(Some(v.clone())); }
    if let Some(v) = &body.cert_id { active.cert_id = Set(Some(v.clone())); }
    if let Some(v) = &body.device_no { active.device_no = Set(Some(v.clone())); }
    if let Some(v) = &body.location { active.location = Set(Some(v.clone())); }
    if let Some(v) = &body.weight { active.weight = Set(Some(v.clone())); }
    if let Some(v) = &body.asset_group_id { active.asset_group_id = Set(Some(v.clone())); }
    if let Some(v) = &body.business_system { active.business_system = Set(Some(v.clone())); }
    if let Some(v) = &body.owner { active.owner = Set(Some(v.clone())); }
    if let Some(v) = &body.contact { active.contact = Set(Some(v.clone())); }
    if let Some(v) = &body.email { active.email = Set(Some(v.clone())); }
    if let Some(v) = &body.description { active.description = Set(Some(v.clone())); }
    if let Some(v) = &body.ip { active.ip = Set(Some(v.clone())); }
    if let Some(v) = &body.tags { active.tags = Set(serde_json::to_value(v).ok()); }
    if let Some(v) = body.trusted_device { active.trusted_device = Set(v); }
    if let Some(v) = &body.asset_type { active.asset_type = Set(Some(v.clone())); }
    if let Some(v) = &body.protection_level { active.protection_level = Set(Some(v.clone())); }
    if let Some(v) = &body.confidentiality { active.confidentiality = Set(Some(v.clone())); }
    if let Some(v) = &body.integrity { active.integrity = Set(Some(v.clone())); }
    if let Some(v) = &body.availability { active.availability = Set(Some(v.clone())); }
    if let Some(v) = &body.importance { active.importance = Set(Some(v.clone())); }
    if let Some(v) = body.auto_fetch { active.auto_fetch = Set(v); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除应用资产 DELETE /api/v1/assets/application/{id}
pub async fn delete_application_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ApplicationAssetEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 批量删除应用资产 POST /api/v1/assets/application/batch-delete
pub async fn batch_delete_application_assets(
    data: web::Data<AppState>,
    body: web::Json<BatchDeleteRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let mut deleted = 0usize;
    for id in &body.ids {
        if let Ok(res) = ApplicationAssetEntity::delete_by_id(id.clone()).exec(&data.db).await {
            if res.rows_affected > 0 { deleted += 1; }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted }))
}

// ==================== 数据库资产 ====================

#[derive(Debug, Deserialize)]
pub struct CreateDatabaseAssetRequest {
    pub name: String,
    pub ip: String,
    pub db_type: String,
    pub port: i32,
    // 阶段8 扩展字段
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_ssl: Option<bool>,
    pub db_name: Option<String>,
    pub login_verified: Option<bool>,
    pub execute_login_scan: Option<bool>,
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    // P0-1 补齐字段
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub trusted_device: Option<bool>,
    pub asset_type: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
}

/// 创建数据库资产 POST /api/v1/assets/database
pub async fn create_database_asset(
    data: web::Data<AppState>,
    body: web::Json<CreateDatabaseAssetRequest>,
) -> impl Responder {
    use argus_core::entity::network_asset::AssetStatus;
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let new = database_asset::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        ip: Set(body.ip.clone()),
        db_type: Set(body.db_type.clone()),
        port: Set(body.port),
        status: Set(AssetStatus::Unknown),
        risk_score: Set(0.0),
        created_at: Set(now),
        // 阶段8 扩展字段
        username: Set(body.username.clone()),
        password: Set(argus_core::crypto::encrypt_opt(body.password.clone())),
        enable_ssl: Set(body.enable_ssl.unwrap_or(false)),
        db_name: Set(body.db_name.clone()),
        login_verified: Set(body.login_verified.unwrap_or(false)),
        execute_login_scan: Set(body.execute_login_scan.unwrap_or(false)),
        device_no: Set(body.device_no.clone()),
        location: Set(body.location.clone()),
        weight: Set(body.weight.clone()),
        asset_group_id: Set(body.asset_group_id.clone()),
        business_system: Set(body.business_system.clone()),
        owner: Set(body.owner.clone()),
        contact: Set(body.contact.clone()),
        email: Set(body.email.clone()),
        updated_at: Set(now),
        // P0-1 补齐字段
        description: Set(body.description.clone()),
        tags: Set(serde_json::to_value(body.tags.clone().unwrap_or_default()).ok()),
        trusted_device: Set(body.trusted_device.unwrap_or(false)),
        asset_type: Set(body.asset_type.clone()),
        protection_level: Set(body.protection_level.clone()),
        confidentiality: Set(body.confidentiality.clone()),
        integrity: Set(body.integrity.clone()),
        availability: Set(body.availability.clone()),
        importance: Set(body.importance.clone()),
    };
    match new.insert(&data.db).await {
        Ok(asset) => HttpResponse::Created().json(asset),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 列出数据库资产 GET /api/v1/assets/database
pub async fn list_database_assets(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match DatabaseAssetEntity::find()
        .order_by_desc(database_asset::Column::CreatedAt)
        .paginate(&data.db, page_size as u64)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => {
            // 脱敏密码字段
            let masked: Vec<_> = items.into_iter().map(|mut a| { a.password = None; a }).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "items": masked,
                "page": page,
                "page_size": page_size,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 获取单个数据库资产 GET /api/v1/assets/database/{id}
pub async fn get_database_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match DatabaseAssetEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(mut asset)) => {
            asset.password = None; // 脱敏密码字段
            HttpResponse::Ok().json(asset)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateDatabaseAssetRequest {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub db_type: Option<String>,
    pub port: Option<i32>,
    pub status: Option<String>,
    pub risk_score: Option<f64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub enable_ssl: Option<bool>,
    pub db_name: Option<String>,
    pub login_verified: Option<bool>,
    pub execute_login_scan: Option<bool>,
    pub device_no: Option<String>,
    pub location: Option<String>,
    pub weight: Option<String>,
    pub asset_group_id: Option<String>,
    pub business_system: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub trusted_device: Option<bool>,
    pub asset_type: Option<String>,
    pub protection_level: Option<String>,
    pub confidentiality: Option<String>,
    pub integrity: Option<String>,
    pub availability: Option<String>,
    pub importance: Option<String>,
}

/// 更新数据库资产 PUT /api/v1/assets/database/{id}
pub async fn update_database_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateDatabaseAssetRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let asset = match DatabaseAssetEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: database_asset::ActiveModel = asset.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.ip { active.ip = Set(v.clone()); }
    if let Some(v) = &body.db_type { active.db_type = Set(v.clone()); }
    if let Some(v) = body.port { active.port = Set(v); }
    if let Some(v) = body.risk_score { active.risk_score = Set(v); }
    if let Some(v) = &body.username { active.username = Set(Some(v.clone())); }
    if let Some(v) = &body.password { active.password = Set(argus_core::crypto::encrypt_opt(Some(v.clone()))); }
    if let Some(v) = body.enable_ssl { active.enable_ssl = Set(v); }
    if let Some(v) = &body.db_name { active.db_name = Set(Some(v.clone())); }
    if let Some(v) = body.login_verified { active.login_verified = Set(v); }
    if let Some(v) = body.execute_login_scan { active.execute_login_scan = Set(v); }
    if let Some(v) = &body.device_no { active.device_no = Set(Some(v.clone())); }
    if let Some(v) = &body.location { active.location = Set(Some(v.clone())); }
    if let Some(v) = &body.weight { active.weight = Set(Some(v.clone())); }
    if let Some(v) = &body.asset_group_id { active.asset_group_id = Set(Some(v.clone())); }
    if let Some(v) = &body.business_system { active.business_system = Set(Some(v.clone())); }
    if let Some(v) = &body.owner { active.owner = Set(Some(v.clone())); }
    if let Some(v) = &body.contact { active.contact = Set(Some(v.clone())); }
    if let Some(v) = &body.email { active.email = Set(Some(v.clone())); }
    if let Some(v) = &body.description { active.description = Set(Some(v.clone())); }
    if let Some(v) = &body.tags { active.tags = Set(serde_json::to_value(v).ok()); }
    if let Some(v) = body.trusted_device { active.trusted_device = Set(v); }
    if let Some(v) = &body.asset_type { active.asset_type = Set(Some(v.clone())); }
    if let Some(v) = &body.protection_level { active.protection_level = Set(Some(v.clone())); }
    if let Some(v) = &body.confidentiality { active.confidentiality = Set(Some(v.clone())); }
    if let Some(v) = &body.integrity { active.integrity = Set(Some(v.clone())); }
    if let Some(v) = &body.availability { active.availability = Set(Some(v.clone())); }
    if let Some(v) = &body.importance { active.importance = Set(Some(v.clone())); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除数据库资产 DELETE /api/v1/assets/database/{id}
pub async fn delete_database_asset(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match DatabaseAssetEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 批量删除数据库资产 POST /api/v1/assets/database/batch-delete
pub async fn batch_delete_database_assets(
    data: web::Data<AppState>,
    body: web::Json<BatchDeleteRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let mut deleted = 0usize;
    for id in &body.ids {
        if let Ok(res) = DatabaseAssetEntity::delete_by_id(id.clone()).exec(&data.db).await {
            if res.rows_affected > 0 { deleted += 1; }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted }))
}

// ==================== 批量导入导出 ====================

use rust_xlsxwriter::{Workbook, XlsxError};

/// 网络资产导入模板列定义（与手册对齐）
const NETWORK_TEMPLATE_COLUMNS: &[&str] = &[
    "名称", "IP", "MAC", "描述", "设备编号", "位置", "标签(逗号分隔)", "可信设备(是/否)",
    "权重", "资产组名称", "网络区域", "业务系统", "资产类型", "负责人", "联系方式", "邮箱",
    "是否工控(是/否)", "工控设备类型", "工控厂商", "工控型号", "工控版本",
    "等级保护级别", "设备机密性", "设备完整性", "设备可用性", "设备重要性",
];

/// 应用资产导入模板列定义
const APPLICATION_TEMPLATE_COLUMNS: &[&str] = &[
    "网站名称", "网站地址", "描述", "标题", "服务器架构", "IP", "页面编码", "操作系统",
    "证书类型", "证书ID", "设备编号", "位置", "标签(逗号分隔)", "可信设备(是/否)",
    "权重", "资产组名称", "业务系统", "资产类型", "负责人", "联系方式", "邮箱",
    "等级保护级别", "设备机密性", "设备完整性", "设备可用性", "设备重要性", "自动获取网站信息(是/否)",
];

/// 数据库资产导入模板列定义
const DATABASE_TEMPLATE_COLUMNS: &[&str] = &[
    "资产名称", "IP", "描述", "数据库类型", "端口", "用户名", "密码", "启用SSL(是/否)",
    "数据库名", "登录验证(是/否)", "执行登录扫描(是/否)", "设备编号", "位置", "标签(逗号分隔)",
    "可信设备(是/否)", "权重", "资产组名称", "业务系统", "资产类型", "负责人", "联系方式", "邮箱",
    "等级保护级别", "设备机密性", "设备完整性", "设备可用性", "设备重要性",
];

/// 生成 xlsx 模板
fn build_template_xlsx(columns: &[&str]) -> Result<Vec<u8>, XlsxError> {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    for (i, col) in columns.iter().enumerate() {
        ws.write_string(0, i as u16, *col)?;
    }
    wb.save_to_buffer()
}

/// 下载网络资产导入模板 GET /api/v1/assets/network/template
pub async fn download_network_template() -> impl Responder {
    match build_template_xlsx(NETWORK_TEMPLATE_COLUMNS) {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=network_assets_template.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 下载应用资产导入模板 GET /api/v1/assets/application/template
pub async fn download_application_template() -> impl Responder {
    match build_template_xlsx(APPLICATION_TEMPLATE_COLUMNS) {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=application_assets_template.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 下载数据库资产导入模板 GET /api/v1/assets/database/template
pub async fn download_database_template() -> impl Responder {
    match build_template_xlsx(DATABASE_TEMPLATE_COLUMNS) {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=database_assets_template.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

fn cell_to_string(cell: &calamine::Data) -> Option<String> {
    match cell {
        calamine::Data::String(s) => Some(s.clone()),
        calamine::Data::Float(f) => Some(f.to_string()),
        calamine::Data::Int(i) => Some(i.to_string()),
        calamine::Data::Bool(b) => Some(b.to_string()),
        calamine::Data::DateTime(dt) => Some(dt.to_string()),
        _ => None,
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim(), "是" | "true" | "True" | "TRUE" | "1" | "yes" | "Yes" | "YES")
}

fn opt_parse_bool(s: String) -> bool {
    parse_bool(&s)
}

/// 导入网络资产 POST /api/v1/assets/network/import (multipart xlsx)
pub async fn import_network_assets(
    data: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> impl Responder {
    use futures_util::StreamExt;
    let mut file_bytes = Vec::new();
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})),
        };
        while let Some(chunk) = field.next().await {
            if let Ok(bytes) = chunk {
                file_bytes.extend_from_slice(&bytes);
            }
        }
    }
    if file_bytes.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "未收到文件"}));
    }
    let mut reader = match calamine::Xlsx::new(std::io::Cursor::new(file_bytes)) {
        Ok(r) => r,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("xlsx 解析失败: {e}")})),
    };
    use calamine::Reader;
    let sheet = match reader.worksheet_range_at(0) {
        Some(Ok(s)) => s,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无法读取工作表"})),
    };
    let now = chrono::Utc::now();
    let mut imported = 0;
    let mut skipped = 0;
    for row in sheet.rows().skip(1) {
        if row.is_empty() || row.iter().all(|c| matches!(c, calamine::Data::Empty)) {
            continue;
        }
        let name = cell_to_string(row.first().unwrap_or(&calamine::Data::Empty));
        let ip = row.get(1).and_then(cell_to_string);
        let (Some(name), Some(ip)) = (name, ip) else {
            skipped += 1;
            continue;
        };
        let mac = row.get(2).and_then(cell_to_string);
        let description = row.get(3).and_then(cell_to_string);
        let device_no = row.get(4).and_then(cell_to_string);
        let location = row.get(5).and_then(cell_to_string);
        let tags: Vec<String> = row.get(6).and_then(cell_to_string)
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default();
        let trusted_device = row.get(7).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let weight = row.get(8).and_then(cell_to_string);
        let asset_group_name = row.get(9).and_then(cell_to_string);
        let network_zone = row.get(10).and_then(cell_to_string);
        let business_system = row.get(11).and_then(cell_to_string);
        let asset_type_str = row.get(12).and_then(cell_to_string).unwrap_or_else(|| "network".to_string());
        let owner = row.get(13).and_then(cell_to_string);
        let contact = row.get(14).and_then(cell_to_string);
        let email = row.get(15).and_then(cell_to_string);
        let is_industrial = row.get(16).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let industrial_device_type = row.get(17).and_then(cell_to_string);
        let industrial_vendor = row.get(18).and_then(cell_to_string);
        let industrial_model = row.get(19).and_then(cell_to_string);
        let industrial_version = row.get(20).and_then(cell_to_string);
        let protection_level = row.get(21).and_then(cell_to_string);
        let confidentiality = row.get(22).and_then(cell_to_string);
        let integrity = row.get(23).and_then(cell_to_string);
        let availability = row.get(24).and_then(cell_to_string);
        let importance = row.get(25).and_then(cell_to_string);

        let asset_type = match asset_type_str.as_str() {
            "application" => AssetType::Application,
            "database" => AssetType::Database,
            _ => AssetType::Network,
        };
        let new = network_asset::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            name: Set(name),
            ip: Set(ip),
            mac: Set(mac),
            os: Set(None),
            asset_type: Set(asset_type),
            status: Set(AssetStatus::Unknown),
            risk_score: Set(0.0),
            tags: Set(serde_json::to_value(tags).unwrap_or_default()),
            created_at: Set(now),
            updated_at: Set(now),
            device_no: Set(device_no),
            location: Set(location),
            weight: Set(weight),
            asset_group_id: Set(asset_group_name),
            network_zone: Set(network_zone),
            business_system: Set(business_system),
            owner: Set(owner),
            contact: Set(contact),
            email: Set(email),
            is_industrial: Set(is_industrial),
            industrial_vendor: Set(industrial_vendor),
            industrial_model: Set(industrial_model),
            industrial_version: Set(industrial_version),
            protection_level: Set(protection_level),
            confidentiality: Set(confidentiality),
            integrity: Set(integrity),
            availability: Set(availability),
            importance: Set(importance),
            description: Set(description),
            trusted_device: Set(trusted_device),
            industrial_device_type: Set(industrial_device_type),
        };
        if new.insert(&data.db).await.is_ok() {
            imported += 1;
        } else {
            skipped += 1;
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "imported": imported,
        "skipped": skipped,
    }))
}

/// 导出所有网络资产 GET /api/v1/assets/network/export
pub async fn export_network_assets(data: web::Data<AppState>) -> impl Responder {
    let assets = match NetworkAssetEntity::find().all(&data.db).await {
        Ok(a) => a,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    for (i, col) in NETWORK_TEMPLATE_COLUMNS.iter().enumerate() {
        ws.write_string(0, i as u16, *col).ok();
    }
    for (r, a) in assets.iter().enumerate() {
        let row = (r + 1) as u32;
        ws.write_string(row, 0, &a.name).ok();
        ws.write_string(row, 1, &a.ip).ok();
        if let Some(v) = &a.mac { ws.write_string(row, 2, v).ok(); }
        if let Some(v) = &a.description { ws.write_string(row, 3, v).ok(); }
        if let Some(v) = &a.device_no { ws.write_string(row, 4, v).ok(); }
        if let Some(v) = &a.location { ws.write_string(row, 5, v).ok(); }
        ws.write_string(row, 6, a.tags.as_array().map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default()).ok();
        ws.write_string(row, 7, if a.trusted_device { "是" } else { "否" }).ok();
        if let Some(v) = &a.weight { ws.write_string(row, 8, v).ok(); }
        if let Some(v) = &a.asset_group_id { ws.write_string(row, 9, v).ok(); }
        if let Some(v) = &a.network_zone { ws.write_string(row, 10, v).ok(); }
        if let Some(v) = &a.business_system { ws.write_string(row, 11, v).ok(); }
        if let Some(v) = &a.owner { ws.write_string(row, 13, v).ok(); }
        if let Some(v) = &a.contact { ws.write_string(row, 14, v).ok(); }
        if let Some(v) = &a.email { ws.write_string(row, 15, v).ok(); }
        ws.write_string(row, 16, if a.is_industrial { "是" } else { "否" }).ok();
        if let Some(v) = &a.industrial_device_type { ws.write_string(row, 17, v).ok(); }
        if let Some(v) = &a.industrial_vendor { ws.write_string(row, 18, v).ok(); }
        if let Some(v) = &a.industrial_model { ws.write_string(row, 19, v).ok(); }
        if let Some(v) = &a.industrial_version { ws.write_string(row, 20, v).ok(); }
        if let Some(v) = &a.protection_level { ws.write_string(row, 21, v).ok(); }
        if let Some(v) = &a.confidentiality { ws.write_string(row, 22, v).ok(); }
        if let Some(v) = &a.integrity { ws.write_string(row, 23, v).ok(); }
        if let Some(v) = &a.availability { ws.write_string(row, 24, v).ok(); }
        if let Some(v) = &a.importance { ws.write_string(row, 25, v).ok(); }
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=network_assets.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 导入应用资产 POST /api/v1/assets/application/import
pub async fn import_application_assets(
    data: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> impl Responder {
    use futures_util::StreamExt;
    let mut file_bytes = Vec::new();
    while let Some(item) = payload.next().await {
        let mut field = match item { Ok(f) => f, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})) };
        while let Some(chunk) = field.next().await {
            if let Ok(bytes) = chunk { file_bytes.extend_from_slice(&bytes); }
        }
    }
    if file_bytes.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "未收到文件"}));
    }
    let mut reader = match calamine::Xlsx::new(std::io::Cursor::new(file_bytes)) {
        Ok(r) => r, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("xlsx 解析失败: {e}")})),
    };
    use calamine::Reader;
    let sheet = match reader.worksheet_range_at(0) { Some(Ok(s)) => s, _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无法读取工作表"})) };
    let now = chrono::Utc::now();
    let mut imported = 0;
    let mut skipped = 0;
    for row in sheet.rows().skip(1) {
        if row.is_empty() || row.iter().all(|c| matches!(c, calamine::Data::Empty)) { continue; }
        let name = cell_to_string(row.first().unwrap_or(&calamine::Data::Empty));
        let url = row.get(1).and_then(cell_to_string);
        let (Some(name), Some(url)) = (name, url) else { skipped += 1; continue; };
        let description = row.get(2).and_then(cell_to_string);
        let title = row.get(3).and_then(cell_to_string);
        let server_arch = row.get(4).and_then(cell_to_string);
        let ip = row.get(5).and_then(cell_to_string);
        let page_encoding = row.get(6).and_then(cell_to_string);
        let os = row.get(7).and_then(cell_to_string);
        let cert_type = row.get(8).and_then(cell_to_string);
        let cert_id = row.get(9).and_then(cell_to_string);
        let device_no = row.get(10).and_then(cell_to_string);
        let location = row.get(11).and_then(cell_to_string);
        let tags: Vec<String> = row.get(12).and_then(cell_to_string).map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()).unwrap_or_default();
        let trusted_device = row.get(13).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let weight = row.get(14).and_then(cell_to_string);
        let asset_group_id = row.get(15).and_then(cell_to_string);
        let business_system = row.get(16).and_then(cell_to_string);
        let asset_type = row.get(17).and_then(cell_to_string);
        let owner = row.get(18).and_then(cell_to_string);
        let contact = row.get(19).and_then(cell_to_string);
        let email = row.get(20).and_then(cell_to_string);
        let protection_level = row.get(21).and_then(cell_to_string);
        let confidentiality = row.get(22).and_then(cell_to_string);
        let integrity = row.get(23).and_then(cell_to_string);
        let availability = row.get(24).and_then(cell_to_string);
        let importance = row.get(25).and_then(cell_to_string);
        let auto_fetch = row.get(26).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);

        let new = application_asset::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            name: Set(name), url: Set(url), title: Set(title), server_arch: Set(server_arch),
            status: Set(AssetStatus::Unknown), risk_score: Set(0.0), created_at: Set(now),
            page_encoding: Set(page_encoding), os: Set(os), cert_type: Set(cert_type), cert_id: Set(cert_id),
            device_no: Set(device_no), location: Set(location), weight: Set(weight),
            asset_group_id: Set(asset_group_id), business_system: Set(business_system),
            owner: Set(owner), contact: Set(contact), email: Set(email), updated_at: Set(now),
            description: Set(description), ip: Set(ip),
            tags: Set(serde_json::to_value(tags).ok()),
            trusted_device: Set(trusted_device), asset_type: Set(asset_type),
            protection_level: Set(protection_level), confidentiality: Set(confidentiality),
            integrity: Set(integrity), availability: Set(availability), importance: Set(importance),
            auto_fetch: Set(auto_fetch),
        };
        if new.insert(&data.db).await.is_ok() { imported += 1; } else { skipped += 1; }
    }
    HttpResponse::Ok().json(serde_json::json!({ "imported": imported, "skipped": skipped }))
}

/// 导出所有应用资产 GET /api/v1/assets/application/export
pub async fn export_application_assets(data: web::Data<AppState>) -> impl Responder {
    let assets = match ApplicationAssetEntity::find().all(&data.db).await {
        Ok(a) => a, Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    for (i, col) in APPLICATION_TEMPLATE_COLUMNS.iter().enumerate() {
        ws.write_string(0, i as u16, *col).ok();
    }
    for (r, a) in assets.iter().enumerate() {
        let row = (r + 1) as u32;
        ws.write_string(row, 0, &a.name).ok();
        ws.write_string(row, 1, &a.url).ok();
        if let Some(v) = &a.description { ws.write_string(row, 2, v).ok(); }
        if let Some(v) = &a.title { ws.write_string(row, 3, v).ok(); }
        if let Some(v) = &a.server_arch { ws.write_string(row, 4, v).ok(); }
        if let Some(v) = &a.ip { ws.write_string(row, 5, v).ok(); }
        if let Some(v) = &a.page_encoding { ws.write_string(row, 6, v).ok(); }
        if let Some(v) = &a.os { ws.write_string(row, 7, v).ok(); }
        if let Some(v) = &a.cert_type { ws.write_string(row, 8, v).ok(); }
        if let Some(v) = &a.cert_id { ws.write_string(row, 9, v).ok(); }
        if let Some(v) = &a.device_no { ws.write_string(row, 10, v).ok(); }
        if let Some(v) = &a.location { ws.write_string(row, 11, v).ok(); }
        if let Some(tags) = &a.tags { ws.write_string(row, 12, tags.as_array().map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default()).ok(); }
        ws.write_string(row, 13, if a.trusted_device { "是" } else { "否" }).ok();
        if let Some(v) = &a.weight { ws.write_string(row, 14, v).ok(); }
        if let Some(v) = &a.asset_group_id { ws.write_string(row, 15, v).ok(); }
        if let Some(v) = &a.business_system { ws.write_string(row, 16, v).ok(); }
        if let Some(v) = &a.asset_type { ws.write_string(row, 17, v).ok(); }
        if let Some(v) = &a.owner { ws.write_string(row, 18, v).ok(); }
        if let Some(v) = &a.contact { ws.write_string(row, 19, v).ok(); }
        if let Some(v) = &a.email { ws.write_string(row, 20, v).ok(); }
        if let Some(v) = &a.protection_level { ws.write_string(row, 21, v).ok(); }
        if let Some(v) = &a.confidentiality { ws.write_string(row, 22, v).ok(); }
        if let Some(v) = &a.integrity { ws.write_string(row, 23, v).ok(); }
        if let Some(v) = &a.availability { ws.write_string(row, 24, v).ok(); }
        if let Some(v) = &a.importance { ws.write_string(row, 25, v).ok(); }
        ws.write_string(row, 26, if a.auto_fetch { "是" } else { "否" }).ok();
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=application_assets.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 导入数据库资产 POST /api/v1/assets/database/import
pub async fn import_database_assets(
    data: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> impl Responder {
    use futures_util::StreamExt;
    let mut file_bytes = Vec::new();
    while let Some(item) = payload.next().await {
        let mut field = match item { Ok(f) => f, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})) };
        while let Some(chunk) = field.next().await {
            if let Ok(bytes) = chunk { file_bytes.extend_from_slice(&bytes); }
        }
    }
    if file_bytes.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "未收到文件"}));
    }
    let mut reader = match calamine::Xlsx::new(std::io::Cursor::new(file_bytes)) {
        Ok(r) => r, Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("xlsx 解析失败: {e}")})),
    };
    use calamine::Reader;
    let sheet = match reader.worksheet_range_at(0) { Some(Ok(s)) => s, _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无法读取工作表"})) };
    let now = chrono::Utc::now();
    let mut imported = 0;
    let mut skipped = 0;
    for row in sheet.rows().skip(1) {
        if row.is_empty() || row.iter().all(|c| matches!(c, calamine::Data::Empty)) { continue; }
        let name = cell_to_string(row.first().unwrap_or(&calamine::Data::Empty));
        let ip = row.get(1).and_then(cell_to_string);
        let (Some(name), Some(ip)) = (name, ip) else { skipped += 1; continue; };
        let description = row.get(2).and_then(cell_to_string);
        let db_type = row.get(3).and_then(cell_to_string).unwrap_or_else(|| "mysql".to_string());
        let port = row.get(4).and_then(cell_to_string).and_then(|s| s.parse().ok()).unwrap_or(3306);
        let username = row.get(5).and_then(cell_to_string);
        let password = row.get(6).and_then(cell_to_string);
        let enable_ssl = row.get(7).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let db_name = row.get(8).and_then(cell_to_string);
        let login_verified = row.get(9).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let execute_login_scan = row.get(10).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let device_no = row.get(11).and_then(cell_to_string);
        let location = row.get(12).and_then(cell_to_string);
        let tags: Vec<String> = row.get(13).and_then(cell_to_string).map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect()).unwrap_or_default();
        let trusted_device = row.get(14).and_then(cell_to_string).map(opt_parse_bool).unwrap_or(false);
        let weight = row.get(15).and_then(cell_to_string);
        let asset_group_id = row.get(16).and_then(cell_to_string);
        let business_system = row.get(17).and_then(cell_to_string);
        let asset_type = row.get(18).and_then(cell_to_string);
        let owner = row.get(19).and_then(cell_to_string);
        let contact = row.get(20).and_then(cell_to_string);
        let email = row.get(21).and_then(cell_to_string);
        let protection_level = row.get(22).and_then(cell_to_string);
        let confidentiality = row.get(23).and_then(cell_to_string);
        let integrity = row.get(24).and_then(cell_to_string);
        let availability = row.get(25).and_then(cell_to_string);
        let importance = row.get(26).and_then(cell_to_string);

        let new = database_asset::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            name: Set(name), ip: Set(ip), db_type: Set(db_type), port: Set(port),
            status: Set(AssetStatus::Unknown), risk_score: Set(0.0), created_at: Set(now),
            username: Set(username), password: Set(argus_core::crypto::encrypt_opt(password)), enable_ssl: Set(enable_ssl),
            db_name: Set(db_name), login_verified: Set(login_verified),
            execute_login_scan: Set(execute_login_scan),
            device_no: Set(device_no), location: Set(location), weight: Set(weight),
            asset_group_id: Set(asset_group_id), business_system: Set(business_system),
            owner: Set(owner), contact: Set(contact), email: Set(email), updated_at: Set(now),
            description: Set(description),
            tags: Set(serde_json::to_value(tags).ok()),
            trusted_device: Set(trusted_device), asset_type: Set(asset_type),
            protection_level: Set(protection_level), confidentiality: Set(confidentiality),
            integrity: Set(integrity), availability: Set(availability), importance: Set(importance),
        };
        if new.insert(&data.db).await.is_ok() { imported += 1; } else { skipped += 1; }
    }
    HttpResponse::Ok().json(serde_json::json!({ "imported": imported, "skipped": skipped }))
}

/// 导出所有数据库资产 GET /api/v1/assets/database/export
pub async fn export_database_assets(data: web::Data<AppState>) -> impl Responder {
    let assets = match DatabaseAssetEntity::find().all(&data.db).await {
        Ok(a) => a, Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    for (i, col) in DATABASE_TEMPLATE_COLUMNS.iter().enumerate() {
        ws.write_string(0, i as u16, *col).ok();
    }
    for (r, a) in assets.iter().enumerate() {
        let row = (r + 1) as u32;
        ws.write_string(row, 0, &a.name).ok();
        ws.write_string(row, 1, &a.ip).ok();
        if let Some(v) = &a.description { ws.write_string(row, 2, v).ok(); }
        ws.write_string(row, 3, &a.db_type).ok();
        ws.write_number(row, 4, a.port as f64).ok();
        if let Some(v) = &a.username { ws.write_string(row, 5, v).ok(); }
        // 出于安全考虑，导出时不包含密码明文，留空由用户重新填写
        ws.write_string(row, 6, "").ok();
        ws.write_string(row, 7, if a.enable_ssl { "是" } else { "否" }).ok();
        if let Some(v) = &a.db_name { ws.write_string(row, 8, v).ok(); }
        ws.write_string(row, 9, if a.login_verified { "是" } else { "否" }).ok();
        ws.write_string(row, 10, if a.execute_login_scan { "是" } else { "否" }).ok();
        if let Some(v) = &a.device_no { ws.write_string(row, 11, v).ok(); }
        if let Some(v) = &a.location { ws.write_string(row, 12, v).ok(); }
        if let Some(tags) = &a.tags { ws.write_string(row, 13, tags.as_array().map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default()).ok(); }
        ws.write_string(row, 14, if a.trusted_device { "是" } else { "否" }).ok();
        if let Some(v) = &a.weight { ws.write_string(row, 15, v).ok(); }
        if let Some(v) = &a.asset_group_id { ws.write_string(row, 16, v).ok(); }
        if let Some(v) = &a.business_system { ws.write_string(row, 17, v).ok(); }
        if let Some(v) = &a.asset_type { ws.write_string(row, 18, v).ok(); }
        if let Some(v) = &a.owner { ws.write_string(row, 19, v).ok(); }
        if let Some(v) = &a.contact { ws.write_string(row, 20, v).ok(); }
        if let Some(v) = &a.email { ws.write_string(row, 21, v).ok(); }
        if let Some(v) = &a.protection_level { ws.write_string(row, 22, v).ok(); }
        if let Some(v) = &a.confidentiality { ws.write_string(row, 23, v).ok(); }
        if let Some(v) = &a.integrity { ws.write_string(row, 24, v).ok(); }
        if let Some(v) = &a.availability { ws.write_string(row, 25, v).ok(); }
        if let Some(v) = &a.importance { ws.write_string(row, 26, v).ok(); }
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=database_assets.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
