//! 工控设备信息库 API

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use argus_core::entity::ics_device_library::{self, Entity as IcsLibEntity};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, ActiveValue::Set};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IcsDeviceRequest {
    pub vendor: String,
    pub model: String,
    pub device_type: String,
    pub protocol: String,
    pub default_port: i32,
    pub firmware: Option<String>,
    pub os: Option<String>,
    pub known_cves: Option<serde_json::Value>,
    pub fingerprint: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

/// 列表 GET /api/v1/templates/ics-devices
pub async fn list_ics_devices(
    data: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let page: u64 = query.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: u64 = query.get("page_size").and_then(|v| v.parse().ok()).unwrap_or(20);

    let mut q = IcsLibEntity::find();
    if let Some(vendor) = query.get("vendor") {
        q = q.filter(ics_device_library::Column::Vendor.contains(vendor.as_str()));
    }
    if let Some(protocol) = query.get("protocol") {
        q = q.filter(ics_device_library::Column::Protocol.eq(protocol.as_str()));
    }
    if let Some(device_type) = query.get("device_type") {
        q = q.filter(ics_device_library::Column::DeviceType.eq(device_type.as_str()));
    }
    if let Some(enabled) = query.get("enabled") {
        q = q.filter(ics_device_library::Column::Enabled.eq(enabled == "true"));
    }

    let paginator = q
        .order_by_asc(ics_device_library::Column::Vendor)
        .paginate(&data.db, page_size);

    let total = paginator.num_items().await.unwrap_or(0);
    let items = match paginator.fetch_page(page - 1).await {
        Ok(i) => i,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": items,
    }))
}

/// 详情 GET /api/v1/templates/ics-devices/{id}
pub async fn get_ics_device(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match IcsLibEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(d)) => HttpResponse::Ok().json(d),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "设备不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建 POST /api/v1/templates/ics-devices
pub async fn create_ics_device(
    data: web::Data<AppState>,
    body: web::Json<IcsDeviceRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let id = uuid::Uuid::new_v4().to_string();

    let active = ics_device_library::ActiveModel {
        id: Set(id),
        vendor: Set(body.vendor.clone()),
        model: Set(body.model.clone()),
        device_type: Set(body.device_type.clone()),
        protocol: Set(body.protocol.clone()),
        default_port: Set(body.default_port),
        firmware: Set(body.firmware.clone()),
        os: Set(body.os.clone()),
        known_cves: Set(body.known_cves.clone()),
        fingerprint: Set(body.fingerprint.clone()),
        description: Set(body.description.clone()),
        enabled: Set(body.enabled.unwrap_or(true)),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match active.insert(&data.db).await {
        Ok(d) => HttpResponse::Ok().json(d),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新 PUT /api/v1/templates/ics-devices/{id}
pub async fn update_ics_device(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<IcsDeviceRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match IcsLibEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(d)) => d,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "设备不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: ics_device_library::ActiveModel = existing.into();
    active.vendor = Set(body.vendor.clone());
    active.model = Set(body.model.clone());
    active.device_type = Set(body.device_type.clone());
    active.protocol = Set(body.protocol.clone());
    active.default_port = Set(body.default_port);
    active.firmware = Set(body.firmware.clone());
    active.os = Set(body.os.clone());
    active.known_cves = Set(body.known_cves.clone());
    active.fingerprint = Set(body.fingerprint.clone());
    active.description = Set(body.description.clone());
    active.enabled = Set(body.enabled.unwrap_or(true));
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(d) => HttpResponse::Ok().json(d),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除 DELETE /api/v1/templates/ics-devices/{id}
pub async fn delete_ics_device(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match IcsLibEntity::delete_by_id(id).exec(&data.db).await {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已删除"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "设备不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
