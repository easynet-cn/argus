//! 资产组 / 资产属性管理 API

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::asset_group::{self, Entity as AssetGroupEntity};
use argus_core::entity::asset_attribute::{self, AttrType, Entity as AssetAttributeEntity};
use argus_core::entity::network_asset::{self, Entity as NetworkAssetEntity};
use crate::state::AppState;
use crate::handler::asset::ListQuery;

// ==================== 资产组 ====================

#[derive(Debug, Deserialize)]
pub struct CreateAssetGroupRequest {
    pub name: String,
    pub parent_id: Option<String>,
    pub ip_range: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAssetGroupRequest {
    pub name: Option<String>,
    pub parent_id: Option<String>,
    pub ip_range: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub email: Option<String>,
    pub location: Option<String>,
}

/// 创建资产组 POST /api/v1/asset-groups
pub async fn create_asset_group(
    data: web::Data<AppState>,
    body: web::Json<CreateAssetGroupRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let new = asset_group::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        parent_id: Set(body.parent_id.clone()),
        ip_range: Set(body.ip_range.clone()),
        owner: Set(body.owner.clone()),
        contact: Set(body.contact.clone()),
        email: Set(body.email.clone()),
        location: Set(body.location.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(g) => HttpResponse::Created().json(g),
        Err(e) => {
            tracing::error!("创建资产组失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 列出资产组（扁平列表）GET /api/v1/asset-groups
pub async fn list_asset_groups(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 500);
    match AssetGroupEntity::find()
        .order_by_asc(asset_group::Column::Name)
        .paginate(&data.db, page_size)
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

/// 资产组树形查询 GET /api/v1/asset-groups/tree
#[derive(Debug, Serialize)]
pub struct AssetGroupNode {
    #[serde(flatten)]
    pub group: asset_group::Model,
    pub children: Vec<AssetGroupNode>,
}

pub async fn get_asset_group_tree(data: web::Data<AppState>) -> impl Responder {
    let all = match AssetGroupEntity::find()
        .order_by_asc(asset_group::Column::Name)
        .all(&data.db)
        .await
    {
        Ok(g) => g,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 构建树：根节点为 parent_id 为 None 的
    fn build_tree(groups: &[asset_group::Model], parent_id: Option<&str>) -> Vec<AssetGroupNode> {
        groups
            .iter()
            .filter(|g| g.parent_id.as_deref() == parent_id)
            .map(|g| AssetGroupNode {
                group: g.clone(),
                children: build_tree(groups, Some(&g.id)),
            })
            .collect()
    }

    let tree = build_tree(&all, None);
    HttpResponse::Ok().json(serde_json::json!({ "items": tree }))
}

/// 资产组详情 GET /api/v1/asset-groups/{id}
pub async fn get_asset_group(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match AssetGroupEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(g)) => HttpResponse::Ok().json(g),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产组未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新资产组 PUT /api/v1/asset-groups/{id}
pub async fn update_asset_group(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateAssetGroupRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let g = match AssetGroupEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(g)) => g,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "资产组未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: asset_group::ActiveModel = g.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.parent_id { active.parent_id = Set(Some(v.clone())); }
    if let Some(v) = &body.ip_range { active.ip_range = Set(Some(v.clone())); }
    if let Some(v) = &body.owner { active.owner = Set(Some(v.clone())); }
    if let Some(v) = &body.contact { active.contact = Set(Some(v.clone())); }
    if let Some(v) = &body.email { active.email = Set(Some(v.clone())); }
    if let Some(v) = &body.location { active.location = Set(Some(v.clone())); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除资产组 DELETE /api/v1/asset-groups/{id}
pub async fn delete_asset_group(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    // 若存在子组则拒绝删除
    let child_count = AssetGroupEntity::find()
        .filter(asset_group::Column::ParentId.eq(id.clone()))
        .count(&data.db)
        .await
        .unwrap_or(0);
    if child_count > 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "该资产组下存在子组，请先删除子组"
        }));
    }
    match AssetGroupEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "资产组未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 按组查看资产 GET /api/v1/asset-groups/{id}/assets
pub async fn list_assets_by_group(
    data: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let id = path.into_inner();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match NetworkAssetEntity::find()
        .filter(network_asset::Column::AssetGroupId.eq(id))
        .order_by_desc(network_asset::Column::CreatedAt)
        .paginate(&data.db, page_size)
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

/// 组内快捷扫描 POST /api/v1/asset-groups/{id}/scan
///
/// 对组内所有资产发起端口扫描（复用扫描引擎 registry）。
#[derive(Debug, Deserialize)]
pub struct GroupScanRequest {
    pub ports: Option<String>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
}

pub async fn scan_asset_group(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<GroupScanRequest>,
) -> impl Responder {
    let group_id = path.into_inner();

    // 取出组内资产 IP
    let assets = match NetworkAssetEntity::find()
        .filter(network_asset::Column::AssetGroupId.eq(group_id.clone()))
        .all(&data.db)
        .await
    {
        Ok(a) => a,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    if assets.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "message": "资产组内无资产",
            "scanned": 0,
        }));
    }

    // 调用端口扫描引擎
    let scanner = match data.registry.get("port_scanner") {
        Some(s) => s,
        None => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "端口扫描引擎未注册"})),
    };

    let task_id = uuid::Uuid::new_v4().to_string();
    let targets: Vec<argus_scanner::Target> = assets
        .iter()
        .map(|a| argus_scanner::Target {
            host: a.ip.clone(),
            ports: None,
            credentials: None,
        })
        .collect();

    let extra_params = serde_json::json!({
        "ports": body.ports.as_ref().and_then(|p| {
            argus_portscanner::port_list::parse_port_range(p).ok()
        }),
        "concurrency": body.concurrency.unwrap_or(500),
        "timeout_ms": body.timeout_ms.unwrap_or(1000),
        "scan_udp": false,
        "fingerprint": true,
    });

    let scan_config = argus_scanner::ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(500),
        timeout_secs: body.timeout_ms.unwrap_or(1000) / 1000,
        extra_params,
    };

    // 异步执行扫描
    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    tokio::spawn(async move {
        match scanner.execute(&scan_config).await {
            Ok(r) => {
                tracing::info!(
                    "资产组扫描任务 {} 完成，扫描主机 {} 台，发现 {} 个结果",
                    task_id_bg,
                    r.hosts_scanned,
                    r.vulnerabilities.len()
                );
                let _ = db;
            }
            Err(e) => {
                tracing::error!("资产组扫描任务 {} 失败: {e}", task_id_bg);
            }
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "message": "扫描已启动",
        "target_count": assets.len(),
    }))
}

// ==================== 资产属性 ====================

#[derive(Debug, Deserialize)]
pub struct CreateAttributeRequest {
    pub name: String,
    pub attr_type: String, // tag / business_system / asset_type
    pub description: Option<String>,
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAttributeRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttributeListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub attr_type: Option<String>,
}

fn parse_attr_type(s: &str) -> AttrType {
    match s {
        "business_system" => AttrType::BusinessSystem,
        "asset_type" => AttrType::AssetType,
        _ => AttrType::Tag,
    }
}

/// 创建资产属性 POST /api/v1/asset-attributes
pub async fn create_attribute(
    data: web::Data<AppState>,
    body: web::Json<CreateAttributeRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let attr_type = parse_attr_type(&body.attr_type);
    let new = asset_attribute::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        attr_type: Set(attr_type),
        description: Set(body.description.clone()),
        icon: Set(body.icon.clone()),
        created_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(a) => HttpResponse::Created().json(a),
        Err(e) => {
            tracing::error!("创建资产属性失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 列出资产属性 GET /api/v1/asset-attributes
pub async fn list_attributes(
    data: web::Data<AppState>,
    query: web::Query<AttributeListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 500);
    let mut q = AssetAttributeEntity::find();
    if let Some(t) = &query.attr_type {
        q = q.filter(asset_attribute::Column::AttrType.eq(parse_attr_type(t)));
    }
    match q
        .order_by_asc(asset_attribute::Column::Name)
        .paginate(&data.db, page_size)
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

/// 资产属性详情 GET /api/v1/asset-attributes/{id}
pub async fn get_attribute(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match AssetAttributeEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(a)) => HttpResponse::Ok().json(a),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "属性未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新资产属性 PUT /api/v1/asset-attributes/{id}
pub async fn update_attribute(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateAttributeRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let a = match AssetAttributeEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "属性未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };
    let mut active: asset_attribute::ActiveModel = a.into();
    if let Some(v) = &body.name { active.name = Set(v.clone()); }
    if let Some(v) = &body.description { active.description = Set(Some(v.clone())); }
    if let Some(v) = &body.icon { active.icon = Set(Some(v.clone())); }
    match active.update(&data.db).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除资产属性 DELETE /api/v1/asset-attributes/{id}
pub async fn delete_attribute(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match AssetAttributeEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "属性未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
