//! 分布式节点管理 API
//!
//! 阶段8 第四批：增强分布式探针
//! - 节点拓扑图（上下级关系）
//! - 心跳上报（含 CPU/内存/硬盘使用率、版本信息）
//! - 免密登录（返回临时 token）
//! - 节点资源监控

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use argus_core::entity::scan_node::{self, Entity as ScanNodeEntity};
use sea_orm::{ActiveModelTrait, EntityTrait, ActiveValue::Set};
use crate::state::AppState;

/// 默认心跳间隔（秒）
const DEFAULT_HEARTBEAT_INTERVAL_SECS: i64 = 30;
/// 超过多少个心跳间隔未上报则标记为 offline
const OFFLINE_THRESHOLD_INTERVALS: i64 = 2;

#[derive(Debug, Deserialize)]
pub struct RegisterNodeRequest {
    pub endpoint: String,
    pub name: Option<String>,
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeResponse {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub status: String,
    pub capabilities: serde_json::Value,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub parent_id: Option<String>,
    pub organization: Option<String>,
}

pub async fn register_node(
    data: web::Data<AppState>,
    body: web::Json<RegisterNodeRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let model = scan_node::ActiveModel {
        id: Set(id.clone()),
        name: Set(body.name.clone().unwrap_or_else(|| format!("node-{}", &id[..8]))),
        endpoint: Set(body.endpoint.clone()),
        region: Set(None),
        status: Set("registered".to_string()),
        capabilities: Set(serde_json::to_value(body.capabilities.clone().unwrap_or_default()).unwrap_or_default()),
        max_concurrent: Set(4),
        current_load: Set(0),
        last_heartbeat: Set(Some(now)),
        registered_at: Set(now),
        metadata: Set(None),
        parent_id: Set(body.parent_id.clone()),
        organization: Set(body.organization.clone()),
        token: Set(None),
        login_url: Set(None),
        docker_node_id: Set(None),
        cpu_usage: Set(None),
        memory_usage: Set(None),
        disk_usage: Set(None),
        system_version: Set(None),
        rule_version: Set(None),
        last_heartbeat_at: Set(Some(now)),
    };
    match model.insert(&data.db).await {
        Ok(m) => HttpResponse::Created().json(serde_json::json!({
            "id": m.id,
            "name": m.name,
            "endpoint": m.endpoint,
            "status": m.status,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("注册失败: {e}")})),
    }
}

pub async fn list_nodes(data: web::Data<AppState>) -> impl Responder {
    let nodes = ScanNodeEntity::find().all(&data.db).await.unwrap_or_default();
    let resp: Vec<NodeResponse> = nodes.into_iter().map(|n| NodeResponse {
        id: n.id,
        name: n.name,
        endpoint: n.endpoint,
        status: n.status,
        capabilities: n.capabilities,
        last_heartbeat: n.last_heartbeat,
        parent_id: n.parent_id,
        organization: n.organization,
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({"total": resp.len(), "nodes": resp}))
}

pub async fn get_node(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ScanNodeEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(n)) => HttpResponse::Ok().json(n),
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    }
}

pub async fn delete_node(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ScanNodeEntity::delete_by_id(id.clone()).exec(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "节点已删除", "id": id})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("删除失败: {e}")})),
    }
}

// ==================== 阶段8 第四批：节点拓扑 ====================

/// 拓扑树节点
#[derive(Debug, Serialize)]
pub struct TopologyNode {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub status: String,
    pub parent_id: Option<String>,
    pub children: Vec<TopologyNode>,
}

/// GET /api/v1/nodes/{id}/topology - 获取节点拓扑图
/// 以指定节点为根，返回其所有下级节点的树形结构
pub async fn get_node_topology(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let root_id = path.into_inner();

    // 获取根节点
    let root = match ScanNodeEntity::find_by_id(root_id.clone()).one(&data.db).await {
        Ok(Some(n)) => n,
        _ => return HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    };

    // 获取所有节点
    let all_nodes = match ScanNodeEntity::find().all(&data.db).await {
        Ok(nodes) => nodes,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("查询节点失败: {e}")
            }));
        }
    };

    // 构建以 root_id 为根的树
    let tree = build_topology_tree(&root_id, &all_nodes);

    HttpResponse::Ok().json(serde_json::json!({
        "root_id": root.id,
        "topology": tree,
    }))
}

/// 递归构建拓扑树
fn build_topology_tree(root_id: &str, all_nodes: &[scan_node::Model]) -> Option<TopologyNode> {
    let root = all_nodes.iter().find(|n| n.id == root_id)?;

    let children: Vec<TopologyNode> = all_nodes
        .iter()
        .filter(|n| n.parent_id.as_deref() == Some(root_id))
        .filter_map(|n| build_topology_tree(&n.id, all_nodes))
        .collect();

    Some(TopologyNode {
        id: root.id.clone(),
        name: root.name.clone(),
        endpoint: root.endpoint.clone(),
        status: root.status.clone(),
        parent_id: root.parent_id.clone(),
        children,
    })
}

// ==================== 阶段8 第四批：心跳上报增强 ====================

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub status: Option<String>,
    /// CPU 使用率（0-100）
    pub cpu_usage: Option<f64>,
    /// 内存使用率（0-100）
    pub memory_usage: Option<f64>,
    /// 硬盘使用率（0-100）
    pub disk_usage: Option<f64>,
    /// 系统版本
    pub system_version: Option<String>,
    /// 规则版本
    pub rule_version: Option<String>,
    /// 当前负载
    pub current_load: Option<i32>,
}

/// POST /api/v1/nodes/{id}/heartbeat - 节点心跳上报
pub async fn heartbeat(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<HeartbeatRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let now = chrono::Utc::now();

    match ScanNodeEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(n)) => {
            let mut active: scan_node::ActiveModel = n.into();
            active.last_heartbeat = Set(Some(now));
            active.last_heartbeat_at = Set(Some(now));

            if let Some(ref status) = body.status {
                active.status = Set(status.clone());
            } else {
                // 默认设为 online
                active.status = Set("online".to_string());
            }
            if let Some(cpu) = body.cpu_usage {
                active.cpu_usage = Set(Some(cpu));
            }
            if let Some(mem) = body.memory_usage {
                active.memory_usage = Set(Some(mem));
            }
            if let Some(disk) = body.disk_usage {
                active.disk_usage = Set(Some(disk));
            }
            if let Some(ref sv) = body.system_version {
                active.system_version = Set(Some(sv.clone()));
            }
            if let Some(ref rv) = body.rule_version {
                active.rule_version = Set(Some(rv.clone()));
            }
            if let Some(load) = body.current_load {
                active.current_load = Set(load);
            }

            match active.update(&data.db).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                    "ok": true,
                    "node_id": id,
                    "timestamp": now.to_rfc3339(),
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            }
        }
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    }
}

// ==================== 阶段8 第四批：免密登录 ====================

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// 登录后跳转 URL（可选）
    pub redirect_url: Option<String>,
}

/// POST /api/v1/nodes/{id}/login - 免密登录（返回临时 token）
pub async fn node_login(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<LoginRequest>,
) -> impl Responder {
    let id = path.into_inner();

    match ScanNodeEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(n)) => {
            // 生成临时 token（UUID，有效期可由调用方控制）
            let temp_token = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now();
            let expire_at = now + chrono::Duration::hours(1);
            let endpoint = n.endpoint.clone();

            // 将临时 token 存入节点 token 字段
            let mut active: scan_node::ActiveModel = n.into();
            active.token = Set(Some(temp_token.clone()));
            active.last_heartbeat_at = Set(Some(now));

            if let Err(e) = active.update(&data.db).await {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("更新节点 token 失败: {e}")
                }));
            }

            // 构造登录 URL
            let login_url = if let Some(redirect) = &body.redirect_url {
                redirect.clone()
            } else {
                format!("{}/login?token={}", endpoint.trim_end_matches('/'), temp_token)
            };

            HttpResponse::Ok().json(serde_json::json!({
                "node_id": id,
                "token": temp_token,
                "login_url": login_url,
                "expire_at": expire_at.to_rfc3339(),
            }))
        }
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    }
}

// ==================== 阶段8 第四批：节点资源监控 ====================

/// GET /api/v1/nodes/{id}/resources - 节点资源监控
pub async fn get_node_resources(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();

    match ScanNodeEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(n)) => {
            // 判断节点是否在线
            let now = chrono::Utc::now();
            let offline = match n.last_heartbeat_at {
                Some(hb) => {
                    let elapsed = (now - hb).num_seconds();
                    elapsed > DEFAULT_HEARTBEAT_INTERVAL_SECS * OFFLINE_THRESHOLD_INTERVALS
                }
                None => true,
            };

            let status = if offline { "offline" } else { &n.status };

            HttpResponse::Ok().json(serde_json::json!({
                "node_id": id,
                "name": n.name,
                "status": status,
                "cpu_usage": n.cpu_usage,
                "memory_usage": n.memory_usage,
                "disk_usage": n.disk_usage,
                "system_version": n.system_version,
                "rule_version": n.rule_version,
                "current_load": n.current_load,
                "max_concurrent": n.max_concurrent,
                "last_heartbeat_at": n.last_heartbeat_at,
                "offline_threshold_secs": DEFAULT_HEARTBEAT_INTERVAL_SECS * OFFLINE_THRESHOLD_INTERVALS,
            }))
        }
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    }
}

// ==================== 内部接口（节点用） ====================

#[derive(Debug, Deserialize)]
pub struct InternalHeartbeatRequest {
    pub node_id: String,
    pub status: Option<String>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    pub system_version: Option<String>,
    pub rule_version: Option<String>,
}

pub async fn node_heartbeat(
    data: web::Data<AppState>,
    body: web::Json<InternalHeartbeatRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    match ScanNodeEntity::find_by_id(body.node_id.clone()).one(&data.db).await {
        Ok(Some(n)) => {
            let mut active: scan_node::ActiveModel = n.into();
            active.last_heartbeat = Set(Some(now));
            active.last_heartbeat_at = Set(Some(now));
            if let Some(ref status) = body.status {
                active.status = Set(status.clone());
            } else {
                active.status = Set("online".to_string());
            }
            if let Some(cpu) = body.cpu_usage {
                active.cpu_usage = Set(Some(cpu));
            }
            if let Some(mem) = body.memory_usage {
                active.memory_usage = Set(Some(mem));
            }
            if let Some(disk) = body.disk_usage {
                active.disk_usage = Set(Some(disk));
            }
            if let Some(ref sv) = body.system_version {
                active.system_version = Set(Some(sv.clone()));
            }
            if let Some(ref rv) = body.rule_version {
                active.rule_version = Set(Some(rv.clone()));
            }
            match active.update(&data.db).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            }
        }
        _ => HttpResponse::NotFound().json(serde_json::json!({"error": "节点未找到"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_topology_tree() {
        use argus_core::entity::scan_node::Model;
        let now = chrono::Utc::now();
        let make_node = |id: &str, parent: Option<&str>| -> Model {
            Model {
                id: id.to_string(),
                name: id.to_string(),
                endpoint: format!("http://{}:8090", id),
                region: None,
                status: "online".to_string(),
                capabilities: serde_json::json!([]),
                max_concurrent: 4,
                current_load: 0,
                last_heartbeat: Some(now),
                registered_at: now,
                metadata: None,
                parent_id: parent.map(|s| s.to_string()),
                organization: None,
                token: None,
                login_url: None,
                docker_node_id: None,
                cpu_usage: None,
                memory_usage: None,
                disk_usage: None,
                system_version: None,
                rule_version: None,
                last_heartbeat_at: Some(now),
            }
        };

        let nodes = vec![
            make_node("root", None),
            make_node("child1", Some("root")),
            make_node("child2", Some("root")),
            make_node("grandchild", Some("child1")),
        ];

        let tree = build_topology_tree("root", &nodes).unwrap();
        assert_eq!(tree.id, "root");
        assert_eq!(tree.children.len(), 2);

        // child1 有一个子节点
        let child1 = tree.children.iter().find(|c| c.id == "child1").unwrap();
        assert_eq!(child1.children.len(), 1);
        assert_eq!(child1.children[0].id, "grandchild");
    }
}
