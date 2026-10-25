//! 节点注册表（内存 + DB 同步）

use crate::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use sea_orm::{DatabaseConnection, EntityTrait, Set, QueryFilter, ColumnTrait};
use argus_core::entity::scan_node;
use chrono::Utc;

pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    db: Option<DatabaseConnection>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self { nodes: Arc::new(RwLock::new(HashMap::new())), db: None }
    }
    
    pub fn with_db(db: DatabaseConnection) -> Self {
        Self { nodes: Arc::new(RwLock::new(HashMap::new())), db: Some(db) }
    }
    
    /// 注册节点
    pub async fn register(&self, info: NodeInfo) -> Result<(), String> {
        let mut nodes = self.nodes.write().await;
        nodes.insert(info.id.clone(), info.clone());
        
        // 同步到数据库
        if let Some(ref db) = self.db {
            let active_model = scan_node::ActiveModel {
                id: Set(info.id.clone()),
                name: Set(info.name.clone()),
                endpoint: Set(info.endpoint.clone()),
                region: Set(info.region.clone()),
                status: Set(info.status.as_str().to_string()),
                capabilities: Set(serde_json::to_value(&info.capabilities).unwrap_or_default()),
                max_concurrent: Set(info.max_concurrent as i32),
                current_load: Set(info.current_load as i32),
                last_heartbeat: Set(info.last_heartbeat),
                registered_at: Set(Utc::now()),
                metadata: Set(None),
                parent_id: Set(None),
                organization: Set(None),
                token: Set(None),
                login_url: Set(None),
                docker_node_id: Set(None),
                cpu_usage: Set(None),
                memory_usage: Set(None),
                disk_usage: Set(None),
                system_version: Set(None),
                rule_version: Set(None),
                last_heartbeat_at: Set(info.last_heartbeat),
            };
            let _ = scan_node::Entity::insert(active_model).exec(db).await;
        }
        
        tracing::info!("节点已注册: {} ({})", info.name, info.id);
        Ok(())
    }
    
    /// 心跳更新
    pub async fn heartbeat(&self, node_id: &str, load: usize) -> Result<(), String> {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.last_heartbeat = Some(Utc::now());
            node.current_load = load;
            node.status = if load >= node.max_concurrent { NodeStatus::Busy } else { NodeStatus::Online };
        }
        
        if let Some(ref db) = self.db {
            let _ = scan_node::Entity::update_many()
                .col_expr(scan_node::Column::LastHeartbeat, sea_orm::sea_query::Expr::value(Utc::now()))
                .col_expr(scan_node::Column::CurrentLoad, sea_orm::sea_query::Expr::value(load as i32))
                .filter(scan_node::Column::Id.eq(node_id))
                .exec(db).await;
        }
        Ok(())
    }
    
    /// 注销节点
    pub async fn deregister(&self, node_id: &str) -> Result<(), String> {
        let mut nodes = self.nodes.write().await;
        nodes.remove(node_id);
        
        if let Some(ref db) = self.db {
            let _ = scan_node::Entity::delete_by_id(node_id.to_string()).exec(db).await;
        }
        Ok(())
    }
    
    /// 列出所有节点
    pub async fn list(&self) -> Vec<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }
    
    /// 获取节点信息
    pub async fn get(&self, node_id: &str) -> Option<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }
    
    /// 选择最低负载的在线节点
    pub async fn pick_node(&self, engine: &str) -> Option<NodeInfo> {
        let nodes = self.nodes.read().await;
        nodes.values()
            .filter(|n| n.status == NodeStatus::Online || n.status == NodeStatus::Busy)
            .filter(|n| n.current_load < n.max_concurrent)
            .filter(|n| n.capabilities.iter().any(|c| c == engine))
            .min_by_key(|n| n.current_load)
            .cloned()
    }
    
    /// 清理离线节点（超过 60 秒无心跳）
    pub async fn cleanup_stale(&self, timeout_secs: u64) {
        let now = Utc::now();
        let mut nodes = self.nodes.write().await;
        let stale: Vec<String> = nodes.iter()
            .filter(|(_, n)| {
                if let Some(last) = n.last_heartbeat {
                    (now - last).num_seconds() > timeout_secs as i64
                } else {
                    true
                }
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(node) = nodes.get_mut(&id) {
                node.status = NodeStatus::Offline;
            }
        }
    }
}

impl Default for NodeRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_register_and_get() {
        let registry = NodeRegistry::new();
        let info = NodeInfo {
            id: "node-1".to_string(),
            name: "Node 1".to_string(),
            endpoint: "http://node1:8090".to_string(),
            region: None,
            status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4,
            current_load: 0,
        };
        registry.register(info).await.unwrap();
        
        let node = registry.get("node-1").await;
        assert!(node.is_some());
        assert_eq!(node.unwrap().name, "Node 1");
    }
    
    #[tokio::test]
    async fn test_heartbeat_updates_load() {
        let registry = NodeRegistry::new();
        let info = NodeInfo {
            id: "node-1".to_string(),
            name: "Node 1".to_string(),
            endpoint: "http://node1:8090".to_string(),
            region: None,
            status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4,
            current_load: 0,
        };
        registry.register(info).await.unwrap();
        
        registry.heartbeat("node-1", 2).await.unwrap();
        let node = registry.get("node-1").await.unwrap();
        assert_eq!(node.current_load, 2);
        assert!(node.last_heartbeat.is_some());
    }
    
    #[tokio::test]
    async fn test_pick_node_by_load() {
        let registry = NodeRegistry::new();
        
        // 注册两个节点，一个负载高一个低
        let info1 = NodeInfo {
            id: "node-1".to_string(), name: "Node 1".to_string(),
            endpoint: "http://node1:8090".to_string(),
            region: None, status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4, current_load: 3,
        };
        let info2 = NodeInfo {
            id: "node-2".to_string(), name: "Node 2".to_string(),
            endpoint: "http://node2:8090".to_string(),
            region: None, status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4, current_load: 1,
        };
        registry.register(info1).await.unwrap();
        registry.register(info2).await.unwrap();
        
        let picked = registry.pick_node("port_scan").await;
        assert!(picked.is_some());
        assert_eq!(picked.unwrap().id, "node-2"); // 应该选负载低的
    }
    
    #[tokio::test]
    async fn test_pick_node_no_capability() {
        let registry = NodeRegistry::new();
        let info = NodeInfo {
            id: "node-1".to_string(), name: "Node 1".to_string(),
            endpoint: "http://node1:8090".to_string(),
            region: None, status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4, current_load: 0,
        };
        registry.register(info).await.unwrap();
        
        let picked = registry.pick_node("fingerprint_scanner").await;
        assert!(picked.is_none()); // 不支持该引擎
    }
    
    #[tokio::test]
    async fn test_deregister() {
        let registry = NodeRegistry::new();
        let info = NodeInfo {
            id: "node-1".to_string(), name: "Node 1".to_string(),
            endpoint: "http://node1:8090".to_string(),
            region: None, status: NodeStatus::Online,
            last_heartbeat: None,
            capabilities: vec!["port_scan".to_string()],
            max_concurrent: 4, current_load: 0,
        };
        registry.register(info).await.unwrap();
        registry.deregister("node-1").await.unwrap();
        assert!(registry.get("node-1").await.is_none());
    }
}
