//! 任务分发器（中心端：分发任务到节点）

use crate::types::*;
use crate::registry::NodeRegistry;
use argus_scanner::ScanConfig;
use sea_orm::{DatabaseConnection, EntityTrait, Set, QueryFilter, ColumnTrait};
use argus_core::entity::task_assignment;
use chrono::Utc;
use std::sync::Arc;

pub struct TaskDispatcher {
    registry: Arc<NodeRegistry>,
    db: Option<DatabaseConnection>,
}

impl TaskDispatcher {
    pub fn new(registry: Arc<NodeRegistry>) -> Self {
        Self { registry, db: None }
    }
    
    pub fn with_db(registry: Arc<NodeRegistry>, db: DatabaseConnection) -> Self {
        Self { registry, db: Some(db) }
    }
    
    /// 分发任务到节点
    /// 按 target 数量切分子任务，分发到负载最低的节点
    pub async fn dispatch(
        &self, task_id: &str, config: &ScanConfig, engine: &str,
    ) -> Result<Vec<String>, String> {
        let _ = config.targets.len();
        
        // 尝试找一个可用节点
        if let Some(node) = self.registry.pick_node(engine).await {
            let assignment_uuid = uuid::Uuid::new_v4();
            let assignment_id = assignment_uuid.to_string();
            
            // 保存到数据库
            if let Some(ref db) = self.db {
                let active_model = task_assignment::ActiveModel {
                    id: Set(assignment_uuid),
                    task_id: Set(task_id.to_string()),
                    node_id: Set(node.id.clone()),
                    engine: Set(engine.to_string()),
                    config: Set(serde_json::to_value(config).unwrap_or_default()),
                    status: Set("dispatched".to_string()),
                    created_at: Set(Utc::now()),
                    dispatched_at: Set(Some(Utc::now())),
                    completed_at: Set(None),
                    result: Set(None),
                };
                let _ = task_assignment::Entity::insert(active_model).exec(db).await;
            }
            
            // 通过 HTTP 发送到节点
            let url = format!("{}/internal/node/task", node.endpoint);
            let payload = serde_json::json!({
                "assignment_id": assignment_id,
                "task_id": task_id,
                "engine": engine,
                "config": config,
            });
            
            match reqwest::Client::new()
                .post(&url)
                .json(&payload)
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("任务 {} 已分发到节点 {}", task_id, node.id);
                }
                Ok(resp) => {
                    return Err(format!("节点返回错误: HTTP {}", resp.status()));
                }
                Err(e) => {
                    return Err(format!("分发失败: {e}"));
                }
            }
            
            return Ok(vec![assignment_id]);
        }
        
        // 无可用节点
        Err("无可用扫描节点".to_string())
    }
    
    /// 获取任务分配状态
    pub async fn get_assignment_status(&self, assignment_id: &str) -> Option<AssignmentStatus> {
        if let Some(ref db) = self.db {
            let record = task_assignment::Entity::find_by_id(
                uuid::Uuid::parse_str(assignment_id).ok()?
            ).one(db).await.ok().flatten()?;
            
            return match record.status.as_str() {
                "pending" => Some(AssignmentStatus::Pending),
                "dispatched" => Some(AssignmentStatus::Dispatched),
                "running" => Some(AssignmentStatus::Running),
                "completed" => Some(AssignmentStatus::Completed),
                "failed" => Some(AssignmentStatus::Failed),
                _ => None,
            };
        }
        None
    }
    
    /// 接收节点上报的结果
    pub async fn receive_result(&self, report: ResultReport) -> Result<(), String> {
        if let Some(ref db) = self.db {
            let _ = task_assignment::Entity::update_many()
                .col_expr(task_assignment::Column::Status, sea_orm::sea_query::Expr::value("completed"))
                .col_expr(task_assignment::Column::CompletedAt, sea_orm::sea_query::Expr::value(Utc::now()))
                .col_expr(task_assignment::Column::Result, sea_orm::sea_query::Expr::value(
                    serde_json::to_value(&report.result).unwrap_or_default()
                ))
                .filter(task_assignment::Column::Id.eq(report.assignment_id.clone()))
                .exec(db).await;
        }
        
        tracing::info!("任务 {} 结果已接收", report.task_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dispatch_no_nodes() {
        let registry = Arc::new(NodeRegistry::new());
        let dispatcher = TaskDispatcher::new(registry);
        
        let config = ScanConfig {
            task_id: "test-task".to_string(),
            targets: vec![],
            concurrency: 1,
            timeout_secs: 10,
            extra_params: serde_json::Value::Null,
        };
        
        let result = dispatcher.dispatch("test-task", &config, "port_scan").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "无可用扫描节点");
    }
}
