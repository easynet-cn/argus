//! 节点端 Daemon（拉取任务 → 本地执行 → 上报结果）

use crate::types::*;
use crate::reporter::NodeReporter;
use argus_scanner::{ScanResult, ScannerRegistry};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub struct NodeDaemon {
    center_url: String,
    node_name: String,
    node_id: Arc<RwLock<Option<String>>>,
    registry: Arc<ScannerRegistry>,
    reporter: NodeReporter,
    capabilities: Vec<String>,
    poll_interval: Duration,
}

impl NodeDaemon {
    pub fn new(
        center_url: impl Into<String>,
        node_name: impl Into<String>,
        registry: Arc<ScannerRegistry>,
        capabilities: Vec<String>,
    ) -> Self {
        let center_url = center_url.into();
        let node_name = node_name.into();
        let reporter = NodeReporter::new(center_url.clone(), String::new());
        Self {
            center_url, node_name,
            node_id: Arc::new(RwLock::new(None)),
            registry,
            reporter,
            capabilities,
            poll_interval: Duration::from_secs(5),
        }
    }
    
    /// 主循环：注册 → 心跳 → 拉任务 → 执行 → 上报
    pub async fn run(&self) -> Result<(), String> {
        // 1. 注册
        let register_req = RegisterRequest {
            name: self.node_name.clone(),
            endpoint: String::new(), // 节点自身的 endpoint
            region: None,
            capabilities: self.capabilities.clone(),
            max_concurrent: 4,
        };
        
        match self.reporter.register(register_req).await {
            Ok(node_id) => {
                let mut id = self.node_id.write().await;
                *id = Some(node_id.clone());
                tracing::info!("节点已注册: ID = {}", node_id);
            }
            Err(e) => {
                tracing::warn!("注册失败: {}，将以匿名模式运行", e);
            }
        }
        
        // 2. 主循环
        loop {
            // 心跳
            if let Err(e) = self.reporter.send_heartbeat(0, &self.capabilities).await {
                tracing::warn!("心跳失败: {}", e);
            }
            
            // 拉取任务
            if let Some(assignment) = self.pull_task().await {
                tracing::info!("收到任务: {} (引擎: {})", assignment.task_id, assignment.engine);
                
                // 本地执行
                let result = self.execute_locally(&assignment).await;
                
                // 上报结果
                let report = ResultReport {
                    assignment_id: assignment.id,
                    task_id: assignment.task_id,
                    node_id: assignment.node_id,
                    result: result.0,
                    error: result.1,
                };
                
                if let Err(e) = self.reporter.report_result(report).await {
                    tracing::error!("结果上报失败: {}", e);
                }
            }
            
            tokio::time::sleep(self.poll_interval).await;
        }
    }
    
    /// 从中心拉取待执行任务
    async fn pull_task(&self) -> Option<TaskAssignment> {
        let node_id = self.node_id.read().await.clone()?;
        let url = format!("{}/internal/node/task/{}", self.center_url, node_id);
        
        let resp = reqwest::get(&url).await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        
        let assignment: TaskAssignment = resp.json().await.ok()?;
        Some(assignment)
    }
    
    /// 本地执行扫描任务
    async fn execute_locally(&self, assignment: &TaskAssignment) -> (ScanResult, Option<String>) {
        let scanner = match self.registry.get(&assignment.engine) {
            Some(s) => s,
            None => {
                let err = format!("引擎 {} 未注册", assignment.engine);
                return (ScanResult {
                    task_id: assignment.task_id.clone(),
                    status: argus_core::entity::task::TaskStatus::Failed,
                    hosts_scanned: 0, vulnerabilities: vec![],
                    duration_secs: 0.0, raw_data: None,
                }, Some(err));
            }
        };
        
        match scanner.execute(&assignment.config).await {
            Ok(result) => (result, None),
            Err(e) => {
                let err = format!("扫描失败: {}", e);
                (ScanResult {
                    task_id: assignment.task_id.clone(),
                    status: argus_core::entity::task::TaskStatus::Failed,
                    hosts_scanned: 0, vulnerabilities: vec![],
                    duration_secs: 0.0, raw_data: None,
                }, Some(err))
            }
        }
    }
}
