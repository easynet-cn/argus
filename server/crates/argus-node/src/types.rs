//! 分布式节点类型

use serde::{Deserialize, Serialize};
use argus_scanner::{ScanConfig, ScanResult};

/// 节点状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    Online,
    Offline,
    Busy,
    Decommissioned,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Online => "online",
            NodeStatus::Offline => "offline",
            NodeStatus::Busy => "busy",
            NodeStatus::Decommissioned => "decommissioned",
        }
    }
}

/// 节点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub region: Option<String>,
    pub status: NodeStatus,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub capabilities: Vec<String>,
    pub max_concurrent: usize,
    pub current_load: usize,
}

impl NodeInfo {
    pub fn new(id: impl Into<String>, name: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            id: id.into(), name: name.into(), endpoint: endpoint.into(),
            region: None, status: NodeStatus::Offline,
            last_heartbeat: None, capabilities: vec![],
            max_concurrent: 4, current_load: 0,
        }
    }
}

/// 任务分配
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAssignment {
    pub id: String,
    pub task_id: String,
    pub node_id: String,
    pub engine: String,
    pub config: ScanConfig,
    pub status: AssignmentStatus,
}

/// 分配状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AssignmentStatus {
    Pending,
    Dispatched,
    Running,
    Completed,
    Failed,
}

impl AssignmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssignmentStatus::Pending => "pending",
            AssignmentStatus::Dispatched => "dispatched",
            AssignmentStatus::Running => "running",
            AssignmentStatus::Completed => "completed",
            AssignmentStatus::Failed => "failed",
        }
    }
}

/// 结果上报
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultReport {
    pub assignment_id: String,
    pub task_id: String,
    pub node_id: String,
    pub result: ScanResult,
    pub error: Option<String>,
}

/// 节点注册请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub endpoint: String,
    pub region: Option<String>,
    pub capabilities: Vec<String>,
    pub max_concurrent: usize,
}

/// 心跳请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: String,
    pub current_load: usize,
    pub capabilities: Vec<String>,
}
