//! 扫描任务实体（sea-orm）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 任务类型
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum TaskType {
    #[sea_orm(string_value = "port_scan")]
    PortScan,
    #[sea_orm(string_value = "host_discovery")]
    HostDiscovery,
    #[sea_orm(string_value = "bruteforce")]
    Bruteforce,
    #[sea_orm(string_value = "baseline_check")]
    BaselineCheck,
    #[sea_orm(string_value = "system_scan")]
    SystemScan,
    #[sea_orm(string_value = "app_scan")]
    AppScan,
    #[sea_orm(string_value = "db_scan")]
    DbScan,
    #[sea_orm(string_value = "image_scan")]
    ImageScan,
    #[sea_orm(string_value = "mobile_scan")]
    MobileScan,
    #[sea_orm(string_value = "vuln_verify")]
    VulnVerify,
    #[sea_orm(string_value = "fingerprint")]
    Fingerprint,
    #[sea_orm(string_value = "vuln_detect")]
    VulnDetect,
    #[sea_orm(string_value = "ics_scan")]
    IcsScan,
    /// 被动扫描（代理/Kafka/pcap/Agent 四种数据源）
    #[sea_orm(string_value = "passive_scan")]
    PassiveScan,
}

/// 任务状态
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum TaskStatus {
    #[sea_orm(string_value = "pending")]
    Pending,
    #[sea_orm(string_value = "running")]
    Running,
    #[sea_orm(string_value = "paused")]
    Paused,
    #[sea_orm(string_value = "completed")]
    Completed,
    #[sea_orm(string_value = "stopped")]
    Stopped,
    #[sea_orm(string_value = "failed")]
    Failed,
}

/// 启动方式
#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(20))")]
pub enum LaunchMode {
    #[sea_orm(string_value = "manual")]
    Manual,
    #[sea_orm(string_value = "scheduled")]
    Scheduled,
    #[sea_orm(string_value = "periodic")]
    Periodic,
}

/// 扫描任务模型
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "scan_tasks")]
pub struct Model {
    #[sea_orm(primary_key, auto_value = false)]
    pub id: String,
    pub name: String,
    pub task_type: TaskType,
    pub status: TaskStatus,
    pub launch_mode: LaunchMode,
    #[sea_orm(column_type = "Json")]
    pub targets: serde_json::Value,
    #[sea_orm(column_type = "Float")]
    pub progress: f32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub locked: bool,
    pub priority: String,
    #[sea_orm(column_type = "Json", nullable)]
    pub schedule_config: Option<serde_json::Value>,
    #[sea_orm(column_type = "Json", nullable)]
    pub params: Option<serde_json::Value>,
    pub node_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
