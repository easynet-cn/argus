//! 基线核查采集器模块
//!
//! 支持多种远程登录方式采集目标主机配置

pub mod ssh;
pub mod telnet;
pub mod smb;
pub mod agent;

use crate::types::{CollectItem, CollectMethod};
use async_trait::async_trait;

/// 采集器统一接口
///
/// 所有采集器（SSH/SMB/Telnet/Agent）实现此 trait
#[async_trait]
pub trait Collector: Send + Sync {
    /// 采集器名称
    fn name(&self) -> &str;

    /// 采集方式
    fn method(&self) -> CollectMethod;

    /// 执行单条采集命令，返回输出文本
    async fn collect_one(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        item: &CollectItem,
        timeout_ms: u64,
    ) -> Result<String, String>;
}

/// 根据采集方式创建采集器
///
/// 注意：Offline 模式不使用采集器，调用方应在调用前判断 method。
pub fn create_collector(method: &CollectMethod) -> Box<dyn Collector> {
    match method {
        CollectMethod::Ssh => Box::new(ssh::SshCollector::new()),
        CollectMethod::Telnet => Box::new(telnet::TelnetCollector::new()),
        CollectMethod::Smb => Box::new(smb::SmbCollector::new()),
        CollectMethod::Agent => Box::new(agent::AgentCollector::new()),
        CollectMethod::Offline => panic!("离线模式不使用采集器"),
    }
}
