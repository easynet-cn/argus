//! 节点结果上报器（节点端：向中心上报结果）

use crate::types::*;
use reqwest::Client;
use std::time::Duration;

pub struct NodeReporter {
    center_url: String,
    node_id: String,
    http: Client,
}

impl NodeReporter {
    pub fn new(center_url: impl Into<String>, node_id: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build().expect("构建 HTTP 客户端失败");
        Self {
            center_url: center_url.into(),
            node_id: node_id.into(),
            http,
        }
    }
    
    /// 上报扫描结果
    pub async fn report_result(&self, result: ResultReport) -> Result<(), String> {
        let url = format!("{}/internal/node/result", self.center_url);
        let resp = self.http.post(&url)
            .json(&result)
            .send().await
            .map_err(|e| format!("上报失败: {e}"))?;
        
        if !resp.status().is_success() {
            return Err(format!("中心返回错误: HTTP {}", resp.status()));
        }
        Ok(())
    }
    
    /// 发送心跳
    pub async fn send_heartbeat(&self, current_load: usize, capabilities: &[String]) -> Result<(), String> {
        let url = format!("{}/internal/node/heartbeat", self.center_url);
        let payload = serde_json::json!({
            "node_id": self.node_id,
            "current_load": current_load,
            "capabilities": capabilities,
        });
        
        let resp = self.http.post(&url)
            .json(&payload)
            .send().await
            .map_err(|e| format!("心跳失败: {e}"))?;
        
        if !resp.status().is_success() {
            return Err(format!("心跳返回错误: HTTP {}", resp.status()));
        }
        Ok(())
    }
    
    /// 注册节点
    pub async fn register(&self, req: RegisterRequest) -> Result<String, String> {
        let url = format!("{}/internal/node/register", self.center_url);
        let resp = self.http.post(&url)
            .json(&req)
            .send().await
            .map_err(|e| format!("注册失败: {e}"))?;
        
        if !resp.status().is_success() {
            return Err(format!("注册返回错误: HTTP {}", resp.status()));
        }
        
        let node_id: String = resp.json().await
            .map_err(|e| format!("解析响应失败: {e}"))?;
        Ok(node_id)
    }
}
