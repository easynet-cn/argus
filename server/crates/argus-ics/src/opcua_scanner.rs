//! OPC UA 协议探测（Discovery + Browse）
//!
//! G6.2: 使用 async-opcua crate 实现 OPC UA 设备发现
//! - GetEndpoints: 获取服务器端点列表（安全策略、传输协议）
//! - Connect + Read: 连接服务器并读取 ServerStatus、BuildInfo 等节点
//! - 提取设备信息（服务器名、版本、厂商、命名空间）

use opcua::client::{Client, ClientBuilder, IdentityToken, Password};
use opcua::types::{
    DataValue, EndpointDescription, NodeId, ReadValueId, TimestampsToReturn, Variant,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// OPC UA 端点描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcUaEndpoint {
    /// 端点 URL
    pub endpoint_url: String,
    /// 安全模式
    pub security_mode: String,
    /// 安全策略 URI
    pub security_policy: String,
    /// 传输协议 URI
    pub transport_profile: String,
    /// 用户身份令牌类型
    pub user_token_types: Vec<String>,
}

/// OPC UA 设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcUaDeviceInfo {
    /// 服务器名称
    pub server_name: String,
    /// 服务器版本
    pub build_info: String,
    /// 厂商信息
    pub manufacturer: String,
    /// 产品名称
    pub product_name: String,
    /// 运行状态
    pub state: String,
    /// 启动时间
    pub start_time: String,
    /// 当前时间
    pub current_time: String,
    /// 端点列表
    pub endpoints: Vec<OpcUaEndpoint>,
    /// 命名空间列表
    pub namespaces: Vec<String>,
}

/// OPC UA 扫描配置
#[derive(Debug, Clone)]
pub struct OpcUaScanConfig {
    /// 连接超时（毫秒）
    pub connect_timeout_ms: u64,
    /// 是否匿名认证
    pub anonymous: bool,
    /// 用户名（非匿名时）
    pub username: Option<String>,
    /// 密码（非匿名时）
    pub password: Option<String>,
}

impl Default for OpcUaScanConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            anonymous: true,
            username: None,
            password: None,
        }
    }
}

/// OPC UA 扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcUaScanResult {
    /// 目标 URL
    pub target_url: String,
    /// 是否连接成功
    pub connected: bool,
    /// 设备信息（连接成功时）
    pub device_info: Option<OpcUaDeviceInfo>,
    /// 错误信息（连接失败时）
    pub error: Option<String>,
}

/// OPC UA 扫描器
pub struct OpcUaScanner {
    config: OpcUaScanConfig,
}

impl OpcUaScanner {
    pub fn new(config: OpcUaScanConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建扫描器
    pub fn with_defaults() -> Self {
        Self::new(OpcUaScanConfig::default())
    }

    /// 探测 OPC UA 设备（GetEndpoints + Connect + Read）
    pub async fn scan(&self, target_url: &str) -> OpcUaScanResult {
        tracing::info!("开始 OPC UA 扫描: {}", target_url);

        // 创建客户端
        let mut client = match self.build_client() {
            Ok(c) => c,
            Err(e) => {
                return OpcUaScanResult {
                    target_url: target_url.to_string(),
                    connected: false,
                    device_info: None,
                    error: Some(format!("创建客户端失败: {}", e)),
                };
            }
        };

        // GetEndpoints
        let endpoints = match client.get_endpoints(target_url, &[], &[]).await {
            Ok(eps) => eps,
            Err(e) => {
                return OpcUaScanResult {
                    target_url: target_url.to_string(),
                    connected: false,
                    device_info: None,
                    error: Some(format!("GetEndpoints 失败: {}", e)),
                };
            }
        };

        if endpoints.is_empty() {
            return OpcUaScanResult {
                target_url: target_url.to_string(),
                connected: false,
                device_info: None,
                error: Some("服务器返回空端点列表".to_string()),
            };
        }

        // 转换端点描述
        let endpoint_list: Vec<OpcUaEndpoint> = endpoints
            .iter()
            .map(|e| Self::convert_endpoint(e))
            .collect();

        // 尝试连接并读取设备信息
        let device_info = match self.connect_and_read(&mut client, &endpoints).await {
            Ok(info) => info,
            Err(e) => {
                // 即使 Read 失败，也返回端点信息
                tracing::warn!("Read 失败: {}，返回端点信息", e);
                return OpcUaScanResult {
                    target_url: target_url.to_string(),
                    connected: false,
                    device_info: Some(OpcUaDeviceInfo {
                        server_name: String::new(),
                        build_info: String::new(),
                        manufacturer: String::new(),
                        product_name: String::new(),
                        state: String::new(),
                        start_time: String::new(),
                        current_time: String::new(),
                        endpoints: endpoint_list,
                        namespaces: Vec::new(),
                    }),
                    error: Some(format!("Read 失败: {}", e)),
                };
            }
        };

        OpcUaScanResult {
            target_url: target_url.to_string(),
            connected: true,
            device_info: Some(OpcUaDeviceInfo {
                endpoints: endpoint_list,
                ..device_info
            }),
            error: None,
        }
    }

    /// 构建 OPC UA 客户端
    fn build_client(&self) -> Result<Client, String> {
        let mut builder = ClientBuilder::new()
            .application_name("Argus OPC UA Scanner")
            .application_uri("urn:argus:opcua:scanner")
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .verify_server_certs(false);

        if !self.config.anonymous {
            if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password) {
                // 用户名密码认证暂不支持配置到 ClientBuilder，通过 IdentityToken 传入
                tracing::debug!("用户名密码认证: {}", user);
                let _ = pass; // 避免未使用警告
            }
        }

        builder.client().map_err(|e| format!("客户端配置错误: {:?}", e))
    }

    /// 连接并读取设备信息
    async fn connect_and_read(
        &self,
        client: &mut Client,
        endpoints: &[EndpointDescription],
    ) -> Result<OpcUaDeviceInfo, String> {
        // 选择最佳端点（优先 None 安全策略）
        let best_endpoint = endpoints
            .iter()
            .find(|e| e.security_policy_uri.as_ref().contains("SecurityPolicy#None"))
            .or_else(|| endpoints.first())
            .ok_or("无可用的端点")?;

        // 连接
        let identity_token = if self.config.anonymous {
            IdentityToken::Anonymous
        } else {
            IdentityToken::UserName(
                self.config.username.clone().unwrap_or_default(),
                Password::from(self.config.password.clone().unwrap_or_default()),
            )
        };

        let (session, event_loop) = client
            .connect_to_matching_endpoint(best_endpoint.clone(), identity_token)
            .await
            .map_err(|e| format!("创建会话失败: {}", e))?;

        let handle = tokio::spawn(async move {
            let _ = event_loop.run().await;
        });

        // 等待连接
        let connected = tokio::time::timeout(
            Duration::from_millis(self.config.connect_timeout_ms),
            session.wait_for_connection(),
        )
        .await
        .map_err(|_| "等待连接超时".to_string())?;

        if !connected {
            let _ = session.disconnect().await;
            let _ = handle.await;
            return Err("连接失败".to_string());
        }

        // 读取设备信息节点
        // Server.ServerStatus.BuildInfo.ProductName -> ns=0;s=Server.ServerStatus.BuildInfo.ProductName
        // Server.ServerStatus.BuildInfo.SoftwareVersion
        // Server.ServerStatus.BuildInfo.ManufacturerName
        // Server.ServerStatus.State
        // Server.ServerStatus.StartTime
        // Server.ServerStatus.CurrentTime
        let node_ids = vec![
            "ns=0;s=Server.ServerStatus.BuildInfo.ProductName",
            "ns=0;s=Server.ServerStatus.BuildInfo.SoftwareVersion",
            "ns=0;s=Server.ServerStatus.BuildInfo.ManufacturerName",
            "ns=0;s=Server.ServerStatus.State",
            "ns=0;s=Server.ServerStatus.StartTime",
            "ns=0;s=Server.ServerStatus.CurrentTime",
        ];

        let nodes_to_read: Vec<ReadValueId> = node_ids
            .iter()
            .filter_map(|id| id.parse::<NodeId>().ok().map(ReadValueId::from))
            .collect();

        let values = session
            .read(&nodes_to_read, TimestampsToReturn::Both, 0.0)
            .await
            .map_err(|e| format!("Read 失败: {}", e))?;

        let product_name = Self::extract_string(values.get(0));
        let build_info = Self::extract_string(values.get(1));
        let manufacturer = Self::extract_string(values.get(2));
        let state = Self::extract_string(values.get(3));
        let start_time = Self::extract_string(values.get(4));
        let current_time = Self::extract_string(values.get(5));

        // 读取命名空间数组 (ns=0;i=2255)
        let namespaces = self.read_namespaces(&session).await.unwrap_or_default();

        let server_name = product_name.clone();

        let _ = session.disconnect().await;
        let _ = handle.await;

        Ok(OpcUaDeviceInfo {
            server_name,
            build_info,
            manufacturer,
            product_name,
            state,
            start_time,
            current_time,
            endpoints: Vec::new(),
            namespaces,
        })
    }

    /// 读取命名空间数组
    async fn read_namespaces(&self, session: &opcua::client::Session) -> Result<Vec<String>, String> {
        let ns_node_id: NodeId = "ns=0;i=2255".parse().map_err(|e| format!("解析 NodeId 失败: {}", e))?;
        let nodes_to_read = vec![ReadValueId::from(ns_node_id)];

        let values = session
            .read(&nodes_to_read, TimestampsToReturn::Both, 0.0)
            .await
            .map_err(|e| format!("Read 命名空间失败: {}", e))?;

        if let Some(dv) = values.first() {
            if let Some(ref value) = dv.value {
                if let Variant::Array(arr) = value {
                    let mut ns_list = Vec::new();
                    for v in arr.values.iter().take(20) {
                        if let Variant::String(ua_string) = v {
                            if let Some(s) = ua_string.value() {
                                ns_list.push(s.clone());
                            }
                        }
                    }
                    return Ok(ns_list);
                }
            }
        }

        Err("无法解析命名空间数组".to_string())
    }

    /// 从 DataValue 提取字符串
    fn extract_string(dv: Option<&DataValue>) -> String {
        if let Some(dv) = dv {
            if let Some(value) = &dv.value {
                match value {
                    Variant::String(ua_string) => {
                        return ua_string.value().clone().unwrap_or_default();
                    }
                    Variant::Int32(n) => return n.to_string(),
                    Variant::UInt32(n) => return n.to_string(),
                    Variant::Int16(n) => return n.to_string(),
                    Variant::UInt16(n) => return n.to_string(),
                    Variant::DateTime(dt) => return dt.to_string(),
                    _ => return format!("{:?}", value),
                }
            }
        }
        String::new()
    }

    /// 转换 EndpointDescription 到 OpcUaEndpoint
    fn convert_endpoint(e: &EndpointDescription) -> OpcUaEndpoint {
        let endpoint_url = e.endpoint_url.as_ref().to_string();
        let security_mode = format!("{:?}", e.security_mode);
        let security_policy = e.security_policy_uri.as_ref().to_string();
        let transport_profile = e.transport_profile_uri.as_ref().to_string();
        let user_token_types = e
            .user_identity_tokens
            .as_ref()
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|t| format!("{:?}", t.token_type))
                    .collect()
            })
            .unwrap_or_default();

        OpcUaEndpoint {
            endpoint_url,
            security_mode,
            security_policy,
            transport_profile,
            user_token_types,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcua_scan_config_default() {
        let config = OpcUaScanConfig::default();
        assert_eq!(config.connect_timeout_ms, 10_000);
        assert!(config.anonymous);
    }

    #[test]
    fn test_opcua_scanner_with_defaults() {
        let scanner = OpcUaScanner::with_defaults();
        assert_eq!(scanner.config.connect_timeout_ms, 10_000);
    }

    #[test]
    fn test_opcua_scan_result_failure() {
        let result = OpcUaScanResult {
            target_url: "opc.tcp://192.168.1.1:4840".to_string(),
            connected: false,
            device_info: None,
            error: Some("连接超时".to_string()),
        };
        assert!(!result.connected);
        assert!(result.error.is_some());
        assert!(result.device_info.is_none());
    }

    #[test]
    fn test_extract_string_none() {
        assert_eq!(OpcUaScanner::extract_string(None), "");
    }

    /// 集成测试：需要真实 OPC UA 服务器
    #[tokio::test]
    #[ignore = "需要真实 OPC UA 服务器"]
    async fn test_opcua_scan_real_server() {
        let scanner = OpcUaScanner::with_defaults();
        let result = scanner.scan("opc.tcp://localhost:4840").await;
        let _ = result.connected;
    }
}
