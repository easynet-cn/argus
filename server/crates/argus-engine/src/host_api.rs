//! Host API - 注入给插件的安全能力接口
//!
//! 插件不直接访问网络/文件系统，必须通过此接口

use async_trait::async_trait;

#[async_trait]
pub trait HostApi: Send + Sync {
    /// 发送 HTTP 请求并获取响应
    async fn http_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String>;

    /// 建立 TCP 连接并发送数据
    async fn tcp_send(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, String>;

    /// DNS 查询
    async fn dns_lookup(&self, domain: &str) -> Result<Vec<String>, String>;
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
