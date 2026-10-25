//! NVD 2.0 API 客户端

use crate::error::VulnDbError;
use crate::types::NvdResponse;
use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::sync::Mutex;

pub struct NvdClient {
    http: reqwest::Client,
    api_key: Option<String>,
    base_url: String,
    last_request: Mutex<Option<DateTime<Utc>>>,
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Argus-Scanner/0.1")
            .build()
            .expect("构建 HTTP 客户端失败");
        Self {
            http, api_key,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            last_request: Mutex::new(None),
        }
    }

    pub async fn fetch_page(
        &self, start_index: i64,
        pub_start_date: Option<DateTime<Utc>>,
        pub_end_date: Option<DateTime<Utc>>,
    ) -> Result<NvdResponse, VulnDbError> {
        let min_interval = if self.api_key.is_some() {
            Duration::from_millis(600)
        } else {
            Duration::from_secs(6)
        };
        
        let mut last_req = self.last_request.lock().await;
        if let Some(last) = *last_req {
            let elapsed = Utc::now().signed_duration_since(last);
            if let Ok(elapsed_std) = elapsed.to_std() {
                if elapsed_std < min_interval {
                    tokio::time::sleep(min_interval - elapsed_std).await;
                }
            }
        }
        
        let mut url = format!("{}?resultsPerPage=2000&startIndex={}", self.base_url, start_index);
        if let (Some(start), Some(end)) = (pub_start_date, pub_end_date) {
            url.push_str(&format!("&pubStartDate={}&pubEndDate={}", 
                start.format("%Y-%m-%dT%H:%M:%S.000"),
                end.format("%Y-%m-%dT%H:%M:%S.000")));
        }
        
        let mut req = self.http.get(&url);
        if let Some(ref key) = self.api_key {
            req = req.header("apiKey", key);
        }
        *last_req = Some(Utc::now());
        drop(last_req);
        
        tracing::info!("NVD API 请求: startIndex={}", start_index);
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VulnDbError::ApiError(format!("HTTP {}: {}", status, body)));
        }
        let nvd_resp: NvdResponse = resp.json().await?;
        Ok(nvd_resp)
    }
}
