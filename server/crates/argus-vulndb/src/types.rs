use serde::{Deserialize, Serialize};

/// NVD API 2.0 响应结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdResponse {
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: i64,
    pub vulnerabilities: Vec<NvdCveItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCveItem {
    pub cve: NvdCve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCve {
    pub id: String,
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "vulnStatus")]
    pub vuln_status: Option<String>,
    pub descriptions: Vec<NvdLangString>,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub weaknesses: Vec<NvdWeakness>,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
    #[serde(default)]
    pub references: Vec<NvdReference>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdLangString {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    pub cvss_v31: Vec<NvdCvssMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    pub cvss_v30: Vec<NvdCvssMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    pub cvss_v2: Vec<NvdCvssMetricV2>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCvssMetric {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f64>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCvssData {
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    #[serde(rename = "baseScore")]
    pub base_score: f64,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCvssMetricV2 {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub metric_type: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssDataV2,
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: Option<f64>,
    #[serde(rename = "impactScore")]
    pub impact_score: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCvssDataV2 {
    pub version: String,
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    #[serde(rename = "baseScore")]
    pub base_score: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdWeakness {
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub weakness_type: Option<String>,
    pub description: Vec<NvdLangString>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdConfiguration {
    pub nodes: Vec<NvdConfigNode>,
    #[serde(default)]
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdConfigNode {
    pub operator: String,
    #[serde(default)]
    pub negate: bool,
    pub cpeMatch: Vec<NvdCpeMatch>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCpeMatch {
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(rename = "versionStartIncluding", default)]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding", default)]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding", default)]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding", default)]
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdReference {
    pub url: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// CPE 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeEntry {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub target_sw: Option<String>,
    pub language: Option<String>,
}

impl CpeEntry {
    pub fn to_uri(&self) -> String {
        format!("cpe:2.3:{}:{}:{}:{}:*:*:*:*:*:*:*", self.part, self.vendor, self.product, self.version)
    }
}

/// 导入统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportStats {
    pub total_cves: usize,
    pub new_cves: usize,
    pub updated_cves: usize,
    pub total_cpes: usize,
    pub total_mappings: usize,
    pub elapsed_secs: f64,
    pub start_year: u16,
    pub end_year: u16,
}

/// 导入进度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportProgress {
    pub task_id: String,
    pub current_year: u16,
    pub current_page: i64,
    pub total_processed: usize,
    pub status: String,
    pub error: Option<String>,
}

/// CISA KEV 导入统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KevStats {
    pub total_kev: usize,
    pub marked: usize,
    pub not_found: usize,
    pub errors: usize,
    pub elapsed_secs: f64,
}

/// OSV 导入统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsvStats {
    pub total_results: usize,
    pub new_cves: usize,
    pub updated_cves: usize,
    pub errors: usize,
    pub elapsed_secs: f64,
}

/// CNNVD 导入统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CnnvdStats {
    pub total_entries: usize,
    pub updated: usize,
    pub not_found: usize,
    pub errors: usize,
    pub elapsed_secs: f64,
}
