use thiserror::Error;

#[derive(Error, Debug)]
pub enum VulnDbError {
    #[error("NVD API 错误: {0}")]
    ApiError(String),
    #[error("数据库错误: {0}")]
    Database(String),
    #[error("CPE 解析错误: {0}")]
    CpeParse(String),
    #[error("导入错误: {0}")]
    Import(String),
    #[error("HTTP 请求失败: {0}")]
    HttpError(String),
    #[error("JSON 解析失败: {0}")]
    JsonError(String),
}

impl From<reqwest::Error> for VulnDbError {
    fn from(e: reqwest::Error) -> Self { VulnDbError::HttpError(e.to_string()) }
}

impl From<sea_orm::DbErr> for VulnDbError {
    fn from(e: sea_orm::DbErr) -> Self { VulnDbError::Database(e.to_string()) }
}

impl From<serde_json::Error> for VulnDbError {
    fn from(e: serde_json::Error) -> Self { VulnDbError::JsonError(e.to_string()) }
}
