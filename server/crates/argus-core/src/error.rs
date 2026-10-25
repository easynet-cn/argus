//! 核心错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("数据库错误: {0}")]
    Database(String),

    #[error("实体未找到: {0}")]
    NotFound(String),

    #[error("参数错误: {0}")]
    BadRequest(String),

    #[error("内部错误: {0}")]
    Internal(String),
}

impl From<sea_orm::DbErr> for CoreError {
    fn from(e: sea_orm::DbErr) -> Self {
        CoreError::Database(e.to_string())
    }
}
