//! 迁移 000002：创建 users 表

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260919_000002_users"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(64) PRIMARY KEY,
                username VARCHAR(64) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email VARCHAR(255),
                role VARCHAR(20) NOT NULL DEFAULT 'viewer',
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 索引
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
        ).await?;
        conn.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);",
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DROP TABLE IF EXISTS users;").await?;
        Ok(())
    }
}
