//! 创建扫描结果表

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
            CREATE TABLE IF NOT EXISTS scan_results (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64) NOT NULL,
                result_type VARCHAR(20) NOT NULL,
                host VARCHAR(255) NOT NULL,
                port INTEGER,
                protocol VARCHAR(20),
                state VARCHAR(20),
                service VARCHAR(100),
                banner TEXT,
                username VARCHAR(255),
                password VARCHAR(255),
                success BOOLEAN,
                response_time_ms BIGINT,
                raw_data JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_scan_results_task_id ON scan_results(task_id);
            CREATE INDEX IF NOT EXISTS idx_scan_results_host ON scan_results(host);
            CREATE INDEX IF NOT EXISTS idx_scan_results_result_type ON scan_results(result_type);
            "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP TABLE IF EXISTS scan_results;"#)
            .await?;
        Ok(())
    }
}
