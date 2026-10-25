//! 阶段8 第四批：分布式探针增强（scan_nodes 表扩展字段）

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        conn.execute_unprepared(
            r#"
            ALTER TABLE scan_nodes
                ADD COLUMN IF NOT EXISTS parent_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS organization VARCHAR(128),
                ADD COLUMN IF NOT EXISTS token TEXT,
                ADD COLUMN IF NOT EXISTS login_url VARCHAR(255),
                ADD COLUMN IF NOT EXISTS docker_node_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS cpu_usage DOUBLE PRECISION,
                ADD COLUMN IF NOT EXISTS memory_usage DOUBLE PRECISION,
                ADD COLUMN IF NOT EXISTS disk_usage DOUBLE PRECISION,
                ADD COLUMN IF NOT EXISTS system_version VARCHAR(64),
                ADD COLUMN IF NOT EXISTS rule_version VARCHAR(64),
                ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        conn.execute_unprepared(
            r#"
            ALTER TABLE scan_nodes
                DROP COLUMN IF EXISTS parent_id,
                DROP COLUMN IF EXISTS organization,
                DROP COLUMN IF EXISTS token,
                DROP COLUMN IF EXISTS login_url,
                DROP COLUMN IF EXISTS docker_node_id,
                DROP COLUMN IF EXISTS cpu_usage,
                DROP COLUMN IF EXISTS memory_usage,
                DROP COLUMN IF EXISTS disk_usage,
                DROP COLUMN IF EXISTS system_version,
                DROP COLUMN IF EXISTS rule_version,
                DROP COLUMN IF EXISTS last_heartbeat_at;
            "#,
        )
        .await?;

        Ok(())
    }
}
