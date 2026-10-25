//! 初始化 schema：创建所有核心表的初始迁移

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

/// 迁移：初始化所有核心表
pub struct Migration;

/// 迁移名称（由 sea-orm-migration 用于记录迁移历史）
impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260919_000001_init"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 网络资产表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS network_assets (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                ip VARCHAR(64) NOT NULL,
                mac VARCHAR(64),
                os VARCHAR(255),
                asset_type VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                tags JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 2. 应用资产表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS application_assets (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url VARCHAR(2048) NOT NULL,
                title VARCHAR(255),
                server_arch VARCHAR(255),
                status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 3. 数据库资产表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS database_assets (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                ip VARCHAR(64) NOT NULL,
                db_type VARCHAR(64) NOT NULL,
                port INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'unknown',
                risk_score DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 4. 漏洞表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                cve VARCHAR(64),
                cvss_v2 DOUBLE PRECISION,
                cvss_v3 DOUBLE PRECISION,
                description TEXT NOT NULL,
                fix_advice TEXT,
                status VARCHAR(20) NOT NULL DEFAULT 'new',
                first_found TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_found TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 5. 扫描任务表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                task_type VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                launch_mode VARCHAR(20) NOT NULL DEFAULT 'manual',
                targets JSONB NOT NULL DEFAULT '[]'::jsonb,
                progress REAL NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ
            );
            "#,
        ).await?;

        // 6. 扫描报告表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS scan_reports (
                id VARCHAR(64) PRIMARY KEY,
                task_id VARCHAR(64) NOT NULL,
                name VARCHAR(255) NOT NULL,
                format VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'generating',
                file_size BIGINT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ).await?;

        // 创建索引
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_network_assets_ip ON network_assets(ip);",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_status ON network_assets(status);",
            "CREATE INDEX IF NOT EXISTS idx_application_assets_url ON application_assets(url);",
            "CREATE INDEX IF NOT EXISTS idx_database_assets_ip ON database_assets(ip);",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);",
            "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve);",
            "CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);",
            "CREATE INDEX IF NOT EXISTS idx_scan_tasks_created_at ON scan_tasks(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_scan_reports_task_id ON scan_reports(task_id);",
        ];

        for stmt_sql in indexes {
            conn.execute_unprepared(stmt_sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let drops = [
            "DROP TABLE IF EXISTS scan_reports;",
            "DROP TABLE IF EXISTS scan_tasks;",
            "DROP TABLE IF EXISTS vulnerabilities;",
            "DROP TABLE IF EXISTS database_assets;",
            "DROP TABLE IF EXISTS application_assets;",
            "DROP TABLE IF EXISTS network_assets;",
        ];

        for stmt_sql in drops {
            conn.execute_unprepared(stmt_sql).await?;
        }

        Ok(())
    }
}
