//! 阶段8 第二批：任务生命周期增强（新增字段）+ 8 大类模板管理表

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 扩展 scan_tasks 表字段
        conn.execute_unprepared(
            r#"
            ALTER TABLE scan_tasks
                ADD COLUMN IF NOT EXISTS locked BOOLEAN NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS priority VARCHAR(10) NOT NULL DEFAULT 'normal',
                ADD COLUMN IF NOT EXISTS schedule_config JSONB,
                ADD COLUMN IF NOT EXISTS params JSONB,
                ADD COLUMN IF NOT EXISTS node_id VARCHAR(64);
            CREATE INDEX IF NOT EXISTS idx_scan_tasks_priority ON scan_tasks(priority);
            CREATE INDEX IF NOT EXISTS idx_scan_tasks_launch_mode ON scan_tasks(launch_mode);
            "#,
        )
        .await?;

        // 2. 端口模板表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS port_templates (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                tcp_ports TEXT NOT NULL DEFAULT '',
                udp_ports TEXT NOT NULL DEFAULT '',
                is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 3. 字典表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS dictionaries (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                dict_type VARCHAR(30) NOT NULL,
                content TEXT NOT NULL,
                is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_dictionaries_type ON dictionaries(dict_type);
            "#,
        )
        .await?;

        // 4. 组合字典表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS combo_dictionaries (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                username_dict_id VARCHAR(64),
                password_dict_id VARCHAR(64),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 5. 证书表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS certificates (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                cert_type VARCHAR(20) NOT NULL,
                cert_data TEXT NOT NULL,
                key_data TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 6. 参数模板表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS param_templates (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                scan_type VARCHAR(30) NOT NULL,
                config JSONB NOT NULL DEFAULT '{}'::jsonb,
                is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_param_templates_type ON param_templates(scan_type);
            "#,
        )
        .await?;

        // 7. 配置模板（基线）表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS config_templates (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                rule_set JSONB NOT NULL DEFAULT '{}'::jsonb,
                is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 删除新表
        let drops = [
            "DROP TABLE IF EXISTS config_templates;",
            "DROP TABLE IF EXISTS param_templates;",
            "DROP TABLE IF EXISTS certificates;",
            "DROP TABLE IF EXISTS combo_dictionaries;",
            "DROP TABLE IF EXISTS dictionaries;",
            "DROP TABLE IF EXISTS port_templates;",
        ];
        for stmt_sql in drops {
            conn.execute_unprepared(stmt_sql).await?;
        }

        // 恢复 scan_tasks 表
        conn.execute_unprepared(
            r#"
            ALTER TABLE scan_tasks
                DROP COLUMN IF EXISTS locked,
                DROP COLUMN IF EXISTS priority,
                DROP COLUMN IF EXISTS schedule_config,
                DROP COLUMN IF EXISTS params,
                DROP COLUMN IF EXISTS node_id;
            "#,
        )
        .await?;

        Ok(())
    }
}
