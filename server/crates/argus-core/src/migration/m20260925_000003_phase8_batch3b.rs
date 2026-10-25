//! 阶段8 第三批（b）：日志审计、角色管理、告警配置、系统配置、用户增强

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 审计日志表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(64) NOT NULL,
                login_ip VARCHAR(64),
                log_type VARCHAR(30) NOT NULL,
                description TEXT NOT NULL,
                status VARCHAR(10) NOT NULL DEFAULT 'success',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(username);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_type ON audit_logs(log_type);
            "#,
        )
        .await?;

        // 2. 角色表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS roles (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(64) NOT NULL UNIQUE,
                description TEXT,
                permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                is_builtin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 插入默认角色
        conn.execute_unprepared(
            r#"
            INSERT INTO roles (id, name, description, permissions, is_builtin) VALUES
                ('superadmin', '超级管理员', '所有权限', '["*"]'::jsonb, TRUE),
                ('admin', '系统管理员', '系统管理权限', '["system","user","role","audit","asset","task","scan","vuln","credential"]'::jsonb, TRUE),
                ('user', '普通用户', '扫描功能权限', '["asset","task","scan","vuln"]'::jsonb, TRUE),
                ('audit', '审计员', '日志审计权限', '["audit","vuln","asset"]'::jsonb, TRUE)
            ON CONFLICT (id) DO NOTHING;
            "#,
        )
        .await?;

        // 3. 告警配置表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS alert_configs (
                id VARCHAR(64) PRIMARY KEY,
                channel VARCHAR(20) NOT NULL,
                enabled BOOLEAN DEFAULT TRUE,
                config JSONB NOT NULL DEFAULT '{}'::jsonb,
                rules JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 4. 系统配置表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS system_settings (
                key VARCHAR(64) PRIMARY KEY,
                value JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .await?;

        // 预置系统配置项
        conn.execute_unprepared(
            r#"
            INSERT INTO system_settings (key, value) VALUES
                ('log_retention_days', '180'::jsonb),
                ('password_min_length', '12'::jsonb),
                ('password_complexity', 'true'::jsonb),
                ('max_failed_attempts', '5'::jsonb),
                ('lock_duration', '300'::jsonb),
                ('login_timeout', '1800'::jsonb),
                ('disk_alert_threshold', '90'::jsonb),
                ('cpu_alert_threshold', '90'::jsonb),
                ('memory_alert_threshold', '90'::jsonb)
            ON CONFLICT (key) DO NOTHING;
            "#,
        )
        .await?;

        // 5. 扩展 users 表
        conn.execute_unprepared(
            r#"
            ALTER TABLE users
                ADD COLUMN IF NOT EXISTS role_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS organization VARCHAR(128),
                ADD COLUMN IF NOT EXISTS phone VARCHAR(32),
                ADD COLUMN IF NOT EXISTS expire_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS first_login_change BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS scan_target_whitelist JSONB DEFAULT '[]'::jsonb,
                ADD COLUMN IF NOT EXISTS scan_target_blacklist JSONB DEFAULT '[]'::jsonb,
                ADD COLUMN IF NOT EXISTS max_scan_ips INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS max_scan_domains INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS login_ip_whitelist JSONB DEFAULT '[]'::jsonb,
                ADD COLUMN IF NOT EXISTS login_ip_blacklist JSONB DEFAULT '[]'::jsonb,
                ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(128),
                ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 删除新表
        let drops = [
            "DROP TABLE IF EXISTS system_settings;",
            "DROP TABLE IF EXISTS alert_configs;",
            "DROP TABLE IF EXISTS roles;",
            "DROP TABLE IF EXISTS audit_logs;",
        ];
        for stmt_sql in drops {
            conn.execute_unprepared(stmt_sql).await?;
        }

        // 恢复 users 表
        conn.execute_unprepared(
            r#"
            ALTER TABLE users
                DROP COLUMN IF EXISTS role_id,
                DROP COLUMN IF EXISTS organization,
                DROP COLUMN IF EXISTS phone,
                DROP COLUMN IF EXISTS expire_at,
                DROP COLUMN IF EXISTS first_login_change,
                DROP COLUMN IF EXISTS scan_target_whitelist,
                DROP COLUMN IF EXISTS scan_target_blacklist,
                DROP COLUMN IF EXISTS max_scan_ips,
                DROP COLUMN IF EXISTS max_scan_domains,
                DROP COLUMN IF EXISTS login_ip_whitelist,
                DROP COLUMN IF EXISTS login_ip_blacklist,
                DROP COLUMN IF EXISTS failed_attempts,
                DROP COLUMN IF EXISTS locked_until,
                DROP COLUMN IF EXISTS totp_secret,
                DROP COLUMN IF EXISTS totp_enabled;
            "#,
        )
        .await?;

        Ok(())
    }
}
