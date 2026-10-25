//! 阶段8 第一批：凭证管理 + 资产组/属性 + 资产字段扩展 + 资产发现

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 凭证表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS credentials (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                ip VARCHAR(64) NOT NULL,
                protocol VARCHAR(20) NOT NULL,
                port INTEGER NOT NULL,
                auth_type VARCHAR(20) NOT NULL DEFAULT 'password',
                username VARCHAR(128),
                password TEXT,
                enable_username VARCHAR(128),
                enable_password TEXT,
                web_url TEXT,
                api_key TEXT,
                encoding VARCHAR(16) DEFAULT 'UTF-8',
                auth_result VARCHAR(20),
                last_auth_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_credentials_ip ON credentials(ip);
            CREATE INDEX IF NOT EXISTS idx_credentials_protocol ON credentials(protocol);
            "#,
        )
        .await?;

        // 2. 资产组表（树形结构）
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS asset_groups (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                parent_id VARCHAR(64),
                ip_range TEXT,
                owner VARCHAR(64),
                contact VARCHAR(64),
                email VARCHAR(128),
                location VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_asset_groups_parent ON asset_groups(parent_id);
            "#,
        )
        .await?;

        // 3. 资产属性表（标签/业务系统/资产类型）
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS asset_attributes (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                attr_type VARCHAR(20) NOT NULL,
                description TEXT,
                icon VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_asset_attributes_type ON asset_attributes(attr_type);
            "#,
        )
        .await?;

        // 4. 资产发现任务表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS discovery_tasks (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                discovery_type VARCHAR(20) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                targets TEXT NOT NULL,
                config JSONB NOT NULL DEFAULT '{}'::jsonb,
                result JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_tasks_status ON discovery_tasks(status);
            CREATE INDEX IF NOT EXISTS idx_discovery_tasks_type ON discovery_tasks(discovery_type);
            "#,
        )
        .await?;

        // 5. 扩展 network_assets 表字段
        conn.execute_unprepared(
            r#"
            ALTER TABLE network_assets
                ADD COLUMN IF NOT EXISTS device_no VARCHAR(128),
                ADD COLUMN IF NOT EXISTS location VARCHAR(255),
                ADD COLUMN IF NOT EXISTS weight VARCHAR(64),
                ADD COLUMN IF NOT EXISTS asset_group_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS network_zone VARCHAR(32),
                ADD COLUMN IF NOT EXISTS business_system VARCHAR(128),
                ADD COLUMN IF NOT EXISTS owner VARCHAR(64),
                ADD COLUMN IF NOT EXISTS contact VARCHAR(64),
                ADD COLUMN IF NOT EXISTS email VARCHAR(128),
                ADD COLUMN IF NOT EXISTS is_industrial BOOLEAN NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS industrial_vendor VARCHAR(128),
                ADD COLUMN IF NOT EXISTS industrial_model VARCHAR(128),
                ADD COLUMN IF NOT EXISTS industrial_version VARCHAR(128),
                ADD COLUMN IF NOT EXISTS protection_level VARCHAR(32),
                ADD COLUMN IF NOT EXISTS confidentiality VARCHAR(8),
                ADD COLUMN IF NOT EXISTS integrity VARCHAR(8),
                ADD COLUMN IF NOT EXISTS availability VARCHAR(8),
                ADD COLUMN IF NOT EXISTS importance VARCHAR(32);
            "#,
        )
        .await?;

        // 6. 扩展 application_assets 表字段
        conn.execute_unprepared(
            r#"
            ALTER TABLE application_assets
                ADD COLUMN IF NOT EXISTS page_encoding VARCHAR(32),
                ADD COLUMN IF NOT EXISTS os VARCHAR(128),
                ADD COLUMN IF NOT EXISTS cert_type VARCHAR(64),
                ADD COLUMN IF NOT EXISTS cert_id VARCHAR(128),
                ADD COLUMN IF NOT EXISTS device_no VARCHAR(128),
                ADD COLUMN IF NOT EXISTS location VARCHAR(255),
                ADD COLUMN IF NOT EXISTS weight VARCHAR(64),
                ADD COLUMN IF NOT EXISTS asset_group_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS business_system VARCHAR(128),
                ADD COLUMN IF NOT EXISTS owner VARCHAR(64),
                ADD COLUMN IF NOT EXISTS contact VARCHAR(64),
                ADD COLUMN IF NOT EXISTS email VARCHAR(128),
                ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
            "#,
        )
        .await?;

        // 7. 扩展 database_assets 表字段
        conn.execute_unprepared(
            r#"
            ALTER TABLE database_assets
                ADD COLUMN IF NOT EXISTS username VARCHAR(128),
                ADD COLUMN IF NOT EXISTS password TEXT,
                ADD COLUMN IF NOT EXISTS enable_ssl BOOLEAN NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS db_name VARCHAR(128),
                ADD COLUMN IF NOT EXISTS login_verified BOOLEAN NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS execute_login_scan BOOLEAN NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS device_no VARCHAR(128),
                ADD COLUMN IF NOT EXISTS location VARCHAR(255),
                ADD COLUMN IF NOT EXISTS weight VARCHAR(64),
                ADD COLUMN IF NOT EXISTS asset_group_id VARCHAR(64),
                ADD COLUMN IF NOT EXISTS business_system VARCHAR(128),
                ADD COLUMN IF NOT EXISTS owner VARCHAR(64),
                ADD COLUMN IF NOT EXISTS contact VARCHAR(64),
                ADD COLUMN IF NOT EXISTS email VARCHAR(128),
                ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 回滚：先恢复现有表（删除新增列），再删除新表

        // 恢复 database_assets
        conn.execute_unprepared(
            r#"
            ALTER TABLE database_assets
                DROP COLUMN IF EXISTS username,
                DROP COLUMN IF EXISTS password,
                DROP COLUMN IF EXISTS enable_ssl,
                DROP COLUMN IF EXISTS db_name,
                DROP COLUMN IF EXISTS login_verified,
                DROP COLUMN IF EXISTS execute_login_scan,
                DROP COLUMN IF EXISTS device_no,
                DROP COLUMN IF EXISTS location,
                DROP COLUMN IF EXISTS weight,
                DROP COLUMN IF EXISTS asset_group_id,
                DROP COLUMN IF EXISTS business_system,
                DROP COLUMN IF EXISTS owner,
                DROP COLUMN IF EXISTS contact,
                DROP COLUMN IF EXISTS email,
                DROP COLUMN IF EXISTS updated_at;
            "#,
        )
        .await?;

        // 恢复 application_assets
        conn.execute_unprepared(
            r#"
            ALTER TABLE application_assets
                DROP COLUMN IF EXISTS page_encoding,
                DROP COLUMN IF EXISTS os,
                DROP COLUMN IF EXISTS cert_type,
                DROP COLUMN IF EXISTS cert_id,
                DROP COLUMN IF EXISTS device_no,
                DROP COLUMN IF EXISTS location,
                DROP COLUMN IF EXISTS weight,
                DROP COLUMN IF EXISTS asset_group_id,
                DROP COLUMN IF EXISTS business_system,
                DROP COLUMN IF EXISTS owner,
                DROP COLUMN IF EXISTS contact,
                DROP COLUMN IF EXISTS email,
                DROP COLUMN IF EXISTS updated_at;
            "#,
        )
        .await?;

        // 恢复 network_assets
        conn.execute_unprepared(
            r#"
            ALTER TABLE network_assets
                DROP COLUMN IF EXISTS device_no,
                DROP COLUMN IF EXISTS location,
                DROP COLUMN IF EXISTS weight,
                DROP COLUMN IF EXISTS asset_group_id,
                DROP COLUMN IF EXISTS network_zone,
                DROP COLUMN IF EXISTS business_system,
                DROP COLUMN IF EXISTS owner,
                DROP COLUMN IF EXISTS contact,
                DROP COLUMN IF EXISTS email,
                DROP COLUMN IF EXISTS is_industrial,
                DROP COLUMN IF EXISTS industrial_vendor,
                DROP COLUMN IF EXISTS industrial_model,
                DROP COLUMN IF EXISTS industrial_version,
                DROP COLUMN IF EXISTS protection_level,
                DROP COLUMN IF EXISTS confidentiality,
                DROP COLUMN IF EXISTS integrity,
                DROP COLUMN IF EXISTS availability,
                DROP COLUMN IF EXISTS importance;
            "#,
        )
        .await?;

        // 删除新表
        let drops = [
            "DROP TABLE IF EXISTS discovery_tasks;",
            "DROP TABLE IF EXISTS asset_attributes;",
            "DROP TABLE IF EXISTS asset_groups;",
            "DROP TABLE IF EXISTS credentials;",
        ];
        for stmt_sql in drops {
            conn.execute_unprepared(stmt_sql).await?;
        }

        Ok(())
    }
}
