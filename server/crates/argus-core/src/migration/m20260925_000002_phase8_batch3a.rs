//! 阶段8 第三批：风险管理（漏洞处置状态/类型字段 + 暴露端口表 + 弱密码表）

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 扩展 vuln_findings 表，新增风险管理字段
        conn.execute_unprepared(
            r#"
            ALTER TABLE vuln_findings
                ADD COLUMN IF NOT EXISTS risk_status VARCHAR(20) NOT NULL DEFAULT 'new',
                ADD COLUMN IF NOT EXISTS risk_type VARCHAR(20) NOT NULL DEFAULT 'system',
                ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(64),
                ADD COLUMN IF NOT EXISTS remediation_note TEXT;
            -- risk_status: new/processing/deferred/fixed/verified/closed/false_positive/ignored/reopened
            -- risk_type: system/application/database/config
            CREATE INDEX IF NOT EXISTS idx_vuln_findings_risk_status ON vuln_findings(risk_status);
            CREATE INDEX IF NOT EXISTS idx_vuln_findings_risk_type ON vuln_findings(risk_type);
            "#,
        )
        .await?;

        // 2. 暴露端口表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS exposure_ports (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64),
                host VARCHAR(255) NOT NULL,
                port INTEGER NOT NULL,
                protocol VARCHAR(10) NOT NULL DEFAULT 'tcp',
                service VARCHAR(64),
                banner TEXT,
                is_risky BOOLEAN DEFAULT FALSE,
                first_found TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_found TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_exposure_ports_host ON exposure_ports(host);
            CREATE INDEX IF NOT EXISTS idx_exposure_ports_port ON exposure_ports(port);
            CREATE INDEX IF NOT EXISTS idx_exposure_ports_risky ON exposure_ports(is_risky);
            "#,
        )
        .await?;

        // 3. 弱密码表
        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS weak_passwords (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64),
                host VARCHAR(255) NOT NULL,
                protocol VARCHAR(20) NOT NULL,
                port INTEGER NOT NULL,
                username VARCHAR(128) NOT NULL,
                password VARCHAR(255) NOT NULL,
                risk_status VARCHAR(20) NOT NULL DEFAULT 'new',
                first_found TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_found TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_weak_passwords_host ON weak_passwords(host);
            CREATE INDEX IF NOT EXISTS idx_weak_passwords_status ON weak_passwords(risk_status);
            "#,
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 删除新表
        let drops = [
            "DROP TABLE IF EXISTS weak_passwords;",
            "DROP TABLE IF EXISTS exposure_ports;",
        ];
        for stmt_sql in drops {
            conn.execute_unprepared(stmt_sql).await?;
        }

        // 恢复 vuln_findings 表
        conn.execute_unprepared(
            r#"
            ALTER TABLE vuln_findings
                DROP COLUMN IF EXISTS risk_status,
                DROP COLUMN IF EXISTS risk_type,
                DROP COLUMN IF EXISTS assigned_to,
                DROP COLUMN IF EXISTS remediation_note;
            "#,
        )
        .await?;

        Ok(())
    }
}
