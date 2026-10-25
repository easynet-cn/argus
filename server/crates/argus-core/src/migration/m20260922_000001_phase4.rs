//! 阶段4：CVE知识库 + 漏洞检测 + 工控 + 分布式节点 + 趋势分析

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 8 张 CREATE TABLE 语句 + 索引
        manager
            .get_connection()
            .execute_unprepared(
                r#"
            -- 1. CVE 主表
            CREATE TABLE IF NOT EXISTS cves (
                id VARCHAR(32) PRIMARY KEY,
                source VARCHAR(20) NOT NULL DEFAULT 'NVD',
                description TEXT NOT NULL,
                cvss_v2 DOUBLE PRECISION,
                cvss_v3 DOUBLE PRECISION,
                cvss_vector VARCHAR(255),
                severity VARCHAR(20),
                published TIMESTAMPTZ,
                last_modified TIMESTAMPTZ,
                references JSONB NOT NULL DEFAULT '[]'::jsonb,
                cpe_configurations JSONB NOT NULL DEFAULT '[]'::jsonb
            );

            CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);

            -- 2. CPE 字典
            CREATE TABLE IF NOT EXISTS cpes (
                id VARCHAR(128) PRIMARY KEY,
                cpe_uri TEXT NOT NULL UNIQUE,
                part VARCHAR(4) NOT NULL,
                vendor VARCHAR(128) NOT NULL,
                product VARCHAR(128) NOT NULL,
                version VARCHAR(128) NOT NULL,
                target_sw VARCHAR(64),
                language VARCHAR(16),
                title VARCHAR(255)
            );

            CREATE INDEX IF NOT EXISTS idx_cpes_vendor_product ON cpes(vendor, product);

            -- 3. CVE-CPE 关联表
            CREATE TABLE IF NOT EXISTS cve_cpe_mappings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                cve_id VARCHAR(32) NOT NULL,
                cpe_uri TEXT NOT NULL,
                vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
                version_end_excluding VARCHAR(64),
                version_end_including VARCHAR(64),
                version_start_excluding VARCHAR(64),
                version_start_including VARCHAR(64)
            );

            CREATE INDEX IF NOT EXISTS idx_cve_cpe_cve ON cve_cpe_mappings(cve_id);
            CREATE INDEX IF NOT EXISTS idx_cve_cpe_cpe ON cve_cpe_mappings(cpe_uri);

            -- 4. 漏洞实例表
            CREATE TABLE IF NOT EXISTS vuln_findings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64) NOT NULL,
                template_id VARCHAR(128),
                cve_id VARCHAR(32),
                target_host VARCHAR(255) NOT NULL,
                target_port INTEGER,
                target_service VARCHAR(64),
                target_cpe TEXT,
                severity VARCHAR(20) NOT NULL,
                cvss DOUBLE PRECISION,
                source VARCHAR(20) NOT NULL DEFAULT 'active',
                status VARCHAR(20) NOT NULL DEFAULT 'new',
                evidence TEXT,
                fix_advice TEXT,
                first_found TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_found TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_vuln_findings_task ON vuln_findings(task_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_findings_cve ON vuln_findings(cve_id);
            CREATE INDEX IF NOT EXISTS idx_vuln_findings_target ON vuln_findings(target_host);

            -- 5. 分布式节点表
            CREATE TABLE IF NOT EXISTS scan_nodes (
                id VARCHAR(64) PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                region VARCHAR(64),
                status VARCHAR(20) NOT NULL DEFAULT 'offline',
                capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
                max_concurrent INTEGER NOT NULL DEFAULT 4,
                current_load INTEGER NOT NULL DEFAULT 0,
                last_heartbeat TIMESTAMPTZ,
                registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                metadata JSONB
            );

            CREATE INDEX IF NOT EXISTS idx_scan_nodes_status ON scan_nodes(status);

            -- 6. 任务分发记录表
            CREATE TABLE IF NOT EXISTS task_assignments (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64) NOT NULL,
                node_id VARCHAR(64) NOT NULL,
                engine VARCHAR(64) NOT NULL,
                config JSONB NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                dispatched_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                result JSONB
            );

            CREATE INDEX IF NOT EXISTS idx_task_assignments_task ON task_assignments(task_id);

            -- 7. 工控设备指纹表
            CREATE TABLE IF NOT EXISTS ics_devices (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id VARCHAR(64) NOT NULL,
                host VARCHAR(255) NOT NULL,
                port INTEGER NOT NULL,
                protocol VARCHAR(20) NOT NULL,
                vendor VARCHAR(128),
                model VARCHAR(128),
                firmware VARCHAR(128),
                device_type VARCHAR(64),
                raw_response JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_ics_devices_task ON ics_devices(task_id);

            -- 8. 扫描任务对比结果表
            CREATE TABLE IF NOT EXISTS scan_task_diffs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                task_id_a VARCHAR(64) NOT NULL,
                task_id_b VARCHAR(64) NOT NULL,
                new_count INTEGER NOT NULL DEFAULT 0,
                fixed_count INTEGER NOT NULL DEFAULT 0,
                persistent_count INTEGER NOT NULL DEFAULT 0,
                new_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
                fixed_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
                persistent_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // DROP TABLE 反向顺序
        manager
            .get_connection()
            .execute_unprepared(
                r#"
            DROP TABLE IF EXISTS scan_task_diffs;
            DROP TABLE IF EXISTS ics_devices;
            DROP TABLE IF EXISTS task_assignments;
            DROP TABLE IF EXISTS scan_nodes;
            DROP TABLE IF EXISTS vuln_findings;
            DROP TABLE IF EXISTS cve_cpe_mappings;
            DROP TABLE IF EXISTS cpes;
            DROP TABLE IF EXISTS cves;
            "#,
            )
            .await?;
        Ok(())
    }
}
