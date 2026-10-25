//! P1: 补齐 vuln_findings 影响范围字段（impact_range）
//!
//!  5.2 系统漏洞详情要求记录"影响范围"（受影响的系统/组件/数据/业务）
//! 此前已补齐 title/description/vuln_type/cvss2/cvss3/evidence/fix_advice，
//! 本迁移追加 impact_range 字段，完成漏洞核心字段的完整对齐。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(VulnFindings::Table)
                    .add_column(ColumnDef::new(VulnFindings::ImpactRange).text())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(VulnFindings::Table)
                    .drop_column(VulnFindings::ImpactRange)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum VulnFindings {
    Table,
    ImpactRange,
}
