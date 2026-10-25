//! P0-4: 补齐 vuln_findings 核心字段（title/description/vuln_type/cvss2/cvss3）

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
                    .add_column(ColumnDef::new(VulnFindings::Title).string_len(256))
                    .add_column(ColumnDef::new(VulnFindings::Description).text())
                    .add_column(ColumnDef::new(VulnFindings::VulnType).string_len(64))
                    .add_column(ColumnDef::new(VulnFindings::Cvss2).double())
                    .add_column(ColumnDef::new(VulnFindings::Cvss3).double())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(VulnFindings::Table)
                    .drop_column(VulnFindings::Title)
                    .drop_column(VulnFindings::Description)
                    .drop_column(VulnFindings::VulnType)
                    .drop_column(VulnFindings::Cvss2)
                    .drop_column(VulnFindings::Cvss3)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum VulnFindings {
    Table,
    Title,
    Description,
    VulnType,
    Cvss2,
    Cvss3,
}
