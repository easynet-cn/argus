//! P1: 补齐 vuln_findings 应用漏洞和数据库漏洞特有字段

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
                    .add_column(ColumnDef::new(VulnFindings::RequestMethod).string_len(16))
                    .add_column(ColumnDef::new(VulnFindings::RequestUrl).text())
                    .add_column(ColumnDef::new(VulnFindings::RequestParams).string())
                    .add_column(ColumnDef::new(VulnFindings::Payload).text())
                    .add_column(ColumnDef::new(VulnFindings::DbInstance).string_len(128))
                    .add_column(ColumnDef::new(VulnFindings::SqlStatement).text())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(VulnFindings::Table)
                    .drop_column(VulnFindings::RequestMethod)
                    .drop_column(VulnFindings::RequestUrl)
                    .drop_column(VulnFindings::RequestParams)
                    .drop_column(VulnFindings::Payload)
                    .drop_column(VulnFindings::DbInstance)
                    .drop_column(VulnFindings::SqlStatement)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum VulnFindings {
    Table,
    RequestMethod,
    RequestUrl,
    RequestParams,
    Payload,
    DbInstance,
    SqlStatement,
}
