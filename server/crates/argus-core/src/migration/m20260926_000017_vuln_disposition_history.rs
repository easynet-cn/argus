//! P1: 漏洞处置历史记录表

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VulnDispositionHistory::Table)
                    .col(ColumnDef::new(VulnDispositionHistory::Id).string_len(64).primary_key())
                    .col(ColumnDef::new(VulnDispositionHistory::VulnId).string_len(64).not_null())
                    .col(ColumnDef::new(VulnDispositionHistory::FromStatus).string_len(32).not_null())
                    .col(ColumnDef::new(VulnDispositionHistory::ToStatus).string_len(32).not_null())
                    .col(ColumnDef::new(VulnDispositionHistory::Operator).string_len(128).not_null())
                    .col(ColumnDef::new(VulnDispositionHistory::Reason).text())
                    .col(ColumnDef::new(VulnDispositionHistory::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_vuln_disp_history_vuln_id")
                    .table(VulnDispositionHistory::Table)
                    .col(VulnDispositionHistory::VulnId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VulnDispositionHistory::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum VulnDispositionHistory {
    Table,
    Id,
    VulnId,
    FromStatus,
    ToStatus,
    Operator,
    Reason,
    CreatedAt,
}
