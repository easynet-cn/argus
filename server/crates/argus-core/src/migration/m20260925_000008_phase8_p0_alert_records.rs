//! P0-6: 创建告警记录表 alert_records

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AlertRecords::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AlertRecords::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(AlertRecords::AlertConfigId).string_len(64))
                    .col(ColumnDef::new(AlertRecords::Title).string_len(256).not_null())
                    .col(ColumnDef::new(AlertRecords::Content).text())
                    .col(ColumnDef::new(AlertRecords::Level).string_len(16).not_null())
                    .col(ColumnDef::new(AlertRecords::Source).string_len(32).not_null())
                    .col(ColumnDef::new(AlertRecords::SourceId).string_len(64))
                    .col(ColumnDef::new(AlertRecords::Status).string_len(16).not_null())
                    .col(ColumnDef::new(AlertRecords::TriggeredAt).date_time().not_null())
                    .col(ColumnDef::new(AlertRecords::AcknowledgedAt).date_time())
                    .col(ColumnDef::new(AlertRecords::AcknowledgedBy).string_len(128))
                    .col(ColumnDef::new(AlertRecords::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_records_status")
                    .table(AlertRecords::Table)
                    .col(AlertRecords::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_records_level")
                    .table(AlertRecords::Table)
                    .col(AlertRecords::Level)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_alert_records_triggered")
                    .table(AlertRecords::Table)
                    .col(AlertRecords::TriggeredAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AlertRecords::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum AlertRecords {
    Table,
    Id,
    AlertConfigId,
    Title,
    Content,
    Level,
    Source,
    SourceId,
    Status,
    TriggeredAt,
    AcknowledgedAt,
    AcknowledgedBy,
    CreatedAt,
}
