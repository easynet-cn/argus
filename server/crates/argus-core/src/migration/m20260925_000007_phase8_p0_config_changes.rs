//! P0-5: 创建配置变更记录表 config_changes

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ConfigChanges::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ConfigChanges::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(ConfigChanges::AssetId).string_len(64).not_null())
                    .col(ColumnDef::new(ConfigChanges::AssetType).string_len(32).not_null())
                    .col(ColumnDef::new(ConfigChanges::ChangeType).string_len(32).not_null())
                    .col(ColumnDef::new(ConfigChanges::ChangeCategory).string_len(16).not_null())
                    .col(ColumnDef::new(ConfigChanges::ItemName).string_len(256).not_null())
                    .col(ColumnDef::new(ConfigChanges::OldValue).text())
                    .col(ColumnDef::new(ConfigChanges::NewValue).text())
                    .col(ColumnDef::new(ConfigChanges::ChangeTime).date_time().not_null())
                    .col(ColumnDef::new(ConfigChanges::Operator).string_len(128))
                    .col(ColumnDef::new(ConfigChanges::Source).string_len(16).not_null())
                    .col(ColumnDef::new(ConfigChanges::RiskLevel).string_len(16).not_null())
                    .col(ColumnDef::new(ConfigChanges::Description).text())
                    .col(ColumnDef::new(ConfigChanges::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // 索引
        manager
            .create_index(
                Index::create()
                    .name("idx_config_changes_asset")
                    .table(ConfigChanges::Table)
                    .col(ConfigChanges::AssetId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_config_changes_time")
                    .table(ConfigChanges::Table)
                    .col(ConfigChanges::ChangeTime)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_config_changes_type")
                    .table(ConfigChanges::Table)
                    .col(ConfigChanges::ChangeType)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ConfigChanges::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum ConfigChanges {
    Table,
    Id,
    AssetId,
    AssetType,
    ChangeType,
    ChangeCategory,
    ItemName,
    OldValue,
    NewValue,
    ChangeTime,
    Operator,
    Source,
    RiskLevel,
    Description,
    CreatedAt,
}
