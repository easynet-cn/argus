//! P1: 补齐 credentials 资产绑定与错误原因字段

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credentials::Table)
                    .add_column(ColumnDef::new(Credentials::AssetId).string_len(64))
                    .add_column(ColumnDef::new(Credentials::AssetType).string_len(32))
                    .add_column(ColumnDef::new(Credentials::ErrorReason).text())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credentials::Table)
                    .drop_column(Credentials::AssetId)
                    .drop_column(Credentials::AssetType)
                    .drop_column(Credentials::ErrorReason)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Credentials {
    Table,
    AssetId,
    AssetType,
    ErrorReason,
}
