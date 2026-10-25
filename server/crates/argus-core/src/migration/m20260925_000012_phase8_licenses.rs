//! 8.7.7: 创建许可证表 licenses

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Licenses::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Licenses::Id).integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(Licenses::LicenseKey).string_len(512).not_null())
                    .col(ColumnDef::new(Licenses::Customer).string_len(256).not_null())
                    .col(ColumnDef::new(Licenses::Product).string_len(128).not_null())
                    .col(ColumnDef::new(Licenses::Edition).string_len(32).not_null())
                    .col(ColumnDef::new(Licenses::MaxNodes).integer().not_null().default(0))
                    .col(ColumnDef::new(Licenses::MaxAssets).integer().not_null().default(0))
                    .col(ColumnDef::new(Licenses::Features).json().not_null())
                    .col(ColumnDef::new(Licenses::IssuedAt).date_time().not_null())
                    .col(ColumnDef::new(Licenses::ExpiresAt).date_time().not_null())
                    .col(ColumnDef::new(Licenses::Status).string_len(16).not_null().default("active"))
                    .col(ColumnDef::new(Licenses::Signature).string_len(256).not_null())
                    .col(ColumnDef::new(Licenses::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Licenses::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_licenses_key")
                    .table(Licenses::Table)
                    .col(Licenses::LicenseKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Licenses::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Licenses {
    Table,
    Id,
    LicenseKey,
    Customer,
    Product,
    Edition,
    MaxNodes,
    MaxAssets,
    Features,
    IssuedAt,
    ExpiresAt,
    Status,
    Signature,
    CreatedAt,
    UpdatedAt,
}
