//! P0-13: 创建指纹规则表 fingerprint_rules，支持自定义指纹库管理

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(FingerprintRules::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(FingerprintRules::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(FingerprintRules::Name).string_len(256).not_null())
                    .col(ColumnDef::new(FingerprintRules::Category).string_len(64))
                    .col(ColumnDef::new(FingerprintRules::MatchType).string_len(32).not_null())
                    .col(ColumnDef::new(FingerprintRules::MatchPattern).text().not_null())
                    .col(ColumnDef::new(FingerprintRules::ServiceName).string_len(128).not_null())
                    .col(ColumnDef::new(FingerprintRules::Vendor).string_len(128))
                    .col(ColumnDef::new(FingerprintRules::VersionPattern).text())
                    .col(ColumnDef::new(FingerprintRules::Cpe).string_len(256))
                    .col(ColumnDef::new(FingerprintRules::Ports).string_len(256))
                    .col(ColumnDef::new(FingerprintRules::Enabled).boolean().not_null().default(true))
                    .col(ColumnDef::new(FingerprintRules::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(FingerprintRules::Priority).integer().not_null().default(100))
                    .col(ColumnDef::new(FingerprintRules::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(FingerprintRules::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fp_rules_category")
                    .table(FingerprintRules::Table)
                    .col(FingerprintRules::Category)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fp_rules_service")
                    .table(FingerprintRules::Table)
                    .col(FingerprintRules::ServiceName)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_fp_rules_enabled")
                    .table(FingerprintRules::Table)
                    .col(FingerprintRules::Enabled)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FingerprintRules::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum FingerprintRules {
    Table,
    Id,
    Name,
    Category,
    MatchType,
    MatchPattern,
    ServiceName,
    Vendor,
    VersionPattern,
    Cpe,
    Ports,
    Enabled,
    IsBuiltin,
    Priority,
    CreatedAt,
    UpdatedAt,
}
