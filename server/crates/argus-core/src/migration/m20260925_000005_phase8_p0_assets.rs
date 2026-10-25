//! P0-1: 补齐应用资产/数据库资产缺失字段，支持批量导入导出

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 应用资产补齐字段
        manager
            .alter_table(
                Table::alter()
                    .table(ApplicationAssets::Table)
                    .add_column(ColumnDef::new(ApplicationAssets::Description).text())
                    .add_column(ColumnDef::new(ApplicationAssets::Ip).string_len(64))
                    .add_column(
                        ColumnDef::new(ApplicationAssets::Tags)
                            .json_binary()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .add_column(ColumnDef::new(ApplicationAssets::TrustedDevice).boolean().default(false))
                    .add_column(ColumnDef::new(ApplicationAssets::AssetType).string_len(64))
                    .add_column(ColumnDef::new(ApplicationAssets::ProtectionLevel).string_len(32))
                    .add_column(ColumnDef::new(ApplicationAssets::Confidentiality).string_len(32))
                    .add_column(ColumnDef::new(ApplicationAssets::Integrity).string_len(32))
                    .add_column(ColumnDef::new(ApplicationAssets::Availability).string_len(32))
                    .add_column(ColumnDef::new(ApplicationAssets::Importance).string_len(32))
                    .add_column(ColumnDef::new(ApplicationAssets::AutoFetch).boolean().default(false))
                    .to_owned(),
            )
            .await?;

        // 数据库资产补齐字段
        manager
            .alter_table(
                Table::alter()
                    .table(DatabaseAssets::Table)
                    .add_column(ColumnDef::new(DatabaseAssets::Description).text())
                    .add_column(
                        ColumnDef::new(DatabaseAssets::Tags)
                            .json_binary()
                            .default(Expr::cust("'[]'::jsonb")),
                    )
                    .add_column(ColumnDef::new(DatabaseAssets::TrustedDevice).boolean().default(false))
                    .add_column(ColumnDef::new(DatabaseAssets::AssetType).string_len(64))
                    .add_column(ColumnDef::new(DatabaseAssets::ProtectionLevel).string_len(32))
                    .add_column(ColumnDef::new(DatabaseAssets::Confidentiality).string_len(32))
                    .add_column(ColumnDef::new(DatabaseAssets::Integrity).string_len(32))
                    .add_column(ColumnDef::new(DatabaseAssets::Availability).string_len(32))
                    .add_column(ColumnDef::new(DatabaseAssets::Importance).string_len(32))
                    .to_owned(),
            )
            .await?;

        // 网络资产补齐描述、可信设备、工控设备类型字段
        manager
            .alter_table(
                Table::alter()
                    .table(NetworkAssets::Table)
                    .add_column(ColumnDef::new(NetworkAssets::Description).text())
                    .add_column(ColumnDef::new(NetworkAssets::TrustedDevice).boolean().default(false))
                    .add_column(ColumnDef::new(NetworkAssets::IndustrialDeviceType).string_len(64))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 应用资产
        for col in [
            ApplicationAssets::Description,
            ApplicationAssets::Ip,
            ApplicationAssets::Tags,
            ApplicationAssets::TrustedDevice,
            ApplicationAssets::AssetType,
            ApplicationAssets::ProtectionLevel,
            ApplicationAssets::Confidentiality,
            ApplicationAssets::Integrity,
            ApplicationAssets::Availability,
            ApplicationAssets::Importance,
            ApplicationAssets::AutoFetch,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(ApplicationAssets::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }

        // 数据库资产
        for col in [
            DatabaseAssets::Description,
            DatabaseAssets::Tags,
            DatabaseAssets::TrustedDevice,
            DatabaseAssets::AssetType,
            DatabaseAssets::ProtectionLevel,
            DatabaseAssets::Confidentiality,
            DatabaseAssets::Integrity,
            DatabaseAssets::Availability,
            DatabaseAssets::Importance,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(DatabaseAssets::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }

        // 网络资产
        for col in [
            NetworkAssets::Description,
            NetworkAssets::TrustedDevice,
            NetworkAssets::IndustrialDeviceType,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(NetworkAssets::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(Iden)]
enum ApplicationAssets {
    Table,
    Description,
    Ip,
    Tags,
    TrustedDevice,
    AssetType,
    ProtectionLevel,
    Confidentiality,
    Integrity,
    Availability,
    Importance,
    AutoFetch,
}

#[derive(Iden)]
enum DatabaseAssets {
    Table,
    Description,
    Tags,
    TrustedDevice,
    AssetType,
    ProtectionLevel,
    Confidentiality,
    Integrity,
    Availability,
    Importance,
}

#[derive(Iden)]
enum NetworkAssets {
    Table,
    Description,
    TrustedDevice,
    IndustrialDeviceType,
}
