//! P0-13b: 创建工控设备信息库表 ics_device_library

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IcsDeviceLibrary::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IcsDeviceLibrary::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(IcsDeviceLibrary::Vendor).string_len(128).not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::Model).string_len(128).not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::DeviceType).string_len(32).not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::Protocol).string_len(32).not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::DefaultPort).integer().not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::Firmware).string_len(128))
                    .col(ColumnDef::new(IcsDeviceLibrary::Os).string_len(128))
                    .col(ColumnDef::new(IcsDeviceLibrary::KnownCves).json())
                    .col(ColumnDef::new(IcsDeviceLibrary::Fingerprint).text())
                    .col(ColumnDef::new(IcsDeviceLibrary::Description).text())
                    .col(ColumnDef::new(IcsDeviceLibrary::Enabled).boolean().not_null().default(true))
                    .col(ColumnDef::new(IcsDeviceLibrary::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(IcsDeviceLibrary::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(IcsDeviceLibrary::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ics_lib_vendor")
                    .table(IcsDeviceLibrary::Table)
                    .col(IcsDeviceLibrary::Vendor)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ics_lib_protocol")
                    .table(IcsDeviceLibrary::Table)
                    .col(IcsDeviceLibrary::Protocol)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IcsDeviceLibrary::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum IcsDeviceLibrary {
    Table,
    Id,
    Vendor,
    Model,
    DeviceType,
    Protocol,
    DefaultPort,
    Firmware,
    Os,
    KnownCves,
    Fingerprint,
    Description,
    Enabled,
    IsBuiltin,
    CreatedAt,
    UpdatedAt,
}
