//! P1: 补齐 dictionaries 文件名字段，支持文件上传/下载

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Dictionaries::Table)
                    .add_column(ColumnDef::new(Dictionaries::Filename).string_len(255))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Dictionaries::Table)
                    .drop_column(Dictionaries::Filename)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Dictionaries {
    Table,
    Filename,
}
