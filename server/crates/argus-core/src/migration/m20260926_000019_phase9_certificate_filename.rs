//! P1: 补齐 certificates 文件名字段（filename）
//!
//!  7.3 证书管理要求记录原始文件名，用于下载时还原文件名。
//! 本迁移追加 filename 字段到 certificates 表。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Certificates::Table)
                    .add_column(ColumnDef::new(Certificates::Filename).string_len(256))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Certificates::Table)
                    .drop_column(Certificates::Filename)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Certificates {
    Table,
    Filename,
}
