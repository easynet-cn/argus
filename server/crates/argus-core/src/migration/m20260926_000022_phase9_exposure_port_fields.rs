//! 暴露端口补齐 HTTP/Web 服务详情字段
//!
//! 暴露端口列表要求展示：组件旗标、版本、响应码、标题、服务器架构、页面编码。
//! 组件旗标已有 banner 字段，本迁移追加 version/response_code/title/server_arch/page_encoding。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ExposurePorts::Table)
                    .add_column(ColumnDef::new(ExposurePorts::Version).string_len(128))
                    .add_column(ColumnDef::new(ExposurePorts::ResponseCode).string_len(16))
                    .add_column(ColumnDef::new(ExposurePorts::Title).string_len(512))
                    .add_column(ColumnDef::new(ExposurePorts::ServerArch).string_len(128))
                    .add_column(ColumnDef::new(ExposurePorts::PageEncoding).string_len(32))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ExposurePorts::Table)
                    .drop_column(ExposurePorts::Version)
                    .drop_column(ExposurePorts::ResponseCode)
                    .drop_column(ExposurePorts::Title)
                    .drop_column(ExposurePorts::ServerArch)
                    .drop_column(ExposurePorts::PageEncoding)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum ExposurePorts {
    Table,
    Version,
    ResponseCode,
    Title,
    ServerArch,
    PageEncoding,
}
