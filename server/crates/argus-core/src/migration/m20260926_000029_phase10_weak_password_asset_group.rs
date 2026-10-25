//! 弱密码按资产组筛选
//!
//! 要求：弱密码列表支持按资产组筛选，批量处理（状态变更）。
//! 本迁移为 weak_passwords 表添加 asset_group_id 字段。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WeakPasswords::Table)
                    .add_column(ColumnDef::new(WeakPasswords::AssetGroupId).string_len(64))
                    .to_owned(),
            )
            .await?;

        // 添加索引便于按资产组筛选
        manager
            .create_index(
                Index::create()
                    .name("idx_weak_password_asset_group")
                    .table(WeakPasswords::Table)
                    .col(WeakPasswords::AssetGroupId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_weak_password_asset_group")
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WeakPasswords::Table)
                    .drop_column(WeakPasswords::AssetGroupId)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum WeakPasswords {
    Table,
    AssetGroupId,
}
