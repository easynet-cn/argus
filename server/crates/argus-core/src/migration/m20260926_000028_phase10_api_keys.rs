//! APIKey 设置
//!
//! 要求：系统设置包含 APIKey 管理，用于外部系统集成认证。
//! API Key 明文仅在创建时返回一次，存储 SHA-256 哈希。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ApiKey::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKey::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(ApiKey::Name).string_len(128).not_null())
                    .col(ColumnDef::new(ApiKey::KeyPrefix).string_len(32).not_null())
                    .col(ColumnDef::new(ApiKey::KeyHash).string_len(64).not_null())
                    .col(ColumnDef::new(ApiKey::UserId).string_len(64).not_null())
                    .col(ColumnDef::new(ApiKey::Scopes).json().default(r#"[["*"]]"#))
                    .col(ColumnDef::new(ApiKey::ExpiresAt).date_time())
                    .col(ColumnDef::new(ApiKey::LastUsedAt).date_time())
                    .col(ColumnDef::new(ApiKey::IsActive).boolean().not_null().default(true))
                    .col(ColumnDef::new(ApiKey::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(ApiKey::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // 按前缀索引（用于快速查找）
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_prefix")
                    .table(ApiKey::Table)
                    .col(ApiKey::KeyPrefix)
                    .to_owned(),
            )
            .await?;

        // 按用户 ID 索引
        manager
            .create_index(
                Index::create()
                    .name("idx_api_key_user")
                    .table(ApiKey::Table)
                    .col(ApiKey::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ApiKey::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum ApiKey {
    Table,
    Id,
    Name,
    KeyPrefix,
    KeyHash,
    UserId,
    Scopes,
    ExpiresAt,
    LastUsedAt,
    IsActive,
    CreatedAt,
    UpdatedAt,
}
