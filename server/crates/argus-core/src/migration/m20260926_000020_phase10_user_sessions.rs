//! 创建用户会话表 user_sessions
//!
//! 用于会话管理：记录每次登录的会话信息（IP/UA/时间），支持强制下线。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserSessions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UserSessions::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(UserSessions::UserId).string_len(64).not_null())
                    .col(ColumnDef::new(UserSessions::Username).string_len(128).not_null())
                    .col(ColumnDef::new(UserSessions::Jti).string_len(64).not_null())
                    .col(ColumnDef::new(UserSessions::LoginIp).string_len(64))
                    .col(ColumnDef::new(UserSessions::UserAgent).string_len(512))
                    .col(ColumnDef::new(UserSessions::LoginAt).date_time().not_null())
                    .col(ColumnDef::new(UserSessions::LastActiveAt).date_time().not_null())
                    .col(ColumnDef::new(UserSessions::ExpiresAt).date_time().not_null())
                    .col(ColumnDef::new(UserSessions::IsActive).boolean().not_null().default(true))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_user_id")
                    .table(UserSessions::Table)
                    .col(UserSessions::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_jti")
                    .table(UserSessions::Table)
                    .col(UserSessions::Jti)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_sessions_active")
                    .table(UserSessions::Table)
                    .col(UserSessions::IsActive)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserSessions::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum UserSessions {
    Table,
    Id,
    UserId,
    Username,
    Jti,
    LoginIp,
    UserAgent,
    LoginAt,
    LastActiveAt,
    ExpiresAt,
    IsActive,
}
