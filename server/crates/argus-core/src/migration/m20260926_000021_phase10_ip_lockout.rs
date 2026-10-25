//! 创建 IP 锁定表 ip_lockouts
//!
//! 记录按 IP 维度的登录失败计数，达到阈值后锁定该 IP 一段时间。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IpLockouts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(IpLockouts::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(IpLockouts::Ip).string_len(64).not_null())
                    .col(ColumnDef::new(IpLockouts::FailedAttempts).integer().not_null().default(0))
                    .col(ColumnDef::new(IpLockouts::LockedUntil).date_time())
                    .col(ColumnDef::new(IpLockouts::LastFailedAt).date_time())
                    .col(ColumnDef::new(IpLockouts::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(IpLockouts::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ip_lockouts_ip")
                    .table(IpLockouts::Table)
                    .col(IpLockouts::Ip)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IpLockouts::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum IpLockouts {
    Table,
    Id,
    Ip,
    FailedAttempts,
    LockedUntil,
    LastFailedAt,
    CreatedAt,
    UpdatedAt,
}
