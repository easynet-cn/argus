//! P1: 补齐 discovery_tasks 结构化扫描参数（网关/扫描模式/排除主机/线程/爆破层级）

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DiscoveryTasks::Table)
                    .add_column(ColumnDef::new(DiscoveryTasks::Gateway).string_len(64))
                    .add_column(ColumnDef::new(DiscoveryTasks::ScanMode).string_len(20))
                    .add_column(ColumnDef::new(DiscoveryTasks::ExcludeHosts).text())
                    .add_column(ColumnDef::new(DiscoveryTasks::Threads).integer())
                    .add_column(ColumnDef::new(DiscoveryTasks::BruteLevel).integer())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DiscoveryTasks::Table)
                    .drop_column(DiscoveryTasks::Gateway)
                    .drop_column(DiscoveryTasks::ScanMode)
                    .drop_column(DiscoveryTasks::ExcludeHosts)
                    .drop_column(DiscoveryTasks::Threads)
                    .drop_column(DiscoveryTasks::BruteLevel)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum DiscoveryTasks {
    Table,
    Gateway,
    ScanMode,
    ExcludeHosts,
    Threads,
    BruteLevel,
}
