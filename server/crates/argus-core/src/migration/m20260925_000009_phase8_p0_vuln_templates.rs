//! P0-12: 创建漏洞模板表 vuln_templates，支持自定义 POC 管理

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VulnTemplates::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(VulnTemplates::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(VulnTemplates::Name).string_len(256).not_null())
                    .col(ColumnDef::new(VulnTemplates::Description).text())
                    .col(ColumnDef::new(VulnTemplates::Severity).string_len(20).not_null())
                    .col(ColumnDef::new(VulnTemplates::Cve).string_len(64))
                    .col(ColumnDef::new(VulnTemplates::Category).string_len(64))
                    .col(ColumnDef::new(VulnTemplates::PluginType).string_len(32))
                    .col(ColumnDef::new(VulnTemplates::TargetType).string_len(32))
                    .col(ColumnDef::new(VulnTemplates::PocContent).text())
                    .col(ColumnDef::new(VulnTemplates::MatchRule).text())
                    .col(ColumnDef::new(VulnTemplates::FixAdvice).text())
                    .col(ColumnDef::new(VulnTemplates::Enabled).boolean().not_null().default(true))
                    .col(ColumnDef::new(VulnTemplates::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(VulnTemplates::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(VulnTemplates::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_vuln_templates_severity")
                    .table(VulnTemplates::Table)
                    .col(VulnTemplates::Severity)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_vuln_templates_category")
                    .table(VulnTemplates::Table)
                    .col(VulnTemplates::Category)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_vuln_templates_enabled")
                    .table(VulnTemplates::Table)
                    .col(VulnTemplates::Enabled)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VulnTemplates::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum VulnTemplates {
    Table,
    Id,
    Name,
    Description,
    Severity,
    Cve,
    Category,
    PluginType,
    TargetType,
    PocContent,
    MatchRule,
    FixAdvice,
    Enabled,
    IsBuiltin,
    CreatedAt,
    UpdatedAt,
}
