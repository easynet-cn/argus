//! 配置模板（基线）补齐结构化分类字段
//!
//! 基线管理要求：基线规则结构化分类（类型/类别/安全级别）。
//! 本迁移追加 config_type/category/security_level/description 字段。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigTemplates::Table)
                    .add_column(
                        ColumnDef::new(ConfigTemplates::ConfigType)
                            .string_len(32)
                            .default("system")
                            .not_null(),
                    )
                    .add_column(
                        ColumnDef::new(ConfigTemplates::Category)
                            .string_len(64)
                            .default("custom")
                            .not_null(),
                    )
                    .add_column(
                        ColumnDef::new(ConfigTemplates::SecurityLevel)
                            .string_len(16)
                            .default("low")
                            .not_null(),
                    )
                    .add_column(ColumnDef::new(ConfigTemplates::Description).text())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ConfigTemplates::Table)
                    .drop_column(ConfigTemplates::ConfigType)
                    .drop_column(ConfigTemplates::Category)
                    .drop_column(ConfigTemplates::SecurityLevel)
                    .drop_column(ConfigTemplates::Description)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum ConfigTemplates {
    Table,
    ConfigType,
    Category,
    SecurityLevel,
    Description,
}
