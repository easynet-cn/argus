//! 用户实体补齐真实姓名与来源字段
//!
//! 用户管理要求记录真实姓名和用户来源（本地/LDAP/OAuth）。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::RealName).string_len(128))
                    .add_column(
                        ColumnDef::new(Users::Source)
                            .string_len(32)
                            .default("local")
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::RealName)
                    .drop_column(Users::Source)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum Users {
    Table,
    RealName,
    Source,
}
