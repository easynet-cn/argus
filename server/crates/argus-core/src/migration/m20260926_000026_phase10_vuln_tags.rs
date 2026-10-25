//! 漏洞标签管理（多对多关联 + 多维检索）
//!
//! 要求：漏洞模板支持标签管理，实现按标签、严重程度、分类、CVE 等多维检索。
//! 本迁移创建 vuln_tags（标签表）和 vuln_template_tags（模板-标签关联表）两张表，
//! 并预置常见漏洞分类标签。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 漏洞标签表
        manager
            .create_table(
                Table::create()
                    .table(VulnTag::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(VulnTag::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(VulnTag::Name).string_len(64).not_null())
                    .col(ColumnDef::new(VulnTag::Color).string_len(16))
                    .col(ColumnDef::new(VulnTag::Description).text())
                    .col(ColumnDef::new(VulnTag::IsBuiltin).boolean().not_null().default(false))
                    .col(ColumnDef::new(VulnTag::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(VulnTag::UpdatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // 标签名唯一索引
        manager
            .create_index(
                Index::create()
                    .name("idx_vuln_tag_name")
                    .table(VulnTag::Table)
                    .col(VulnTag::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // 漏洞模板-标签关联表
        manager
            .create_table(
                Table::create()
                    .table(VulnTemplateTag::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(VulnTemplateTag::Id).string_len(64).not_null().primary_key())
                    .col(ColumnDef::new(VulnTemplateTag::VulnTemplateId).string_len(64).not_null())
                    .col(ColumnDef::new(VulnTemplateTag::TagId).string_len(64).not_null())
                    .col(ColumnDef::new(VulnTemplateTag::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;

        // 关联表索引：按模板 ID 查标签
        manager
            .create_index(
                Index::create()
                    .name("idx_vtt_template_id")
                    .table(VulnTemplateTag::Table)
                    .col(VulnTemplateTag::VulnTemplateId)
                    .to_owned(),
            )
            .await?;

        // 关联表索引：按标签 ID 查模板
        manager
            .create_index(
                Index::create()
                    .name("idx_vtt_tag_id")
                    .table(VulnTemplateTag::Table)
                    .col(VulnTemplateTag::TagId)
                    .to_owned(),
            )
            .await?;

        // 关联表唯一约束：同一模板同一标签只能关联一次
        manager
            .create_index(
                Index::create()
                    .name("idx_vtt_template_tag_unique")
                    .table(VulnTemplateTag::Table)
                    .col(VulnTemplateTag::VulnTemplateId)
                    .col(VulnTemplateTag::TagId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // 预置内置漏洞分类标签
        // (name, color, description)
        let builtin_tags: &[(&str, &str, &str)] = &[
            ("远程代码执行", "#FF0000", "Remote Code Execution，可在目标上执行任意代码"),
            ("权限提升", "#FF4500", "Privilege Escalation，可获取更高权限"),
            ("信息泄露", "#FFA500", "Information Disclosure，泄露敏感信息"),
            ("SQL注入", "#DC143C", "SQL Injection，可操纵数据库查询"),
            ("跨站脚本", "#FF6347", "Cross-Site Scripting，注入恶意脚本"),
            ("未授权访问", "#FF8C00", "Unauthorized Access，无需认证即可访问"),
            ("弱口令", "#FFD700", "Weak Password，存在默认或弱密码"),
            ("配置错误", "#4169E1", "Misconfiguration，安全配置不当"),
            ("拒绝服务", "#B22222", "Denial of Service，可导致服务不可用"),
            ("目录遍历", "#CD853F", "Directory Traversal，可访问越权文件"),
            ("命令注入", "#FF1493", "Command Injection，可执行系统命令"),
            ("文件上传", "#FF69B4", "Unrestricted File Upload，可上传恶意文件"),
            ("文件包含", "#DA70D6", "File Inclusion，可包含任意文件"),
            ("CRLF注入", "#9370DB", "CRLF Injection，注入HTTP头"),
            ("XXE", "#8B008B", "XML External Entity，可读取文件/SSRF"),
            ("SSRF", "#800080", "Server-Side Request Forgery，服务端请求伪造"),
            ("CSRF", "#9400D3", "Cross-Site Request Forgery，跨站请求伪造"),
            ("反序列化", "#6A5ACD", "Deserialization，反序列化漏洞"),
            ("越权访问", "#7B68EE", "Broken Access Control，可越权操作"),
            ("组件漏洞", "#483D8B", "第三方组件已知漏洞"),
        ];

        let conn = manager.get_connection();
        let now = chrono::Utc::now().naive_utc();
        for (idx, (name, color, desc)) in builtin_tags.iter().enumerate() {
            let id = format!("vtag-builtin-{:04}", idx + 1);
            let sql = format!(
                "INSERT INTO vuln_tags (id, name, color, description, is_builtin, created_at, updated_at) VALUES ('{}', '{}', '{}', '{}', true, '{}', '{}')",
                id, name, color, desc.replace('\'', "''"), now, now
            );
            conn.execute_unprepared(&sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(VulnTemplateTag::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(VulnTag::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum VulnTag {
    Table,
    Id,
    Name,
    Color,
    Description,
    IsBuiltin,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum VulnTemplateTag {
    Table,
    Id,
    VulnTemplateId,
    TagId,
    CreatedAt,
}
