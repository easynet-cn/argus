//! 数据库迁移管理

pub mod m20260919_000001_init;
pub mod m20260919_000002_users;
pub mod m20260920_000001_scan_results;
pub mod m20260922_000001_phase4;
pub mod m20260924_000001_phase8_batch1;
pub mod m20260925_000001_phase8_batch2;
pub mod m20260925_000002_phase8_batch3a;
pub mod m20260925_000003_phase8_batch3b;
pub mod m20260925_000004_phase8_batch4;
pub mod m20260925_000005_phase8_p0_assets;
pub mod m20260925_000006_phase8_p0_vuln_fields;
pub mod m20260925_000007_phase8_p0_config_changes;
pub mod m20260925_000008_phase8_p0_alert_records;
pub mod m20260925_000009_phase8_p0_vuln_templates;
pub mod m20260925_000010_phase8_p0_fingerprint_rules;
pub mod m20260925_000011_phase8_ics_device_library;
pub mod m20260925_000012_phase8_licenses;
pub mod m20260926_000013_phase9_vuln_app_db_fields;
pub mod m20260926_000014_phase9_credential_binding;
pub mod m20260926_000015_phase9_dictionary_filename;
pub mod m20260926_000016_phase9_discovery_params;
pub mod m20260926_000017_vuln_disposition_history;
pub mod m20260926_000018_phase9_vuln_impact_range;
pub mod m20260926_000019_phase9_certificate_filename;
pub mod m20260926_000020_phase10_user_sessions;
pub mod m20260926_000021_phase10_ip_lockout;
pub mod m20260926_000022_phase9_exposure_port_fields;
pub mod m20260926_000023_phase10_config_template_category;
pub mod m20260926_000024_phase10_user_real_name;
pub mod m20260926_000025_phase10_port_violation_service_risk;
pub mod m20260926_000026_phase10_vuln_tags;
pub mod m20260926_000027_phase10_builtin_baseline_templates;
pub mod m20260926_000028_phase10_api_keys;
pub mod m20260926_000029_phase10_weak_password_asset_group;

use sea_orm_migration::prelude::*;
use sea_orm_migration::MigratorTrait;

/// Argus Migrator
pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260919_000001_init::Migration),
            Box::new(m20260919_000002_users::Migration),
            Box::new(m20260920_000001_scan_results::Migration),
            Box::new(m20260922_000001_phase4::Migration),
            Box::new(m20260924_000001_phase8_batch1::Migration),
            Box::new(m20260925_000001_phase8_batch2::Migration),
            Box::new(m20260925_000002_phase8_batch3a::Migration),
            Box::new(m20260925_000003_phase8_batch3b::Migration),
            Box::new(m20260925_000004_phase8_batch4::Migration),
            Box::new(m20260925_000005_phase8_p0_assets::Migration),
            Box::new(m20260925_000006_phase8_p0_vuln_fields::Migration),
            Box::new(m20260925_000007_phase8_p0_config_changes::Migration),
            Box::new(m20260925_000008_phase8_p0_alert_records::Migration),
            Box::new(m20260925_000009_phase8_p0_vuln_templates::Migration),
            Box::new(m20260925_000010_phase8_p0_fingerprint_rules::Migration),
            Box::new(m20260925_000011_phase8_ics_device_library::Migration),
            Box::new(m20260925_000012_phase8_licenses::Migration),
            Box::new(m20260926_000013_phase9_vuln_app_db_fields::Migration),
            Box::new(m20260926_000014_phase9_credential_binding::Migration),
            Box::new(m20260926_000015_phase9_dictionary_filename::Migration),
            Box::new(m20260926_000016_phase9_discovery_params::Migration),
            Box::new(m20260926_000017_vuln_disposition_history::Migration),
            Box::new(m20260926_000018_phase9_vuln_impact_range::Migration),
            Box::new(m20260926_000019_phase9_certificate_filename::Migration),
            Box::new(m20260926_000020_phase10_user_sessions::Migration),
            Box::new(m20260926_000021_phase10_ip_lockout::Migration),
            Box::new(m20260926_000022_phase9_exposure_port_fields::Migration),
            Box::new(m20260926_000023_phase10_config_template_category::Migration),
            Box::new(m20260926_000024_phase10_user_real_name::Migration),
            Box::new(m20260926_000025_phase10_port_violation_service_risk::Migration),
            Box::new(m20260926_000026_phase10_vuln_tags::Migration),
            Box::new(m20260926_000027_phase10_builtin_baseline_templates::Migration),
            Box::new(m20260926_000028_phase10_api_keys::Migration),
            Box::new(m20260926_000029_phase10_weak_password_asset_group::Migration),
        ]
    }
}

/// 执行数据库迁移（up）
pub async fn run_migrations(db: &sea_orm::DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    Migrator::up(db, None).await
}

/// 回滚最后一个迁移（down）
pub async fn rollback_migration(db: &sea_orm::DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    Migrator::down(db, Some(1)).await
}

/// 刷新数据库（先全部 down，再全部 up）
pub async fn refresh_database(db: &sea_orm::DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    Migrator::refresh(db).await
}

/// 重置数据库（down 全部，up 全部）
pub async fn reset_database(db: &sea_orm::DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    Migrator::reset(db).await
}
