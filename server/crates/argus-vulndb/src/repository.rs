//! CVE 查询接口

use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, PaginatorTrait};
use argus_core::entity::{cve as cves, cve_cpe};
use std::collections::HashMap;

pub async fn find_by_cve_id(db: &DatabaseConnection, cve_id: &str) -> Option<cves::Model> {
    cves::Entity::find_by_id(cve_id.to_string()).one(db).await.ok().flatten()
}

pub async fn find_by_cpe(db: &DatabaseConnection, cpe_uri: &str) -> Vec<cves::Model> {
    let mappings = cve_cpe::Entity::find()
        .filter(cve_cpe::Column::CpeUri.eq(cpe_uri))
        .all(db).await.unwrap_or_default();
    let cve_ids: Vec<String> = mappings.iter().map(|m| m.cve_id.clone()).collect();
    if cve_ids.is_empty() { return vec![]; }
    cves::Entity::find()
        .filter(cves::Column::Id.is_in(cve_ids))
        .all(db).await.unwrap_or_default()
}

pub async fn search_by_keyword(db: &DatabaseConnection, keyword: &str, limit: u64, offset: u64) -> Vec<cves::Model> {
    cves::Entity::find()
        .filter(cves::Column::Description.contains(keyword))
        .paginate(db, limit)
        .fetch_page(offset)
        .await.unwrap_or_default()
}

pub async fn find_by_severity(db: &DatabaseConnection, severity: &str) -> Vec<cves::Model> {
    cves::Entity::find()
        .filter(cves::Column::Severity.eq(severity.to_uppercase()))
        .all(db).await.unwrap_or_default()
}

pub async fn count_total(db: &DatabaseConnection) -> u64 {
    cves::Entity::find().count(db).await.unwrap_or(0)
}

pub async fn stats_by_year(db: &DatabaseConnection) -> Vec<(i32, u64)> {
    let all = cves::Entity::find().all(db).await.unwrap_or_default();
    let mut counts: HashMap<i32, u64> = HashMap::new();
    for cve in all {
        if let Some(dt) = cve.published {
            let year = dt.format("%Y").to_string().parse::<i32>().unwrap_or(0);
            *counts.entry(year).or_insert(0) += 1;
        }
    }
    let mut result: Vec<(i32, u64)> = counts.into_iter().collect();
    result.sort_by_key(|(y, _)| *y);
    result
}

pub async fn stats_by_severity(db: &DatabaseConnection) -> Vec<(String, u64)> {
    let all = cves::Entity::find().all(db).await.unwrap_or_default();
    let mut counts: HashMap<String, u64> = HashMap::new();
    for cve in all {
        let sev = cve.severity.unwrap_or_else(|| "UNKNOWN".to_string()).to_uppercase();
        *counts.entry(sev).or_insert(0) += 1;
    }
    counts.into_iter().collect()
}
