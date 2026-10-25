//! 仪表盘聚合 API
//!
//! 路由前缀：/api/v1/dashboard
//! 提供一次调用即可获取首页所需的全部统计数据，避免前端发起多次 HTTP 请求。

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, EntityTrait, PaginatorTrait, QueryOrder, Statement,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::task::{self, Entity as ScanTaskEntity};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct OverviewQuery {
    /// 统计趋势的天数（默认 30）
    pub days: Option<i64>,
}

/// 执行原始 SQL 返回单数值
async fn scalar_count(db: &sea_orm::DatabaseConnection, sql: &str) -> i64 {
    let rows = match db
        .query_all_raw(Statement::from_string(DatabaseBackend::Postgres, sql.to_string()))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("统计查询失败: {e}");
            return 0;
        }
    };
    if let Some(row) = rows.into_iter().next() {
        row.try_get("", "count").unwrap_or(0)
    } else {
        0
    }
}

/// 分组统计结果项（序列化为 {key, count} 对象）
#[derive(Debug, Serialize)]
pub struct KeyCount {
    pub key: String,
    pub count: i64,
}

/// 执行原始 SQL 返回 {key, count} 分组
async fn count_group_by(
    db: &sea_orm::DatabaseConnection,
    sql: &str,
    key_col: &str,
) -> Vec<KeyCount> {
    let rows = match db
        .query_all_raw(Statement::from_string(DatabaseBackend::Postgres, sql.to_string()))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("分组统计查询失败: {e}");
            return Vec::new();
        }
    };
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let key: String = row.try_get("", key_col).unwrap_or_default();
        let count: i64 = row.try_get("", "count").unwrap_or(0);
        result.push(KeyCount { key, count });
    }
    result
}

/// GET /api/v1/dashboard/overview
///
/// 聚合返回仪表盘所需的全部统计：资产数、漏洞统计、端口统计、
/// 弱密码统计、漏洞趋势、操作系统分布、风险网络资产 TOP10、最近任务。
pub async fn overview(
    data: web::Data<AppState>,
    query: web::Query<OverviewQuery>,
) -> impl Responder {
    let days = query.days.unwrap_or(30).clamp(1, 365);

    // —— 资产数 ——
    let network_count = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM network_assets").await;
    let application_count =
        scalar_count(&data.db, "SELECT COUNT(*) AS count FROM application_assets").await;
    let database_count =
        scalar_count(&data.db, "SELECT COUNT(*) AS count FROM database_assets").await;

    // —— 漏洞统计 ——
    let vuln_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM vuln_findings").await;

    let vuln_by_severity = count_group_by(
        &data.db,
        "SELECT severity AS key, COUNT(*) AS count FROM vuln_findings GROUP BY severity ORDER BY count DESC",
        "key",
    )
    .await;

    let vuln_by_status = count_group_by(
        &data.db,
        "SELECT risk_status AS key, COUNT(*) AS count FROM vuln_findings GROUP BY risk_status ORDER BY count DESC",
        "key",
    )
    .await;

    let vuln_by_type = count_group_by(
        &data.db,
        "SELECT risk_type AS key, COUNT(*) AS count FROM vuln_findings GROUP BY risk_type ORDER BY count DESC",
        "key",
    )
    .await;

    let fixed_count = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_status IN ('fixed', 'verified', 'closed')",
    )
    .await;
    let fix_rate = if vuln_total > 0 {
        fixed_count as f64 / vuln_total as f64
    } else {
        0.0
    };

    // —— 端口统计 ——
    let port_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM exposure_ports").await;
    let port_risky = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM exposure_ports WHERE is_risky = TRUE",
    )
    .await;
    let port_top = count_group_by(
        &data.db,
        "SELECT port::text AS key, COUNT(*) AS count FROM exposure_ports GROUP BY port ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;
    let port_by_protocol = count_group_by(
        &data.db,
        "SELECT protocol AS key, COUNT(*) AS count FROM exposure_ports WHERE is_risky = TRUE GROUP BY protocol ORDER BY count DESC",
        "key",
    )
    .await;

    // —— 弱密码统计 ——
    let wp_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM weak_passwords").await;
    let wp_top_assets = count_group_by(
        &data.db,
        "SELECT host AS key, COUNT(*) AS count FROM weak_passwords GROUP BY host ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;
    let wp_by_username = count_group_by(
        &data.db,
        "SELECT username AS key, COUNT(*) AS count FROM weak_passwords GROUP BY username ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;
    let wp_by_protocol = count_group_by(
        &data.db,
        "SELECT protocol AS key, COUNT(*) AS count FROM weak_passwords GROUP BY protocol ORDER BY count DESC",
        "key",
    )
    .await;

    // —— 漏洞趋势（按天） ——
    let vuln_trend = count_group_by(
        &data.db,
        &format!(
            "SELECT to_char(first_found::date, 'YYYY-MM-DD') AS key, COUNT(*) AS count \
             FROM vuln_findings \
             WHERE first_found >= now() - interval '{} days' \
             GROUP BY first_found::date \
             ORDER BY first_found::date",
            days
        ),
        "key",
    )
    .await;

    // —— 操作系统分布 ——
    let os_distribution = count_group_by(
        &data.db,
        "SELECT COALESCE(NULLIF(os, ''), '未知') AS key, COUNT(*) AS count FROM network_assets GROUP BY os ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;

    // —— 风险网络资产 TOP10（按漏洞数） ——
    let top_risky_assets = count_group_by(
        &data.db,
        "SELECT target_host AS key, COUNT(*) AS count FROM vuln_findings WHERE risk_type = 'system' GROUP BY target_host ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;

    // —— 按风险类型拆分：系统 / 应用 / 数据库 漏洞 ——
    // 各类型的漏洞总数、等级分布、风险主机 TOP10
    let mut type_sections = serde_json::Map::new();
    for (risk_type, section_key) in [
        ("system", "system"),
        ("application", "application"),
        ("database", "database"),
    ] {
        let total = scalar_count(
            &data.db,
            &format!("SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_type = '{risk_type}'"),
        )
        .await;
        let by_severity = count_group_by(
            &data.db,
            &format!(
                "SELECT severity AS key, COUNT(*) AS count FROM vuln_findings WHERE risk_type = '{risk_type}' GROUP BY severity ORDER BY count DESC"
            ),
            "key",
        )
        .await;
        let top_assets = count_group_by(
            &data.db,
            &format!(
                "SELECT target_host AS key, COUNT(*) AS count FROM vuln_findings WHERE risk_type = '{risk_type}' GROUP BY target_host ORDER BY count DESC LIMIT 10"
            ),
            "key",
        )
        .await;
        type_sections.insert(
            section_key.to_string(),
            serde_json::json!({
                "total": total,
                "by_severity": by_severity,
                "top_assets": top_assets,
            }),
        );
    }

    // —— 基线核查不符合项统计（scan_results 中 result_type = baseline_check） ——
    let baseline_noncompliant = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM scan_results WHERE result_type = 'baseline_check' AND success = FALSE",
    )
    .await;
    // 不符合项 TOP10（按规则名称）
    let baseline_top_items = count_group_by(
        &data.db,
        "SELECT raw_data->>'rule_name' AS key, COUNT(*) AS count FROM scan_results \
         WHERE result_type = 'baseline_check' AND success = FALSE \
         GROUP BY raw_data->>'rule_name' ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;
    // 不符合 IP TOP10（按主机）
    let baseline_top_hosts = count_group_by(
        &data.db,
        "SELECT host AS key, COUNT(*) AS count FROM scan_results \
         WHERE result_type = 'baseline_check' AND success = FALSE \
         GROUP BY host ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;

    // —— 网络资产风险等级分布（4 档：严重 75+ / 高危 50-75 / 中危 25-50 / 低危 0-25） ——
    let risk_level_distribution = vec![
        ("严重", scalar_count(&data.db, "SELECT COUNT(*) AS count FROM network_assets WHERE risk_score >= 75").await),
        ("高危", scalar_count(&data.db, "SELECT COUNT(*) AS count FROM network_assets WHERE risk_score >= 50 AND risk_score < 75").await),
        ("中危", scalar_count(&data.db, "SELECT COUNT(*) AS count FROM network_assets WHERE risk_score >= 25 AND risk_score < 50").await),
        ("低危", scalar_count(&data.db, "SELECT COUNT(*) AS count FROM network_assets WHERE risk_score < 25").await),
    ];

    // —— 最近 5 个任务 ——
    let recent_tasks = match ScanTaskEntity::find()
        .order_by_desc(task::Column::CreatedAt)
        .paginate(&data.db, 5)
        .fetch_page(0)
        .await
    {
        Ok(items) => items
            .into_iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "task_type": format!("{:?}", t.task_type).to_lowercase(),
                    "status": format!("{:?}", t.status).to_lowercase(),
                    "progress": t.progress,
                    "created_at": t.created_at,
                    "started_at": t.started_at,
                    "finished_at": t.finished_at,
                    "launch_mode": format!("{:?}", t.launch_mode).to_lowercase(),
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            tracing::error!("查询最近任务失败: {e}");
            Vec::new()
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "assets": {
            "network": network_count,
            "application": application_count,
            "database": database_count,
            "total": network_count + application_count + database_count,
        },
        "vulns": {
            "total": vuln_total,
            "by_severity": vuln_by_severity,
            "by_status": vuln_by_status,
            "by_type": vuln_by_type,
            "fixed_count": fixed_count,
            "fix_rate": fix_rate,
        },
        // 按风险类型拆分（系统 / 应用 / 数据库）
        "vuln_types": type_sections,
        // 基线核查不符合项统计
        "baseline": {
            "noncompliant_total": baseline_noncompliant,
            "top_items": baseline_top_items,
            "top_hosts": baseline_top_hosts,
        },
        "ports": {
            "total": port_total,
            "risky_count": port_risky,
            "top_ports": port_top,
            "risky_by_protocol": port_by_protocol,
        },
        "weak_passwords": {
            "total": wp_total,
            "top_assets": wp_top_assets,
            "by_username": wp_by_username,
            "by_protocol": wp_by_protocol,
        },
        "vuln_trend": vuln_trend,
        "os_distribution": os_distribution,
        "top_risky_assets": top_risky_assets,
        "risk_level_distribution": risk_level_distribution.into_iter().map(|(k, v)| serde_json::json!({"key": k, "count": v})).collect::<Vec<_>>(),
        "recent_tasks": recent_tasks,
    }))
}
