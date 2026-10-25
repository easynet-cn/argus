//! 风险管理 API
//!
//! 路由前缀：/api/v1/risk
//! 包含：漏洞处置状态机、暴露端口、弱密码、风险统计总览。

use actix_web::{web, HttpMessage, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Statement, TransactionTrait, ActiveValue::Set,
};
use serde::{Deserialize, Serialize};

use argus_core::entity::exposure_port::{self, Entity as ExposurePortEntity};
use argus_core::entity::vuln_disposition_history::{self, Entity as VulnDispositionHistoryEntity};
use argus_core::entity::vuln_finding::{self, Entity as VulnFindingEntity};
use argus_core::entity::weak_password::{self, Entity as WeakPasswordEntity};
use crate::state::AppState;

// ==================== 风险状态机 ====================

/// 合法的风险处置状态
pub const VALID_RISK_STATUSES: &[&str] = &[
    "new",
    "processing",
    "deferred",
    "fixed",
    "verified",
    "closed",
    "false_positive",
    "ignored",
    "reopened",
];

/// 返回某个状态允许转换到的目标状态列表
fn allowed_next_statuses(current: &str) -> &'static [&'static str] {
    match current {
        "new" => &["processing", "deferred", "ignored", "false_positive"],
        "processing" => &["fixed", "deferred", "ignored"],
        "fixed" => &["verified", "closed", "reopened"],
        "verified" => &["closed"],
        "closed" => &["reopened"],
        "deferred" => &["processing"],
        "false_positive" => &["reopened"],
        "ignored" => &["reopened"],
        "reopened" => &["processing", "deferred", "ignored", "false_positive"],
        _ => &[],
    }
}

/// 校验状态转换是否合法
fn is_valid_transition(from: &str, to: &str) -> bool {
    allowed_next_statuses(from).contains(&to)
}

/// 记录一条漏洞处置历史
async fn record_disposition(
    db: &impl ConnectionTrait,
    vuln_id: &str,
    from_status: &str,
    to_status: &str,
    operator: &str,
    reason: Option<String>,
) {
    let history = vuln_disposition_history::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        vuln_id: Set(vuln_id.to_string()),
        from_status: Set(from_status.to_string()),
        to_status: Set(to_status.to_string()),
        operator: Set(operator.to_string()),
        reason: Set(reason),
        created_at: Set(chrono::Utc::now()),
    };
    if let Err(e) = history.insert(db).await {
        tracing::warn!("记录漏洞处置历史失败: {e}");
    }
}

// ==================== 请求/响应结构 ====================

#[derive(Debug, Deserialize)]
pub struct VulnListQuery {
    pub risk_type: Option<String>,
    pub risk_status: Option<String>,
    pub severity: Option<String>,
    pub host: Option<String>,
    pub cve_id: Option<String>,
    pub name: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVulnStatusRequest {
    pub risk_status: String,
    pub assigned_to: Option<String>,
    pub remediation_note: Option<String>,
    /// 处置原因/备注（写入历史记录）
    pub reason: Option<String>,
    /// 操作人（可选，默认取当前登录用户）
    pub operator: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchUpdateVulnStatusRequest {
    pub ids: Vec<String>,
    pub risk_status: String,
    pub assigned_to: Option<String>,
    pub remediation_note: Option<String>,
    pub reason: Option<String>,
    pub operator: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PortListQuery {
    pub host: Option<String>,
    pub port: Option<i32>,
    pub is_risky: Option<bool>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct WeakPasswordListQuery {
    pub host: Option<String>,
    pub protocol: Option<String>,
    pub username: Option<String>,
    pub risk_status: Option<String>,
    pub asset_group_id: Option<String>,
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BatchStatusResult {
    pub updated: usize,
    pub failed: Vec<BatchStatusFailure>,
}

#[derive(Debug, Serialize)]
pub struct BatchStatusFailure {
    pub id: String,
    pub reason: String,
}

// ==================== 工具函数 ====================

/// 分组统计结果项（序列化为 {key, count} 对象）
#[derive(Debug, Serialize)]
pub struct KeyCount {
    pub key: String,
    pub count: i64,
}

/// 执行原始 COUNT GROUP BY SQL，返回 {key, count} 列表
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
            tracing::error!("统计查询失败: {e}");
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

/// 执行原始 SQL 返回单个数值
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

// ==================== 漏洞列表 ====================

/// GET /api/v1/risk/vulns
pub async fn list_vulns(
    data: web::Data<AppState>,
    query: web::Query<VulnListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 500);

    let mut q = VulnFindingEntity::find();
    if let Some(v) = &query.risk_type {
        q = q.filter(vuln_finding::Column::RiskType.eq(v.clone()));
    }
    if let Some(v) = &query.risk_status {
        q = q.filter(vuln_finding::Column::RiskStatus.eq(v.clone()));
    }
    if let Some(v) = &query.severity {
        q = q.filter(vuln_finding::Column::Severity.eq(v.clone()));
    }
    if let Some(v) = &query.host {
        q = q.filter(vuln_finding::Column::TargetHost.eq(v.clone()));
    }
    if let Some(v) = &query.cve_id {
        q = q.filter(vuln_finding::Column::CveId.eq(v.clone()));
    }
    if let Some(v) = &query.name {
        q = q.filter(vuln_finding::Column::Title.contains(v.clone()));
    }

    match q
        .order_by_desc(vuln_finding::Column::LastFound)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 漏洞详情 ====================

/// GET /api/v1/risk/vulns/{id}
pub async fn get_vuln_detail(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let uid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无效的漏洞 ID"})),
    };
    match VulnFindingEntity::find_by_id(uid).one(&data.db).await {
        Ok(Some(vuln)) => HttpResponse::Ok().json(vuln),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "漏洞未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 修改漏洞处置状态 ====================

/// PUT /api/v1/risk/vulns/{id}/status
pub async fn update_vuln_status(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateVulnStatusRequest>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    let id = path.into_inner();
    let target_status = body.risk_status.trim().to_lowercase();

    if !VALID_RISK_STATUSES.contains(&target_status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("无效的风险状态: {}", target_status)
        }));
    }

    let uid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "无效的漏洞 ID"})),
    };

    let vuln = match VulnFindingEntity::find_by_id(uid).one(&data.db).await {
        Ok(Some(v)) => v,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "漏洞未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    if !is_valid_transition(&vuln.risk_status, &target_status) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!(
                "非法状态转换: {} -> {}，允许的目标状态: {:?}",
                vuln.risk_status,
                target_status,
                allowed_next_statuses(&vuln.risk_status)
            )
        }));
    }

    // 操作人：优先取请求体，其次取 JWT 中的用户名，最后 "system"
    let operator = body.operator.clone().unwrap_or_else(|| {
        req.extensions()
            .get::<argus_core::auth::Claims>()
            .map(|c| c.username.clone())
            .unwrap_or_else(|| "system".to_string())
    });

    let from_status = vuln.risk_status.clone();
    let mut active: vuln_finding::ActiveModel = vuln.into();
    active.risk_status = Set(target_status.clone());
    if let Some(v) = &body.assigned_to {
        active.assigned_to = Set(Some(v.clone()));
    }
    if let Some(v) = &body.remediation_note {
        active.remediation_note = Set(Some(v.clone()));
    }
    match active.update(&data.db).await {
        Ok(updated) => {
            record_disposition(
                &data.db,
                &id,
                &from_status,
                &target_status,
                &operator,
                body.reason.clone(),
            )
            .await;
            HttpResponse::Ok().json(updated)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 批量修改漏洞状态（事务） ====================

/// PUT /api/v1/risk/vulns/batch-status
pub async fn batch_update_vuln_status(
    data: web::Data<AppState>,
    body: web::Json<BatchUpdateVulnStatusRequest>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    let target_status = body.risk_status.trim().to_lowercase();

    if !VALID_RISK_STATUSES.contains(&target_status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("无效的风险状态: {}", target_status)
        }));
    }

    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }

    let operator = body.operator.clone().unwrap_or_else(|| {
        req.extensions()
            .get::<argus_core::auth::Claims>()
            .map(|c| c.username.clone())
            .unwrap_or_else(|| "system".to_string())
    });

    let txn = match data.db.begin().await {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut updated = 0usize;
    let mut failed: Vec<BatchStatusFailure> = Vec::new();

    for raw_id in &body.ids {
        // 解析 UUID
        let uid = match uuid::Uuid::parse_str(raw_id) {
            Ok(u) => u,
            Err(_) => {
                failed.push(BatchStatusFailure {
                    id: raw_id.clone(),
                    reason: "无效的 UUID".to_string(),
                });
                continue;
            }
        };
        let vuln = match VulnFindingEntity::find_by_id(uid).one(&txn).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                failed.push(BatchStatusFailure {
                    id: raw_id.clone(),
                    reason: "漏洞未找到".to_string(),
                });
                continue;
            }
            Err(e) => {
                failed.push(BatchStatusFailure {
                    id: raw_id.clone(),
                    reason: format!("查询失败: {e}"),
                });
                continue;
            }
        };

        if !is_valid_transition(&vuln.risk_status, &target_status) {
            failed.push(BatchStatusFailure {
                id: raw_id.clone(),
                reason: format!(
                    "非法状态转换: {} -> {}",
                    vuln.risk_status, target_status
                ),
            });
            continue;
        }

        let from_status = vuln.risk_status.clone();
        let mut active: vuln_finding::ActiveModel = vuln.into();
        active.risk_status = Set(target_status.clone());
        if let Some(v) = &body.assigned_to {
            active.assigned_to = Set(Some(v.clone()));
        }
        if let Some(v) = &body.remediation_note {
            active.remediation_note = Set(Some(v.clone()));
        }
        if let Err(e) = active.update(&txn).await {
            failed.push(BatchStatusFailure {
                id: raw_id.clone(),
                reason: format!("更新失败: {e}"),
            });
            continue;
        }
        record_disposition(
            &txn,
            raw_id,
            &from_status,
            &target_status,
            &operator,
            body.reason.clone(),
        )
        .await;
        updated += 1;
    }

    if let Err(e) = txn.commit().await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("事务提交失败: {e}")
        }));
    }

    HttpResponse::Ok().json(BatchStatusResult { updated, failed })
}

// ==================== 漏洞处置历史 ====================

/// GET /api/v1/risk/vulns/{id}/disposition-history
pub async fn get_vuln_disposition_history(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match VulnDispositionHistoryEntity::find()
        .filter(vuln_disposition_history::Column::VulnId.eq(id))
        .order_by_desc(vuln_disposition_history::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({ "items": items })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 漏洞统计 ====================

/// GET /api/v1/risk/vulns/stats
pub async fn vuln_stats(data: web::Data<AppState>) -> impl Responder {
    let total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM vuln_findings").await;

    let by_severity = count_group_by(
        &data.db,
        "SELECT severity AS key, COUNT(*) AS count FROM vuln_findings GROUP BY severity ORDER BY count DESC",
        "key",
    )
    .await;

    let by_status = count_group_by(
        &data.db,
        "SELECT risk_status AS key, COUNT(*) AS count FROM vuln_findings GROUP BY risk_status ORDER BY count DESC",
        "key",
    )
    .await;

    let by_type = count_group_by(
        &data.db,
        "SELECT risk_type AS key, COUNT(*) AS count FROM vuln_findings GROUP BY risk_type ORDER BY count DESC",
        "key",
    )
    .await;

    // 修复率：已修复(verified+closed) / 总数
    let fixed_count = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_status IN ('fixed', 'verified', 'closed')",
    )
    .await;
    let fix_rate = if total > 0 {
        fixed_count as f64 / total as f64
    } else {
        0.0
    };

    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
        "fixed_count": fixed_count,
        "fix_rate": fix_rate,
    }))
}

// ==================== 暴露端口 ====================

/// GET /api/v1/risk/ports
pub async fn list_ports(
    data: web::Data<AppState>,
    query: web::Query<PortListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 500);

    let mut q = ExposurePortEntity::find();
    if let Some(v) = &query.host {
        q = q.filter(exposure_port::Column::Host.eq(v.clone()));
    }
    if let Some(v) = query.port {
        q = q.filter(exposure_port::Column::Port.eq(v));
    }
    if let Some(v) = query.is_risky {
        q = q.filter(exposure_port::Column::IsRisky.eq(v));
    }

    match q
        .order_by_desc(exposure_port::Column::LastFound)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /api/v1/risk/ports/stats
pub async fn port_stats(data: web::Data<AppState>) -> impl Responder {
    let total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM exposure_ports").await;
    let risky_count = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM exposure_ports WHERE is_risky = TRUE",
    )
    .await;

    // TOP10 暴露端口
    let top_ports = count_group_by(
        &data.db,
        "SELECT port::text AS key, COUNT(*) AS count FROM exposure_ports GROUP BY port ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;

    // 风险端口分布（按协议）
    let by_protocol = count_group_by(
        &data.db,
        "SELECT protocol AS key, COUNT(*) AS count FROM exposure_ports WHERE is_risky = TRUE GROUP BY protocol ORDER BY count DESC",
        "key",
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "risky_count": risky_count,
        "top_ports": top_ports,
        "risky_by_protocol": by_protocol,
    }))
}

/// 暴露端口 XLSX 导出 GET /api/v1/risk/ports/export
pub async fn export_ports_xlsx(data: web::Data<AppState>) -> impl Responder {
    use rust_xlsxwriter::Workbook;

    let items = match ExposurePortEntity::find()
        .order_by_desc(exposure_port::Column::LastFound)
        .all(&data.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let headers = [
        "主机", "端口", "协议", "服务", "Banner", "版本", "响应码", "标题",
        "服务器架构", "页面编码", "是否风险", "首次发现", "最后发现",
    ];
    for (i, h) in headers.iter().enumerate() {
        ws.write_string(0, i as u16, *h).ok();
    }
    for (row, p) in items.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, &p.host).ok();
        ws.write_number(r, 1, p.port as f64).ok();
        ws.write_string(r, 2, &p.protocol).ok();
        ws.write_string(r, 3, p.service.clone().unwrap_or_default()).ok();
        ws.write_string(r, 4, p.banner.clone().unwrap_or_default()).ok();
        ws.write_string(r, 5, p.version.clone().unwrap_or_default()).ok();
        ws.write_string(r, 6, p.response_code.clone().unwrap_or_default()).ok();
        ws.write_string(r, 7, p.title.clone().unwrap_or_default()).ok();
        ws.write_string(r, 8, p.server_arch.clone().unwrap_or_default()).ok();
        ws.write_string(r, 9, p.page_encoding.clone().unwrap_or_default()).ok();
        ws.write_string(r, 10, if p.is_risky.unwrap_or(false) { "是" } else { "否" }).ok();
        ws.write_string(r, 11, p.first_found.to_rfc3339()).ok();
        ws.write_string(r, 12, p.last_found.to_rfc3339()).ok();
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=exposed_ports.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 弱密码 ====================

/// GET /api/v1/risk/weak-passwords
/// 支持按 host/protocol/username/risk_status/asset_group_id 筛选
pub async fn list_weak_passwords(
    data: web::Data<AppState>,
    query: web::Query<WeakPasswordListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 500);

    let mut q = WeakPasswordEntity::find();
    if let Some(v) = &query.host {
        q = q.filter(weak_password::Column::Host.eq(v.clone()));
    }
    if let Some(v) = &query.protocol {
        q = q.filter(weak_password::Column::Protocol.eq(v.clone()));
    }
    if let Some(v) = &query.username {
        q = q.filter(weak_password::Column::Username.eq(v.clone()));
    }
    if let Some(v) = &query.risk_status {
        q = q.filter(weak_password::Column::RiskStatus.eq(v.clone()));
    }
    if let Some(v) = &query.asset_group_id {
        q = q.filter(weak_password::Column::AssetGroupId.eq(v.clone()));
    }

    match q
        .order_by_desc(weak_password::Column::LastFound)
        .paginate(&data.db, page_size)
        .fetch_page((page - 1) as u64)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// GET /api/v1/risk/weak-passwords/stats
pub async fn weak_password_stats(data: web::Data<AppState>) -> impl Responder {
    let total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM weak_passwords").await;

    // TOP10 风险资产（按 host 统计弱密码数量）
    let top_assets = count_group_by(
        &data.db,
        "SELECT host AS key, COUNT(*) AS count FROM weak_passwords GROUP BY host ORDER BY count DESC LIMIT 10",
        "key",
    )
    .await;

    // 用户名分布
    let by_username = count_group_by(
        &data.db,
        "SELECT username AS key, COUNT(*) AS count FROM weak_passwords GROUP BY username ORDER BY count DESC",
        "key",
    )
    .await;

    // 协议分布
    let by_protocol = count_group_by(
        &data.db,
        "SELECT protocol AS key, COUNT(*) AS count FROM weak_passwords GROUP BY protocol ORDER BY count DESC",
        "key",
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "total": total,
        "top_assets": top_assets,
        "by_username": by_username,
        "by_protocol": by_protocol,
    }))
}

/// 弱密码 XLSX 导出 GET /api/v1/risk/weak-passwords/export
pub async fn export_weak_passwords_xlsx(data: web::Data<AppState>) -> impl Responder {
    use rust_xlsxwriter::Workbook;

    let items = match WeakPasswordEntity::find()
        .order_by_desc(weak_password::Column::LastFound)
        .all(&data.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    let headers = ["主机", "协议", "端口", "用户名", "密码", "风险状态", "首次发现", "最后发现"];
    for (i, h) in headers.iter().enumerate() {
        ws.write_string(0, i as u16, *h).ok();
    }
    for (row, w) in items.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, &w.host).ok();
        ws.write_string(r, 1, &w.protocol).ok();
        ws.write_number(r, 2, w.port as f64).ok();
        ws.write_string(r, 3, &w.username).ok();
        ws.write_string(r, 4, &w.password).ok();
        ws.write_string(r, 5, &w.risk_status).ok();
        ws.write_string(r, 6, w.first_found.to_rfc3339()).ok();
        ws.write_string(r, 7, w.last_found.to_rfc3339()).ok();
    }
    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=weak_passwords.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 批量删除弱密码 POST /api/v1/risk/weak-passwords/batch-delete
pub async fn batch_delete_weak_passwords(
    data: web::Data<AppState>,
    body: web::Json<BatchDeleteRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let mut deleted = 0usize;
    for raw_id in &body.ids {
        if let Ok(uid) = uuid::Uuid::parse_str(raw_id) {
            if let Ok(res) = WeakPasswordEntity::delete_by_id(uid).exec(&data.db).await {
                if res.rows_affected > 0 { deleted += 1; }
            }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "deleted": deleted }))
}

/// 弱密码批量状态更新 PUT /api/v1/risk/weak-passwords/batch-status
#[derive(Debug, Deserialize)]
pub struct WeakPasswordBatchStatusRequest {
    pub ids: Vec<String>,
    /// 新状态：new / processing / resolved / ignored
    pub risk_status: String,
}

pub async fn batch_update_weak_password_status(
    data: web::Data<AppState>,
    body: web::Json<WeakPasswordBatchStatusRequest>,
) -> impl Responder {
    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }
    let valid_statuses = ["new", "processing", "resolved", "ignored"];
    if !valid_statuses.contains(&body.risk_status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("无效的 risk_status，支持: {:?}", valid_statuses)}));
    }
    let mut updated = 0usize;
    let mut failed = Vec::new();
    for raw_id in &body.ids {
        if let Ok(uid) = uuid::Uuid::parse_str(raw_id) {
            let existing = match WeakPasswordEntity::find_by_id(uid).one(&data.db).await {
                Ok(Some(t)) => t,
                Ok(None) => {
                    failed.push(serde_json::json!({"id": raw_id, "reason": "不存在"}));
                    continue;
                }
                Err(e) => {
                    failed.push(serde_json::json!({"id": raw_id, "reason": e.to_string()}));
                    continue;
                }
            };
            let mut active: weak_password::ActiveModel = existing.into();
            active.risk_status = Set(body.risk_status.clone());
            match active.update(&data.db).await {
                Ok(_) => updated += 1,
                Err(e) => failed.push(serde_json::json!({"id": raw_id, "reason": e.to_string()})),
            }
        } else {
            failed.push(serde_json::json!({"id": raw_id, "reason": "无效的 UUID"}));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({
        "updated": updated,
        "failed": failed,
    }))
}

// ==================== 风险总览 ====================

/// GET /api/v1/risk/summary
pub async fn summary(data: web::Data<AppState>) -> impl Responder {
    let vuln_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM vuln_findings").await;
    let vuln_new = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_status = 'new'",
    )
    .await;
    let vuln_processing = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_status = 'processing'",
    )
    .await;
    let vuln_closed = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM vuln_findings WHERE risk_status IN ('verified', 'closed')",
    )
    .await;

    let port_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM exposure_ports").await;
    let port_risky = scalar_count(
        &data.db,
        "SELECT COUNT(*) AS count FROM exposure_ports WHERE is_risky = TRUE",
    )
    .await;

    let wp_total = scalar_count(&data.db, "SELECT COUNT(*) AS count FROM weak_passwords").await;

    HttpResponse::Ok().json(serde_json::json!({
        "vulnerabilities": {
            "total": vuln_total,
            "new": vuln_new,
            "processing": vuln_processing,
            "closed": vuln_closed,
        },
        "exposure_ports": {
            "total": port_total,
            "risky": port_risky,
        },
        "weak_passwords": {
            "total": wp_total,
        },
    }))
}

// ==================== 批量删除漏洞 ====================

/// 批量删除漏洞 POST /api/v1/risk/vulns/batch-delete
#[derive(Debug, Deserialize)]
pub struct BatchDeleteRequest {
    pub ids: Vec<String>,
}

pub async fn batch_delete_vulns(
    data: web::Data<AppState>,
    body: web::Json<BatchDeleteRequest>,
) -> impl Responder {
    use sea_orm::EntityTrait;

    if body.ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "ids 不能为空"}));
    }

    let mut deleted = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for raw_id in &body.ids {
        match uuid::Uuid::parse_str(raw_id) {
            Ok(uid) => {
                match VulnFindingEntity::delete_by_id(uid).exec(&data.db).await {
                    Ok(res) if res.rows_affected > 0 => deleted += 1,
                    Ok(_) => failed.push(format!("{raw_id}: 未找到")),
                    Err(e) => failed.push(format!("{raw_id}: {e}")),
                }
            }
            Err(_) => failed.push(format!("{raw_id}: 无效 UUID")),
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "deleted": deleted,
        "failed": failed,
    }))
}

// ==================== 漏洞 XLSX 导出 ====================

/// 导出漏洞为 XLSX GET /api/v1/risk/vulns/export
pub async fn export_vulns_xlsx(data: web::Data<AppState>) -> impl Responder {
    use rust_xlsxwriter::Workbook;

    let vulns = match VulnFindingEntity::find()
        .order_by_desc(vuln_finding::Column::LastFound)
        .all(&data.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();

    let headers = ["标题", "CVE", "类型", "严重程度", "CVSS2", "CVSS3", "风险类型", "风险状态", "目标主机", "端口", "服务", "描述", "影响范围", "证据", "修复建议", "首次发现", "最后发现"];
    for (i, h) in headers.iter().enumerate() {
        ws.write_string(0, i as u16, *h).ok();
    }

    for (row, v) in vulns.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, v.title.clone().unwrap_or_default()).ok();
        ws.write_string(r, 1, v.cve_id.clone().unwrap_or_default()).ok();
        ws.write_string(r, 2, v.vuln_type.clone().unwrap_or_default()).ok();
        ws.write_string(r, 3, &v.severity).ok();
        if let Some(c) = v.cvss2 { ws.write_number(r, 4, c).ok(); }
        if let Some(c) = v.cvss3 { ws.write_number(r, 5, c).ok(); }
        ws.write_string(r, 6, &v.risk_type).ok();
        ws.write_string(r, 7, &v.risk_status).ok();
        ws.write_string(r, 8, &v.target_host).ok();
        if let Some(p) = v.target_port { ws.write_number(r, 9, p as f64).ok(); }
        ws.write_string(r, 10, v.target_service.clone().unwrap_or_default()).ok();
        ws.write_string(r, 11, v.description.clone().unwrap_or_default()).ok();
        ws.write_string(r, 12, v.impact_range.clone().unwrap_or_default()).ok();
        ws.write_string(r, 13, v.evidence.clone().unwrap_or_default()).ok();
        ws.write_string(r, 14, v.fix_advice.clone().unwrap_or_default()).ok();
        ws.write_string(r, 15, v.first_found.to_rfc3339()).ok();
        ws.write_string(r, 16, v.last_found.to_rfc3339()).ok();
    }

    match wb.save_to_buffer() {
        Ok(buf) => HttpResponse::Ok()
            .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            .insert_header(("Content-Disposition", "attachment; filename=vulns.xlsx"))
            .body(buf),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 清空所有数据 ====================

/// 清空所有暴露端口数据 POST /api/v1/risk/ports/clear-all
pub async fn clear_all_ports(data: web::Data<AppState>) -> impl Responder {
    match ExposurePortEntity::delete_many().exec(&data.db).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({ "deleted": res.rows_affected })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 清空所有漏洞数据 POST /api/v1/risk/vulns/clear-all
pub async fn clear_all_vulns(data: web::Data<AppState>) -> impl Responder {
    match VulnFindingEntity::delete_many().exec(&data.db).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({ "deleted": res.rows_affected })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 清空所有弱密码数据 POST /api/v1/risk/weak-passwords/clear-all
pub async fn clear_all_weak_passwords(data: web::Data<AppState>) -> impl Responder {
    match WeakPasswordEntity::delete_many().exec(&data.db).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({ "deleted": res.rows_affected })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 单元测试（状态机） ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(is_valid_transition("new", "processing"));
        assert!(is_valid_transition("new", "deferred"));
        assert!(is_valid_transition("new", "ignored"));
        assert!(is_valid_transition("new", "false_positive"));
        assert!(!is_valid_transition("new", "fixed"));
        assert!(!is_valid_transition("new", "closed"));

        assert!(is_valid_transition("processing", "fixed"));
        assert!(is_valid_transition("processing", "deferred"));
        assert!(is_valid_transition("processing", "ignored"));
        assert!(!is_valid_transition("processing", "verified"));

        assert!(is_valid_transition("fixed", "verified"));
        assert!(is_valid_transition("fixed", "closed"));
        assert!(is_valid_transition("fixed", "reopened"));

        assert!(is_valid_transition("verified", "closed"));
        assert!(!is_valid_transition("verified", "reopened"));

        assert!(is_valid_transition("closed", "reopened"));
        assert!(!is_valid_transition("closed", "processing"));

        assert!(is_valid_transition("deferred", "processing"));
        assert!(!is_valid_transition("deferred", "fixed"));

        assert!(is_valid_transition("false_positive", "reopened"));
        assert!(is_valid_transition("ignored", "reopened"));
    }

    #[test]
    fn test_all_statuses_covered() {
        for s in VALID_RISK_STATUSES {
            // 每个状态都应能被查询到允许的目标列表（即便是空）
            let _ = allowed_next_statuses(s);
        }
    }
}
