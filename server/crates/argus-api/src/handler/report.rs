//! 统一报表生成与下载 API
//!
//! 支持根据任务 ID 生成多格式（HTML/XLSX/JSON）扫描报表，
//! 包含任务概览、漏洞统计、资产统计、风险分布等内容。

use actix_web::{web, HttpResponse, Responder};
use rust_xlsxwriter::Workbook;
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set, ActiveModelTrait,
};
use serde::Deserialize;

use argus_core::entity::task::{self, Entity as ScanTaskEntity};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use crate::state::AppState;

/// 报表生成请求
#[derive(Debug, Deserialize)]
pub struct GenerateReportRequest {
    pub task_id: String,
    /// 报表格式: html / xlsx / json
    pub format: Option<String>,
    pub name: Option<String>,
}

/// 报表下载查询参数
#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    pub format: Option<String>,
}

/// 生成报表 POST /api/v1/reports/generate
pub async fn generate_report(
    data: web::Data<AppState>,
    body: web::Json<GenerateReportRequest>,
) -> impl Responder {
    let task_id = body.task_id.clone();
    let format = body.format.as_deref().unwrap_or("html");

    let task = match ScanTaskEntity::find_by_id(task_id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "任务未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 查询该任务的扫描结果
    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .all(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // 按结果类型统计
    let mut vuln_count = 0;
    let mut port_count = 0;
    let mut weak_pwd_count = 0;
    let mut baseline_count = 0;
    let mut other_count = 0;

    for r in &results {
        match r.result_type {
            ResultType::VulnDetect => vuln_count += 1,
            ResultType::PortScan => port_count += 1,
            ResultType::Bruteforce => weak_pwd_count += 1,
            ResultType::BaselineCheck => baseline_count += 1,
            _ => other_count += 1,
        }
    }

    let report_data = serde_json::json!({
        "task_id": task.id,
        "task_name": task.name,
        "task_type": task.task_type,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "summary": {
            "total": results.len(),
            "vuln_count": vuln_count,
            "port_count": port_count,
            "weak_password_count": weak_pwd_count,
            "baseline_count": baseline_count,
            "other_count": other_count,
        },
        "results": results,
    });

    let filename = format!(
        "report_{}_{}.{}",
        task.id,
        body.name.as_deref().unwrap_or("scan"),
        format
    );

    match format {
        "json" => HttpResponse::Ok()
            .content_type("application/json")
            .insert_header(("Content-Disposition", format!("attachment; filename=\"{filename}\"")))
            .json(report_data),
        "xlsx" => {
            let buf = match build_xlsx_report(&report_data) {
                Ok(b) => b,
                Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            };
            HttpResponse::Ok()
                .content_type("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{filename}\"")))
                .body(buf)
        }
        _ => {
            // 默认 HTML 格式
            let html = build_html_report(&report_data);
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{filename}\"")))
                .body(html)
        }
    }
}

/// 下载报表 GET /api/v1/reports/{task_id}/download
pub async fn download_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<DownloadQuery>,
) -> impl Responder {
    let task_id = path.into_inner();
    let format = query.format.as_deref().unwrap_or("html");
    // 复用生成逻辑
    let req = GenerateReportRequest {
        task_id,
        format: Some(format.to_string()),
        name: None,
    };
    generate_report(data, web::Json(req)).await
}

// ==================== HTML 报表生成 ====================

fn build_html_report(data: &serde_json::Value) -> String {
    let task_name = data["task_name"].as_str().unwrap_or("扫描报表");
    let summary = &data["summary"];
    let empty_results: Vec<serde_json::Value> = Vec::new();
    let results = data["results"].as_array().unwrap_or(&empty_results);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>");
    html.push_str(task_name);
    html.push_str("</title><style>");
    html.push_str("body{font-family:Arial,sans-serif;margin:20px;color:#333}");
    html.push_str("h1{color:#1a73e8}h2{color:#333;border-bottom:2px solid #1a73e8;padding-bottom:6px}");
    html.push_str("table{border-collapse:collapse;width:100%;margin:12px 0}");
    html.push_str("th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:13px}");
    html.push_str("th{background:#f1f3f4}tr:nth-child(even){background:#f9f9f9}");
    html.push_str(".stat{display:inline-block;background:#e8f0fe;color:#1a73e8;padding:4px 12px;border-radius:12px;margin:4px;font-size:13px}");
    html.push_str(".vuln{color:#d93025}.warn{color:#f9ab00}.ok{color:#1e8e3e}");
    html.push_str("</style></head><body>");
    html.push_str(&format!("<h1>{task_name}</h1>"));
    html.push_str(&format!("<p>任务 ID: {} | 创建时间: {}</p>",
        data["task_id"].as_str().unwrap_or(""),
        data["created_at"].as_str().unwrap_or("")));

    html.push_str("<h2>统计概览</h2><div>");
    html.push_str(&format!("<span class=\"stat\">总计: {}</span>", summary["total"]));
    html.push_str(&format!("<span class=\"stat vuln\">漏洞: {}</span>", summary["vuln_count"]));
    html.push_str(&format!("<span class=\"stat\">端口: {}</span>", summary["port_count"]));
    html.push_str(&format!("<span class=\"stat warn\">弱口令: {}</span>", summary["weak_password_count"]));
    html.push_str(&format!("<span class=\"stat\">基线: {}</span>", summary["baseline_count"]));
    html.push_str("</div>");

    html.push_str("<h2>扫描结果明细</h2>");
    if results.is_empty() {
        html.push_str("<p>无扫描结果</p>");
    } else {
        html.push_str("<table><thead><tr><th>#</th><th>目标</th><th>端口</th><th>服务</th><th>状态</th><th>类型</th></tr></thead><tbody>");
        for (i, r) in results.iter().enumerate() {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                i + 1,
                r["host"].as_str().unwrap_or(""),
                r["port"].as_i64().map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
                r["service"].as_str().unwrap_or("-"),
                r["state"].as_str().unwrap_or("-"),
                r["result_type"].as_str().unwrap_or("-")
            ));
        }
        html.push_str("</tbody></table>");
    }

    html.push_str("</body></html>");
    html
}

// ==================== XLSX 报表生成 ====================

fn build_xlsx_report(data: &serde_json::Value) -> Result<Vec<u8>, rust_xlsxwriter::XlsxError> {
    let mut wb = Workbook::new();

    // Sheet 1: 概览
    let ws1 = wb.add_worksheet();
    ws1.set_name("概览")?;
    ws1.write_string(0, 0, "任务名称")?;
    ws1.write_string(0, 1, data["task_name"].as_str().unwrap_or(""))?;
    ws1.write_string(1, 0, "任务 ID")?;
    ws1.write_string(1, 1, data["task_id"].as_str().unwrap_or(""))?;
    ws1.write_string(2, 0, "任务类型")?;
    ws1.write_string(2, 1, data["task_type"].as_str().unwrap_or(""))?;
    ws1.write_string(3, 0, "创建时间")?;
    ws1.write_string(3, 1, data["created_at"].as_str().unwrap_or(""))?;

    let summary = &data["summary"];
    ws1.write_string(5, 0, "统计项")?;
    ws1.write_string(5, 1, "数量")?;
    ws1.write_string(6, 0, "总计")?;
    ws1.write_number(6, 1, summary["total"].as_i64().unwrap_or(0) as f64)?;
    ws1.write_string(7, 0, "漏洞")?;
    ws1.write_number(7, 1, summary["vuln_count"].as_i64().unwrap_or(0) as f64)?;
    ws1.write_string(8, 0, "端口")?;
    ws1.write_number(8, 1, summary["port_count"].as_i64().unwrap_or(0) as f64)?;
    ws1.write_string(9, 0, "弱口令")?;
    ws1.write_number(9, 1, summary["weak_password_count"].as_i64().unwrap_or(0) as f64)?;
    ws1.write_string(10, 0, "基线")?;
    ws1.write_number(10, 1, summary["baseline_count"].as_i64().unwrap_or(0) as f64)?;

    // Sheet 2: 明细
    let ws2 = wb.add_worksheet();
    ws2.set_name("扫描明细")?;
    ws2.write_string(0, 0, "序号")?;
    ws2.write_string(0, 1, "目标")?;
    ws2.write_string(0, 2, "端口")?;
    ws2.write_string(0, 3, "服务")?;
    ws2.write_string(0, 4, "状态")?;
    ws2.write_string(0, 5, "结果类型")?;

    if let Some(results) = data["results"].as_array() {
        for (i, r) in results.iter().enumerate() {
            let row = (i + 1) as u32;
            ws2.write_number(row, 0, (i + 1) as f64)?;
            ws2.write_string(row, 1, r["host"].as_str().unwrap_or(""))?;
            if let Some(p) = r["port"].as_i64() {
                ws2.write_number(row, 2, p as f64)?;
            }
            ws2.write_string(row, 3, r["service"].as_str().unwrap_or("-"))?;
            ws2.write_string(row, 4, r["state"].as_str().unwrap_or("-"))?;
            ws2.write_string(row, 5, r["result_type"].as_str().unwrap_or("-"))?;
        }
    }

    wb.save_to_buffer()
}
