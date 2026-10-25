//! 模板管理 API
//!
//! 包含 8 大类模板：
//! 1. 漏洞模板（内存，原有）
//! 2. 端口模板
//! 3. 字典
//! 4. 组合字典
//! 5. 证书
//! 6. 参数模板
//! 7. 配置模板（基线）

use actix_web::{web, HttpResponse, Responder};
use futures_util::StreamExt;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::{Deserialize, Serialize};
use argus_sysvuln::TemplateLoader;
use crate::state::AppState;
use std::sync::RwLock;

use argus_core::entity::port_template::{self, Entity as PortTemplateEntity};
use argus_core::entity::port_violation_rule::{self, Entity as PortViolationRuleEntity};
use argus_core::entity::service_risk_level::{self, Entity as ServiceRiskLevelEntity};
use argus_core::entity::dictionary::{self, DictType, Entity as DictionaryEntity};
use argus_core::entity::combo_dictionary::{self, Entity as ComboDictionaryEntity};
use argus_core::entity::certificate::{self, CertType, Entity as CertificateEntity};
use argus_core::entity::param_template::{self, Entity as ParamTemplateEntity};
use argus_core::entity::config_template::{self, Entity as ConfigTemplateEntity};
use argus_core::scan_param_config;

/// 全局模板加载器（内存缓存）
static TEMPLATE_LOADER: std::sync::LazyLock<RwLock<TemplateLoader>> =
    std::sync::LazyLock::new(|| {
        let mut loader = TemplateLoader::new();
        let _ = loader.load_builtin();
        RwLock::new(loader)
    });

#[derive(Debug, Deserialize)]
pub struct CreateTemplateRequest {
    pub yaml: String,
}

pub async fn list_templates(_data: web::Data<AppState>) -> impl Responder {
    let loader = TEMPLATE_LOADER.read().unwrap();
    let templates: Vec<serde_json::Value> = loader.templates().iter().map(|t| {
        serde_json::json!({
            "id": t.id,
            "name": t.name,
            "severity": t.severity,
            "cve": t.cve,
            "cvss": t.cvss,
            "category": t.metadata.category,
            "tags": t.metadata.tags,
            "service": t.metadata.service,
            "port": t.metadata.port,
        })
    }).collect();
    HttpResponse::Ok().json(serde_json::json!({"total": templates.len(), "templates": templates}))
}

pub async fn get_template(
    _data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let loader = TEMPLATE_LOADER.read().unwrap();
    match loader.templates().iter().find(|t| t.id == id) {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "模板未找到"})),
    }
}

pub async fn create_template(
    _data: web::Data<AppState>,
    body: web::Json<CreateTemplateRequest>,
) -> impl Responder {
    let mut loader = TEMPLATE_LOADER.write().unwrap();
    match loader.load_str(&body.yaml) {
        Ok(()) => HttpResponse::Created().json(serde_json::json!({"message": "模板已添加", "total": loader.len()})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})),
    }
}

pub async fn validate_template(
    _data: web::Data<AppState>,
    body: web::Json<CreateTemplateRequest>,
) -> impl Responder {
    match argus_engine::PluginTemplate::from_yaml(&body.yaml) {
        Ok(t) => HttpResponse::Ok().json(serde_json::json!({"valid": true, "id": t.id, "name": t.name})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"valid": false, "error": e.to_string()})),
    }
}

// ==================== 通用分页查询 ====================

#[derive(Debug, Deserialize)]
pub struct TemplateListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub name: Option<String>,
}

fn page_params(q: &TemplateListQuery) -> (u64, u64) {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(20).clamp(1, 100);
    (page, page_size)
}

fn db_err(e: sea_orm::DbErr) -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
}

fn not_found(msg: &str) -> HttpResponse {
    HttpResponse::NotFound().json(serde_json::json!({"error": msg}))
}

fn bad_request(msg: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({"error": msg}))
}

// ==================== 2. 端口模板 ====================

#[derive(Debug, Deserialize)]
pub struct PortTemplateRequest {
    pub name: String,
    pub tcp_ports: Option<String>,
    pub udp_ports: Option<String>,
}

/// 计算端口字符串中的端口数量
fn count_ports(ports_str: &str) -> usize {
    if ports_str.trim().is_empty() { return 0; }
    ports_str.split(',').filter(|p| !p.trim().is_empty()).count()
}

pub async fn list_port_templates(
    data: web::Data<AppState>,
    query: web::Query<TemplateListQuery>,
) -> impl Responder {
    let (page, page_size) = page_params(&query);
    let mut q = PortTemplateEntity::find();
    if let Some(name) = &query.name {
        q = q.filter(port_template::Column::Name.contains(name.clone()));
    }
    match q
        .order_by_desc(port_template::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => {
            let enriched: Vec<serde_json::Value> = items.iter().map(|t| {
                let tcp_count = count_ports(&t.tcp_ports);
                let udp_count = count_ports(&t.udp_ports);
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "tcp_ports": t.tcp_ports,
                    "udp_ports": t.udp_ports,
                    "is_builtin": t.is_builtin,
                    "tcp_port_count": tcp_count,
                    "udp_port_count": udp_count,
                    "total_port_count": tcp_count + udp_count,
                    "task_ref_count": 0,
                    "created_at": t.created_at,
                    "updated_at": t.updated_at,
                })
            }).collect();
            HttpResponse::Ok().json(serde_json::json!({"items": enriched, "page": page, "page_size": page_size}))
        }
        Err(e) => db_err(e),
    }
}

/// 复制端口模板 POST /api/v1/templates/ports/{id}/copy
pub async fn copy_port_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口模板未找到"),
        Err(e) => return db_err(e),
    };
    let now = chrono::Utc::now();
    let new = port_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(format!("{} - 副本", t.name)),
        tcp_ports: Set(t.tcp_ports),
        udp_ports: Set(t.udp_ports),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(c) => HttpResponse::Created().json(c),
        Err(e) => db_err(e),
    }
}

pub async fn get_port_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match PortTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("端口模板未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_port_template(
    data: web::Data<AppState>,
    body: web::Json<PortTemplateRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let new = port_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        tcp_ports: Set(body.tcp_ports.clone().unwrap_or_default()),
        udp_ports: Set(body.udp_ports.clone().unwrap_or_default()),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_port_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<PortTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置端口模板不允许修改"); }
    let mut active: port_template::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.tcp_ports = Set(body.tcp_ports.clone().unwrap_or_default());
    active.udp_ports = Set(body.udp_ports.clone().unwrap_or_default());
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_port_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortTemplateEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置端口模板不允许删除"); }
    match PortTemplateEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("端口模板未找到"),
        Err(e) => db_err(e),
    }
}

// ==================== 3. 字典 ====================

#[derive(Debug, Deserialize)]
pub struct DictionaryRequest {
    pub name: String,
    pub dict_type: String,
    pub content: String,
    pub filename: Option<String>,
}

fn parse_dict_type(s: &str) -> Option<DictType> {
    match s {
        "username" => Some(DictType::Username),
        "password" => Some(DictType::Password),
        "subdomain" => Some(DictType::Subdomain),
        "sensitive_dir" => Some(DictType::SensitiveDir),
        "sensitive_keyword" => Some(DictType::SensitiveKeyword),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct DictionaryListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub dict_type: Option<String>,
    pub name: Option<String>,
}

pub async fn list_dictionaries(
    data: web::Data<AppState>,
    query: web::Query<DictionaryListQuery>,
) -> impl Responder {
    let (page, page_size) = page_params(&TemplateListQuery {
        page: query.page,
        page_size: query.page_size,
        name: None,
    });
    let mut q = DictionaryEntity::find();
    if let Some(dt) = &query.dict_type {
        if let Some(t) = parse_dict_type(dt) {
            q = q.filter(dictionary::Column::DictType.eq(t));
        }
    }
    if let Some(name) = &query.name {
        q = q.filter(dictionary::Column::Name.contains(name.clone()));
    }
    match q
        .order_by_desc(dictionary::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match DictionaryEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("字典未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_dictionary(
    data: web::Data<AppState>,
    body: web::Json<DictionaryRequest>,
) -> impl Responder {
    let dict_type = match parse_dict_type(&body.dict_type) {
        Some(t) => t,
        None => return bad_request("不支持的字典类型"),
    };
    let now = chrono::Utc::now();
    let new = dictionary::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        dict_type: Set(dict_type),
        content: Set(body.content.clone()),
        filename: Set(body.filename.clone()),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<DictionaryRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match DictionaryEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("字典未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置字典不允许修改"); }
    let dict_type = match parse_dict_type(&body.dict_type) {
        Some(t) => t,
        None => return bad_request("不支持的字典类型"),
    };
    let mut active: dictionary::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.dict_type = Set(dict_type);
    active.content = Set(body.content.clone());
    active.filename = Set(body.filename.clone());
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match DictionaryEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("字典未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置字典不允许删除"); }
    match DictionaryEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("字典未找到"),
        Err(e) => db_err(e),
    }
}

/// 读取一个 Field 的全部字节
async fn read_field_bytes(mut field: actix_multipart::Field) -> Vec<u8> {
    let mut buf = Vec::new();
    while let Some(chunk) = field.next().await {
        if let Ok(c) = chunk {
            buf.extend_from_slice(&c);
        }
    }
    buf
}

/// 上传文件创建字典 POST /api/v1/templates/dictionaries/upload (multipart/form-data)
/// 字段：name, dict_type, file
pub async fn upload_dictionary(
    data: web::Data<AppState>,
    mut payload: actix_multipart::Multipart,
) -> impl Responder {
    let mut name = String::new();
    let mut dict_type_str = String::new();
    let mut filename = String::new();
    let mut content = String::new();

    while let Some(field) = payload.next().await {
        let field = match field {
            Ok(f) => f,
            Err(_) => continue,
        };
        let field_name = field.name().map(|s| s.to_string()).unwrap_or_default();
        match field_name.as_str() {
            "name" => {
                name = String::from_utf8_lossy(&read_field_bytes(field).await).to_string();
            }
            "dict_type" => {
                dict_type_str = String::from_utf8_lossy(&read_field_bytes(field).await).to_string();
            }
            "file" => {
                filename = field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .unwrap_or("")
                    .to_string();
                content = String::from_utf8_lossy(&read_field_bytes(field).await).to_string();
            }
            _ => {}
        }
    }

    if name.is_empty() || dict_type_str.is_empty() {
        return bad_request("缺少 name 或 dict_type 字段");
    }
    let dict_type = match parse_dict_type(&dict_type_str) {
        Some(t) => t,
        None => return bad_request("不支持的字典类型"),
    };

    let now = chrono::Utc::now();
    let new = dictionary::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(name),
        dict_type: Set(dict_type),
        content: Set(content),
        filename: Set(if filename.is_empty() { None } else { Some(filename) }),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

/// 下载字典内容为文本文件 GET /api/v1/templates/dictionaries/{id}/download
pub async fn download_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match DictionaryEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("字典未找到"),
        Err(e) => return db_err(e),
    };
    let fname = t.filename.clone().unwrap_or_else(|| format!("{}.txt", t.name));
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", fname),
        ))
        .body(t.content)
}

// ==================== 社工字典生成器 ====================

/// 社工字典生成请求（6 维度个人信息）
#[derive(Debug, Deserialize)]
pub struct SocialEngineerDictRequest {
    /// 姓名
    pub name: Option<String>,
    /// 生日（YYYY-MM-DD）
    pub birthday: Option<String>,
    /// 手机号
    pub phone: Option<String>,
    /// 邮箱
    pub email: Option<String>,
    /// 身份证号
    pub id_card: Option<String>,
    /// 公司/组织名
    pub company: Option<String>,
    /// 特殊字符追加（默认 true）
    #[serde(default = "default_true")]
    pub with_special: bool,
}

fn default_true() -> bool { true }

/// 生成社工程字典 POST /api/v1/templates/dictionaries/social-engineer
pub async fn generate_social_engineer_dict(
    body: web::Json<SocialEngineerDictRequest>,
) -> impl Responder {
    let mut candidates: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // 维度1：姓名相关
    if let Some(name) = &body.name {
        let name = name.trim();
        if !name.is_empty() {
            candidates.insert(name.to_string());
            candidates.insert(name.to_lowercase());
            // 取姓氏和名字的简单拆分（支持中文单字名）
            if name.chars().count() >= 2 {
                let surname: String = name.chars().take(1).collect();
                let given: String = name.chars().skip(1).collect();
                candidates.insert(surname.clone());
                candidates.insert(given.clone());
                candidates.insert(format!("{}{}", given, surname));
            }
            // 英文姓名取首字母
            let initials: String = name
                .split_whitespace()
                .filter_map(|w| w.chars().next())
                .collect();
            if !initials.is_empty() {
                candidates.insert(initials.clone());
                candidates.insert(initials.to_lowercase());
            }
        }
    }

    // 维度2：生日相关
    if let Some(bday) = &body.birthday {
        let bday = bday.trim();
        candidates.insert(bday.to_string());
        // 提取 YYYY MM DD
        let parts: Vec<&str> = bday.split(|c| c == '-' || c == '/' || c == '.').collect();
        if parts.len() == 3 {
            let (y, m, d) = (parts[0], parts[1], parts[2]);
            candidates.insert(y.to_string());
            candidates.insert(format!("{}{}", m, d));
            candidates.insert(format!("{}{}{}", y, m, d));
            candidates.insert(format!("{}.{}.{}", y, m, d));
            // 后六位（常见密码）
            if y.len() == 4 {
                candidates.insert(format!("{}{}", &y[2..], m));
                candidates.insert(format!("{}{}", &y[2..], d));
                candidates.insert(format!("{}{}{}", &y[2..], m, d));
            }
        }
    }

    // 维度3：手机号
    if let Some(phone) = &body.phone {
        let phone = phone.trim();
        if !phone.is_empty() {
            candidates.insert(phone.to_string());
            if phone.len() >= 6 {
                candidates.insert(phone[phone.len()-6..].to_string()); // 后6位
                candidates.insert(phone[phone.len()-4..].to_string()); // 后4位
            }
        }
    }

    // 维度4：邮箱（取 @ 前部分）
    if let Some(email) = &body.email {
        if let Some(local) = email.split('@').next() {
            let local = local.trim();
            if !local.is_empty() {
                candidates.insert(local.to_string());
                candidates.insert(local.to_lowercase());
            }
        }
    }

    // 维度5：身份证号（后6位、出生日期段）
    if let Some(id) = &body.id_card {
        let id = id.trim();
        if id.len() >= 6 {
            candidates.insert(id[id.len()-6..].to_string());
        }
        if id.len() == 18 {
            // 18 位身份证：第7-14位是生日 YYYYMMDD
            let birth = &id[6..14];
            candidates.insert(birth.to_string());
            candidates.insert(format!("{}.{}.{}", &birth[0..4], &birth[4..6], &birth[6..8]));
        }
    }

    // 维度6：公司/组织名
    if let Some(company) = &body.company {
        let company = company.trim();
        if !company.is_empty() {
            candidates.insert(company.to_string());
            candidates.insert(company.to_lowercase());
            // 取每个词首字母
            let initials: String = company
                .split_whitespace()
                .filter_map(|w| w.chars().next())
                .collect();
            if !initials.is_empty() {
                candidates.insert(initials.clone());
                candidates.insert(initials.to_lowercase());
            }
        }
    }

    // 组合：姓名 + 生日后4位 / 手机号后4位
    let name_parts: Vec<String> = if let Some(name) = &body.name {
        vec![name.trim().to_string(), name.trim().to_lowercase()]
    } else {
        Vec::new()
    };
    let suffixes: Vec<String> = {
        let mut s = Vec::new();
        if let Some(bday) = &body.birthday {
            let parts: Vec<&str> = bday.split(|c| c == '-' || c == '/' || c == '.').collect();
            if parts.len() == 3 {
                s.push(format!("{}{}", parts[1], parts[2]));
                if parts[0].len() == 4 {
                    s.push(parts[0][2..].to_string());
                }
            }
        }
        if let Some(phone) = &body.phone {
            if phone.len() >= 4 {
                s.push(phone[phone.len()-4..].to_string());
            }
        }
        s
    };
    for n in &name_parts {
        for suf in &suffixes {
            candidates.insert(format!("{}{}", n, suf));
            candidates.insert(format!("{}{}", suf, n));
        }
    }

    // 追加常见特殊字符后缀
    let mut result: Vec<String> = candidates.into_iter().filter(|s| !s.is_empty()).collect();
    if body.with_special {
        let specials = ["!", "@", "#", "123", "123456", "520", "521"];
        let base: Vec<String> = result.clone();
        for b in &base {
            for sp in &specials {
                result.push(format!("{}{}", b, sp));
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "count": result.len(),
        "items": result,
    }))
}

// ==================== 4. 组合字典 ====================

#[derive(Debug, Deserialize)]
pub struct ComboDictionaryRequest {
    pub name: String,
    pub username_dict_id: Option<String>,
    pub password_dict_id: Option<String>,
}

pub async fn list_combo_dictionaries(
    data: web::Data<AppState>,
    query: web::Query<TemplateListQuery>,
) -> impl Responder {
    let (page, page_size) = page_params(&query);
    match ComboDictionaryEntity::find()
        .order_by_desc(combo_dictionary::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_combo_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ComboDictionaryEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("组合字典未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_combo_dictionary(
    data: web::Data<AppState>,
    body: web::Json<ComboDictionaryRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let new = combo_dictionary::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        username_dict_id: Set(body.username_dict_id.clone()),
        password_dict_id: Set(body.password_dict_id.clone()),
        created_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_combo_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ComboDictionaryRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ComboDictionaryEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("组合字典未找到"),
        Err(e) => return db_err(e),
    };
    let mut active: combo_dictionary::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.username_dict_id = Set(body.username_dict_id.clone());
    active.password_dict_id = Set(body.password_dict_id.clone());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_combo_dictionary(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ComboDictionaryEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("组合字典未找到"),
        Err(e) => db_err(e),
    }
}

// ==================== 5. 证书 ====================

#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    pub name: String,
    pub cert_type: String,
    pub cert_data: String,
    pub key_data: Option<String>,
    pub filename: Option<String>,
}

/// 证书响应（私钥脱敏）
#[derive(Debug, Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub name: String,
    pub cert_type: String,
    pub cert_data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<certificate::Model> for CertificateResponse {
    fn from(m: certificate::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            cert_type: match m.cert_type {
                CertType::Pem => "pem".to_string(),
                CertType::PfxP12 => "pfx_p12".to_string(),
            },
            cert_data: m.cert_data,
            key_data: m.key_data.as_ref().map(|_| "******".to_string()),
            filename: m.filename,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

fn parse_cert_type(s: &str) -> Option<CertType> {
    match s {
        "pem" => Some(CertType::Pem),
        "pfx_p12" | "pfx" | "p12" => Some(CertType::PfxP12),
        _ => None,
    }
}

pub async fn list_certificates(
    data: web::Data<AppState>,
    query: web::Query<TemplateListQuery>,
) -> impl Responder {
    let (page, page_size) = page_params(&query);
    let mut q = CertificateEntity::find();
    if let Some(name) = &query.name {
        q = q.filter(certificate::Column::Name.contains(name.clone()));
    }
    match q
        .order_by_desc(certificate::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => {
            let resp: Vec<CertificateResponse> = items.into_iter().map(CertificateResponse::from).collect();
            HttpResponse::Ok().json(serde_json::json!({"items": resp, "page": page, "page_size": page_size}))
        }
        Err(e) => db_err(e),
    }
}

pub async fn get_certificate(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match CertificateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(CertificateResponse::from(t)),
        Ok(None) => not_found("证书未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_certificate(
    data: web::Data<AppState>,
    body: web::Json<CertificateRequest>,
) -> impl Responder {
    let cert_type = match parse_cert_type(&body.cert_type) {
        Some(t) => t,
        None => return bad_request("不支持的证书类型（pem/pfx_p12）"),
    };
    let now = chrono::Utc::now();
    let new = certificate::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        cert_type: Set(cert_type),
        cert_data: Set(body.cert_data.clone()),
        key_data: Set(body.key_data.clone()),
        filename: Set(body.filename.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(CertificateResponse::from(t)),
        Err(e) => db_err(e),
    }
}

pub async fn update_certificate(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CertificateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match CertificateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("证书未找到"),
        Err(e) => return db_err(e),
    };
    let cert_type = match parse_cert_type(&body.cert_type) {
        Some(t) => t,
        None => return bad_request("不支持的证书类型（pem/pfx_p12）"),
    };
    let mut active: certificate::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.cert_type = Set(cert_type);
    active.cert_data = Set(body.cert_data.clone());
    active.key_data = Set(body.key_data.clone());
    active.filename = Set(body.filename.clone());
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(CertificateResponse::from(u)),
        Err(e) => db_err(e),
    }
}

pub async fn delete_certificate(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match CertificateEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("证书未找到"),
        Err(e) => db_err(e),
    }
}

/// GET /api/v1/templates/certificates/{id}/download
/// 下载证书文件（返回 cert_data 原文，文件名优先用 filename 字段，否则用 name）
pub async fn download_certificate(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match CertificateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => {
            // 文件名优先用 filename 字段，否则用 name；扩展名按 cert_type 推断
            let ext = match t.cert_type {
                CertType::Pem => "pem",
                CertType::PfxP12 => "pfx",
            };
            let filename = t
                .filename
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("{}.{}", t.name, ext));
            let content_type = match t.cert_type {
                CertType::Pem => "application/x-pem-file",
                CertType::PfxP12 => "application/x-pkcs12",
            };
            HttpResponse::Ok()
                .content_type(content_type)
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                ))
                .body(t.cert_data)
        }
        Ok(None) => not_found("证书未找到"),
        Err(e) => db_err(e),
    }
}

// ==================== 6. 参数模板 ====================

#[derive(Debug, Deserialize)]
pub struct ParamTemplateRequest {
    pub name: String,
    pub scan_type: String,
    pub config: Option<serde_json::Value>,
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ParamTemplateListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub scan_type: Option<String>,
}

pub async fn list_param_templates(
    data: web::Data<AppState>,
    query: web::Query<ParamTemplateListQuery>,
) -> impl Responder {
    let (page, page_size) = page_params(&TemplateListQuery {
        page: query.page,
        page_size: query.page_size,
        name: None,
    });
    let mut q = ParamTemplateEntity::find();
    if let Some(st) = &query.scan_type {
        q = q.filter(param_template::Column::ScanType.eq(st.as_str()));
    }
    match q
        .order_by_desc(param_template::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_param_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ParamTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("参数模板未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_param_template(
    data: web::Data<AppState>,
    body: web::Json<ParamTemplateRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let is_default = body.is_default.unwrap_or(false);
    // schema 校验：config 必须符合 ScanParamConfig 结构
    let config = body.config.clone().unwrap_or_else(|| serde_json::json!({}));
    let vr = scan_param_config::validate_config(&config);
    if !vr.is_valid() {
        return bad_request(&format!("参数模板 config 校验失败: {}", vr.errors.join("; ")));
    }
    let new = param_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        scan_type: Set(body.scan_type.clone()),
        config: Set(config),
        is_builtin: Set(false),
        is_default: Set(is_default),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_param_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ParamTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ParamTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("参数模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置参数模板不允许修改"); }
    // schema 校验：若提交了 config，必须符合 ScanParamConfig 结构
    if let Some(c) = &body.config {
        let vr = scan_param_config::validate_config(c);
        if !vr.is_valid() {
            return bad_request(&format!("参数模板 config 校验失败: {}", vr.errors.join("; ")));
        }
    }
    let mut active: param_template::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.scan_type = Set(body.scan_type.clone());
    if let Some(c) = &body.config { active.config = Set(c.clone()); }
    if let Some(d) = body.is_default { active.is_default = Set(d); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_param_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ParamTemplateEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("参数模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置参数模板不允许删除"); }
    match ParamTemplateEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("参数模板未找到"),
        Err(e) => db_err(e),
    }
}

/// 设为默认参数模板 POST /api/v1/templates/params/{id}/default
pub async fn set_param_template_default(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ParamTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("参数模板未找到"),
        Err(e) => return db_err(e),
    };
    // 同 scan_type 下其它模板取消默认
    let others = ParamTemplateEntity::find()
        .filter(param_template::Column::ScanType.eq(t.scan_type.as_str()))
        .filter(param_template::Column::Id.ne(t.id.as_str()))
        .all(&data.db)
        .await;
    if let Ok(list) = others {
        for o in list {
            if o.is_default {
                let mut a: param_template::ActiveModel = o.into();
                a.is_default = Set(false);
                a.updated_at = Set(chrono::Utc::now());
                let _ = a.update(&data.db).await;
            }
        }
    }
    let mut active: param_template::ActiveModel = t.into();
    active.is_default = Set(true);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

/// 参数模板 schema GET /api/v1/templates/params/schema
///
/// 返回结构化配置的字段定义（6 组 30 字段），供前端动态渲染表单。
pub async fn get_param_template_schema() -> impl Responder {
    HttpResponse::Ok().json(scan_param_config::json_schema())
}

/// 参数模板导出 GET /api/v1/templates/params/{id}/export
///
/// 返回单个参数模板的 JSON（含 config），文件名 `param_template_<name>.json`。
pub async fn export_param_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ParamTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => {
            let body = serde_json::json!({
                "id": t.id,
                "name": t.name,
                "scan_type": t.scan_type,
                "config": t.config,
                "is_builtin": t.is_builtin,
                "is_default": t.is_default,
            });
            let filename = format!("param_template_{}.json", t.name);
            HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .json(body)
        }
        Ok(None) => not_found("参数模板未找到"),
        Err(e) => db_err(e),
    }
}

/// 参数模板导入 POST /api/v1/templates/params/import
///
/// 接受导出格式的 JSON，校验后创建新模板（id 重新生成，name 冲突时追加后缀）。
pub async fn import_param_template(
    data: web::Data<AppState>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let name = body.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
    let scan_type = body.get("scan_type").and_then(|v| v.as_str()).map(|s| s.to_string());
    let config = body.get("config").cloned().unwrap_or_else(|| serde_json::json!({}));
    let (name, scan_type) = match (name, scan_type) {
        (Some(n), Some(s)) => (n, s),
        _ => return bad_request("import body 缺少 name 或 scan_type"),
    };
    // schema 校验
    let vr = scan_param_config::validate_config(&config);
    if !vr.is_valid() {
        return bad_request(&format!("参数模板 config 校验失败: {}", vr.errors.join("; ")));
    }
    // 名称冲突处理：若同名同 scan_type 已存在，追加 "_imported_<suffix>"
    let mut final_name = name.clone();
    let mut suffix = 0;
    loop {
        let exists = ParamTemplateEntity::find()
            .filter(param_template::Column::Name.eq(final_name.clone()))
            .filter(param_template::Column::ScanType.eq(scan_type.clone()))
            .one(&data.db)
            .await;
        if matches!(exists, Ok(Some(_))) {
            suffix += 1;
            final_name = format!("{}_imported_{}", name, suffix);
        } else {
            break;
        }
    }
    let now = chrono::Utc::now();
    let new = param_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(final_name.clone()),
        scan_type: Set(scan_type),
        config: Set(config),
        is_builtin: Set(false),
        is_default: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

/// 参数模板复制 POST /api/v1/templates/params/{id}/copy
///
/// 复制现有参数模板（含 config），名称追加 "_copy" 后缀，is_default 重置为 false。
#[derive(Debug, Deserialize)]
pub struct CopyParamTemplateRequest {
    pub new_name: Option<String>,
}
pub async fn copy_param_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<CopyParamTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let src = match ParamTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("参数模板未找到"),
        Err(e) => return db_err(e),
    };
    let new_name = body.new_name.clone().unwrap_or_else(|| format!("{}_copy", src.name));
    let now = chrono::Utc::now();
    let new = param_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(new_name),
        scan_type: Set(src.scan_type.clone()),
        config: Set(src.config.clone()),
        is_builtin: Set(false),
        is_default: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

// ==================== 7. 配置模板（基线）====================

#[derive(Debug, Deserialize)]
pub struct ConfigTemplateRequest {
    pub name: String,
    pub rule_set: Option<serde_json::Value>,
    pub config_type: Option<String>,
    pub category: Option<String>,
    pub security_level: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigTemplateListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub config_type: Option<String>,
    pub category: Option<String>,
    pub security_level: Option<String>,
}

pub async fn list_config_templates(
    data: web::Data<AppState>,
    query: web::Query<ConfigTemplateListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let mut q = ConfigTemplateEntity::find();
    if let Some(v) = &query.config_type {
        q = q.filter(config_template::Column::ConfigType.eq(v.as_str()));
    }
    if let Some(v) = &query.category {
        q = q.filter(config_template::Column::Category.eq(v.as_str()));
    }
    if let Some(v) = &query.security_level {
        q = q.filter(config_template::Column::SecurityLevel.eq(v.as_str()));
    }
    match q
        .order_by_desc(config_template::Column::CreatedAt)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_config_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ConfigTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("配置模板未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_config_template(
    data: web::Data<AppState>,
    body: web::Json<ConfigTemplateRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let new = config_template::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        rule_set: Set(body.rule_set.clone().unwrap_or_else(|| serde_json::json!({}))),
        is_builtin: Set(false),
        config_type: Set(body.config_type.clone().unwrap_or_else(|| "system".to_string())),
        category: Set(body.category.clone().unwrap_or_else(|| "custom".to_string())),
        security_level: Set(body.security_level.clone().unwrap_or_else(|| "low".to_string())),
        description: Set(body.description.clone()),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_config_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ConfigTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ConfigTemplateEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("配置模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置配置模板不允许修改"); }
    let mut active: config_template::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    if let Some(r) = &body.rule_set { active.rule_set = Set(r.clone()); }
    if let Some(v) = &body.config_type { active.config_type = Set(v.clone()); }
    if let Some(v) = &body.category { active.category = Set(v.clone()); }
    if let Some(v) = &body.security_level { active.security_level = Set(v.clone()); }
    if body.description.is_some() { active.description = Set(body.description.clone()); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_config_template(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ConfigTemplateEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("配置模板未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置配置模板不允许删除"); }
    match ConfigTemplateEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("配置模板未找到"),
        Err(e) => db_err(e),
    }
}

// ==================== 8. 协议/服务风险等级 ====================

#[derive(Debug, Deserialize)]
pub struct ServiceRiskListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub name: Option<String>,
    pub risk_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceRiskRequest {
    pub service_name: String,
    pub default_port: Option<i32>,
    pub protocol: Option<String>,
    pub risk_level: Option<String>,
    pub description: Option<String>,
}

pub async fn list_service_risks(
    data: web::Data<AppState>,
    query: web::Query<ServiceRiskListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 200);
    let mut q = ServiceRiskLevelEntity::find();
    if let Some(name) = &query.name {
        q = q.filter(service_risk_level::Column::ServiceName.contains(name.clone()));
    }
    if let Some(level) = &query.risk_level {
        q = q.filter(service_risk_level::Column::RiskLevel.eq(level.clone()));
    }
    match q
        .order_by_asc(service_risk_level::Column::ServiceName)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_service_risk(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ServiceRiskLevelEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("服务风险等级未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_service_risk(
    data: web::Data<AppState>,
    body: web::Json<ServiceRiskRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let new = service_risk_level::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        service_name: Set(body.service_name.clone()),
        default_port: Set(body.default_port),
        protocol: Set(body.protocol.clone().unwrap_or_else(|| "tcp".to_string())),
        risk_level: Set(body.risk_level.clone().unwrap_or_else(|| "medium".to_string())),
        description: Set(body.description.clone()),
        is_builtin: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_service_risk(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<ServiceRiskRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ServiceRiskLevelEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("服务风险等级未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置服务风险等级不允许修改"); }
    let mut active: service_risk_level::ActiveModel = t.into();
    active.service_name = Set(body.service_name.clone());
    active.default_port = Set(body.default_port);
    if let Some(p) = &body.protocol { active.protocol = Set(p.clone()); }
    if let Some(l) = &body.risk_level { active.risk_level = Set(l.clone()); }
    active.description = Set(body.description.clone());
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_service_risk(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match ServiceRiskLevelEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("服务风险等级未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置服务风险等级不允许删除"); }
    match ServiceRiskLevelEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("服务风险等级未找到"),
        Err(e) => db_err(e),
    }
}

// ==================== 9. 端口违规配置 ====================

#[derive(Debug, Deserialize)]
pub struct PortViolationListQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub name: Option<String>,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub risk_level: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PortViolationRequest {
    pub name: String,
    pub port: i32,
    pub protocol: Option<String>,
    pub service_name: Option<String>,
    pub risk_level: Option<String>,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_port_violations(
    data: web::Data<AppState>,
    query: web::Query<PortViolationListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 200);
    let mut q = PortViolationRuleEntity::find();
    if let Some(name) = &query.name {
        q = q.filter(port_violation_rule::Column::Name.contains(name.clone()));
    }
    if let Some(port) = query.port {
        q = q.filter(port_violation_rule::Column::Port.eq(port));
    }
    if let Some(proto) = &query.protocol {
        q = q.filter(port_violation_rule::Column::Protocol.eq(proto.clone()));
    }
    if let Some(level) = &query.risk_level {
        q = q.filter(port_violation_rule::Column::RiskLevel.eq(level.clone()));
    }
    if let Some(en) = query.enabled {
        q = q.filter(port_violation_rule::Column::Enabled.eq(en));
    }
    match q
        .order_by_asc(port_violation_rule::Column::Port)
        .paginate(&data.db, page_size)
        .fetch_page(page - 1)
        .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({"items": items, "page": page, "page_size": page_size})),
        Err(e) => db_err(e),
    }
}

pub async fn get_port_violation(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match PortViolationRuleEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => not_found("端口违规规则未找到"),
        Err(e) => db_err(e),
    }
}

pub async fn create_port_violation(
    data: web::Data<AppState>,
    body: web::Json<PortViolationRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let new = port_violation_rule::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        name: Set(body.name.clone()),
        port: Set(body.port),
        protocol: Set(body.protocol.clone().unwrap_or_else(|| "tcp".to_string())),
        service_name: Set(body.service_name.clone()),
        risk_level: Set(body.risk_level.clone().unwrap_or_else(|| "medium".to_string())),
        description: Set(body.description.clone()),
        remediation: Set(body.remediation.clone()),
        is_builtin: Set(false),
        enabled: Set(body.enabled.unwrap_or(true)),
        created_at: Set(now),
        updated_at: Set(now),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => db_err(e),
    }
}

pub async fn update_port_violation(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<PortViolationRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortViolationRuleEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口违规规则未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置端口违规规则不允许修改"); }
    let mut active: port_violation_rule::ActiveModel = t.into();
    active.name = Set(body.name.clone());
    active.port = Set(body.port);
    if let Some(p) = &body.protocol { active.protocol = Set(p.clone()); }
    active.service_name = Set(body.service_name.clone());
    if let Some(l) = &body.risk_level { active.risk_level = Set(l.clone()); }
    active.description = Set(body.description.clone());
    active.remediation = Set(body.remediation.clone());
    if let Some(en) = body.enabled { active.enabled = Set(en); }
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

pub async fn delete_port_violation(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortViolationRuleEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口违规规则未找到"),
        Err(e) => return db_err(e),
    };
    if t.is_builtin { return bad_request("内置端口违规规则不允许删除"); }
    match PortViolationRuleEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => not_found("端口违规规则未找到"),
        Err(e) => db_err(e),
    }
}

/// 启用/禁用端口违规规则 PATCH /api/v1/templates/port-violations/{id}/toggle
pub async fn toggle_port_violation(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let t = match PortViolationRuleEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return not_found("端口违规规则未找到"),
        Err(e) => return db_err(e),
    };
    let new_enabled = !t.enabled;
    let mut active: port_violation_rule::ActiveModel = t.into();
    active.enabled = Set(new_enabled);
    active.updated_at = Set(chrono::Utc::now());
    match active.update(&data.db).await {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => db_err(e),
    }
}

/// 违规检测：给定端口列表，返回命中的违规规则
/// POST /api/v1/templates/port-violations/check
#[derive(Debug, Deserialize)]
pub struct PortViolationCheckRequest {
    /// 待检测的端口列表：[{port: 23, protocol: "tcp", service: "Telnet"}]
    pub ports: Vec<PortViolationCheckItem>,
}

#[derive(Debug, Deserialize)]
pub struct PortViolationCheckItem {
    pub port: i32,
    pub protocol: Option<String>,
    pub service: Option<String>,
}

pub async fn check_port_violations(
    data: web::Data<AppState>,
    body: web::Json<PortViolationCheckRequest>,
) -> impl Responder {
    // 获取所有启用的违规规则
    let rules = match PortViolationRuleEntity::find()
        .filter(port_violation_rule::Column::Enabled.eq(true))
        .all(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => return db_err(e),
    };

    let mut violations: Vec<serde_json::Value> = Vec::new();
    for item in &body.ports {
        let proto = item.protocol.as_deref().unwrap_or("tcp");
        for rule in &rules {
            if rule.port != 0 && rule.port != item.port { continue; }
            if rule.protocol != proto { continue; }
            // 服务名匹配：规则有 service_name 时必须匹配（大小写不敏感）
            if let Some(svc) = &rule.service_name {
                if let Some(s) = &item.service {
                    if !s.eq_ignore_ascii_case(svc) { continue; }
                }
            }
            violations.push(serde_json::json!({
                "port": item.port,
                "protocol": proto,
                "service": item.service,
                "rule_id": rule.id,
                "rule_name": rule.name,
                "risk_level": rule.risk_level,
                "description": rule.description,
                "remediation": rule.remediation,
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "total": violations.len(),
        "violations": violations,
    }))
}
