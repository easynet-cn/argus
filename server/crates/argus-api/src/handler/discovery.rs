//! 资产发现 API
//!
//! 支持 IP 发现、子域名发现、流量发现三种模式。
//! 发现任务异步执行（tokio::spawn），不阻塞 API 响应。

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    ActiveValue::Set,
};
use serde::Deserialize;

use argus_core::entity::discovery_task::{
    self, DiscoveryStatus, DiscoveryType, Entity as DiscoveryTaskEntity,
};
use argus_core::entity::network_asset::{self, AssetStatus, AssetType, Entity as NetworkAssetEntity};
use argus_core::entity::application_asset::{self, Entity as ApplicationAssetEntity};
use crate::state::AppState;
use crate::handler::asset::ListQuery;

// ==================== 请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct CreateDiscoveryRequest {
    pub name: String,
    pub discovery_type: String, // ip / subdomain / traffic
    pub targets: String,        // IP/域名/网卡
    #[serde(default)]
    pub config: serde_json::Value,
    /// IP 发现：网关
    pub gateway: Option<String>,
    /// IP 发现：扫描模式（ping/arp/all）
    pub scan_mode: Option<String>,
    /// IP 发现：排除主机（逗号分隔）
    pub exclude_hosts: Option<String>,
    /// 子域名发现：并发线程数
    pub threads: Option<i32>,
    /// 子域名发现：爆破层级
    pub brute_level: Option<i32>,
}

// ==================== 枚举转换 ====================

fn parse_discovery_type(s: &str) -> DiscoveryType {
    match s {
        "subdomain" => DiscoveryType::Subdomain,
        "traffic" => DiscoveryType::Traffic,
        _ => DiscoveryType::Ip,
    }
}

// ==================== API 处理函数 ====================

/// 创建发现任务 POST /api/v1/discovery
pub async fn create_discovery(
    data: web::Data<AppState>,
    body: web::Json<CreateDiscoveryRequest>,
) -> impl Responder {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let discovery_type = parse_discovery_type(&body.discovery_type);
    let new = discovery_task::ActiveModel {
        id: Set(id),
        name: Set(body.name.clone()),
        discovery_type: Set(discovery_type),
        status: Set(DiscoveryStatus::Pending),
        targets: Set(body.targets.clone()),
        config: Set(body.config.clone()),
        result: Set(None),
        gateway: Set(body.gateway.clone()),
        scan_mode: Set(body.scan_mode.clone()),
        exclude_hosts: Set(body.exclude_hosts.clone()),
        threads: Set(body.threads),
        brute_level: Set(body.brute_level),
        created_at: Set(now),
        started_at: Set(None),
        finished_at: Set(None),
    };
    match new.insert(&data.db).await {
        Ok(t) => HttpResponse::Created().json(t),
        Err(e) => {
            tracing::error!("创建发现任务失败: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// 发现任务列表 GET /api/v1/discovery
pub async fn list_discovery(
    data: web::Data<AppState>,
    query: web::Query<ListQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    match DiscoveryTaskEntity::find()
        .order_by_desc(discovery_task::Column::CreatedAt)
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

/// 发现任务详情（含结果）GET /api/v1/discovery/{id}
pub async fn get_discovery(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match DiscoveryTaskEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => HttpResponse::Ok().json(t),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "发现任务未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除发现任务 DELETE /api/v1/discovery/{id}
pub async fn delete_discovery(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match DiscoveryTaskEntity::delete_by_id(id).exec(&data.db).await {
        Ok(res) if res.rows_affected > 0 => HttpResponse::NoContent().finish(),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "发现任务未找到"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 执行发现任务 POST /api/v1/discovery/{id}/run
///
/// 异步执行，立即返回，不阻塞响应。
pub async fn run_discovery(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let task = match DiscoveryTaskEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "发现任务未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    if task.status == DiscoveryStatus::Running {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "任务已在运行中"}));
    }

    // 更新状态为 running
    let now = chrono::Utc::now();
    let mut active: discovery_task::ActiveModel = task.clone().into();
    active.status = Set(DiscoveryStatus::Running);
    active.started_at = Set(Some(now));
    if let Err(e) = active.update(&data.db).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    let db = data.db.clone();
    let task_id = task.id.clone();
    let targets = task.targets.clone();
    let config = task.config.clone();
    let discovery_type = task.discovery_type.clone();
    // gateway 字段已持久化，供后续支持网关模式扫描时使用
    let _gateway = task.gateway;
    let scan_mode = task.scan_mode.clone();
    let exclude_hosts = task.exclude_hosts.clone();
    let threads = task.threads;
    let brute_level = task.brute_level;

    // 异步执行发现
    tokio::spawn(async move {
        let result = match discovery_type {
            DiscoveryType::Ip => run_ip_discovery(&targets, &config, scan_mode.as_deref(), exclude_hosts.as_deref()).await,
            DiscoveryType::Subdomain => run_subdomain_discovery(&targets, &config, threads, brute_level).await,
            DiscoveryType::Traffic => run_traffic_discovery(&targets, &config).await,
        };

        let (status, result_json) = match result {
            Ok(r) => (DiscoveryStatus::Completed, Some(r)),
            Err(e) => {
                tracing::error!("发现任务 {} 失败: {e}", task_id);
                (
                    DiscoveryStatus::Failed,
                    Some(serde_json::json!({"error": e.to_string()})),
                )
            }
        };

        // 更新任务结果
        if let Ok(t) = DiscoveryTaskEntity::find_by_id(task_id.clone()).one(&db).await {
            if let Some(t) = t {
                let mut active: discovery_task::ActiveModel = t.into();
                active.status = Set(status);
                active.result = Set(result_json);
                active.finished_at = Set(Some(chrono::Utc::now()));
                if let Err(e) = active.update(&db).await {
                    tracing::error!("更新发现任务结果失败: {e}");
                }
            }
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "id": task.id,
        "status": "running",
        "message": "发现任务已启动",
    }))
}

/// IP 发现：调用 argus-portscanner 的主机存活探测 + 端口扫描
async fn run_ip_discovery(
    targets: &str,
    config: &serde_json::Value,
    scan_mode: Option<&str>,
    exclude_hosts: Option<&str>,
) -> Result<serde_json::Value, String> {
    use argus_portscanner::host::ping_hosts;
    use argus_portscanner::port_list::parse_port_range;

    let exclude: std::collections::HashSet<String> = exclude_hosts
        .map(|s| s.split(',').map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect())
        .unwrap_or_default();

    let hosts: Vec<String> = targets
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !exclude.contains(s))
        .collect();

    if hosts.is_empty() {
        return Err("目标列表为空".to_string());
    }

    // scan_mode: ping(默认)/arp/all，当前仅实现 ping；arp/all 预留
    let _mode = scan_mode.unwrap_or("ping");

    let timeout_ms = config.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(1000);
    let concurrency = config.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(500) as usize;

    // 主机存活探测
    let alive_results = ping_hosts(&hosts, timeout_ms, concurrency).await;
    let alive_hosts: Vec<&str> = alive_results
        .iter()
        .filter(|r| r.alive)
        .map(|r| r.host.as_str())
        .collect();

    // 端口扫描（top 100）
    let ports = config
        .get("ports")
        .and_then(|v| v.as_str())
        .and_then(|p| parse_port_range(p).ok())
        .unwrap_or_else(|| argus_portscanner::port_list::get_ports_by_template(
            &argus_portscanner::port_list::PortTemplate::Top100,
        ));

    let mut discovered = Vec::new();
    for host in &alive_hosts {
        let results = argus_portscanner::tcp::scan_tcp_ports(
            host,
            &ports,
            argus_portscanner::types::TcpScanType::Connect,
            timeout_ms,
            concurrency,
            None,
        )
        .await;

        let open_ports: Vec<serde_json::Value> = results
            .iter()
            .filter(|r| r.state == argus_portscanner::types::PortState::Open)
            .map(|r| {
                serde_json::json!({
                    "port": r.port,
                    "protocol": r.protocol_to_string(),
                    "service": r.service,
                    "banner": r.banner,
                })
            })
            .collect();

        let open_port_nums: Vec<u16> = results
            .iter()
            .filter(|r| r.state == argus_portscanner::types::PortState::Open)
            .map(|r| r.port)
            .collect();
        let banners: Vec<String> = results
            .iter()
            .filter_map(|r| r.banner.clone())
            .collect();

        // MAC：通过系统 ARP 表查询
        let mac = get_mac_from_arp(host);
        // 主机名：反向 DNS（系统 host 命令）
        let hostname = get_hostname_by_ip(host);
        // 设备类型 / 厂商 / OS：基于开放端口与 banner 推断
        let device_type = infer_device_type(&open_port_nums);
        let vendor = infer_vendor(&open_port_nums, &banners, mac.as_deref());
        let os = infer_os(&banners, &open_port_nums);
        // 设备名 / 版本：基于 banner 解析产品名与版本号
        let (device_name, version) = infer_device_name_and_version(&banners);

        discovered.push(serde_json::json!({
            "ip": host,
            "mac": mac,
            "hostname": hostname,
            "device_type": device_type,
            "device_name": device_name,
            "vendor": vendor,
            "version": version,
            "os": os,
            "open_ports": open_ports,
            "alive": true,
        }));
    }

    Ok(serde_json::json!({
        "type": "ip",
        "total_targets": hosts.len(),
        "alive_count": alive_hosts.len(),
        "hosts": discovered,
    }))
}

/// 从系统 ARP 表查询 MAC 地址（跨平台尽力而为）
fn get_mac_from_arp(ip: &str) -> Option<String> {
    let output = if cfg!(target_os = "linux") {
        std::process::Command::new("arp").arg("-n").arg(ip).output()
    } else {
        std::process::Command::new("arp").arg(ip).output()
    };
    let out = output.ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // 匹配形如 xx:xx:xx:xx:xx:xx 的 MAC
    for line in text.lines() {
        if line.contains(ip) {
            if let Some(m) = regex_find_mac(line) {
                return Some(m);
            }
        }
    }
    None
}

/// 简单正则匹配 MAC 地址
fn regex_find_mac(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 17 <= bytes.len() {
        let seg = &text[i..i + 17];
        let mut ok = true;
        for (j, c) in seg.chars().enumerate() {
            let is_hex = c.is_ascii_hexdigit();
            let is_colon = c == ':';
            match j % 3 {
                0 | 1 => if !is_hex { ok = false; break; },
                2 => if !is_colon { ok = false; break; },
                _ => {}
            }
        }
        if ok {
            return Some(seg.to_string());
        }
        i += 1;
    }
    None
}

/// 通过系统命令反向解析主机名
fn get_hostname_by_ip(ip: &str) -> Option<String> {
    let cmd = if cfg!(target_os = "windows") { "nslookup" } else { "host" };
    let output = std::process::Command::new(cmd).arg(ip).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // host 输出："1.2.3.4.in-addr.arpa domain name pointer hostname."
    for line in text.lines() {
        if let Some(idx) = line.find("pointer ") {
            let mut h = line[idx + 8..].trim().to_string();
            if h.ends_with('.') { h.pop(); }
            if !h.is_empty() { return Some(h); }
        }
        if let Some(idx) = line.find("name = ") {
            let mut h = line[idx + 7..].trim().to_string();
            if h.ends_with('.') { h.pop(); }
            if !h.is_empty() { return Some(h); }
        }
    }
    None
}

/// 根据开放端口推断设备类型
fn infer_device_type(open_ports: &[u16]) -> Option<String> {
    let has = |p: u16| open_ports.contains(&p);
    if has(9100) || has(515) { return Some("printer".to_string()); }
    if has(3306) || has(5432) || has(1521) || has(1433) { return Some("database".to_string()); }
    if has(22) && !has(80) && !has(443) { return Some("server".to_string()); }
    if has(80) || has(443) { return Some("web_server".to_string()); }
    if has(53) { return Some("dns_server".to_string()); }
    if has(21) { return Some("ftp_server".to_string()); }
    if has(23) { return Some("network_device".to_string()); }
    if open_ports.is_empty() { Some("host".to_string()) } else { Some("server".to_string()) }
}

/// 根据端口/banner/MAC 推断厂商
fn infer_vendor(open_ports: &[u16], banners: &[String], mac: Option<&str>) -> Option<String> {
    // 优先从 banner 识别
    for b in banners {
        let lb = b.to_lowercase();
        if lb.contains("nginx") { return Some("Nginx".to_string()); }
        if lb.contains("apache") { return Some("Apache".to_string()); }
        if lb.contains("microsoft") || lb.contains("iis") { return Some("Microsoft".to_string()); }
        if lb.contains("openssh") { return Some("OpenSSH".to_string()); }
        if lb.contains("mysql") { return Some("Oracle/MySQL".to_string()); }
        if lb.contains("postgresql") { return Some("PostgreSQL".to_string()); }
    }
    // MAC OUI 前 3 字节（简化常见厂商）
    if let Some(m) = mac {
        let oui = m.get(0..8).unwrap_or("").to_lowercase();
        match oui.as_str() {
            "00:1c:42" | "00:0c:29" | "00:50:56" => return Some("VMware".to_string()),
            "08:00:27" => return Some("VirtualBox".to_string()),
            "f0:1f:af" | "3c:5a:b4" => return Some("Apple".to_string()),
            "00:1a:2b" | "00:1b:21" => return Some("Cisco".to_string()),
            _ => {}
        }
    }
    // 端口特征
    let has = |p: u16| open_ports.contains(&p);
    if has(5060) { return Some("VoIP".to_string()); }
    if has(9100) { return Some("Printer".to_string()); }
    None
}

/// 根据 banner 解析设备名（产品名）与版本号
///
/// 与 `infer_vendor`（厂商/公司）不同：`device_name` 返回具体产品名（如
/// "Apache HTTP Server"、"OpenSSH"），`version` 返回版本号字符串（如
/// "2.4.41"、"8.4p1"）。二者从 banner 的 Server/Product 行解析。
fn infer_device_name_and_version(banners: &[String]) -> (Option<String>, Option<String>) {
    for b in banners {
        let lb = b.to_lowercase();
        // SSH banner 形如 "SSH-2.0-OpenSSH_8.4p1 Debian-5ubuntu1"
        if lb.starts_with("ssh-") {
            let product = "OpenSSH".to_string();
            // 提取 OpenSSH_<version> 中的版本
            let version = extract_version_token(b, "openssh_");
            return (Some(product), version);
        }
        // HTTP Server header 形如 "Apache/2.4.41 (Ubuntu)"、"nginx/1.18.0"
        if lb.starts_with("apache/") || lb.contains("apache/") {
            let product = "Apache HTTP Server".to_string();
            return (Some(product), extract_version_token(b, "apache/"));
        }
        if lb.starts_with("nginx/") || lb.contains("nginx/") {
            let product = "nginx".to_string();
            return (Some(product), extract_version_token(b, "nginx/"));
        }
        if lb.contains("microsoft-iis") {
            let product = "Microsoft IIS".to_string();
            return (Some(product), extract_version_token(b, "microsoft-iis/"));
        }
        // MySQL/MariaDB banner 形如 "8.0.26-0ubuntu0.20.04.1" 或 "5.7.31-log"
        if lb.contains("mysql") || looks_like_mysql_version(&lb) {
            let product = if lb.contains("mariadb") { "MariaDB".to_string() } else { "MySQL".to_string() };
            return (Some(product), extract_leading_version(b));
        }
        // PostgreSQL banner 形如 "PostgreSQL 13.3"
        if lb.contains("postgresql ") {
            let product = "PostgreSQL".to_string();
            return (Some(product), extract_version_token(b, "postgresql "));
        }
        // Redis banner 形如 "Redis 6.0.16" 或 "-ERR wrong number of arguments...\r\n" 无版本
        if lb.contains("redis") {
            return (Some("Redis".to_string()), extract_version_token(b, "redis "));
        }
        // SMTP banner 形如 "220 mail.example.com ESMTP Postfix (Ubuntu)"
        if lb.contains("postfix") {
            return (Some("Postfix".to_string()), None);
        }
        // FTP banner 形如 "220 (vsFTPd 3.0.3)"、"220 ProFTPD 1.3.5a Server"
        if lb.contains("vsftpd") {
            return (Some("vsftpd".to_string()), extract_version_token(b, "vsftpd "));
        }
        if lb.contains("proftpd") {
            return (Some("ProFTPD".to_string()), extract_version_token(b, "proftpd "));
        }
        // Microsoft RDP/Windows banner 形如 "\x03\x00\x00...Freerdp" 或含 "Microsoft Terminal Services"
        if lb.contains("microsoft terminal services") || lb.contains("x224") {
            return (Some("Microsoft RDP".to_string()), None);
        }
        // SNMP banner 形如 "Cisco IOS Software" 等
        if lb.contains("cisco ios") {
            return (Some("Cisco IOS".to_string()), extract_version_token(b, "version "));
        }
    }
    (None, None)
}

/// 从 banner 中提取 `<prefix>` 之后的版本号（到空格/换行/斜杠前停止）
fn extract_version_token(banner: &str, prefix_lower: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    let idx = lower.find(prefix_lower)?;
    let start = idx + prefix_lower.len();
    let rest = &banner[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',' || c == ';')
        .unwrap_or(rest.len());
    let ver = rest[..end].trim_end_matches('-').to_string();
    if ver.is_empty() {
        None
    } else {
        Some(ver)
    }
}

/// MySQL banner 版本常以纯数字开头（如 "8.0.26-0ubuntu0.20.04.1"）
fn looks_like_mysql_version(lb: &str) -> bool {
    let first = lb.split_whitespace().next().unwrap_or("");
    first.chars().next().map_or(false, |c| c.is_ascii_digit())
        && first.contains('.')
}

/// 提取 banner 起始处的版本号（数字.数字... 形式）
fn extract_leading_version(banner: &str) -> Option<String> {
    let first = banner.split_whitespace().next().unwrap_or("");
    // 取到第一个非版本字符（非数字/点/字母）停止
    let end = first
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'))
        .unwrap_or(first.len());
    let ver = first[..end].to_string();
    if ver.is_empty() || !ver.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        None
    } else {
        Some(ver)
    }
}

/// 根据 banner/端口推断操作系统
fn infer_os(banners: &[String], open_ports: &[u16]) -> Option<String> {
    for b in banners {
        let lb = b.to_lowercase();
        if lb.contains("windows") { return Some("Windows".to_string()); }
        if lb.contains("linux") { return Some("Linux".to_string()); }
        if lb.contains("ubuntu") { return Some("Ubuntu".to_string()); }
        if lb.contains("debian") { return Some("Debian".to_string()); }
        if lb.contains("centos") { return Some("CentOS".to_string()); }
        if lb.contains("freebsd") { return Some("FreeBSD".to_string()); }
    }
    let has = |p: u16| open_ports.contains(&p);
    // Windows 常见端口
    if has(135) || has(139) || has(445) || has(3389) { return Some("Windows".to_string()); }
    // Linux 常见端口
    if has(22) && (has(80) || has(443) || has(3306) || has(5432)) { return Some("Linux".to_string()); }
    None
}

/// 子域名发现：DNS 查询 + 字典爆破
async fn run_subdomain_discovery(
    targets: &str,
    config: &serde_json::Value,
    threads: Option<i32>,
    brute_level: Option<i32>,
) -> Result<serde_json::Value, String> {
    use futures_util::stream::{self, StreamExt};

    let domain = targets.split(',').next().map(|s| s.trim().to_string()).unwrap_or_default();
    if domain.is_empty() {
        return Err("域名为空".to_string());
    }

    // 子域名字典
    let dict: Vec<String> = config
        .get("subdomain_dict")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
                "vpn", "proxy", "web", "app", "blog", "shop", "cdn", "img",
                "static", "m", "mobile", "docs",
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
        });

    // 爆破层级：level 1 使用单段字典；level 2 追加常见二级组合（a-z0-9 单字符等）
    let mut brute_dict = dict.clone();
    if brute_level.unwrap_or(1) >= 2 {
        let mut extra: Vec<String> = Vec::new();
        for prefix in &dict {
            for c in 'a'..='z' {
                extra.push(format!("{}{}", prefix, c));
            }
        }
        brute_dict.extend(extra);
    }

    let concurrency = threads.map(|t| t.max(1) as usize)
        .or_else(|| config.get("concurrency").and_then(|v| v.as_u64()).map(|v| v as usize))
        .unwrap_or(50);

    let results: Vec<serde_json::Value> = stream::iter(brute_dict)
        .map(|sub| {
            let domain = domain.clone();
            async move {
                let full = format!("{}.{}", sub, domain);
                match tokio::net::lookup_host(format!("{}:0", full)).await {
                    Ok(mut addrs) => {
                        let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                        if !ips.is_empty() {
                            Some(serde_json::json!({
                                "subdomain": full,
                                "ips": ips,
                            }))
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    Ok(serde_json::json!({
        "type": "subdomain",
        "domain": domain,
        "found_count": results.len(),
        "subdomains": results,
    }))
}

/// 流量发现：pcap 抓包解析
async fn run_traffic_discovery(targets: &str, config: &serde_json::Value) -> Result<serde_json::Value, String> {
    use argus_portscanner::pcap_capture::PcapCapture;

    let interface = targets.split(',').next().map(|s| s.trim().to_string()).unwrap_or_else(|| "any".to_string());
    let duration_secs = config.get("duration_secs").and_then(|v| v.as_u64()).unwrap_or(10);
    let filter = config.get("filter").and_then(|v| v.as_str());

    let mut cap = PcapCapture::new(&interface, filter);
    cap.start().map_err(|e| format!("启动抓包失败: {e}"))?;

    // 抓取指定时长
    tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
    cap.stop();

    let packet_count = cap.packet_count();

    Ok(serde_json::json!({
        "type": "traffic",
        "interface": interface,
        "duration_secs": duration_secs,
        "packet_count": packet_count,
        "message": "流量抓包完成，可下载 pcap 文件分析",
    }))
}

/// 将发现结果导入资产库 POST /api/v1/discovery/{id}/import-assets
pub async fn import_discovered_assets(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    let task = match DiscoveryTaskEntity::find_by_id(id).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "发现任务未找到"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let result = match task.result {
        Some(r) => r,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "发现任务无结果"})),
    };

    let mut imported = 0;
    let mut skipped = 0;

    match task.discovery_type {
        DiscoveryType::Ip => {
            // 从 hosts 数组导入
            if let Some(hosts) = result.get("hosts").and_then(|h| h.as_array()) {
                for host in hosts {
                    let ip = match host.get("ip").and_then(|v| v.as_str()) {
                        Some(ip) => ip.to_string(),
                        None => continue,
                    };
                    // 检查是否已存在
                    let exists = NetworkAssetEntity::find()
                        .filter(network_asset::Column::Ip.eq(ip.clone()))
                        .one(&data.db)
                        .await;
                    if matches!(exists, Ok(Some(_))) {
                        skipped += 1;
                        continue;
                    }
                    let now = chrono::Utc::now();
                    let new = network_asset::ActiveModel {
                        id: Set(uuid::Uuid::new_v4().to_string()),
                        name: Set(ip.clone()),
                        ip: Set(ip),
                        mac: Set(None),
                        os: Set(None),
                        asset_type: Set(AssetType::Network),
                        status: Set(AssetStatus::Unknown),
                        risk_score: Set(0.0),
                        tags: Set(serde_json::json!(["discovered"])),
                        created_at: Set(now),
                        updated_at: Set(now),
                        device_no: Set(None),
                        location: Set(None),
                        weight: Set(None),
                        asset_group_id: Set(None),
                        network_zone: Set(None),
                        business_system: Set(None),
                        owner: Set(None),
                        contact: Set(None),
                        email: Set(None),
                        is_industrial: Set(false),
                        industrial_vendor: Set(None),
                        industrial_model: Set(None),
                        industrial_version: Set(None),
                        protection_level: Set(None),
                        confidentiality: Set(None),
                        integrity: Set(None),
                        availability: Set(None),
                        importance: Set(None),
                        description: Set(None),
                        trusted_device: Set(false),
                        industrial_device_type: Set(None),
                    };
                    if new.insert(&data.db).await.is_ok() {
                        imported += 1;
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
        DiscoveryType::Subdomain => {
            // 子域名作为应用资产导入（系统对齐：域名归属应用资产）
            if let Some(subdomains) = result.get("subdomains").and_then(|s| s.as_array()) {
                for sub in subdomains {
                    let name = match sub.get("subdomain").and_then(|v| v.as_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    // 解析 IP 列表，取第一个
                    let ip = sub
                        .get("ips")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    // 已存在检查（按 name）
                    let exists = ApplicationAssetEntity::find()
                        .filter(application_asset::Column::Name.eq(name.clone()))
                        .one(&data.db)
                        .await;
                    if matches!(exists, Ok(Some(_))) {
                        skipped += 1;
                        continue;
                    }
                    let now = chrono::Utc::now();
                    let url = format!("https://{}", name);
                    let new = application_asset::ActiveModel {
                        id: Set(uuid::Uuid::new_v4().to_string()),
                        name: Set(name.clone()),
                        url: Set(url),
                        title: Set(None),
                        server_arch: Set(None),
                        status: Set(AssetStatus::Unknown),
                        risk_score: Set(0.0),
                        created_at: Set(now),
                        updated_at: Set(now),
                        page_encoding: Set(None),
                        os: Set(None),
                        cert_type: Set(None),
                        cert_id: Set(None),
                        device_no: Set(None),
                        location: Set(None),
                        weight: Set(None),
                        asset_group_id: Set(None),
                        business_system: Set(None),
                        owner: Set(None),
                        contact: Set(None),
                        email: Set(None),
                        description: Set(None),
                        ip: Set(ip),
                        tags: Set(Some(serde_json::json!(["discovered", "subdomain"]))),
                        trusted_device: Set(false),
                        asset_type: Set(Some("website".to_string())),
                        protection_level: Set(None),
                        confidentiality: Set(None),
                        integrity: Set(None),
                        availability: Set(None),
                        importance: Set(None),
                        auto_fetch: Set(false),
                    };
                    if new.insert(&data.db).await.is_ok() {
                        imported += 1;
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
        DiscoveryType::Traffic => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "流量发现结果需手动分析 pcap 文件后导入"
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "imported": imported,
        "skipped": skipped,
        "message": format!("成功导入 {} 个资产，跳过 {} 个", imported, skipped),
    }))
}

// ==================== G4.5 拓扑 Trace 路径数据采集 ====================

/// Traceroute 请求参数
#[derive(Debug, Deserialize)]
pub struct TracerouteRequest {
    /// 目标主机（域名或 IP）
    pub target: String,
    /// 最大跳数（默认 30）
    #[serde(default)]
    pub max_hops: Option<u8>,
    /// 每跳超时毫秒（默认 1000）
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// 执行 traceroute 探测
///
/// POST /api/v1/discovery/traceroute
///
/// 通过递增 TTL 的 ICMP Echo Request 探测到目标路径上的每一跳路由器。
/// 注意：需要 root 权限创建 raw socket；非 root 用户会返回错误。
pub async fn traceroute(
    _data: web::Data<AppState>,
    body: web::Json<TracerouteRequest>,
) -> impl Responder {
    let max_hops = body.max_hops.unwrap_or(30).clamp(1, 64);
    let timeout_ms = body.timeout_ms.unwrap_or(1000).min(10000);

    let result =
        argus_portscanner::traceroute::traceroute(&body.target, max_hops, timeout_ms).await;

    if result.error.is_some() {
        HttpResponse::BadRequest().json(result)
    } else {
        HttpResponse::Ok().json(result)
    }
}
