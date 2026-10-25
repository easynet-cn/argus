//! 系统处理函数：扫描引擎列表 + 系统配置

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, EntityTrait, ActiveValue::Set};
use serde::Deserialize;

use argus_core::entity::system_setting::{self, Entity as SystemSettingEntity};
use crate::state::AppState;

/// 列出已注册的扫描引擎（GET /api/v1/scanners）
pub async fn list_scanners(data: web::Data<AppState>) -> impl Responder {
    let scanners = data.registry.list();
    HttpResponse::Ok().json(serde_json::json!({
        "scanners": scanners,
    }))
}

// ==================== 系统配置 ====================

/// GET /api/v1/system/settings - 获取所有系统配置
pub async fn list_settings(data: web::Data<AppState>) -> impl Responder {
    match SystemSettingEntity::find().all(&data.db).await {
        Ok(items) => {
            let map: std::collections::HashMap<String, serde_json::Value> = items
                .into_iter()
                .map(|s| (s.key, s.value))
                .collect();
            HttpResponse::Ok().json(serde_json::json!({ "settings": map }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: serde_json::Value,
}

/// PUT /api/v1/system/settings/{key} - 更新系统配置
pub async fn update_setting(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateSettingRequest>,
) -> impl Responder {
    let key = path.into_inner();
    let now = chrono::Utc::now();

    // 检查是否已存在
    match SystemSettingEntity::find_by_id(key.clone()).one(&data.db).await {
        Ok(Some(existing)) => {
            let mut active: system_setting::ActiveModel = existing.into();
            active.value = Set(body.value.clone());
            active.updated_at = Set(now);
            match active.update(&data.db).await {
                Ok(updated) => HttpResponse::Ok().json(serde_json::json!({
                    "key": updated.key,
                    "value": updated.value,
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            }
        }
        Ok(None) => {
            // 不存在则新建
            let new = system_setting::ActiveModel {
                key: Set(key.clone()),
                value: Set(body.value.clone()),
                updated_at: Set(now),
            };
            match new.insert(&data.db).await {
                Ok(created) => HttpResponse::Ok().json(serde_json::json!({
                    "key": created.key,
                    "value": created.value,
                })),
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 密码策略（10.9 系统设置）====================

/// GET /api/v1/system/password-policy - 获取当前密码策略
///
/// 返回 PasswordPolicy，所有字段在用户创建/修改密码时强制生效。
/// 若未配置，返回默认策略（min_length=8、require_complexity=true、expiry_days=90 等）。
pub async fn get_password_policy(data: web::Data<AppState>) -> impl Responder {
    let policy = crate::handler::admin::get_password_policy(&data.db).await;
    HttpResponse::Ok().json(policy)
}

#[derive(Debug, Deserialize)]
pub struct UpdatePasswordPolicyRequest {
    pub policy: crate::handler::admin::PasswordPolicy,
}

/// PUT /api/v1/system/password-policy - 更新密码策略
///
/// 策略持久化在 system_settings 表 key=password_policy。
/// 更新后立即对后续的创建/修改密码生效。
pub async fn update_password_policy(
    data: web::Data<AppState>,
    body: web::Json<UpdatePasswordPolicyRequest>,
) -> impl Responder {
    let value = match serde_json::to_value(&body.policy) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({"error": format!("序列化策略失败: {e}")}),
            )
        }
    };
    let now = chrono::Utc::now();
    // upsert：先查存在则更新，否则新建
    match SystemSettingEntity::find_by_id(crate::handler::admin::PASSWORD_POLICY_KEY.to_string())
        .one(&data.db)
        .await
    {
        Ok(Some(existing)) => {
            let mut active: system_setting::ActiveModel = existing.into();
            active.value = Set(value.clone());
            active.updated_at = Set(now);
            match active.update(&data.db).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                    "message": "密码策略更新成功",
                    "policy": value,
                })),
                Err(e) => HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": e.to_string()})),
            }
        }
        Ok(None) => {
            let new = system_setting::ActiveModel {
                key: Set(crate::handler::admin::PASSWORD_POLICY_KEY.to_string()),
                value: Set(value.clone()),
                updated_at: Set(now),
            };
            match new.insert(&data.db).await {
                Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                    "message": "密码策略创建成功",
                    "policy": value,
                })),
                Err(e) => HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": e.to_string()})),
            }
        }
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 网络配置 ====================

/// 获取网络配置 GET /api/v1/system/network
/// 接口信息使用 if-addrs crate（跨平台），MTU/state/路由/DNS 为平台特定实现
pub async fn get_network_config() -> impl Responder {
    use if_addrs::{IfAddr, get_if_addrs};

    // 跨平台获取网络接口及 IP 地址
    let raw_ifaces = match get_if_addrs() {
        Ok(ifaces) => ifaces,
        Err(_) => Vec::new(),
    };

    // 按接口名分组地址
    let mut iface_map: std::collections::BTreeMap<String, Vec<serde_json::Value>> = std::collections::BTreeMap::new();
    for iface in &raw_ifaces {
        let (family, address, prefixlen) = match &iface.addr {
            IfAddr::V4(v4) => {
                let prefixlen = netmask_to_prefixlen_v4(&v4.netmask);
                ("inet", v4.ip.to_string(), prefixlen)
            }
            IfAddr::V6(v6) => {
                let prefixlen = netmask_to_prefixlen_v6(&v6.netmask);
                ("inet6", v6.ip.to_string(), prefixlen)
            }
        };
        iface_map.entry(iface.name.clone()).or_default().push(serde_json::json!({
            "family": family,
            "address": address,
            "prefixlen": prefixlen,
        }));
    }

    // 组装接口信息，MTU/state 从平台特定来源读取
    let interfaces: Vec<serde_json::Value> = iface_map.into_iter().map(|(name, addresses)| {
        let (state, mtu) = get_iface_state_and_mtu(&name);
        serde_json::json!({
            "name": name,
            "state": state,
            "mtu": mtu,
            "addresses": addresses,
        })
    }).collect();

    // 路由表（平台特定：Linux 用 ip route，其他平台暂不支持）
    let routes = get_routes();

    // DNS（平台特定：Linux 读 /etc/resolv.conf）
    let dns = get_dns_servers();

    HttpResponse::Ok().json(serde_json::json!({
        "interfaces": interfaces,
        "routes": routes,
        "dns": dns,
    }))
}

/// 获取接口状态和 MTU（平台特定）
fn get_iface_state_and_mtu(name: &str) -> (String, u64) {
    #[cfg(target_os = "linux")]
    {
        let state = std::fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        (state, mtu)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        (String::new(), 0)
    }
}

/// 获取路由表（平台特定）
fn get_routes() -> Vec<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        Command::new("ip").arg("-j").arg("route").output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// 获取 DNS 服务器（平台特定）
fn get_dns_servers() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
    }
    #[cfg(not(target_os = "linux"))]
    {
        serde_json::json!({ "nameservers": [], "search": [] })
    }
}

/// 将 IPv4 子网掩码转换为前缀长度
fn netmask_to_prefixlen_v4(netmask: &std::net::Ipv4Addr) -> u8 {
    let octets = netmask.octets();
    let bits: u32 = u32::from_be_bytes(octets);
    bits.count_ones() as u8
}

/// 将 IPv6 子网掩码转换为前缀长度
fn netmask_to_prefixlen_v6(netmask: &std::net::Ipv6Addr) -> u8 {
    let segments = netmask.segments();
    let mut count = 0u8;
    for seg in segments {
        count += seg.count_ones() as u8;
    }
    count
}

/// 解析 /etc/resolv.conf
fn parse_resolv_conf(content: &str) -> serde_json::Value {
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if let Some(ns) = line.split_whitespace().nth(1) {
                nameservers.push(ns);
            }
        } else if line.starts_with("search") {
            search.extend(line.split_whitespace().skip(1).map(|s| s.to_string()));
        }
    }
    serde_json::json!({
        "nameservers": nameservers,
        "search": search,
    })
}

/// Hosts 配置请求
#[derive(Debug, Deserialize)]
pub struct HostsRequest {
    pub entries: Vec<String>,
    /// 是否覆盖现有自定义条目（保留系统默认 localhost）
    pub overwrite: Option<bool>,
}

/// 更新 Hosts PUT /api/v1/system/network/hosts
pub async fn update_hosts(body: web::Json<HostsRequest>) -> impl Responder {
    const HOSTS_PATH: &str = "/etc/hosts";
    const HOSTS_MARKER: &str = "# >>> argus-managed-hosts >>>";
    const HOSTS_MARKER_END: &str = "# <<< argus-managed-hosts <<<";

    // 读取现有 hosts
    let existing = std::fs::read_to_string(HOSTS_PATH).unwrap_or_default();

    let overwrite = body.overwrite.unwrap_or(false);
    let new_entries = body.entries.join("\n");

    let new_content = if existing.contains(HOSTS_MARKER) && existing.contains(HOSTS_MARKER_END) {
        // 替换 argus 管理的块
        let before = existing.split(HOSTS_MARKER).next().unwrap_or("");
        let after = existing.split(HOSTS_MARKER_END).nth(1).unwrap_or("");
        format!("{before}{HOSTS_MARKER}\n{new_entries}\n{HOSTS_MARKER_END}{after}")
    } else if overwrite {
        // 覆盖模式：保留系统默认行，追加 argus 块
        let system_lines: Vec<&str> = existing.lines()
            .filter(|l| {
                let l = l.trim();
                l.starts_with("127.") || l.starts_with("::1") || l.starts_with("#") || l.is_empty()
            })
            .collect();
        let mut content = system_lines.join("\n");
        content.push_str(&format!("\n{HOSTS_MARKER}\n{new_entries}\n{HOSTS_MARKER_END}\n"));
        content
    } else {
        // 追加模式
        format!("{existing}\n{HOSTS_MARKER}\n{new_entries}\n{HOSTS_MARKER_END}\n")
    };

    match std::fs::write(HOSTS_PATH, new_content) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Hosts 已更新"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 服务管理 ====================

/// 服务操作请求
#[derive(Debug, Deserialize)]
pub struct ServiceRequest {
    pub service: String,
    pub action: String, // status / start / stop / restart
}

/// 服务管理 POST /api/v1/system/services
pub async fn manage_service(body: web::Json<ServiceRequest>) -> impl Responder {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        let output = match body.action.as_str() {
            "status" => Command::new("systemctl").args(["status", &body.service]).output(),
            "start" => Command::new("systemctl").args(["start", &body.service]).output(),
            "stop" => Command::new("systemctl").args(["stop", &body.service]).output(),
            "restart" => Command::new("systemctl").args(["restart", &body.service]).output(),
            _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "不支持的操作"})),
        };

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                HttpResponse::Ok().json(serde_json::json!({
                    "success": o.status.success(),
                    "stdout": stdout,
                    "stderr": stderr,
                }))
            }
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        HttpResponse::NotImplemented().json(serde_json::json!({
            "error": "服务管理仅在 Linux (systemd) 平台可用",
        }))
    }
}

/// 列出关键服务状态 GET /api/v1/system/services
/// 使用 sysinfo 通过进程名判断服务是否运行（跨平台）
pub async fn list_services() -> impl Responder {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

    // 服务名到进程名的映射（用于跨平台进程匹配）
    let service_map: &[(&str, &[&str])] = &[
        ("argus", &["argus"]),
        ("nginx", &["nginx"]),
        ("postgresql", &["postgres", "postmaster"]),
        ("redis", &["redis-server"]),
        ("docker", &["dockerd"]),
    ];

    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new())
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut results = Vec::new();
    for (svc_name, proc_names) in service_map {
        let running = sys.processes().values().any(|p| {
            let name = p.name().to_string_lossy();
            proc_names.iter().any(|pn| name == *pn)
        });
        let state = if running { "active" } else { "inactive" };
        results.push(serde_json::json!({
            "service": svc_name,
            "state": state,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({ "services": results }))
}

// ==================== 系统备份 ====================

/// 备份请求
#[derive(Debug, Deserialize)]
pub struct BackupRequest {
    pub backup_type: Option<String>, // config / data / full
    pub backup_path: Option<String>,
}

/// 手动备份 POST /api/v1/system/backup
/// 使用 tar + flate2 crate 跨平台打包，不依赖系统 tar 命令
pub async fn create_backup(
    data: web::Data<AppState>,
    body: web::Json<BackupRequest>,
) -> impl Responder {
    let backup_type = body.backup_type.clone().unwrap_or_else(|| "config".to_string());
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");

    // 跨平台默认备份路径
    #[cfg(target_os = "linux")]
    let default_dir = "/var/backups";
    #[cfg(target_os = "macos")]
    let default_dir = "/tmp/argus-backups";
    #[cfg(target_os = "windows")]
    let default_dir = "C:\\argus\\backups";

    let default_path = format!("{default_dir}/argus_{backup_type}_{timestamp}.tar.gz");
    let backup_path = body.backup_path.clone().unwrap_or(default_path);

    // 根据类型选择备份内容
    #[cfg(target_os = "linux")]
    let paths = match backup_type.as_str() {
        "config" => vec!["/etc/argus"],
        "data" => vec!["/var/lib/argus"],
        "full" => vec!["/etc/argus", "/var/lib/argus"],
        _ => vec!["/etc/argus"],
    };
    #[cfg(not(target_os = "linux"))]
    let paths: Vec<&str> = match backup_type.as_str() {
        "config" => vec!["./config"],
        "data" => vec!["./data"],
        "full" => vec!["./config", "./data"],
        _ => vec!["./config"],
    };

    // 确保备份目录存在
    if let Some(parent) = std::path::Path::new(&backup_path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    // 使用 tar + flate2 跨平台打包
    let result = std::fs::File::create(&backup_path).map_err(|e| e.to_string()).and_then(|file| {
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        for path in &paths {
            let p = std::path::Path::new(path);
            if p.exists() {
                if p.is_dir() {
                    builder.append_dir_all(p, p).map_err(|e| e.to_string())?;
                } else {
                    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
                    builder.append_file(p, &mut f).map_err(|e| e.to_string())?;
                }
            }
        }

        builder.finish().map_err(|e| e.to_string())
    });

    match result {
        Ok(_) => {
            // 记录备份日志
            let now = chrono::Utc::now();
            let active = system_setting::ActiveModel {
                key: Set(format!("backup_last_{backup_type}")),
                value: Set(serde_json::json!({
                    "path": backup_path,
                    "time": now.to_rfc3339(),
                })),
                updated_at: Set(now),
            };
            let _ = active.save(&data.db).await;

            HttpResponse::Ok().json(serde_json::json!({
                "message": "备份完成",
                "path": backup_path,
                "type": backup_type,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e})),
    }
}

/// 获取备份历史 GET /api/v1/system/backup/history
pub async fn backup_history(data: web::Data<AppState>) -> impl Responder {
    let mut history = Vec::new();
    for key in ["backup_last_config", "backup_last_data", "backup_last_full"] {
        if let Ok(Some(s)) = SystemSettingEntity::find_by_id(key).one(&data.db).await {
            history.push(serde_json::json!({
                "type": key.strip_prefix("backup_last_").unwrap_or(key),
                "info": s.value,
            }));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({ "history": history }))
}

/// 备份策略配置
#[derive(Debug, Deserialize)]
pub struct BackupPolicyRequest {
    pub enabled: bool,
    pub cron: String,
    pub backup_type: String,
    pub retention_days: i32,
}

/// 设置备份策略 PUT /api/v1/system/backup/policy
pub async fn set_backup_policy(
    data: web::Data<AppState>,
    body: web::Json<BackupPolicyRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let active = system_setting::ActiveModel {
        key: Set("backup_policy".to_string()),
        value: Set(serde_json::json!({
            "enabled": body.enabled,
            "cron": body.cron,
            "backup_type": body.backup_type,
            "retention_days": body.retention_days,
        })),
        updated_at: Set(now),
    };
    match active.save(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "备份策略已保存"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 系统监控 ====================

/// 获取系统资源使用情况 GET /api/v1/system/monitor
/// 使用 sysinfo crate 跨平台获取 CPU/内存/磁盘信息
pub async fn system_monitor() -> impl Responder {
    use sysinfo::{System, Disks};

    let mut sys = System::new_all();
    // 刷新两次以获取准确的 CPU 使用率
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    std::thread::sleep(std::time::Duration::from_millis(100));
    sys.refresh_cpu_usage();

    // CPU 使用率（跨平台）
    let cpu_usage = sys.global_cpu_usage();
    let cpu_cores = sys.cpus().len();
    let cpu_brand = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default();

    // 内存使用（跨平台，sysinfo 单位为字节）
    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let memory_percent = if total_memory > 0 {
        (used_memory as f64 / total_memory as f64) * 100.0
    } else {
        0.0
    };

    // Swap
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();

    // 磁盘使用（跨平台，sysinfo 0.32 中 Disks 独立于 System）
    let disks = Disks::new_with_refreshed_list();
    let disks_json: Vec<serde_json::Value> = disks.list().iter().map(|disk| {
        let total = disk.total_space();
        let available = disk.available_space();
        let used = total.saturating_sub(available);
        let usage_percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        serde_json::json!({
            "name": disk.name().to_string_lossy(),
            "file_system": disk.file_system().to_string_lossy(),
            "mount_point": disk.mount_point().to_string_lossy(),
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "usage_percent": usage_percent,
        })
    }).collect();

    // 系统运行时间（跨平台）
    let uptime_seconds = System::uptime();

    // 系统负载（仅 Linux/macOS，Windows 返回 0）
    let load_avg = get_load_average();

    HttpResponse::Ok().json(serde_json::json!({
        "cpu": {
            "usage_percent": cpu_usage,
            "cores": cpu_cores,
            "brand": cpu_brand,
        },
        "memory": {
            "total_bytes": total_memory,
            "used_bytes": used_memory,
            "usage_percent": memory_percent,
        },
        "swap": {
            "total_bytes": total_swap,
            "used_bytes": used_swap,
        },
        "disks": disks_json,
        "load_average": load_avg,
        "uptime_seconds": uptime_seconds,
    }))
}

/// 获取系统负载平均值（跨平台：Linux/macOS 读取 /proc/loadavg 或 sysctl，Windows 不支持返回 0）
fn get_load_average() -> serde_json::Value {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = content.trim().split_whitespace().collect();
            if parts.len() >= 3 {
                return serde_json::json!({
                    "1min": parts[0].parse::<f64>().unwrap_or(0.0),
                    "5min": parts[1].parse::<f64>().unwrap_or(0.0),
                    "15min": parts[2].parse::<f64>().unwrap_or(0.0),
                });
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("sysctl").args(["-n", "vm.loadavg"]).output() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // 格式: { 1.00 2.00 3.00 }
            let cleaned = s.trim_matches(|c: char| c == '{' || c == '}' || c == ' ');
            let parts: Vec<&str> = cleaned.split_whitespace().collect();
            if parts.len() >= 3 {
                return serde_json::json!({
                    "1min": parts[0].parse::<f64>().unwrap_or(0.0),
                    "5min": parts[1].parse::<f64>().unwrap_or(0.0),
                    "15min": parts[2].parse::<f64>().unwrap_or(0.0),
                });
            }
        }
    }
    serde_json::json!({ "1min": 0.0, "5min": 0.0, "15min": 0.0 })
}

// ==================== APIKey 管理（10.9） ====================

use argus_core::entity::api_key::{self, Entity as ApiKeyEntity};
use sea_orm::{ColumnTrait, QueryFilter, QueryOrder, PaginatorTrait};

/// APIKey 创建请求
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub user_id: String,
    pub scopes: Option<Vec<String>>,
    /// 过期时间（ISO 8601，None 表示永不过期）
    pub expires_at: Option<String>,
}

/// APIKey 更新请求
#[derive(Debug, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<String>,
    pub is_active: Option<bool>,
}

/// 列出 APIKey GET /api/v1/system/api-keys
pub async fn list_api_keys(data: web::Data<AppState>) -> impl Responder {
    match ApiKeyEntity::find()
        .order_by_desc(api_key::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(keys) => {
            // 列表返回时脱敏 key_hash，仅返回前缀
            let items: Vec<serde_json::Value> = keys
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "id": k.id,
                        "name": k.name,
                        "key_prefix": k.key_prefix,
                        "user_id": k.user_id,
                        "scopes": k.scopes,
                        "expires_at": k.expires_at,
                        "last_used_at": k.last_used_at,
                        "is_active": k.is_active,
                        "created_at": k.created_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(serde_json::json!({"items": items}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 创建 APIKey POST /api/v1/system/api-keys
/// 返回完整的 API Key 明文（仅此一次）
pub async fn create_api_key(
    data: web::Data<AppState>,
    body: web::Json<CreateApiKeyRequest>,
) -> impl Responder {
    let now = chrono::Utc::now();

    // 生成随机 API Key: ak-<48 hex chars>
    let random_bytes: [u8; 24] = {
        use rand_core::RngCore;
        let mut rng = rand_core::OsRng;
        let mut buf = [0u8; 24];
        rng.fill_bytes(&mut buf);
        buf
    };
    let key_plain = format!("ak-{}", hex::encode(random_bytes));
    let key_prefix = key_plain[..12].to_string(); // "ak-xxxxxxxx"

    // SHA-256 哈希
    let key_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key_plain.as_bytes());
        hex::encode(hasher.finalize())
    };

    let scopes = serde_json::to_value(body.scopes.clone().unwrap_or_else(|| vec!["*".to_string()]))
        .unwrap_or(serde_json::json!(["*"]));

    let expires_at = body.expires_at.as_deref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    let id = uuid::Uuid::new_v4().to_string();
    let active = api_key::ActiveModel {
        id: Set(id.clone()),
        name: Set(body.name.clone()),
        key_prefix: Set(key_prefix),
        key_hash: Set(key_hash),
        user_id: Set(body.user_id.clone()),
        scopes: Set(scopes),
        expires_at: Set(expires_at),
        last_used_at: Set(None),
        is_active: Set(true),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match active.insert(&data.db).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "name": body.name,
            "api_key": key_plain,  // 明文仅返回一次
            "key_prefix": key_plain[..12],
            "message": "请妥善保存此 API Key，它不会再次显示"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新 APIKey PUT /api/v1/system/api-keys/{id}
pub async fn update_api_key(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<UpdateApiKeyRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let existing = match ApiKeyEntity::find_by_id(id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": "APIKey 不存在"})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    let mut active: api_key::ActiveModel = existing.into();
    if let Some(name) = &body.name { active.name = Set(name.clone()); }
    if let Some(scopes) = &body.scopes {
        active.scopes = Set(serde_json::to_value(scopes).unwrap_or(serde_json::json!(["*"])));
    }
    if let Some(exp) = body.expires_at.as_deref() {
        if exp.is_empty() {
            active.expires_at = Set(None);
        } else {
            match chrono::DateTime::parse_from_rfc3339(exp) {
                Ok(dt) => active.expires_at = Set(Some(dt.with_timezone(&chrono::Utc))),
                Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("无效的过期时间: {e}")})),
            }
        }
    }
    if let Some(active_flag) = body.is_active { active.is_active = Set(active_flag); }
    active.updated_at = Set(chrono::Utc::now());

    match active.update(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "APIKey 已更新"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 删除 APIKey DELETE /api/v1/system/api-keys/{id}
pub async fn delete_api_key(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match ApiKeyEntity::delete_by_id(id).exec(&data.db).await {
        Ok(r) if r.rows_affected > 0 => HttpResponse::Ok().json(serde_json::json!({"message": "已删除"})),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "APIKey 不存在"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 获取 WSUS 和任务设置 GET /api/v1/system/task-settings
pub async fn get_task_settings(data: web::Data<AppState>) -> impl Responder {
    let settings = SystemSettingEntity::find()
        .filter(sea_orm::sea_query::Expr::cust("key LIKE 'task_%' OR key LIKE 'wsus_%'"))
        .all(&data.db)
        .await;
    match settings {
        Ok(items) => {
            let map: std::collections::HashMap<String, serde_json::Value> = items
                .into_iter()
                .map(|s| (s.key, s.value))
                .collect();
            HttpResponse::Ok().json(map)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 更新 WSUS 或任务设置 PUT /api/v1/system/task-settings/{key}
pub async fn update_task_setting(
    data: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let key = path.into_inner();
    // 仅允许 task_ 或 wsus_ 前缀的设置
    if !key.starts_with("task_") && !key.starts_with("wsus_") {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "仅支持 task_ 或 wsus_ 前缀的设置项"}));
    }
    let now = chrono::Utc::now();
    let value = body.into_inner();
    let active = system_setting::ActiveModel {
        key: Set(key.clone()),
        value: Set(value),
        updated_at: Set(now),
    };
    match SystemSettingEntity::insert(active)
        .on_conflict(
            sea_orm::sea_query::OnConflict::column(system_setting::Column::Key)
                .update_column(system_setting::Column::Value)
                .update_column(system_setting::Column::UpdatedAt)
                .to_owned(),
        )
        .exec(&data.db)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": format!("{} 已更新", key)})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
