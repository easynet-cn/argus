//! 扫描任务执行 API
//!
//! 支持异步任务化：提交后立即返回 task_id，后台执行扫描，
//! 通过 GET /scan/status/{task_id} 轮询状态，POST /scan/cancel/{task_id} 取消。

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use argus_core::entity::task::{self, Entity as ScanTaskEntity, TaskStatus, TaskType};
use argus_core::entity::scan_result::{self, Entity as ScanResultEntity, ResultType};
use argus_core::entity::credential::{self, Entity as CredentialEntity, AuthResult};
use argus_core::entity::asset_group::{self, Entity as AssetGroupEntity};
use argus_core::entity::network_asset::{self, Entity as NetworkAssetEntity};
use argus_core::scan_param_config::{self, ScanParamConfig};
use argus_scanner::{ScanConfig, Target, Credentials};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, ActiveValue::Set};
use std::net::Ipv4Addr;
use crate::state::AppState;

// ==================== 端口扫描 ====================

/// 端口扫描请求
#[derive(Debug, Deserialize)]
pub struct PortScanRequest {
    pub hosts: Vec<String>,
    pub ports: Option<String>,
    /// TCP 扫描类型: connect/syn/ack/null/xmas/fin/window，默认 connect
    pub tcp_scan_type: Option<String>,
    pub scan_udp: Option<bool>,
    pub fingerprint: Option<bool>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub rate_limit: Option<u32>,
    /// 按资产组发起扫描（6.1 扫描目标选择）
    ///
    /// 指定后从 network_asset 表查询该组下所有 IP，与 hosts 合并。
    /// 允许 hosts 为空（仅用资产组）；也允许两者同时指定。
    pub asset_group_id: Option<String>,
}

/// 异步提交响应（通用）
#[derive(Debug, Serialize)]
pub struct TaskAccepted {
    pub task_id: String,
    pub status: String,
    pub message: String,
}

/// 执行端口扫描（POST /api/v1/scan/port）
/// 异步：立即返回 task_id，后台执行
pub async fn scan_ports(
    data: web::Data<AppState>,
    body: web::Json<PortScanRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    // G6.1 按资产组发起扫描：查询组内 IP 并与 hosts 合并
    let mut all_hosts = body.hosts.clone();
    if let Some(gid) = &body.asset_group_id {
        use argus_core::entity::network_asset::{self, Entity as NetworkAssetEntity};
        match NetworkAssetEntity::find()
            .filter(network_asset::Column::AssetGroupId.eq(gid.clone()))
            .filter(network_asset::Column::Status.eq(argus_core::entity::network_asset::AssetStatus::Active))
            .all(&data.db)
            .await
        {
            Ok(assets) => {
                let group_ips: Vec<String> = assets.iter().map(|a| a.ip.clone()).collect();
                tracing::info!("资产组 {} 包含 {} 个 IP", gid, group_ips.len());
                all_hosts.extend(group_ips);
            }
            Err(e) => {
                tracing::warn!("查询资产组 {} 失败: {}", gid, e);
            }
        }
        // 去重
        all_hosts.sort();
        all_hosts.dedup();
    }

    if all_hosts.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "扫描目标为空（hosts 和 asset_group_id 均未提供有效 IP）"
        }));
    }

    let targets: Vec<Target> = all_hosts.iter().map(|h| Target {
        host: h.clone(),
        ports: None,
        credentials: None,
    }).collect();

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("port-scan-{}", &task_id[..8])),
        task_type: Set(TaskType::PortScan),
        status: Set(TaskStatus::Running),
        launch_mode: Set(argus_core::entity::task::LaunchMode::Manual),
        targets: Set(serde_json::to_value(&all_hosts).unwrap_or_default()),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(None),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        tracing::error!("创建扫描任务失败: {e}");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("创建任务失败: {e}")
        }));
    }

    let params = serde_json::json!({
        "tcp_scan_type": body.tcp_scan_type.as_deref().unwrap_or("connect"),
        "scan_udp": body.scan_udp.unwrap_or(false),
        "fingerprint": body.fingerprint.unwrap_or(true),
        "concurrency": body.concurrency.unwrap_or(1000),
        "timeout_ms": body.timeout_ms.unwrap_or(1000),
        "rate_limit": body.rate_limit.unwrap_or(0),
        "ports": body.ports.as_ref().and_then(|p| {
            argus_portscanner::port_list::parse_port_range(p).ok()
        }),
    });

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(1000),
        timeout_secs: body.timeout_ms.unwrap_or(1000) / 1000,
        extra_params: params,
    };

    // 获取扫描引擎
    let scanner = match data.registry.get("port_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "端口扫描引擎未注册"
            }));
        }
    };

    // 克隆 db 和 registry 供后台任务使用
    let db = data.db.clone();
    let task_id_bg = task_id.clone();

    // spawn 后台任务
    tokio::spawn(async move {
        tracing::info!("端口扫描任务 {} 后台执行中", task_id_bg);

        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("扫描执行失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };

        // 提取并持久化扫描结果
        let port_results: Vec<argus_portscanner::types::PortScanResult> = result.raw_data
            .as_ref()
            .and_then(|raw| serde_json::from_value(raw.clone()).ok())
            .unwrap_or_default();

        if let Err(e) = save_port_scan_results(&db, &task_id_bg, &port_results).await {
            tracing::error!("保存扫描结果失败: {e}");
        }

        // 更新任务状态为完成
        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
        tracing::info!("端口扫描任务 {} 完成", task_id_bg);
    });

    HttpResponse::Accepted().json(TaskAccepted {
        task_id,
        status: "running".to_string(),
        message: "扫描任务已提交，使用 GET /api/v1/scan/status/{task_id} 查询进度".to_string(),
    })
}

/// 保存端口扫描结果到数据库
async fn save_port_scan_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    results: &[argus_portscanner::types::PortScanResult],
) -> Result<(), sea_orm::DbErr> {
    use argus_portscanner::types::Protocol;

    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = results
        .iter()
        .map(|r| scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id.to_string()),
            result_type: Set(ResultType::PortScan),
            host: Set(r.host.clone()),
            port: Set(Some(r.port as i32)),
            protocol: Set(Some(match r.protocol {
                Protocol::Tcp => "tcp".to_string(),
                Protocol::Udp => "udp".to_string(),
            })),
            state: Set(Some(r.state.as_str().to_string())),
            service: Set(r.service.clone()),
            banner: Set(r.banner.clone()),
            username: Set(None),
            password: Set(None),
            success: Set(None),
            response_time_ms: Set(Some(r.response_time_ms as i64)),
            raw_data: Set(Some(serde_json::to_value(r).unwrap_or_default())),
            created_at: Set(now),
        })
        .collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

// ==================== 口令猜解 ====================

/// 口令猜解请求
#[derive(Debug, Deserialize)]
pub struct BruteForceRequest {
    pub host: String,
    pub protocol: String,
    pub port: Option<u16>,
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub concurrency: Option<usize>,
    pub timeout_ms: Option<u64>,
    pub stop_on_success: Option<bool>,
    /// 字典分级: weak(top10)/medium(top50)/strong(top100)
    ///
    /// 指定后使用内置字典，覆盖 usernames/passwords
    pub dict_level: Option<String>,
    /// 多目标支持（逗号分隔的 IP 列表，与 host 二选一）
    pub hosts: Option<Vec<String>>,
    /// 端口扫描联动爆破（true = 先扫端口，再对开放端口自动爆破）
    ///
    /// 6.7 口令猜解中的"端口扫描联动"模式。
    /// 启用后忽略 protocol/port 字段，先对 hosts 做 TCP 端口扫描，
    /// 再对匹配到爆破协议的开放端口自动发起猜解。
    pub link_port_scan: Option<bool>,
}

/// 端口号 → 爆破协议映射（仅返回已实现爆破逻辑的协议）
fn port_to_brute_protocol(port: u16) -> Option<argus_bruteforce::types::Protocol> {
    use argus_bruteforce::types::Protocol;
    let proto = match port {
        21 => Protocol::Ftp,
        22 => Protocol::Ssh,
        23 => Protocol::Telnet,
        25 => Protocol::Smtp,
        110 => Protocol::Pop3,
        143 => Protocol::Imap,
        389 => Protocol::Ldap,
        445 => Protocol::Smb,
        554 => Protocol::Rtsp,
        1433 => Protocol::Mssql,
        1521 => Protocol::Oracle,
        3306 => Protocol::Mysql,
        3389 => Protocol::Rdp,
        5432 => Protocol::Postgresql,
        5900 => Protocol::Vnc,
        6379 => Protocol::Redis,
        27017 => Protocol::Mongodb,
        _ => return None,
    };
    // 只返回已实现爆破逻辑的协议
    if proto.is_supported() {
        Some(proto)
    } else {
        None
    }
}

/// 执行口令猜解（POST /api/v1/scan/bruteforce）
/// 异步：立即返回 task_id，后台执行
pub async fn scan_bruteforce(
    data: web::Data<AppState>,
    body: web::Json<BruteForceRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let protocol = match argus_bruteforce::types::Protocol::from_str(&body.protocol) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("不支持的协议: {}", body.protocol)
            }));
        }
    };

    // 拦截未实现爆破逻辑的协议，避免创建无效任务和产出误导性结果
    if !protocol.is_supported() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!(
                "协议 {} 的爆破功能暂未实现，已支持的协议: ssh/mysql/redis/postgresql",
                protocol.as_str()
            )
        }));
    }

    // 字典分级：weak/medium/strong → 内置 Top10/Top50/Top100 字典
    use argus_bruteforce::dictionary::{UsernameDict, PasswordDict, get_usernames, get_passwords};
    let (usernames, passwords) = match body.dict_level.as_deref() {
        Some("weak") => (
            get_usernames(&UsernameDict::Top10),
            get_passwords(&PasswordDict::Top10),
        ),
        Some("medium") => (
            get_usernames(&UsernameDict::Top50),
            get_passwords(&PasswordDict::Top50),
        ),
        Some("strong") => (
            get_usernames(&UsernameDict::Top50),
            get_passwords(&PasswordDict::Top100),
        ),
        _ => (body.usernames.clone(), body.passwords.clone()),
    };

    // 多目标支持：hosts 优先于 host
    let target_hosts: Vec<String> = body.hosts.clone()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| vec![body.host.clone()]);

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("bruteforce-{}", &task_id[..8])),
        task_type: Set(TaskType::Bruteforce),
        status: Set(TaskStatus::Running),
        launch_mode: Set(argus_core::entity::task::LaunchMode::Manual),
        targets: Set(serde_json::to_value(&target_hosts).unwrap_or_default()),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(Some(serde_json::json!({
            "dict_level": body.dict_level,
            "protocol": protocol.as_str(),
        }))),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        tracing::error!("创建爆破任务失败: {e}");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("创建任务失败: {e}")
        }));
    }

    let targets: Vec<Target> = target_hosts.iter().map(|h| Target {
        host: h.clone(),
        ports: None,
        credentials: None,
    }).collect();

    let params = serde_json::json!({
        "host": target_hosts[0],
        "protocol": protocol.as_str(),
        "port": body.port,
        "usernames": usernames,
        "passwords": passwords,
        "concurrency": body.concurrency.unwrap_or(100),
        "timeout_ms": body.timeout_ms.unwrap_or(5000),
        "stop_on_success": body.stop_on_success.unwrap_or(true),
        "dict_level": body.dict_level,
    });

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: body.concurrency.unwrap_or(100),
        timeout_secs: body.timeout_ms.unwrap_or(5000) / 1000,
        extra_params: params,
    };

    let scanner = match data.registry.get("brute_force") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "口令猜解引擎未注册"
            }));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    let link_port_scan = body.link_port_scan.unwrap_or(false);
    let dict_level_bg = body.dict_level.clone();
    let usernames_bg = usernames.clone();
    let passwords_bg = passwords.clone();
    let concurrency_bg = body.concurrency.unwrap_or(100);
    let timeout_ms_bg = body.timeout_ms.unwrap_or(5000);
    let stop_on_success_bg = body.stop_on_success.unwrap_or(true);
    let target_hosts_bg = target_hosts.clone();

    tokio::spawn(async move {
        tracing::info!("口令猜解任务 {} 后台执行中", task_id_bg);

        // G6.7 端口扫描联动爆破：先扫端口，再对开放端口自动爆破
        if link_port_scan {
            tracing::info!("任务 {} 启用端口扫描联动模式", task_id_bg);
            let mut all_brute_results: Vec<argus_bruteforce::types::BruteForceResult> = Vec::new();

            // 1. 主机存活探测
            use argus_portscanner::host::ping_hosts;
            let alive_results = ping_hosts(&target_hosts_bg, 1000, 100).await;
            let alive_hosts: Vec<String> = alive_results
                .iter()
                .filter(|r| r.alive)
                .map(|r| r.host.clone())
                .collect();
            tracing::info!("任务 {} 存活主机 {}/{}", task_id_bg, alive_hosts.len(), target_hosts_bg.len());

            // 2. 端口扫描（常见爆破协议端口）
            use argus_portscanner::tcp::scan_tcp_ports;
            use argus_portscanner::host::resolve_host;
            // 爆破协议常用端口列表
            let brute_ports: Vec<u16> = vec![
                21, 22, 23, 25, 110, 143, 389, 445, 554, 1433, 1521,
                3306, 3389, 5432, 5900, 6379, 27017,
            ];
            for host in &alive_hosts {
                let ip = match resolve_host(host).await {
                    Some(ip) => ip,
                    None => continue,
                };
                let open_results = scan_tcp_ports(&ip, &brute_ports, argus_portscanner::types::TcpScanType::Connect, 2000, 50, None).await;
                let open_ports: Vec<u16> = open_results
                    .iter()
                    .filter(|r| r.state == argus_portscanner::types::PortState::Open)
                    .map(|r| r.port)
                    .collect();
                tracing::info!("主机 {} 开放爆破端口: {:?}", host, open_ports);

                // 3. 对每个开放端口映射到爆破协议并执行
                for port in open_ports {
                    let proto = match port_to_brute_protocol(port) {
                        Some(p) => p,
                        None => continue,
                    };
                    // 构建单目标的 ScanConfig
                    let linked_targets = vec![Target {
                        host: host.clone(),
                        ports: Some(vec![port]),
                        credentials: None,
                    }];
                    let linked_params = serde_json::json!({
                        "host": host,
                        "protocol": proto.as_str(),
                        "port": port,
                        "usernames": usernames_bg,
                        "passwords": passwords_bg,
                        "concurrency": concurrency_bg,
                        "timeout_ms": timeout_ms_bg,
                        "stop_on_success": stop_on_success_bg,
                        "dict_level": dict_level_bg,
                    });
                    let linked_config = ScanConfig {
                        task_id: format!("{}-{}-{}", task_id_bg, host, port),
                        targets: linked_targets,
                        concurrency: concurrency_bg,
                        timeout_secs: timeout_ms_bg / 1000,
                        extra_params: linked_params,
                    };
                    match scanner.execute(&linked_config).await {
                        Ok(r) => {
                            let results: Vec<argus_bruteforce::types::BruteForceResult> = r
                                .raw_data
                                .as_ref()
                                .and_then(|raw| serde_json::from_value(raw.clone()).ok())
                                .unwrap_or_default();
                            all_brute_results.extend(results);
                        }
                        Err(e) => {
                            tracing::warn!("联动爆破 {}:{} ({}) 失败: {}", host, port, proto.as_str(), e);
                        }
                    }
                }
            }

            if let Err(e) = save_bruteforce_results(&db, &task_id_bg, &all_brute_results).await {
                tracing::error!("保存联动爆破结果失败: {e}");
            }
            let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
            tracing::info!("端口扫描联动爆破任务 {} 完成", task_id_bg);
            return;
        }

        // 常规模式：直接执行爆破
        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("爆破执行失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };

        let brute_results: Vec<argus_bruteforce::types::BruteForceResult> = result.raw_data
            .as_ref()
            .and_then(|raw| serde_json::from_value(raw.clone()).ok())
            .unwrap_or_default();

        if let Err(e) = save_bruteforce_results(&db, &task_id_bg, &brute_results).await {
            tracing::error!("保存爆破结果失败: {e}");
        }

        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
        tracing::info!("口令猜解任务 {} 完成", task_id_bg);
    });

    HttpResponse::Accepted().json(TaskAccepted {
        task_id,
        status: "running".to_string(),
        message: "爆破任务已提交，使用 GET /api/v1/scan/status/{task_id} 查询进度".to_string(),
    })
}

/// 保存口令猜解结果到数据库
async fn save_bruteforce_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    results: &[argus_bruteforce::types::BruteForceResult],
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = results
        .iter()
        .map(|r| scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id.to_string()),
            result_type: Set(ResultType::Bruteforce),
            host: Set(r.host.clone()),
            port: Set(Some(r.port as i32)),
            protocol: Set(Some(r.protocol.as_str().to_string())),
            state: Set(None),
            service: Set(None),
            banner: Set(None),
            username: Set(Some(r.credential.username.clone())),
            password: Set(Some(r.credential.password.clone())),
            success: Set(Some(r.success)),
            response_time_ms: Set(None),
            raw_data: Set(Some(serde_json::to_value(r).unwrap_or_default())),
            created_at: Set(now),
        })
        .collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

// ==================== 弱密码复检 ====================

/// 弱密码复检请求
#[derive(Debug, Deserialize)]
pub struct WeakPasswordRecheckRequest {
    /// 原始爆破任务 ID
    pub task_id: String,
    /// 复检超时（毫秒）
    pub timeout_ms: Option<u64>,
    /// 并发数
    pub concurrency: Option<usize>,
}

/// 弱密码复检（POST /api/v1/scan/weak-password-recheck）
///
/// 6.7 弱密码复检 API：
/// 加载之前爆破任务的成功凭证，逐一重新登录验证，
/// 返回仍可登录（未修复）和已修复的凭证列表。
pub async fn weak_password_recheck(
    data: web::Data<AppState>,
    body: web::Json<WeakPasswordRecheckRequest>,
) -> impl Responder {
    // 从 scan_results 表加载原始爆破任务的成功结果
    let prev_results: Vec<scan_result::Model> = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(body.task_id.clone()))
        .filter(scan_result::Column::ResultType.eq(ResultType::Bruteforce))
        .filter(scan_result::Column::Success.eq(true))
        .all(&data.db)
        .await
        .unwrap_or_default();

    if prev_results.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "task_id": body.task_id,
            "total": 0,
            "still_vulnerable": 0,
            "fixed": 0,
            "results": [],
            "message": "没有找到成功的弱密码记录"
        }));
    }

    // 构造 BruteForceResult 用于复检
    let bf_results: Vec<argus_bruteforce::types::BruteForceResult> = prev_results
        .iter()
        .filter_map(|r| {
            let protocol = argus_bruteforce::types::Protocol::from_str(
                r.protocol.as_deref().unwrap_or("ssh")
            )?;
            Some(argus_bruteforce::types::BruteForceResult {
                host: r.host.clone(),
                port: r.port.unwrap_or(22) as u16,
                protocol,
                credential: argus_bruteforce::types::Credential {
                    username: r.username.clone().unwrap_or_default(),
                    password: r.password.clone().unwrap_or_default(),
                },
                success: true,
                response_time_ms: 0,
                error: None,
            })
        })
        .collect();

    let timeout_ms = body.timeout_ms.unwrap_or(5000);
    let concurrency = body.concurrency.unwrap_or(50);

    let bf = argus_bruteforce::BruteForce::new();
    let (recheck_results, unfixed_count) = bf.recheck_weak_passwords(&bf_results, timeout_ms, concurrency).await;

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": body.task_id,
        "total": bf_results.len(),
        "still_vulnerable": unfixed_count,
        "fixed": recheck_results.iter().filter(|r| r.fixed).count(),
        "results": recheck_results
    }))
}

// ==================== 基线核查 ====================

/// 基线核查请求
#[derive(Debug, Deserialize)]
pub struct BaselineScanRequest {
    pub host: String,
    pub method: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub rule_set: Option<String>,
    pub timeout_ms: Option<u64>,
    /// 离线采集数据（method=offline 时必填）
    pub offline_data: Option<serde_json::Value>,
    /// 采集项逐条选择（6.6 采集项选择）
    ///
    /// 指定后仅检查列出的规则 ID（如 ["linux.password_policy", "linux.ssh_config"]）。
    /// 未指定或为空时检查 rule_set 下的所有规则。
    pub rule_ids: Option<Vec<String>>,
}

/// 执行基线核查（POST /api/v1/scan/baseline）
/// 异步：立即返回 task_id，后台执行采集 + 规则判定
pub async fn scan_baseline(
    data: web::Data<AppState>,
    body: web::Json<BaselineScanRequest>,
) -> impl Responder {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let targets = vec![Target {
        host: body.host.clone(),
        ports: None,
        credentials: Some(argus_scanner::Credentials {
            username: body.username.clone().unwrap_or_default(),
            password: body.password.clone().unwrap_or_default(),
            auth_type: None,
        }),
    }];

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("baseline-{}", &task_id[..8])),
        task_type: Set(TaskType::BaselineCheck),
        status: Set(TaskStatus::Running),
        launch_mode: Set(argus_core::entity::task::LaunchMode::Manual),
        targets: Set(serde_json::json!([body.host])),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(None),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        tracing::error!("创建基线核查任务失败: {e}");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("创建任务失败: {e}")
        }));
    }

    let params = serde_json::json!({
        "host": body.host,
        "method": body.method.clone().unwrap_or_else(|| "ssh".to_string()),
        "port": body.port,
        "username": body.username,
        "password": body.password,
        "rule_set": body.rule_set.clone().unwrap_or_else(|| "gbt22239_l3_linux".to_string()),
        "timeout_ms": body.timeout_ms.unwrap_or(10000),
        "offline_data": body.offline_data,
        "rule_ids": body.rule_ids,
    });

    let scan_config = ScanConfig {
        task_id: task_id.clone(),
        targets,
        concurrency: 1,
        timeout_secs: body.timeout_ms.unwrap_or(10000) / 1000,
        extra_params: params,
    };

    let scanner = match data.registry.get("baseline_scanner") {
        Some(s) => s,
        None => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Failed).await;
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "基线核查引擎未注册"
            }));
        }
    };

    let db = data.db.clone();
    let task_id_bg = task_id.clone();

    tokio::spawn(async move {
        tracing::info!("基线核查任务 {} 后台执行中", task_id_bg);

        let result = match scanner.execute(&scan_config).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("基线核查执行失败: {e}");
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                return;
            }
        };

        // 从 raw_data 提取基线报告并持久化
        if let Some(raw) = &result.raw_data {
            if let Ok(report) = serde_json::from_value::<argus_baseline::BaselineReport>(raw.clone()) {
                if let Err(e) = save_baseline_results(&db, &task_id_bg, &report).await {
                    tracing::error!("保存基线核查结果失败: {e}");
                }
            }
        }

        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
        tracing::info!("基线核查任务 {} 完成", task_id_bg);
    });

    HttpResponse::Accepted().json(TaskAccepted {
        task_id,
        status: "running".to_string(),
        message: "基线核查任务已提交，使用 GET /api/v1/scan/status/{task_id} 查询进度".to_string(),
    })
}

/// 保存基线核查结果到数据库
async fn save_baseline_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    report: &argus_baseline::BaselineReport,
) -> Result<(), sea_orm::DbErr> {
    use argus_baseline::ComplianceLevel;

    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = report
        .results
        .iter()
        .map(|r| scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set(task_id.to_string()),
            result_type: Set(ResultType::BaselineCheck),
            host: Set(report.host.clone()),
            port: Set(None),
            protocol: Set(None),
            state: Set(Some(r.compliance.as_str().to_string())),
            service: Set(Some(r.category.clone())),
            banner: Set(r.collected_output.clone()),
            username: Set(None),
            password: Set(None),
            success: Set(Some(r.compliance == ComplianceLevel::Compliant)),
            response_time_ms: Set(None),
            raw_data: Set(Some(serde_json::to_value(r).unwrap_or_default())),
            created_at: Set(now),
        })
        .collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

// ==================== 任务状态与控制 ====================

/// 任务状态响应
#[derive(Debug, Serialize)]
pub struct TaskStatusResponse {
    pub task_id: String,
    pub status: String,
    pub task_type: String,
    pub progress: f32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub result_count: u64,
    pub open_port_count: u64,
    pub success_count: u64,
}

/// 查询扫描任务状态（GET /api/v1/scan/status/{task_id}）
pub async fn get_scan_status(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();

    let task = match ScanTaskEntity::find_by_id(task_id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("任务不存在: {task_id}")
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("查询失败: {e}")
            }));
        }
    };

    // 统计结果数
    let result_count = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .count(&data.db)
        .await
        .unwrap_or(0);

    let open_port_count = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .filter(scan_result::Column::State.eq("open"))
        .count(&data.db)
        .await
        .unwrap_or(0);

    let success_count = ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .filter(scan_result::Column::Success.eq(true))
        .count(&data.db)
        .await
        .unwrap_or(0);

    HttpResponse::Ok().json(TaskStatusResponse {
        task_id: task.id.clone(),
        status: format!("{:?}", task.status).to_lowercase(),
        task_type: format!("{:?}", task.task_type).to_lowercase(),
        progress: task.progress,
        created_at: task.created_at.to_rfc3339(),
        started_at: task.started_at.map(|t| t.to_rfc3339()),
        finished_at: task.finished_at.map(|t| t.to_rfc3339()),
        result_count,
        open_port_count,
        success_count,
    })
}

/// 取消扫描任务（POST /api/v1/scan/cancel/{task_id}）
pub async fn cancel_scan(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();

    // 查询任务
    let task = match ScanTaskEntity::find_by_id(task_id.clone()).one(&data.db).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("任务不存在: {task_id}")
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("查询失败: {e}")
            }));
        }
    };

    // 检查是否正在运行
    if task.status != TaskStatus::Running {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("任务不在运行中，当前状态: {:?}", task.status)
        }));
    }

    // 尝试取消扫描引擎中的任务（忽略错误，引擎可能未注册或任务已结束）
    let scanner_name = match task.task_type {
        TaskType::PortScan => "port_scanner",
        TaskType::Bruteforce => "brute_force",
        TaskType::BaselineCheck => "baseline_scanner",
        _ => {
            let _ = update_task_status(&data.db, &task_id, TaskStatus::Stopped).await;
            return HttpResponse::Ok().json(serde_json::json!({
                "task_id": task_id,
                "status": "stopped",
                "message": "任务已取消"
            }));
        }
    };

    if let Some(scanner) = data.registry.get(scanner_name) {
        let _ = scanner.cancel(&task_id).await;
    }

    // 更新任务状态为 Stopped
    let _ = update_task_status(&data.db, &task_id, TaskStatus::Stopped).await;

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "status": "stopped",
        "message": "任务已取消"
    }))
}

// ==================== 扫描结果查询 ====================

/// 查询任务的扫描结果（GET /api/v1/scan/results/{task_id}）
pub async fn get_scan_results(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();

    let results = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .order_by_asc(scan_result::Column::Port)
        .all(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("查询结果失败: {e}")
            }));
        }
    };

    let total = results.len();
    let open_count = results.iter().filter(|r| r.state.as_deref() == Some("open")).count();
    let success_count = results.iter().filter(|r| r.success == Some(true)).count();

    HttpResponse::Ok().json(serde_json::json!({
        "task_id": task_id,
        "total": total,
        "open_ports": open_count,
        "success_count": success_count,
        "results": results,
    }))
}

// ==================== 基线核查汇总报告 ====================

/// 查询基线核查汇总报告（GET /api/v1/scan/baseline/report/{task_id}）
///
/// 从 scan_results 中 result_type=BaselineCheck 的记录重建汇总报告，
/// 包含合规率、分类统计、不合规项修复建议等。
/// 注：rule_set 名称未逐条持久化，重建时无法还原，留空返回。
pub async fn get_baseline_report(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let task_id = path.into_inner();

    // 查询该任务的所有基线核查结果（按时间正序）
    let records = match ScanResultEntity::find()
        .filter(scan_result::Column::TaskId.eq(task_id.clone()))
        .filter(scan_result::Column::ResultType.eq(ResultType::BaselineCheck))
        .order_by_asc(scan_result::Column::CreatedAt)
        .all(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("查询基线结果失败: {e}")
            }));
        }
    };

    if records.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("任务 {task_id} 无基线核查结果")
        }));
    }

    // 从 raw_data 重建 CheckResult 列表
    let check_results: Vec<argus_baseline::CheckResult> = records
        .iter()
        .filter_map(|r| {
            r.raw_data
                .as_ref()
                .and_then(|raw| serde_json::from_value::<argus_baseline::CheckResult>(raw.clone()).ok())
        })
        .collect();

    let host = records.first().map(|r| r.host.clone()).unwrap_or_default();
    let timestamp = records
        .first()
        .map(|r| r.created_at)
        .unwrap_or_else(chrono::Utc::now);

    // 重建汇总报告（直接构造结构体以保留原始时间戳）
    let summary = argus_baseline::BaselineSummary::from_results(&check_results);
    let report = argus_baseline::BaselineReport {
        host,
        rule_set: String::new(), // rule_set 未逐条持久化，无法还原
        timestamp,
        summary,
        results: check_results,
    };

    HttpResponse::Ok().json(report)
}

/// 更新任务状态
async fn update_task_status(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    status: TaskStatus,
) -> Result<(), sea_orm::DbErr> {
    let task = ScanTaskEntity::find_by_id(task_id.to_string()).one(db).await?;
    if let Some(t) = task {
        let mut active: task::ActiveModel = t.into();
        let is_finished = matches!(status, TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Stopped);
        active.status = Set(status);
        if is_finished {
            active.finished_at = Set(Some(chrono::Utc::now()));
        }
        active.update(db).await?;
    }
    Ok(())
}

// ==================== 登录主机扫描 ====================

/// 登录扫描请求
#[derive(Debug, Deserialize)]
pub struct LoginScanRequest {
    /// 凭证 ID 列表（优先使用）
    pub credential_ids: Option<Vec<String>>,
    /// 资产类型: system / database / application
    pub asset_type: Option<String>,
    /// 资产 ID（与 asset_type 配合使用，根据资产 IP 匹配凭证）
    pub asset_id: Option<String>,
    /// 超时（毫秒），默认 5000
    pub timeout_ms: Option<u64>,
}

/// 登录主机扫描 POST /api/v1/scan/login
///
/// 支持两种模式：
/// 1. 指定 credential_ids，对这些凭证执行登录验证
/// 2. 指定 asset_type + asset_id，根据资产 IP 匹配凭证并验证
/// 验证结果会更新凭证的 auth_result 和数据库资产的 login_verified 字段。
pub async fn scan_login(
    data: web::Data<AppState>,
    body: web::Json<LoginScanRequest>,
) -> impl Responder {
    // 收集需要验证的凭证列表
    let credentials = if let Some(ids) = &body.credential_ids {
        if ids.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "credential_ids 不能为空"}));
        }
        match CredentialEntity::find()
            .filter(credential::Column::Id.is_in(ids.clone()))
            .all(&data.db)
            .await
        {
            Ok(c) => c,
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
        }
    } else if let (Some(asset_type), Some(asset_id)) = (&body.asset_type, &body.asset_id) {
        // 根据资产类型查找资产 IP
        let asset_ip = match asset_type.as_str() {
            "system" => {
                use argus_core::entity::network_asset::Entity as NetEntity;
                match NetEntity::find_by_id(asset_id.clone()).one(&data.db).await {
                    Ok(Some(a)) => Some(a.ip),
                    _ => None,
                }
            }
            "database" => {
                use argus_core::entity::database_asset::Entity as DbEntity;
                match DbEntity::find_by_id(asset_id.clone()).one(&data.db).await {
                    Ok(Some(a)) => Some(a.ip),
                    _ => None,
                }
            }
            "application" => {
                use argus_core::entity::application_asset::Entity as AppEntity;
                match AppEntity::find_by_id(asset_id.clone()).one(&data.db).await {
                    Ok(Some(a)) => a.ip,
                    _ => None,
                }
            }
            _ => None,
        };

        match asset_ip {
            Some(ip) => {
                match CredentialEntity::find()
                    .filter(credential::Column::Ip.eq(ip))
                    .all(&data.db)
                    .await
                {
                    Ok(c) => c,
                    Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
                }
            }
            None => return HttpResponse::NotFound().json(serde_json::json!({"error": "资产未找到或无 IP"})),
        }
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "请提供 credential_ids 或 asset_type + asset_id"
        }));
    };

    if credentials.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "未找到匹配的凭证"}));
    }

    let db = data.db.clone();
    let asset_type = body.asset_type.clone();
    let asset_id = body.asset_id.clone();

    // 执行登录验证（顺序执行，避免并发连接问题）
    let mut results: Vec<serde_json::Value> = Vec::with_capacity(credentials.len());
    for cred in &credentials {
        let (success, message) = crate::handler::credential::verify_with_protocol(cred).await;
        // 更新凭证认证结果
        let mut active: credential::ActiveModel = cred.clone().into();
        active.auth_result = Set(Some(if success { AuthResult::Success } else { AuthResult::Failed }));
        active.last_auth_at = Set(Some(chrono::Utc::now()));
        let _ = active.update(&db).await;
        results.push(serde_json::json!({
            "credential_id": cred.id,
            "ip": cred.ip,
            "protocol": cred.protocol,
            "port": cred.port,
            "username": cred.username,
            "success": success,
            "message": message,
        }));
    }

    let success_count = results.iter().filter(|r| r["success"].as_bool().unwrap_or(false)).count();

    // 如果是数据库资产，更新 login_verified 状态
    if asset_type.as_deref() == Some("database") {
        if let Some(id) = &asset_id {
            use argus_core::entity::database_asset::Entity as DbEntity;
            if let Ok(Some(db_asset)) = DbEntity::find_by_id(id.clone()).one(&data.db).await {
                let mut active: argus_core::entity::database_asset::ActiveModel = db_asset.into();
                active.login_verified = Set(success_count > 0);
                let _ = active.update(&data.db).await;
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "total": results.len(),
        "success_count": success_count,
        "failed_count": results.len() - success_count,
        "results": results,
    }))
}

/// 下载离线采集脚本模板 GET /api/v1/scan/baseline/offline-script
///
/// 返回一个 Shell 脚本，用户在目标主机上运行后会生成符合离线核查格式的 JSON 文件。
/// 脚本按规则集的采集项执行命令，并将 {item_id: output} 写入 result.json。
pub async fn baseline_offline_script() -> impl Responder {
    let script = r#"#!/bin/bash
# Argus 基线离线采集脚本
# 用法: bash collect_offline.sh
# 执行后会在当前目录生成 baseline_offline_result.json
# 将该文件内容作为 offline_data 传入 POST /api/v1/scan/baseline (method=offline)

OUTPUT="baseline_offline_result.json"
echo "{" > "$OUTPUT"
FIRST=1

run_item() {
    local item_id="$1"
    local cmd="$2"
    local output
    output=$(eval "$cmd" 2>/dev/null)
    # JSON 转义
    output=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')
    if [ $FIRST -eq 1 ]; then
        FIRST=0
    else
        echo "," >> "$OUTPUT"
    fi
    echo "  \"$item_id\": $output" >> "$OUTPUT"
}

# ==== 以下按规则集采集项填写 ====
# 示例（gbt22239_l3_linux）：
run_item "os_version" "cat /etc/os-release 2>/dev/null | head -5"
run_item "ssh_config" "grep -E '^(PermitRootLogin|PasswordAuthentication|Protocol)' /etc/ssh/sshd_config 2>/dev/null"
run_item "password_policy" "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN)' /etc/login.defs 2>/dev/null"
run_item "fail_lock" "grep -E '^(deny|unlock_time)' /etc/security/faillock.conf 2>/dev/null || grep pam_faillock /etc/pam.d/system-auth 2>/dev/null"
run_item "auditd_status" "systemctl is-active auditd 2>/dev/null; auditctl -s 2>/dev/null | head -3"
run_item "firewall_status" "systemctl is-active firewalld 2>/dev/null || iptables -L -n 2>/dev/null | head -5"
# ==== 采集项结束 ====

echo "" >> "$OUTPUT"
echo "}" >> "$OUTPUT"
echo "离线采集完成，结果已写入 $OUTPUT"
echo "请将该文件内容作为 offline_data 调用基线核查接口。"
"#;

    HttpResponse::Ok()
        .content_type("text/x-shellscript; charset=utf-8")
        .insert_header(("Content-Disposition", "attachment; filename=\"collect_offline.sh\""))
        .body(script)
}

// ==================== 离线 Hash 爆破 ====================

/// 离线 Hash 爆破请求
#[derive(Debug, Deserialize)]
pub struct HashCrackRequest {
    /// Hash 列表
    pub hashes: Vec<String>,
    /// 自定义字典（可选）
    pub dict: Option<Vec<String>>,
    /// 是否使用内置字典（默认 true）
    pub use_builtin_dict: Option<bool>,
    /// 内置字典类型: top10 / top50 / top100（默认 top100）
    pub builtin_dict: Option<String>,
}

/// 离线 Hash 爆破 POST /api/v1/scan/hash-crack
///
/// 支持 MD5/SHA1/SHA256/SHA512，自动识别 Hash 类型。
/// 可使用自定义字典或内置弱密码字典。
pub async fn scan_hash_crack(body: web::Json<HashCrackRequest>) -> impl Responder {
    if body.hashes.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "hashes 不能为空"}));
    }

    // 构建字典
    let mut dict: Vec<String> = Vec::new();

    // 自定义字典
    if let Some(custom) = &body.dict {
        dict.extend(custom.iter().cloned());
    }

    // 内置字典
    if body.use_builtin_dict.unwrap_or(true) {
        let builtin = body.builtin_dict.as_deref().unwrap_or("top100");
        let builtin_words = match builtin {
            "top10" => argus_bruteforce::dictionary::top10_passwords(),
            "top50" => argus_bruteforce::dictionary::top50_passwords(),
            _ => argus_bruteforce::dictionary::top100_passwords(),
        };
        dict.extend(builtin_words);
    }

    if dict.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "字典为空，请提供自定义字典或启用内置字典"}));
    }

    // 执行爆破
    let results = argus_bruteforce::hash_crack::crack_batch(&body.hashes, &dict);

    let cracked_count = results.iter().filter(|r| r.cracked).count();

    HttpResponse::Ok().json(serde_json::json!({
        "total": results.len(),
        "cracked_count": cracked_count,
        "dict_size": dict.len(),
        "results": results.iter().map(|r| serde_json::json!({
            "hash": r.hash,
            "hash_type": r.hash_type,
            "cracked": r.cracked,
            "plaintext": r.plaintext,
        })).collect::<Vec<_>>(),
    }))
}

// ==================== 统一扫描入口 ====================

/// 统一扫描请求
#[derive(Debug, Deserialize)]
pub struct UnifiedScanRequest {
    /// 扫描类型: system / application / database / mobile / vuln_verify
    pub scan_type: String,
    /// 扫描目标列表（IP、域名、URL 等）— 当 target_type=ip 或未指定 config 时使用
    #[serde(default)]
    pub targets: Option<Vec<String>>,
    /// 端口列表（可选，覆盖 config.port.custom_ports）
    pub ports: Option<Vec<u16>>,
    /// 并发数
    pub concurrency: Option<usize>,
    /// 超时（毫秒）
    pub timeout_ms: Option<u64>,
    /// 扩展参数（自由 JSON，向后兼容；最终与 config 解析结果合并）
    pub params: Option<serde_json::Value>,
    /// 参数模板 ID（可选，引用 param_templates 表；解析后 inline config 覆盖同名字段）
    pub param_template_id: Option<String>,
    /// 内联参数配置（可选，覆盖模板同名字段）
    #[serde(default)]
    pub config: Option<ScanParamConfig>,
    /// 顶层快捷字段：资产组 ID（等价于 config.target.target_type=asset_group + config.target.asset_group_id）
    pub asset_group_id: Option<String>,
    /// 顶层快捷字段：凭证 ID 列表（等价于 config.auth.login_scan=true + config.auth.credential_ids）
    pub credential_ids: Option<Vec<String>>,
}

// ==================== 统一扫描辅助函数 ====================

/// 从 param_templates 表加载配置并解析为 ScanParamConfig
///
/// 失败（不存在/JSON 不符合 schema）返回 None，调用方降级使用 inline config。
async fn load_param_template_config(
    db: &sea_orm::DatabaseConnection,
    template_id: &str,
) -> Option<ScanParamConfig> {
    use argus_core::entity::param_template::{self, Entity as ParamTemplateEntity};
    let model = ParamTemplateEntity::find_by_id(template_id.to_string())
        .one(db)
        .await
        .ok()
        .flatten()?;
    serde_json::from_value::<ScanParamConfig>(model.config).ok()
}

/// 合并两个 ScanParamConfig：inline 覆盖 template 同名字段
fn merge_config(inline: Option<ScanParamConfig>, from_template: Option<ScanParamConfig>) -> ScanParamConfig {
    let mut result = from_template.unwrap_or_default();
    if let Some(inline) = inline {
        // target
        if inline.target.target_type.is_some() {
            result.target.target_type = inline.target.target_type;
        }
        if inline.target.ip_range.is_some() {
            result.target.ip_range = inline.target.ip_range;
        }
        if inline.target.asset_group_id.is_some() {
            result.target.asset_group_id = inline.target.asset_group_id;
        }
        if inline.target.exclude_hosts.is_some() {
            result.target.exclude_hosts = inline.target.exclude_hosts;
        }
        // port
        if inline.port.template.is_some() {
            result.port.template = inline.port.template;
        }
        if inline.port.custom_ports.is_some() {
            result.port.custom_ports = inline.port.custom_ports;
        }
        if inline.port.scan_mode.is_some() {
            result.port.scan_mode = inline.port.scan_mode;
        }
        if inline.port.speed.is_some() {
            result.port.speed = inline.port.speed;
        }
        // performance
        if inline.performance.concurrency.is_some() {
            result.performance.concurrency = inline.performance.concurrency;
        }
        if inline.performance.timeout_ms.is_some() {
            result.performance.timeout_ms = inline.performance.timeout_ms;
        }
        if inline.performance.retries.is_some() {
            result.performance.retries = inline.performance.retries;
        }
        if inline.performance.rate_limit.is_some() {
            result.performance.rate_limit = inline.performance.rate_limit;
        }
        // plugins
        if inline.plugins.vuln_scan.is_some() {
            result.plugins.vuln_scan = inline.plugins.vuln_scan;
        }
        if inline.plugins.port_scan.is_some() {
            result.plugins.port_scan = inline.plugins.port_scan;
        }
        if inline.plugins.weak_password.is_some() {
            result.plugins.weak_password = inline.plugins.weak_password;
        }
        if inline.plugins.baseline_check.is_some() {
            result.plugins.baseline_check = inline.plugins.baseline_check;
        }
        if inline.plugins.service_ident.is_some() {
            result.plugins.service_ident = inline.plugins.service_ident;
        }
        if inline.plugins.fingerprint.is_some() {
            result.plugins.fingerprint = inline.plugins.fingerprint;
        }
        if inline.plugins.vuln_verify.is_some() {
            result.plugins.vuln_verify = inline.plugins.vuln_verify;
        }
        // auth
        if inline.auth.login_scan.is_some() {
            result.auth.login_scan = inline.auth.login_scan;
        }
        if inline.auth.credential_ids.is_some() {
            result.auth.credential_ids = inline.auth.credential_ids;
        }
        // advanced
        if inline.advanced.skip_host_discovery.is_some() {
            result.advanced.skip_host_discovery = inline.advanced.skip_host_discovery;
        }
        if inline.advanced.reverse_dns.is_some() {
            result.advanced.reverse_dns = inline.advanced.reverse_dns;
        }
        if inline.advanced.ics_protocols.is_some() {
            result.advanced.ics_protocols = inline.advanced.ics_protocols;
        }
        if inline.advanced.capture.is_some() {
            result.advanced.capture = inline.advanced.capture;
        }
        if inline.advanced.auto_report.is_some() {
            result.advanced.auto_report = inline.advanced.auto_report;
        }
    }
    result
}

/// 展开 CIDR (a.b.c.d/n) 为 IP 列表，限制最多 65536 个避免爆内存
fn expand_cidr_to_hosts(cidr: &str) -> Vec<String> {
    let cidr = cidr.trim();
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        // 无前缀长度，按单 IP 处理
        return vec![cidr.to_string()];
    }
    let ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return vec![cidr.to_string()],
    };
    let prefix: u32 = match parts[1].parse() {
        Ok(n) if n <= 32 => n,
        Ok(_) | Err(_) => return vec![cidr.to_string()],
    };
    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 { 0u32 } else { (!0u32) << (32 - prefix) };
    let network = ip_u32 & mask;
    let broadcast = if prefix == 32 {
        network
    } else if prefix == 0 {
        !0u32
    } else {
        network | !mask
    };
    // 限制：/16 以下展开（最多 65536），更宽网段直接返回网络地址避免爆内存
    if prefix < 16 {
        return vec![Ipv4Addr::from(network).to_string()];
    }
    let mut hosts = Vec::new();
    let mut cur = network;
    while cur <= broadcast {
        hosts.push(Ipv4Addr::from(cur).to_string());
        if cur == broadcast {
            break;
        }
        cur = cur.wrapping_add(1);
    }
    hosts
}

/// 解析扫描目标 IP 列表
///
/// 优先级：
/// 1. 如果 body.targets 非空，直接用（IP 模式）
/// 2. 如果 asset_group_id 顶层字段提供，查询 asset_group + 关联 network_asset
/// 3. 如果 config.target.target_type=asset_group，使用 config.target.asset_group_id
/// 4. 如果 config.target.ip_range 提供，展开 CIDR
async fn resolve_scan_targets(
    db: &sea_orm::DatabaseConnection,
    config: &ScanParamConfig,
    body_targets: &Option<Vec<String>>,
    top_asset_group_id: &Option<String>,
) -> Result<Vec<String>, String> {
    // 1. body.targets 优先
    if let Some(targets) = body_targets {
        if !targets.is_empty() {
            return Ok(targets.clone());
        }
    }
    // 2. 顶层 asset_group_id 快捷字段
    if let Some(gid) = top_asset_group_id {
        return load_asset_group_targets(db, gid).await;
    }
    // 3. config.target.target_type
    match config.target.target_type.as_deref() {
        Some("asset_group") => {
            let gid = config.target.asset_group_id.as_ref()
                .ok_or_else(|| "target_type=asset_group 但未提供 asset_group_id".to_string())?;
            load_asset_group_targets(db, gid).await
        }
        Some("ip") | None | Some("") => {
            // 4. config.target.ip_range
            if let Some(ip_range) = &config.target.ip_range {
                let mut all = Vec::new();
                for part in ip_range.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    all.extend(expand_cidr_to_hosts(part));
                }
                if all.is_empty() {
                    return Err("未提供扫描目标：targets 为空且 config.target.ip_range 为空".to_string());
                }
                Ok(all)
            } else {
                Err("未提供扫描目标：targets 为空、无 asset_group_id、无 config.target.ip_range".to_string())
            }
        }
        Some(other) => Err(format!("不支持的 target_type: {other}（合法: ip/asset_group/asset_attribute）")),
    }
}

/// 加载资产组内所有网络资产 IP
async fn load_asset_group_targets(
    db: &sea_orm::DatabaseConnection,
    group_id: &str,
) -> Result<Vec<String>, String> {
    // 先查 asset_group 是否存在，尝试 ip_range 展开
    let group = AssetGroupEntity::find_by_id(group_id.to_string())
        .one(db)
        .await
        .map_err(|e| format!("查询资产组失败: {e}"))?
        .ok_or_else(|| format!("资产组 {group_id} 不存在"))?;

    let mut hosts: Vec<String> = Vec::new();

    // 优先用组内 network_asset.ip（精确资产）
    let assets = NetworkAssetEntity::find()
        .filter(network_asset::Column::AssetGroupId.eq(group_id.to_string()))
        .all(db)
        .await
        .map_err(|e| format!("查询资产组内资产失败: {e}"))?;

    for a in &assets {
        if !a.ip.is_empty() {
            hosts.push(a.ip.clone());
        }
    }

    // 若组内无资产，尝试展开 asset_group.ip_range
    if hosts.is_empty() {
        if let Some(ip_range) = &group.ip_range {
            for part in ip_range.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                hosts.extend(expand_cidr_to_hosts(part));
            }
        }
    }

    if hosts.is_empty() {
        return Err(format!("资产组 {group_id} 内无可用资产"));
    }
    Ok(hosts)
}

/// 解析端口列表
///
/// 优先级：body.ports > config.port.template > config.port.custom_ports
fn resolve_port_list(
    config: &ScanParamConfig,
    body_ports: &Option<Vec<u16>>,
) -> Option<Vec<u16>> {
    if let Some(p) = body_ports {
        return Some(p.clone());
    }
    use argus_portscanner::port_list::{top100_tcp_ports, top1000_tcp_ports, parse_port_range};
    match config.port.template.as_deref() {
        Some("top100") => Some(top100_tcp_ports()),
        Some("top1000") => Some(top1000_tcp_ports()),
        Some("full") => Some((1..=65535).collect()),
        Some("custom") => {
            config.port.custom_ports.as_ref()
                .and_then(|s| parse_port_range(s).ok())
        }
        Some(other) => {
            tracing::warn!("未知端口模板 '{other}'，回退到 custom_ports");
            config.port.custom_ports.as_ref()
                .and_then(|s| parse_port_range(s).ok())
        }
        None => config.port.custom_ports.as_ref().and_then(|s| parse_port_range(s).ok()),
    }
}

/// 加载凭证并按 IP 绑定到 targets
///
/// 给定 targets 和 credential_ids，从 credentials 表查询凭证，
/// 按 ip 字段匹配 target.host（同一主机可能有多组凭证，取首个）。
async fn resolve_targets_with_credentials(
    db: &sea_orm::DatabaseConnection,
    hosts: Vec<String>,
    credential_ids: &[String],
) -> Result<Vec<Target>, String> {
    if credential_ids.is_empty() {
        return Ok(hosts.into_iter().map(|h| Target {
            host: h,
            ports: None,
            credentials: None,
        }).collect());
    }

    // 查询指定凭证
    let creds = CredentialEntity::find()
        .filter(credential::Column::Id.is_in(credential_ids.iter().cloned().collect::<Vec<_>>()))
        .all(db)
        .await
        .map_err(|e| format!("查询凭证失败: {e}"))?;

    // 按 IP 建立索引（同 IP 多组凭证取首个）
    use std::collections::HashMap;
    let mut by_host: HashMap<String, Credentials> = HashMap::new();
    for c in &creds {
        let username = c.username.clone().unwrap_or_default();
        // 凭证密码字段在 entity 是明文（迁移时已加密存储，读取时自动解密由 handler 负责）
        let password = c.password.clone().unwrap_or_default();
        by_host.entry(c.ip.clone()).or_insert(Credentials {
            username,
            password,
            auth_type: Some(format!("{:?}", c.auth_type).to_lowercase()),
        });
    }

    // 给每个 target 绑定凭证（凭证 IP 与 target.host 精确匹配）
    let targets = hosts.into_iter().map(|h| {
        let creds = by_host.get(&h).cloned();
        Target {
            host: h,
            ports: None,
            credentials: creds,
        }
    }).collect();
    Ok(targets)
}

/// 把 ScanParamConfig 解析结果合并到 extra_params（自由 JSON）
///
/// 策略：body.params（自由 JSON）为基础，再覆盖 config 中结构化字段的解析值。
fn merge_config_into_params(
    config: &ScanParamConfig,
    body_params: Option<serde_json::Value>,
    resolved_ports: &Option<Vec<u16>>,
) -> serde_json::Value {
    let mut params = body_params.unwrap_or(serde_json::json!({}));
    if let Some(map) = params.as_object_mut() {
        // 端口扫描
        if let Some(ports) = resolved_ports {
            map.insert("ports".to_string(), serde_json::to_value(ports).unwrap_or_default());
        }
        if let Some(v) = &config.port.scan_mode {
            map.insert("tcp_scan_type".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = &config.port.speed {
            map.insert("speed".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        // 性能
        if let Some(v) = config.performance.concurrency {
            map.insert("concurrency".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = config.performance.timeout_ms {
            map.insert("timeout_ms".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = config.performance.retries {
            map.insert("retries".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = config.performance.rate_limit {
            map.insert("rate_limit".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        // 插件开关
        let plugins = serde_json::json!({
            "vuln_scan": config.plugins.vuln_scan,
            "port_scan": config.plugins.port_scan,
            "weak_password": config.plugins.weak_password,
            "baseline_check": config.plugins.baseline_check,
            "service_ident": config.plugins.service_ident,
            "fingerprint": config.plugins.fingerprint,
            "vuln_verify": config.plugins.vuln_verify,
        });
        map.insert("plugins".to_string(), plugins);
        // 认证
        map.insert("login_scan".to_string(), serde_json::to_value(config.auth.login_scan).unwrap_or_default());
        if let Some(ids) = &config.auth.credential_ids {
            map.insert("credential_ids".to_string(), serde_json::to_value(ids).unwrap_or_default());
        }
        // 高级
        if let Some(v) = config.advanced.skip_host_discovery {
            map.insert("skip_host_discovery".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = config.advanced.reverse_dns {
            map.insert("reverse_dns".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(list) = &config.advanced.ics_protocols {
            map.insert("ics_protocols".to_string(), serde_json::to_value(list).unwrap_or_default());
        }
        if let Some(v) = config.advanced.capture {
            map.insert("capture".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        if let Some(v) = config.advanced.auto_report {
            map.insert("auto_report".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
        // 排除主机
        if let Some(v) = &config.target.exclude_hosts {
            map.insert("exclude_hosts".to_string(), serde_json::to_value(v).unwrap_or_default());
        }
    }
    params
}

// ==================== 统一扫描入口 ====================

/// 统一扫描入口 POST /api/v1/scans
///
/// 根据 scan_type 分发到对应扫描器：
/// - system: 系统漏洞扫描
/// - application: 应用漏洞扫描
/// - database: 数据库漏洞扫描
/// - mobile: 移动应用扫描
/// - vuln_verify: 漏洞验证扫描
///
/// 支持：
/// - 参数模板引用（param_template_id）+ inline config 覆盖
/// - 目标选择（IP/资产组）
/// - 端口模板（top100/top1000/full/custom）
/// - 扫描模式（connect/syn/ack/null/xmas/fin/window）
/// - 插件开关（vuln_scan/port_scan/weak_password/baseline_check/...）
/// - 认证配置（绑定凭证执行登录扫描）
pub async fn create_unified_scan(
    data: web::Data<AppState>,
    body: web::Json<UnifiedScanRequest>,
) -> impl Responder {
    use argus_core::entity::task::LaunchMode;

    let scan_type = body.scan_type.clone();
    let task_type = match scan_type.as_str() {
        "system" => TaskType::SystemScan,
        "application" => TaskType::AppScan,
        "database" => TaskType::DbScan,
        "mobile" => TaskType::MobileScan,
        "vuln_verify" => TaskType::VulnVerify,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("不支持的扫描类型: {scan_type}，支持: system/application/database/mobile/vuln_verify")
        })),
    };

    // ---- 1. 解析 ScanParamConfig（模板 + inline 合并）----
    let template_config = match &body.param_template_id {
        Some(id) => load_param_template_config(&data.db, id).await,
        None => None,
    };
    let merged_config = merge_config(body.config.clone(), template_config);

    // 应用顶层快捷字段到 merged_config（覆盖 config.target.target_type / asset_group_id）
    let mut merged_config = merged_config;
    if let Some(gid) = &body.asset_group_id {
        merged_config.target.target_type = Some("asset_group".to_string());
        merged_config.target.asset_group_id = Some(gid.clone());
    }
    if let Some(ids) = &body.credential_ids {
        merged_config.auth.login_scan = Some(true);
        merged_config.auth.credential_ids = Some(ids.clone());
    }

    // ---- 2. 解析扫描目标 IP 列表 ----
    let hosts = match resolve_scan_targets(&data.db, &merged_config, &body.targets, &body.asset_group_id).await {
        Ok(h) => h,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("解析扫描目标失败: {e}")
        })),
    };

    if hosts.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "扫描目标列表为空"
        }));
    }

    // ---- 3. 解析端口列表 ----
    let resolved_ports = resolve_port_list(&merged_config, &body.ports);

    // ---- 4. 解析认证配置：加载凭证并绑定到 targets ----
    let credential_ids: Vec<String> = merged_config.auth.credential_ids.clone()
        .unwrap_or_else(|| body.credential_ids.clone().unwrap_or_default());
    let scan_targets = match resolve_targets_with_credentials(&data.db, hosts, &credential_ids).await {
        Ok(t) => t,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("解析凭证失败: {e}")
        })),
    };

    // ---- 5. 合并 ScanParamConfig 字段到 extra_params ----
    let extra_params = merge_config_into_params(&merged_config, body.params.clone(), &resolved_ports);

    // ---- 6. 解析并发/超时（优先 body，回退 config，最终默认）----
    let concurrency = body.concurrency
        .or(merged_config.performance.concurrency.map(|v| v as usize))
        .unwrap_or(10);
    let timeout_ms = body.timeout_ms
        .or(merged_config.performance.timeout_ms)
        .unwrap_or(5000);
    let timeout_secs = timeout_ms / 1000;

    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let target_hosts: Vec<String> = scan_targets.iter().map(|t| t.host.clone()).collect();
    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(format!("{}-scan-{}", scan_type, &task_id[..8])),
        task_type: Set(task_type),
        status: Set(TaskStatus::Running),
        launch_mode: Set(LaunchMode::Manual),
        targets: Set(serde_json::to_value(&target_hosts).unwrap_or_default()),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(Some(extra_params.clone())),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        tracing::error!("创建扫描任务失败: {e}");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("创建任务失败: {e}")
        }));
    }

    // 根据扫描类型分发执行
    let db = data.db.clone();
    let registry = data.registry.clone();
    let scan_type_clone = scan_type.clone();
    let task_id_bg = task_id.clone();

    tokio::spawn(async move {
        let scan_config = ScanConfig {
            task_id: task_id_bg.clone(),
            targets: scan_targets,
            concurrency,
            timeout_secs,
            extra_params,
        };

        // 根据扫描类型选择 registry 中的扫描器
        // P0 #7 修复：scanner_key 与 registry 注册名对齐
        // - system → vulnerability_scanner（CVE/CVSS 主动模板探测 + 被动 CPE 匹配）
        // - application → app_scanner（WebScanner：OWASP Top 10 + 安全头部 + 参数注入）
        // - database → db_scanner（DbScanner：未授权访问 + 默认库 + 危险配置）
        // - mobile → mobile_scanner（MobileScanner：APK 解析 + 组件/配置检测）
        // - vuln_verify → vuln_verify_scanner（VulnVerifyScanner：对指定 CVE 重新执行模板验证）
        let scanner_key = match scan_type_clone.as_str() {
            "system" => "vulnerability_scanner",
            "application" => "app_scanner",
            "database" => "db_scanner",
            "mobile" => "mobile_scanner",
            "vuln_verify" => "vuln_verify_scanner",
            _ => "vulnerability_scanner",
        };

        // 尝试从 registry 获取扫描器，若不存在则标记任务为待执行
        let result_msg = match registry.get(scanner_key) {
            Some(scanner) => {
                match scanner.execute(&scan_config).await {
                    Ok(_) => {
                        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
                        "扫描完成".to_string()
                    }
                    Err(e) => {
                        tracing::error!("{scanner_key} 执行失败: {e}");
                        let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                        format!("扫描失败: {e}")
                    }
                }
            }
            None => {
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Pending).await;
                format!("扫描器 {scanner_key} 未注册，任务已创建待执行")
            }
        };
        tracing::info!("统一扫描任务 {task_id_bg} 结束: {result_msg}");
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "scan_type": scan_type,
        "status": "running",
        "message": format!("{scan_type} 扫描任务已提交，使用 GET /api/v1/scan/status/{task_id} 查询状态")
    }))
}

// ==================== 被动扫描 ====================

/// 被动扫描模式
///
/// 4 种数据源：
/// - proxy: HTTP 代理模式，浏览器流量经代理转发时被动扫描
/// - kafka: Kafka 消费模式，从消息队列拉取 HTTP 事务
/// - pcap: pcap 文件模式，离线解析抓包文件
/// - agent: Agent 采集模式，解析 Nginx/Apache 访问日志
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PassiveScanMode {
    Proxy,
    Kafka,
    Pcap,
    Agent,
}

/// 代理模式配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyScanConfig {
    /// 监听地址，默认 0.0.0.0
    pub listen_addr: Option<String>,
    /// 监听端口，默认 8888
    pub listen_port: Option<u16>,
    /// 采集时长（秒），到达后停止代理并执行扫描
    pub duration_secs: Option<u64>,
}

/// Kafka 模式配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KafkaScanConfig {
    /// Kafka broker 地址列表（逗号分隔）
    pub brokers: String,
    /// Topic 名称
    pub topic: String,
    /// 消费组 ID
    pub group_id: Option<String>,
    /// 最大消费消息数（0 = 不限）
    pub max_messages: Option<usize>,
}

/// pcap 文件模式配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PcapScanConfig {
    /// pcap 文件路径
    pub file_path: String,
}

/// Agent 模式配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentScanConfig {
    /// 访问日志文件路径
    pub log_path: String,
    /// 单批最大事务数，默认 100
    pub batch_size: Option<usize>,
}

/// 被动扫描请求
#[derive(Debug, Deserialize, Serialize)]
pub struct PassiveScanRequest {
    /// 扫描模式
    pub mode: PassiveScanMode,
    /// 任务名称（可选，自动生成）
    pub name: Option<String>,
    /// 代理模式配置（mode=proxy 时必填）
    pub proxy_config: Option<ProxyScanConfig>,
    /// Kafka 模式配置（mode=kafka 时必填）
    pub kafka_config: Option<KafkaScanConfig>,
    /// pcap 模式配置（mode=pcap 时必填）
    pub pcap_config: Option<PcapScanConfig>,
    /// Agent 模式配置（mode=agent 时必填）
    pub agent_config: Option<AgentScanConfig>,
}

/// 创建被动扫描任务（POST /api/v1/scan/passive）
///
/// 根据指定的数据源模式创建被动扫描任务，后台执行：
/// 1. proxy: 启动 HTTP 代理 → 采集指定时长 → 执行 OWASP 被动扫描
/// 2. kafka: 连接 Kafka broker → 消费 HTTP 事务消息 → 执行被动扫描
/// 3. pcap: 读取 pcap 文件 → 解析 TCP 流提取 HTTP 事务 → 执行被动扫描
/// 4. agent: 读取访问日志 → 解析 CLF/Combined 格式为 HTTP 事务 → 执行被动扫描
pub async fn create_passive_scan(
    data: web::Data<AppState>,
    body: web::Json<PassiveScanRequest>,
) -> impl Responder {
    // 校验模式对应配置
    match &body.mode {
        PassiveScanMode::Proxy => {
            if body.proxy_config.is_none() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "代理模式需要 proxy_config"
                }));
            }
        }
        PassiveScanMode::Kafka => {
            if body.kafka_config.is_none() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Kafka 模式需要 kafka_config"
                }));
            }
        }
        PassiveScanMode::Pcap => {
            if body.pcap_config.is_none() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "pcap 模式需要 pcap_config"
                }));
            }
        }
        PassiveScanMode::Agent => {
            if body.agent_config.is_none() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Agent 模式需要 agent_config"
                }));
            }
        }
    }

    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let mode_str = match &body.mode {
        PassiveScanMode::Proxy => "proxy",
        PassiveScanMode::Kafka => "kafka",
        PassiveScanMode::Pcap => "pcap",
        PassiveScanMode::Agent => "agent",
    };
    let task_name = body.name.clone().unwrap_or_else(|| format!("passive-scan-{}-{}", mode_str, &task_id[..8]));

    // 序列化请求参数用于任务记录
    let params = serde_json::to_value(&body.0).unwrap_or_default();

    let new_task = task::ActiveModel {
        id: Set(task_id.clone()),
        name: Set(task_name),
        task_type: Set(TaskType::PassiveScan),
        status: Set(TaskStatus::Running),
        launch_mode: Set(argus_core::entity::task::LaunchMode::Manual),
        targets: Set(serde_json::json!([])),
        progress: Set(0.0),
        created_at: Set(now),
        started_at: Set(Some(now)),
        finished_at: Set(None),
        locked: Set(false),
        priority: Set("normal".to_string()),
        schedule_config: Set(None),
        params: Set(Some(params)),
        node_id: Set(None),
    };

    if let Err(e) = ScanTaskEntity::insert(new_task).exec(&data.db).await {
        tracing::error!("创建被动扫描任务失败: {e}");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("创建任务失败: {e}")
        }));
    }

    // 后台执行被动扫描
    let db = data.db.clone();
    let task_id_bg = task_id.clone();
    let mode = body.mode.clone();
    let proxy_cfg = body.proxy_config.clone();
    let kafka_cfg = body.kafka_config.clone();
    let pcap_cfg = body.pcap_config.clone();
    let agent_cfg = body.agent_config.clone();

    tokio::spawn(async move {
        tracing::info!("被动扫描任务 {} ({}) 后台执行中", task_id_bg, match &mode {
            PassiveScanMode::Proxy => "proxy",
            PassiveScanMode::Kafka => "kafka",
            PassiveScanMode::Pcap => "pcap",
            PassiveScanMode::Agent => "agent",
        });

        let result_msg = match execute_passive_scan(&mode, &proxy_cfg, &kafka_cfg, &pcap_cfg, &agent_cfg).await {
            Ok(findings) => {
                tracing::info!("被动扫描任务 {} 完成，发现 {} 个漏洞", task_id_bg, findings.len());
                if let Err(e) = save_passive_scan_results(&db, &task_id_bg, &findings).await {
                    tracing::error!("保存被动扫描结果失败: {e}");
                }
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Completed).await;
                format!("完成，发现 {} 个漏洞", findings.len())
            }
            Err(e) => {
                tracing::error!("被动扫描任务 {} 失败: {}", task_id_bg, e);
                let _ = update_task_status(&db, &task_id_bg, TaskStatus::Failed).await;
                format!("扫描失败: {e}")
            }
        };
        tracing::info!("被动扫描任务 {} 结束: {}", task_id_bg, result_msg);
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "task_id": task_id,
        "mode": mode_str,
        "status": "running",
        "message": format!("被动扫描任务已提交，使用 GET /api/v1/scan/status/{task_id} 查询状态")
    }))
}

/// 执行被动扫描（根据模式构建数据源并运行 PassiveScanner）
///
/// 返回 Vec<VulnFinding>，由调用方持久化。
async fn execute_passive_scan(
    mode: &PassiveScanMode,
    proxy_cfg: &Option<ProxyScanConfig>,
    kafka_cfg: &Option<KafkaScanConfig>,
    pcap_cfg: &Option<PcapScanConfig>,
    agent_cfg: &Option<AgentScanConfig>,
) -> Result<Vec<argus_webscan::VulnFinding>, String> {
    use argus_webscan::{PassiveScanner, TrafficSource, KafkaSource, PcapSource, HttpProxy, ProxyConfig};
    use argus_webscan::AgentCollector;
    use argus_webscan::AgentConfig;

    match mode {
        PassiveScanMode::Proxy => {
            let cfg = proxy_cfg.as_ref().unwrap();
            let proxy_cfg = ProxyConfig {
                listen_addr: cfg.listen_addr.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
                listen_port: cfg.listen_port.unwrap_or(8888),
            };
            let proxy = std::sync::Arc::new(HttpProxy::new(proxy_cfg));

            // 启动代理监听（非阻塞）
            let proxy_for_listen = proxy.clone();
            let proxy_handle = tokio::spawn(async move {
                if let Err(e) = proxy_for_listen.run().await {
                    tracing::warn!("代理监听结束: {e}");
                }
            });

            // 等待指定时长
            let duration = std::time::Duration::from_secs(cfg.duration_secs.unwrap_or(60));
            tokio::time::sleep(duration).await;

            // 停止代理监听（abort spawn）
            proxy_handle.abort();

            // 对采集到的事务执行被动扫描
            let findings = proxy.run_passive_scan().await;
            Ok(findings)
        }
        PassiveScanMode::Kafka => {
            let cfg = kafka_cfg.as_ref().unwrap();
            let source = KafkaSource::new(
                cfg.brokers.clone(),
                cfg.topic.clone(),
                cfg.group_id.clone().unwrap_or_else(|| "argus-passive".to_string()),
            );
            let mut scanner = PassiveScanner::new();
            let findings = scanner.scan_source(&source).await;
            Ok(findings)
        }
        PassiveScanMode::Pcap => {
            let cfg = pcap_cfg.as_ref().unwrap();
            let source = PcapSource::new(cfg.file_path.clone());
            let mut scanner = PassiveScanner::new();
            let findings = scanner.scan_source(&source).await;
            Ok(findings)
        }
        PassiveScanMode::Agent => {
            let cfg = agent_cfg.as_ref().unwrap();
            let mut agent_cfg = AgentConfig::default();
            agent_cfg.log_path = cfg.log_path.clone();
            if let Some(bs) = cfg.batch_size {
                agent_cfg.batch_size = bs;
            }
            let collector = AgentCollector::new(agent_cfg);
            let mut scanner = PassiveScanner::new();
            let findings = scanner.scan_source(&collector).await;
            Ok(findings)
        }
    }
}

/// 保存被动扫描结果到 scan_results 表
///
/// 被动扫描产生的 VulnFinding 存为 result_type=VulnDetect 的记录，
/// raw_data 字段保存完整 VulnFinding JSON。
async fn save_passive_scan_results(
    db: &sea_orm::DatabaseConnection,
    task_id: &str,
    findings: &[argus_webscan::VulnFinding],
) -> Result<(), sea_orm::DbErr> {
    let now = chrono::Utc::now();
    let models: Vec<scan_result::ActiveModel> = findings
        .iter()
        .map(|f| {
            // 从 URL 提取 host
            let host = f.url
                .split("//")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or(&f.url)
                .to_string();

            scan_result::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                task_id: Set(task_id.to_string()),
                result_type: Set(ResultType::VulnDetect),
                host: Set(host),
                port: Set(None),
                protocol: Set(None),
                state: Set(Some(format!("{:?}", f.severity).to_lowercase())),
                service: Set(Some(format!("{:?}", f.category))),
                banner: Set(Some(f.evidence.clone())),
                username: Set(None),
                password: Set(None),
                success: Set(None),
                response_time_ms: Set(None),
                raw_data: Set(Some(serde_json::to_value(f).unwrap_or_default())),
                created_at: Set(now),
            }
        })
        .collect();

    if !models.is_empty() {
        ScanResultEntity::insert_many(models).exec(db).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{MockDatabase, MockExecResult, DatabaseConnection, DatabaseBackend};
    use sea_orm::sea_query::Value;
    use std::collections::BTreeMap;
    use argus_portscanner::types::{PortScanResult, PortState, Protocol};

    /// 构造 count 查询的 MockRow（列名 "num_items"）
    fn make_count_row(n: i64) -> BTreeMap<String, Value> {
        let mut row = BTreeMap::new();
        row.insert("num_items".to_string(), Value::BigInt(Some(n)));
        row
    }

    /// 构造测试用的 PortScanResult
    fn make_port_result(host: &str, port: u16, state: PortState) -> PortScanResult {
        PortScanResult {
            host: host.to_string(),
            port,
            protocol: Protocol::Tcp,
            state,
            service: Some("http".to_string()),
            banner: Some("nginx".to_string()),
            response_time_ms: 10,
        }
    }

    // ========== 序列化测试 ==========

    #[test]
    fn test_task_accepted_serialization() {
        let accepted = TaskAccepted {
            task_id: "abc-123".to_string(),
            status: "running".to_string(),
            message: "扫描任务已提交".to_string(),
        };
        let json = serde_json::to_value(&accepted).unwrap();
        assert_eq!(json["task_id"], "abc-123");
        assert_eq!(json["status"], "running");
        assert!(json["message"].as_str().unwrap().contains("扫描任务已提交"));
    }

    #[test]
    fn test_task_status_response_serialization() {
        let resp = TaskStatusResponse {
            task_id: "task-001".to_string(),
            status: "completed".to_string(),
            task_type: "portscan".to_string(),
            progress: 1.0,
            created_at: "2026-09-20T10:00:00+00:00".to_string(),
            started_at: Some("2026-09-20T10:00:01+00:00".to_string()),
            finished_at: Some("2026-09-20T10:00:05+00:00".to_string()),
            result_count: 10,
            open_port_count: 5,
            success_count: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["task_id"], "task-001");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["progress"], 1.0);
        assert_eq!(json["result_count"], 10);
        assert_eq!(json["open_port_count"], 5);
        assert_eq!(json["success_count"], 3);
    }

    // ========== 请求反序列化测试 ==========

    #[test]
    fn test_port_scan_request_deserialization() {
        let json = r#"{"hosts":["192.168.1.1","10.0.0.1"],"ports":"1-100","scan_udp":true,"fingerprint":true,"concurrency":500,"timeout_ms":2000,"rate_limit":1000}"#;
        let req: PortScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hosts.len(), 2);
        assert_eq!(req.ports, Some("1-100".to_string()));
        assert_eq!(req.scan_udp, Some(true));
        assert_eq!(req.concurrency, Some(500));
        assert_eq!(req.timeout_ms, Some(2000));
        assert_eq!(req.rate_limit, Some(1000));
    }

    #[test]
    fn test_port_scan_request_minimal() {
        let json = r#"{"hosts":["127.0.0.1"]}"#;
        let req: PortScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hosts, vec!["127.0.0.1"]);
        assert!(req.ports.is_none());
    }

    #[test]
    fn test_port_scan_request_empty_hosts() {
        let json = r#"{"hosts":[]}"#;
        let req: PortScanRequest = serde_json::from_str(json).unwrap();
        assert!(req.hosts.is_empty());
    }

    #[test]
    fn test_bruteforce_request_deserialization() {
        let json = r#"{"host":"192.168.1.100","protocol":"ssh","port":22,"usernames":["root","admin"],"passwords":["123456","password"],"concurrency":50,"timeout_ms":3000,"stop_on_success":true}"#;
        let req: BruteForceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.host, "192.168.1.100");
        assert_eq!(req.protocol, "ssh");
        assert_eq!(req.port, Some(22));
        assert_eq!(req.usernames, vec!["root", "admin"]);
        assert_eq!(req.passwords, vec!["123456", "password"]);
        assert_eq!(req.stop_on_success, Some(true));
    }

    #[test]
    fn test_bruteforce_request_minimal() {
        let json = r#"{"host":"127.0.0.1","protocol":"mysql","usernames":["root"],"passwords":[""]}"#;
        let req: BruteForceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.host, "127.0.0.1");
        assert_eq!(req.protocol, "mysql");
        assert!(req.port.is_none());
        assert_eq!(req.usernames, vec!["root"]);
        assert_eq!(req.passwords, vec![""]);
    }

    // ========== MockDatabase 持久化测试 ==========

    #[tokio::test]
    async fn test_save_port_scan_results_with_mock_db() {
        // PostgreSQL 的 INSERT...RETURNING 被当作 query 处理，
        // 需要返回与插入数量相同的 Model
        let now = chrono::Utc::now();
        let mock_models: Vec<scan_result::Model> = (0..3).map(|i| scan_result::Model {
            id: format!("uuid-{i}"),
            task_id: "task-001".to_string(),
            result_type: ResultType::PortScan,
            host: "192.168.1.1".to_string(),
            port: Some(80 + i as i32),
            protocol: Some("tcp".to_string()),
            state: Some("open".to_string()),
            service: Some("http".to_string()),
            banner: Some("nginx".to_string()),
            username: None,
            password: None,
            success: None,
            response_time_ms: Some(10),
            raw_data: Some(serde_json::json!({})),
            created_at: now,
        }).collect();

        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![mock_models])
            .append_exec_results(vec![
                MockExecResult {
                    last_insert_id: 100,
                    rows_affected: 3,
                },
            ])
            .into_connection();

        let results = vec![
            make_port_result("192.168.1.1", 80, PortState::Open),
            make_port_result("192.168.1.1", 443, PortState::Open),
            make_port_result("192.168.1.1", 22, PortState::Closed),
        ];

        let ret = save_port_scan_results(&db, "task-001", &results).await;
        assert!(ret.is_ok(), "保存端口扫描结果应成功: {:?}", ret.err());
    }

    #[tokio::test]
    async fn test_save_empty_port_scan_results() {
        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .into_connection();

        let ret = save_port_scan_results(&db, "task-empty", &[]).await;
        assert!(ret.is_ok(), "保存空结果应成功");
    }

    #[tokio::test]
    async fn test_update_task_status_completed() {
        let now = chrono::Utc::now();
        let task_model = task::Model {
            id: "task-002".to_string(),
            name: "test-scan".to_string(),
            task_type: TaskType::PortScan,
            status: TaskStatus::Running,
            launch_mode: argus_core::entity::task::LaunchMode::Manual,
            targets: serde_json::json!([]),
            progress: 0.5,
            created_at: now,
            started_at: Some(now),
            finished_at: None,
            locked: false,
            priority: "normal".to_string(),
            schedule_config: None,
            params: None,
            node_id: None,
        };

        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model.clone()], vec![task_model]])
            .append_exec_results(vec![
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
            ])
            .into_connection();

        let ret = update_task_status(&db, "task-002", TaskStatus::Completed).await;
        assert!(ret.is_ok(), "更新任务状态为 Completed 应成功: {:?}", ret.err());
    }

    #[tokio::test]
    async fn test_update_task_status_failed() {
        let now = chrono::Utc::now();
        let task_model = task::Model {
            id: "task-003".to_string(),
            name: "test-fail".to_string(),
            task_type: TaskType::Bruteforce,
            status: TaskStatus::Running,
            launch_mode: argus_core::entity::task::LaunchMode::Manual,
            targets: serde_json::json!(["192.168.1.1"]),
            progress: 0.0,
            created_at: now,
            started_at: Some(now),
            finished_at: None,
            locked: false,
            priority: "normal".to_string(),
            schedule_config: None,
            params: None,
            node_id: None,
        };

        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model.clone()], vec![task_model]])
            .append_exec_results(vec![
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
            ])
            .into_connection();

        let ret = update_task_status(&db, "task-003", TaskStatus::Failed).await;
        assert!(ret.is_ok(), "更新任务状态为 Failed 应成功: {:?}", ret.err());
    }

    #[tokio::test]
    async fn test_update_task_status_stopped() {
        let now = chrono::Utc::now();
        let task_model = task::Model {
            id: "task-004".to_string(),
            name: "test-cancel".to_string(),
            task_type: TaskType::PortScan,
            status: TaskStatus::Running,
            launch_mode: argus_core::entity::task::LaunchMode::Manual,
            targets: serde_json::json!(["10.0.0.1"]),
            progress: 0.3,
            created_at: now,
            started_at: Some(now),
            finished_at: None,
            locked: false,
            priority: "normal".to_string(),
            schedule_config: None,
            params: None,
            node_id: None,
        };

        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model.clone()], vec![task_model]])
            .append_exec_results(vec![
                MockExecResult {
                    last_insert_id: 0,
                    rows_affected: 1,
                },
            ])
            .into_connection();

        let ret = update_task_status(&db, "task-004", TaskStatus::Stopped).await;
        assert!(ret.is_ok(), "更新任务状态为 Stopped 应成功: {:?}", ret.err());
    }

    #[tokio::test]
    async fn test_update_task_status_task_not_found() {
        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<task::Model>::new()])
            .into_connection();

        let ret = update_task_status(&db, "nonexistent", TaskStatus::Failed).await;
        assert!(ret.is_ok(), "任务不存在时应正常返回");
    }

    // ========== ScanResult ActiveModel 构造测试 ==========

    #[test]
    fn test_scan_result_active_model_port_scan() {
        let now = chrono::Utc::now();
        let model = scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set("task-port-001".to_string()),
            result_type: Set(ResultType::PortScan),
            host: Set("192.168.1.1".to_string()),
            port: Set(Some(80)),
            protocol: Set(Some("tcp".to_string())),
            state: Set(Some("open".to_string())),
            service: Set(Some("http".to_string())),
            banner: Set(None),
            username: Set(None),
            password: Set(None),
            success: Set(None),
            response_time_ms: Set(Some(15)),
            raw_data: Set(Some(serde_json::json!({"port": 80}))),
            created_at: Set(now),
        };
        let _ = model;
    }

    #[test]
    fn test_scan_result_active_model_bruteforce() {
        let now = chrono::Utc::now();
        let model = scan_result::ActiveModel {
            id: Set(uuid::Uuid::new_v4().to_string()),
            task_id: Set("task-bf-001".to_string()),
            result_type: Set(ResultType::Bruteforce),
            host: Set("192.168.1.100".to_string()),
            port: Set(Some(22)),
            protocol: Set(Some("ssh".to_string())),
            state: Set(None),
            service: Set(None),
            banner: Set(None),
            username: Set(Some("root".to_string())),
            password: Set(Some("123456".to_string())),
            success: Set(Some(true)),
            response_time_ms: Set(None),
            raw_data: Set(Some(serde_json::json!({"success": true}))),
            created_at: Set(now),
        };
        let _ = model;
    }

    // ========== Bruteforce 结果持久化测试 ==========

    #[tokio::test]
    async fn test_save_bruteforce_results_with_mock_db() {
        // PostgreSQL 的 INSERT...RETURNING 需要 2 个 Model 作为 query 返回
        let now = chrono::Utc::now();
        let mock_models: Vec<scan_result::Model> = (0..2).map(|i| scan_result::Model {
            id: format!("bf-uuid-{i}"),
            task_id: "task-bf-001".to_string(),
            result_type: ResultType::Bruteforce,
            host: "192.168.1.100".to_string(),
            port: Some(22),
            protocol: Some("ssh".to_string()),
            state: None,
            service: None,
            banner: None,
            username: Some("root".to_string()),
            password: Some("123456".to_string()),
            success: Some(i == 0),
            response_time_ms: None,
            raw_data: Some(serde_json::json!({"success": i == 0})),
            created_at: now,
        }).collect();

        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![mock_models])
            .append_exec_results(vec![
                MockExecResult {
                    last_insert_id: 200,
                    rows_affected: 2,
                },
            ])
            .into_connection();

        let results = vec![
            argus_bruteforce::types::BruteForceResult {
                host: "192.168.1.100".to_string(),
                port: 22,
                protocol: argus_bruteforce::types::Protocol::Ssh,
                credential: argus_bruteforce::types::Credential {
                    username: "root".to_string(),
                    password: "123456".to_string(),
                },
                success: true,
                response_time_ms: 50,
                error: None,
            },
            argus_bruteforce::types::BruteForceResult {
                host: "192.168.1.100".to_string(),
                port: 22,
                protocol: argus_bruteforce::types::Protocol::Ssh,
                credential: argus_bruteforce::types::Credential {
                    username: "admin".to_string(),
                    password: "wrong".to_string(),
                },
                success: false,
                response_time_ms: 55,
                error: Some("auth failed".to_string()),
            },
        ];

        let ret = save_bruteforce_results(&db, "task-bf-001", &results).await;
        assert!(ret.is_ok(), "保存爆破结果应成功: {:?}", ret.err());
    }

    #[tokio::test]
    async fn test_save_empty_bruteforce_results() {
        let db: DatabaseConnection = MockDatabase::new(DatabaseBackend::Postgres)
            .into_connection();

        let ret = save_bruteforce_results(&db, "task-empty", &[]).await;
        assert!(ret.is_ok(), "保存空爆破结果应成功");
    }

    // ========== 端口扫描结果转换逻辑测试 ==========

    #[test]
    fn test_port_result_to_active_model_fields() {
        let result = make_port_result("10.0.0.1", 8080, PortState::Open);
        // 验证 PortScanResult 字段
        assert_eq!(result.host, "10.0.0.1");
        assert_eq!(result.port, 8080);
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.service.as_deref(), Some("http"));
        assert_eq!(result.banner.as_deref(), Some("nginx"));
        assert_eq!(result.response_time_ms, 10);
    }

    #[test]
    fn test_port_result_closed_state() {
        let result = make_port_result("10.0.0.1", 9999, PortState::Closed);
        assert_eq!(result.state, PortState::Closed);
    }

    #[test]
    fn test_port_result_filtered_state() {
        let result = make_port_result("10.0.0.1", 1234, PortState::Filtered);
        assert_eq!(result.state, PortState::Filtered);
    }

    // ========== API Handler 集成测试（actix-web TestRequest）==========

    use actix_web::{App, http::StatusCode};
    use argus_scanner::ScannerRegistry;

    /// 构造测试用 AppState（空 registry + MockDatabase）
    fn make_test_state(db: DatabaseConnection) -> AppState {
        AppState {
            registry: std::sync::Arc::new(ScannerRegistry::new()),
            db,
            revoked_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// 构造测试用的 task::Model
    fn make_task_model(
        id: &str,
        status: TaskStatus,
        task_type: TaskType,
        progress: f32,
    ) -> task::Model {
        let now = chrono::Utc::now();
        // 先计算 finished_at 避免移动 status
        let is_finished = matches!(status, TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Stopped);
        task::Model {
            id: id.to_string(),
            name: format!("test-{id}"),
            task_type,
            status,
            launch_mode: argus_core::entity::task::LaunchMode::Manual,
            targets: serde_json::json!([]),
            progress,
            created_at: now,
            started_at: Some(now),
            finished_at: if is_finished { Some(now) } else { None },
            locked: false,
            priority: "normal".to_string(),
            schedule_config: None,
            params: None,
            node_id: None,
        }
    }

    // ---------- get_scan_status 测试 ----------

    #[tokio::test]
    async fn test_get_scan_status_task_not_found() {
        // find_by_id 返回空 → 404
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<task::Model>::new()])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/status/{task_id}", web::get().to(get_scan_status))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/status/nonexistent-task")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("任务不存在"));
    }

    #[tokio::test]
    async fn test_get_scan_status_running_task() {
        // 运行中任务：find_by_id 返回 task + 3 次 count（每个返回 i64 数字行）
        let task_model = make_task_model("task-run-001", TaskStatus::Running, TaskType::PortScan, 0.5);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model]])          // find_by_id → task::Model
            .append_query_results(vec![vec![make_count_row(5)]])  // result_count
            .append_query_results(vec![vec![make_count_row(2)]])  // open_port_count
            .append_query_results(vec![vec![make_count_row(0)]])  // success_count
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/status/{task_id}", web::get().to(get_scan_status))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/status/task-run-001")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["task_id"], "task-run-001");
        assert_eq!(body["status"], "running");
        assert_eq!(body["task_type"], "portscan");
        assert_eq!(body["progress"], 0.5);
        assert_eq!(body["result_count"], 5);
        assert_eq!(body["open_port_count"], 2);
        assert_eq!(body["success_count"], 0);
    }

    #[tokio::test]
    async fn test_get_scan_status_completed_task() {
        // 已完成任务：status=Completed，有 finished_at
        let task_model = make_task_model("task-done-001", TaskStatus::Completed, TaskType::Bruteforce, 1.0);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model]])           // find_by_id
            .append_query_results(vec![vec![make_count_row(10)]])  // result_count
            .append_query_results(vec![vec![make_count_row(0)]])   // open_port_count
            .append_query_results(vec![vec![make_count_row(3)]])   // success_count
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/status/{task_id}", web::get().to(get_scan_status))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/status/task-done-001")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["status"], "completed");
        assert_eq!(body["task_type"], "bruteforce");
        assert_eq!(body["progress"], 1.0);
        assert_eq!(body["result_count"], 10);
        assert_eq!(body["success_count"], 3);
        // finished_at 应该存在
        assert!(body["finished_at"].is_string());
    }

    // ---------- get_scan_results 测试 ----------

    #[tokio::test]
    async fn test_get_scan_results_empty() {
        // 查询空结果
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<scan_result::Model>::new()])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/results/{task_id}", web::get().to(get_scan_results))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/results/empty-task")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["task_id"], "empty-task");
        assert_eq!(body["total"], 0);
        assert_eq!(body["open_ports"], 0);
        assert_eq!(body["success_count"], 0);
    }

    #[tokio::test]
    async fn test_get_scan_results_with_data() {
        // 查询有数据的结果
        let now = chrono::Utc::now();
        let result_models = vec![
            scan_result::Model {
                id: "r-1".to_string(),
                task_id: "task-with-data".to_string(),
                result_type: ResultType::PortScan,
                host: "192.168.1.1".to_string(),
                port: Some(80),
                protocol: Some("tcp".to_string()),
                state: Some("open".to_string()),
                service: Some("http".to_string()),
                banner: Some("nginx".to_string()),
                username: None,
                password: None,
                success: None,
                response_time_ms: Some(10),
                raw_data: Some(serde_json::json!({"port": 80})),
                created_at: now,
            },
            scan_result::Model {
                id: "r-2".to_string(),
                task_id: "task-with-data".to_string(),
                result_type: ResultType::PortScan,
                host: "192.168.1.1".to_string(),
                port: Some(22),
                protocol: Some("tcp".to_string()),
                state: Some("closed".to_string()),
                service: None,
                banner: None,
                username: None,
                password: None,
                success: None,
                response_time_ms: Some(5),
                raw_data: Some(serde_json::json!({"port": 22})),
                created_at: now,
            },
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![result_models])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/results/{task_id}", web::get().to(get_scan_results))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/results/task-with-data")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["task_id"], "task-with-data");
        assert_eq!(body["total"], 2);
        assert_eq!(body["open_ports"], 1);
        assert_eq!(body["success_count"], 0);
        assert_eq!(body["results"].as_array().unwrap().len(), 2);
    }

    // ---------- cancel_scan 测试 ----------

    #[tokio::test]
    async fn test_cancel_scan_task_not_found() {
        // 任务不存在 → 404
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<task::Model>::new()])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/cancel/{task_id}", web::post().to(cancel_scan))
        ).await;

        let resp = actix_web::test::TestRequest::post()
            .uri("/scan/cancel/nonexistent")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("任务不存在"));
    }

    #[tokio::test]
    async fn test_cancel_scan_task_not_running() {
        // 任务已完成（非 Running）→ 400
        let task_model = make_task_model("task-done-002", TaskStatus::Completed, TaskType::PortScan, 1.0);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![task_model]])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/cancel/{task_id}", web::post().to(cancel_scan))
        ).await;

        let resp = actix_web::test::TestRequest::post()
            .uri("/scan/cancel/task-done-002")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("不在运行中"));
    }

    #[tokio::test]
    async fn test_cancel_scan_running_task() {
        // 运行中任务 → 取消成功 → 200
        // cancel_scan 流程：
        //   1. find_by_id（query）→ Running task_model
        //   2. registry.get("port_scanner") → None（空 registry，跳过 cancel）
        //   3. update_task_status(Stopped):
        //      a. find_by_id（query）→ task_model
        //      b. update（UPDATE...RETURNING → query）→ task_model
        //      c. exec（exec_results）
        let task_model = make_task_model("task-running-001", TaskStatus::Running, TaskType::PortScan, 0.5);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![
                vec![task_model.clone()],  // cancel_scan 的 find_by_id
                vec![task_model.clone()],  // update_task_status 的 find_by_id
                vec![task_model],          // update (UPDATE...RETURNING)
            ])
            .append_exec_results(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 },
            ])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/cancel/{task_id}", web::post().to(cancel_scan))
        ).await;

        let resp = actix_web::test::TestRequest::post()
            .uri("/scan/cancel/task-running-001")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["task_id"], "task-running-001");
        assert_eq!(body["status"], "stopped");
        assert!(body["message"].as_str().unwrap().contains("已取消"));
    }

    #[tokio::test]
    async fn test_cancel_scan_bruteforce_running_task() {
        // 爆破任务取消（TaskType::Bruteforce → scanner_name = "brute_force"）
        let task_model = make_task_model("task-bf-run-001", TaskStatus::Running, TaskType::Bruteforce, 0.3);
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![
                vec![task_model.clone()],
                vec![task_model.clone()],
                vec![task_model],
            ])
            .append_exec_results(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 },
            ])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/cancel/{task_id}", web::post().to(cancel_scan))
        ).await;

        let resp = actix_web::test::TestRequest::post()
            .uri("/scan/cancel/task-bf-run-001")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["status"], "stopped");
    }

    // ---------- get_baseline_report 测试 ----------

    #[tokio::test]
    async fn test_get_baseline_report_not_found() {
        // 无基线核查结果 → 404
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![Vec::<scan_result::Model>::new()])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/baseline/report/{task_id}", web::get().to(get_baseline_report))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/baseline/report/no-such-task")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["error"].as_str().unwrap().contains("无基线核查结果"));
    }

    #[tokio::test]
    async fn test_get_baseline_report_with_data() {
        // 有基线核查结果 → 200 + 汇总报告（合规率/分类/修复建议）
        let now = chrono::Utc::now();
        let cr_compliant = serde_json::json!({
            "rule_id": "r1", "rule_name": "密码策略", "category": "身份鉴别",
            "requirement_id": "8.1.1", "severity": "high",
            "compliance": "compliant", "collected_output": null,
            "message": null, "fix_advice": null
        });
        let cr_non_compliant = serde_json::json!({
            "rule_id": "r2", "rule_name": "SSH 空闲超时", "category": "访问控制",
            "requirement_id": "8.1.3", "severity": "medium",
            "compliance": "noncompliant", "collected_output": null,
            "message": "未配置 ClientAliveInterval", "fix_advice": "设置 ClientAliveInterval 600"
        });
        let result_models = vec![
            scan_result::Model {
                id: "br-1".to_string(), task_id: "task-baseline-001".to_string(),
                result_type: ResultType::BaselineCheck, host: "192.168.1.1".to_string(),
                port: None, protocol: None, state: Some("compliant".to_string()),
                service: Some("身份鉴别".to_string()), banner: None,
                username: None, password: None, success: Some(true),
                response_time_ms: None, raw_data: Some(cr_compliant), created_at: now,
            },
            scan_result::Model {
                id: "br-2".to_string(), task_id: "task-baseline-001".to_string(),
                result_type: ResultType::BaselineCheck, host: "192.168.1.1".to_string(),
                port: None, protocol: None, state: Some("non_compliant".to_string()),
                service: Some("访问控制".to_string()), banner: None,
                username: None, password: None, success: Some(false),
                response_time_ms: None, raw_data: Some(cr_non_compliant), created_at: now,
            },
        ];

        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![result_models])
            .into_connection();

        let state = make_test_state(db);
        let app = actix_web::test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/scan/baseline/report/{task_id}", web::get().to(get_baseline_report))
        ).await;

        let resp = actix_web::test::TestRequest::get()
            .uri("/scan/baseline/report/task-baseline-001")
            .send_request(&app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["host"], "192.168.1.1");
        assert_eq!(body["summary"]["total"], 2);
        assert_eq!(body["summary"]["compliant"], 1);
        assert_eq!(body["summary"]["non_compliant"], 1);
        assert_eq!(body["results"].as_array().unwrap().len(), 2);
        // 验证修复建议透传
        let results = body["results"].as_array().unwrap();
        assert_eq!(results[1]["fix_advice"], "设置 ClientAliveInterval 600");
    }
}


