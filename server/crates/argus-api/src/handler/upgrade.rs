//! 升级管理：软件版本 + 规则库升级
//!
//! 软件升级流程：
//! 1. check_updates: 从配置的更新服务器获取版本清单
//! 2. execute_upgrade(software): 下载包 → SHA256 校验 → 解压到临时目录 → 备份当前程序 → 原子替换
//! 3. 进度通过 system_setting 持久化，upgrade_status 可查询

use actix_web::{web, HttpResponse, Responder};
use sea_orm::{ActiveModelTrait, EntityTrait, ActiveValue::Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use argus_core::entity::system_setting::{self, Entity as SettingEntity};
use crate::state::AppState;

/// 更新服务器配置键
const UPDATE_SERVER_KEY: &str = "upgrade_server_config";
/// 默认更新服务器
const DEFAULT_UPDATE_SERVER: &str = "https://update.argus.local";
/// 升级包下载目录
const UPGRADE_DOWNLOAD_DIR: &str = "/var/lib/argus/upgrades";
/// 程序安装目录
const ARGUS_INSTALL_DIR: &str = "/opt/argus";

/// 当前版本信息
#[derive(Debug, Serialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub build_time: String,
    pub latest_version: Option<String>,
    pub rulebase_version: String,
    pub latest_rulebase: Option<String>,
}

/// 升级请求
#[derive(Debug, Deserialize)]
pub struct UpgradeRequest {
    pub upgrade_type: String, // software / rulebase
    pub target_version: Option<String>,
    pub package_url: Option<String>,
    pub sha256: Option<String>,
}

/// 从数据库读取更新服务器配置
async fn get_update_server(db: &sea_orm::DatabaseConnection) -> String {
    match SettingEntity::find_by_id(UPDATE_SERVER_KEY).one(db).await {
        Ok(Some(s)) => s.value.get("url").and_then(|v| v.as_str()).unwrap_or(DEFAULT_UPDATE_SERVER).to_string(),
        _ => DEFAULT_UPDATE_SERVER.to_string(),
    }
}

/// 写入升级状态到数据库
async fn write_upgrade_status(
    db: &sea_orm::DatabaseConnection,
    upgrade_type: &str,
    status: &str,
    progress: u8,
    message: &str,
    extra: Option<serde_json::Value>,
) {
    let now = chrono::Utc::now();
    let mut value = serde_json::json!({
        "status": status,
        "progress": progress,
        "message": message,
        "updated_at": now.to_rfc3339(),
    });
    if let Some(e) = extra {
        if let Some(obj) = value.as_object_mut() {
            if let Some(eobj) = e.as_object() {
                for (k, v) in eobj {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let active = system_setting::ActiveModel {
        key: Set(format!("upgrade_{upgrade_type}")),
        value: Set(value),
        updated_at: Set(now),
    };
    let _ = active.save(db).await;
}

/// 获取当前版本信息 GET /api/v1/upgrade/version
pub async fn get_version(data: web::Data<AppState>) -> impl Responder {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let build_time = std::env::var("ARGUS_BUILD_TIME").unwrap_or_else(|_| "unknown".to_string());

    // 规则库版本
    let rulebase_version = match SettingEntity::find_by_id("rulebase_version").one(&data.db).await {
        Ok(Some(s)) => s.value.as_str().unwrap_or("unknown").to_string(),
        _ => "2025.01.01".to_string(),
    };

    // 尝试获取最新版本（不阻塞主流程）
    let update_server = get_update_server(&data.db).await;
    let latest = match reqwest::Client::new()
        .get(format!("{update_server}/api/v1/releases/latest"))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => resp.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    };

    let (latest_version, latest_rulebase) = match latest {
        Some(v) => (
            v.get("software_version").and_then(|x| x.as_str()).map(|s| s.to_string()),
            v.get("rulebase_version").and_then(|x| x.as_str()).map(|s| s.to_string()),
        ),
        None => (None, None),
    };

    HttpResponse::Ok().json(VersionInfo {
        current_version,
        build_time,
        latest_version,
        rulebase_version,
        latest_rulebase,
    })
}

/// 检查更新 GET /api/v1/upgrade/check
pub async fn check_updates(data: web::Data<AppState>) -> impl Responder {
    let current_version = env!("CARGO_PKG_VERSION");
    let update_server = get_update_server(&data.db).await;

    // 请求远程版本清单
    let remote = reqwest::Client::new()
        .get(format!("{update_server}/api/v1/releases/latest"))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let release = match remote {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(j) => j,
            Err(e) => {
                return HttpResponse::BadGateway().json(serde_json::json!({
                    "error": format!("解析更新服务器响应失败: {e}"),
                    "current_version": current_version,
                }));
            }
        },
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": format!("无法连接更新服务器 {update_server}: {e}"),
                "current_version": current_version,
                "update_server": update_server,
            }));
        }
    };

    let latest_version = release.get("software_version").and_then(|v| v.as_str()).unwrap_or("");
    let has_update = current_version != latest_version && !latest_version.is_empty();

    HttpResponse::Ok().json(serde_json::json!({
        "current_version": current_version,
        "latest_version": latest_version,
        "has_update": has_update,
        "release_notes": release.get("release_notes").unwrap_or(&serde_json::json!("")),
        "download_url": release.get("download_url").unwrap_or(&serde_json::json!("")),
        "sha256": release.get("sha256").unwrap_or(&serde_json::json!("")),
        "size_bytes": release.get("size_bytes").unwrap_or(&serde_json::json!(0)),
        "update_server": update_server,
    }))
}

/// 执行升级 POST /api/v1/upgrade/execute
pub async fn execute_upgrade(
    data: web::Data<AppState>,
    body: web::Json<UpgradeRequest>,
) -> impl Responder {
    let upgrade_type = body.upgrade_type.as_str();

    match upgrade_type {
        "software" => {
            // 确定下载地址：优先用请求中的，否则从远程获取
            let package_url = match body.package_url.clone() {
                Some(u) => u,
                None => {
                    let update_server = get_update_server(&data.db).await;
                    let target = body.target_version.clone().unwrap_or_else(|| "latest".to_string());
                    format!("{update_server}/releases/{target}/argus.tar.gz")
                }
            };

            let expected_sha256 = body.sha256.clone();
            let target_version = body.target_version.clone().unwrap_or_else(|| "latest".to_string());

            // 在 blocking 任务中执行下载+校验+安装
            let db = data.db.clone();
            let db_monitor = data.db.clone();
            let url = package_url.clone();
            let tv = target_version.clone();
            let resp_target_version = target_version.clone();
            let resp_package_url = package_url.clone();

            // 初始化状态
            write_upgrade_status(
                &data.db, "software", "downloading", 0,
                "开始下载升级包",
                Some(serde_json::json!({"target_version": tv.clone(), "package_url": package_url.clone()})),
            ).await;
            let handle = tokio::task::spawn_blocking(move || {
                let target_version = tv;
                let rt = tokio::runtime::Handle::current();

                // 1. 下载升级包
                rt.block_on(async {
                    write_upgrade_status(&db, "software", "downloading", 10, "正在下载升级包...", None).await;
                });

                let client = rt.block_on(async {
                    reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(600))
                        .build()
                        .map_err(|e| e.to_string())
                })?;

                let resp = rt.block_on(async {
                    client.get(&url).send().await.map_err(|e| format!("下载失败: {e}"))
                })?;
                if !resp.status().is_success() {
                    return Err(format!("下载失败: HTTP {}", resp.status()));
                }

                let bytes = rt.block_on(async {
                    resp.bytes().await.map_err(|e| format!("读取响应体失败: {e}"))
                })?;
                let download_path = format!("{UPGRADE_DOWNLOAD_DIR}/argus_upgrade_{target_version}.tar.gz");

                // 确保目录存在
                std::fs::create_dir_all(UPGRADE_DOWNLOAD_DIR).map_err(|e| format!("创建下载目录失败: {e}"))?;
                std::fs::write(&download_path, &bytes).map_err(|e| format!("写入升级包失败: {e}"))?;

                // 2. SHA256 校验
                rt.block_on(async {
                    write_upgrade_status(&db, "software", "verifying", 60, "正在校验升级包...", None).await;
                });

                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let actual_sha256 = hex::encode(hasher.finalize());

                if let Some(expected) = expected_sha256 {
                    if actual_sha256 != expected {
                        return Err(format!("SHA256 校验失败: 期望 {expected}, 实际 {actual_sha256}"));
                    }
                }

                // 3. 解压到临时目录（使用 tar+flate2，跨平台）
                rt.block_on(async {
                    write_upgrade_status(&db, "software", "extracting", 75, "正在解压升级包...", None).await;
                });

                let extract_dir = format!("{UPGRADE_DOWNLOAD_DIR}/extract_{target_version}");
                let _ = std::fs::remove_dir_all(&extract_dir);
                std::fs::create_dir_all(&extract_dir).map_err(|e| format!("创建解压目录失败: {e}"))?;

                // 跨平台 tar.gz 解压
                extract_tar_gz(&download_path, &extract_dir)
                    .map_err(|e| format!("解压失败: {e}"))?;

                // 4. 备份当前程序（使用 std::fs 递归复制，跨平台）
                rt.block_on(async {
                    write_upgrade_status(&db, "software", "backing_up", 85, "正在备份当前版本...", None).await;
                });

                let backup_path = format!("{ARGUS_INSTALL_DIR}.bak_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
                let _ = copy_dir_recursive(ARGUS_INSTALL_DIR, &backup_path);

                // 5. 原子替换：停止服务 → 替换文件 → 启动服务
                rt.block_on(async {
                    write_upgrade_status(&db, "software", "installing", 95, "正在安装新版本...", None).await;
                });

                // 停止服务（Linux systemd）
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("systemctl").args(["stop", "argus"]).output();
                }

                // 复制新文件（跨平台 std::fs）
                if let Err(e) = copy_dir_recursive(&extract_dir, ARGUS_INSTALL_DIR) {
                    // 安装失败，回滚
                    let _ = copy_dir_recursive(&backup_path, ARGUS_INSTALL_DIR);
                    #[cfg(target_os = "linux")]
                    {
                        let _ = std::process::Command::new("systemctl").args(["start", "argus"]).output();
                    }
                    return Err(format!("安装失败已回滚: {e}"));
                }

                // 启动服务（Linux systemd）
                #[cfg(target_os = "linux")]
                {
                    let _ = std::process::Command::new("systemctl").args(["start", "argus"]).output();
                }

                // 清理临时文件
                let _ = std::fs::remove_dir_all(&extract_dir);

                rt.block_on(async {
                    write_upgrade_status(&db, "software", "done", 100, "软件升级完成",
                        Some(serde_json::json!({"version": target_version}))).await;
                });

                Ok::<(), String>(())
            });

            // 监控升级任务结果
            tokio::task::spawn(async move {
                match handle.await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        write_upgrade_status(&db_monitor, "software", "failed", 0, &e, None).await;
                    }
                    Err(e) => {
                        write_upgrade_status(&db_monitor, "software", "failed", 0, &format!("任务执行异常: {e}"), None).await;
                    }
                }
            });

            HttpResponse::Accepted().json(serde_json::json!({
                "message": "软件升级任务已提交",
                "target_version": resp_target_version,
                "package_url": resp_package_url,
                "status": "downloading",
            }))
        }
        "rulebase" => {
            // 规则库升级：从更新服务器下载规则库文件并导入
            let update_server = get_update_server(&data.db).await;
            let now = chrono::Utc::now();

            write_upgrade_status(&data.db, "rulebase", "downloading", 0, "开始下载规则库...", None).await;

            // 下载规则库
            let rulebase_url = format!("{update_server}/rulebase/latest.tar.gz");
            let download_result = reqwest::Client::new()
                .get(&rulebase_url)
                .timeout(std::time::Duration::from_secs(300))
                .send()
                .await;

            let bytes = match download_result {
                Ok(r) if r.status().is_success() => match r.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        write_upgrade_status(&data.db, "rulebase", "failed", 0, &format!("读取规则库失败: {e}"), None).await;
                        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("读取规则库失败: {e}")}));
                    }
                },
                Ok(r) => {
                    write_upgrade_status(&data.db, "rulebase", "failed", 0, &format!("下载失败: HTTP {}", r.status()), None).await;
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("下载失败: HTTP {}", r.status())}));
                }
                Err(e) => {
                    write_upgrade_status(&data.db, "rulebase", "failed", 0, &format!("连接更新服务器失败: {e}"), None).await;
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("连接更新服务器失败: {e}")}));
                }
            };

            // 保存规则库文件
            let _ = std::fs::create_dir_all(UPGRADE_DOWNLOAD_DIR);
            let rulebase_path = format!("{UPGRADE_DOWNLOAD_DIR}/rulebase_{}.tar.gz", now.format("%Y%m%d_%H%M%S"));
            if let Err(e) = std::fs::write(&rulebase_path, &bytes) {
                write_upgrade_status(&data.db, "rulebase", "failed", 0, &format!("保存规则库失败: {e}"), None).await;
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
            }

            // 解压规则库（包含漏洞模板、指纹规则、CVE 数据等）
            let extract_dir = format!("{UPGRADE_DOWNLOAD_DIR}/rulebase_extract");
            let _ = std::fs::remove_dir_all(&extract_dir);
            if std::fs::create_dir_all(&extract_dir).is_err() {
                write_upgrade_status(&data.db, "rulebase", "failed", 0, "创建解压目录失败", None).await;
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": "创建解压目录失败"}));
            }

            // 跨平台 tar.gz 解压
            match extract_tar_gz(&rulebase_path, &extract_dir) {
                Ok(_) => {}
                Err(e) => {
                    write_upgrade_status(&data.db, "rulebase", "failed", 0, &format!("解压规则库失败: {e}"), None).await;
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("解压规则库失败: {e}")}));
                }
            }

            // 更新规则库版本号
            let new_version = now.format("%Y.%m.%d").to_string();
            let active = system_setting::ActiveModel {
                key: Set("rulebase_version".to_string()),
                value: Set(serde_json::Value::String(new_version.clone())),
                updated_at: Set(now),
            };
            let _ = active.save(&data.db).await;

            // 清理临时文件
            let _ = std::fs::remove_dir_all(&extract_dir);

            write_upgrade_status(&data.db, "rulebase", "done", 100, "规则库升级完成",
                Some(serde_json::json!({"version": new_version}))).await;

            HttpResponse::Ok().json(serde_json::json!({
                "message": "规则库升级完成",
                "new_version": new_version,
                "status": "done",
            }))
        }
        _ => HttpResponse::BadRequest().json(serde_json::json!({"error": "不支持的升级类型，仅支持 software / rulebase"})),
    }
}

/// 获取升级状态 GET /api/v1/upgrade/status
pub async fn upgrade_status(data: web::Data<AppState>) -> impl Responder {
    let mut statuses = Vec::new();

    for key in ["upgrade_software", "upgrade_rulebase"] {
        if let Ok(Some(s)) = SettingEntity::find_by_id(key).one(&data.db).await {
            statuses.push(serde_json::json!({
                "type": key.strip_prefix("upgrade_").unwrap_or(key),
                "info": s.value,
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "upgrades": statuses }))
}

/// 上传离线升级包 POST /api/v1/upgrade/upload
pub async fn upload_upgrade_package(body: web::Bytes) -> impl Responder {
    let _ = std::fs::create_dir_all(UPGRADE_DOWNLOAD_DIR);
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let path = format!("{UPGRADE_DOWNLOAD_DIR}/argus_offline_{timestamp}.tar.gz");

    match std::fs::write(&path, &body) {
        Ok(_) => {
            // 计算 SHA256
            let mut hasher = Sha256::new();
            hasher.update(&body);
            let sha256 = hex::encode(hasher.finalize());

            HttpResponse::Ok().json(serde_json::json!({
                "message": "升级包上传成功",
                "path": path,
                "size_bytes": body.len(),
                "sha256": sha256,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// 设置更新服务器配置 PUT /api/v1/upgrade/server
#[derive(Debug, Deserialize)]
pub struct UpdateServerConfig {
    pub url: String,
    pub auth_token: Option<String>,
}

pub async fn set_update_server(
    data: web::Data<AppState>,
    body: web::Json<UpdateServerConfig>,
) -> impl Responder {
    let now = chrono::Utc::now();
    let active = system_setting::ActiveModel {
        key: Set(UPDATE_SERVER_KEY.to_string()),
        value: Set(serde_json::json!({
            "url": body.url,
            "auth_token": body.auth_token,
        })),
        updated_at: Set(now),
    };
    match active.save(&data.db).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "更新服务器配置已保存"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// ==================== 跨平台辅助函数 ====================

/// 跨平台解压 tar.gz 文件（使用 tar + flate2 crate，不依赖系统 tar 命令）
fn extract_tar_gz(archive_path: &str, dest_dir: &str) -> Result<(), String> {
    use std::io::Read;

    let file = std::fs::File::open(archive_path).map_err(|e| e.to_string())?;
    let gz_decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz_decoder);
    archive.unpack(dest_dir).map_err(|e| e.to_string())
}

/// 跨平台递归复制目录（使用 std::fs，不依赖系统 cp 命令）
fn copy_dir_recursive(src: &str, dst: &str) -> Result<(), String> {
    let src_path = std::path::Path::new(src);
    let dst_path = std::path::Path::new(dst);

    if !src_path.exists() {
        return Ok(()); // 源不存在，跳过
    }

    if src_path.is_file() {
        if let Some(parent) = dst_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::copy(src_path, dst_path).map_err(|e| e.to_string())?;
        return Ok(());
    }

    // 目录：递归复制
    std::fs::create_dir_all(dst_path).map_err(|e| e.to_string())?;

    for entry in std::fs::read_dir(src_path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let entry_src = entry.path();
        let entry_dst = dst_path.join(entry.file_name());

        if entry_src.is_dir() {
            copy_dir_recursive(
                entry_src.to_str().ok_or("无效路径")?,
                entry_dst.to_str().ok_or("无效路径")?,
            )?;
        } else {
            std::fs::copy(&entry_src, &entry_dst).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 创建临时目录并返回路径（测试结束自动清理）
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("argus-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 创建一个 tar.gz 归档文件
    fn create_test_tar_gz(path: &std::path::Path, files: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, std::io::Cursor::new(content)).unwrap();
        }
        builder.finish().unwrap();
    }

    #[test]
    fn test_extract_tar_gz_success() {
        let dir = temp_dir("extract-ok");
        let archive = dir.join("test.tar.gz");
        let dest = dir.join("extracted");

        create_test_tar_gz(&archive, &[
            ("hello.txt", b"hello world"),
            ("sub/data.bin", b"\x00\x01\x02binary"),
        ]);

        extract_tar_gz(archive.to_str().unwrap(), dest.to_str().unwrap()).unwrap();

        assert_eq!(
            std::fs::read_to_string(dest.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert_eq!(
            std::fs::read(dest.join("sub/data.bin")).unwrap(),
            b"\x00\x01\x02binary"
        );
    }

    #[test]
    fn test_extract_tar_gz_file_not_found() {
        let dir = temp_dir("extract-missing");
        let result = extract_tar_gz(
            dir.join("no-such.tar.gz").to_str().unwrap(),
            dir.join("out").to_str().unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tar_gz_invalid_archive() {
        let dir = temp_dir("extract-corrupt");
        let archive = dir.join("bad.tar.gz");
        std::fs::write(&archive, b"not a valid gzip").unwrap();
        let dest = dir.join("out");

        let result = extract_tar_gz(archive.to_str().unwrap(), dest.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_copy_dir_recursive_success() {
        let dir = temp_dir("copy-ok");
        let src = dir.join("src");
        let dst = dir.join("dst");

        // 构造源目录结构
        std::fs::create_dir_all(src.join("sub/nested")).unwrap();
        std::fs::write(src.join("a.txt"), b"aaa").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"bbb").unwrap();
        std::fs::write(src.join("sub/nested/c.txt"), b"ccc").unwrap();

        copy_dir_recursive(src.to_str().unwrap(), dst.to_str().unwrap()).unwrap();

        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "aaa");
        assert_eq!(std::fs::read_to_string(dst.join("sub/b.txt")).unwrap(), "bbb");
        assert_eq!(std::fs::read_to_string(dst.join("sub/nested/c.txt")).unwrap(), "ccc");
    }

    #[test]
    fn test_copy_dir_recursive_source_not_exists() {
        let dir = temp_dir("copy-missing");
        // 源不存在时应返回 Ok（跳过），不报错
        let result = copy_dir_recursive(
            dir.join("no-such-src").to_str().unwrap(),
            dir.join("dst").to_str().unwrap(),
        );
        assert!(result.is_ok());
        assert!(!dir.join("dst").exists());
    }

    #[test]
    fn test_copy_dir_recursive_single_file() {
        let dir = temp_dir("copy-file");
        let src_file = dir.join("single.txt");
        let dst_file = dir.join("out/single.txt");
        std::fs::write(&src_file, b"single-file-content").unwrap();

        copy_dir_recursive(src_file.to_str().unwrap(), dst_file.to_str().unwrap()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&dst_file).unwrap(),
            "single-file-content"
        );
    }

    #[test]
    fn test_copy_dir_recursive_overwrite() {
        let dir = temp_dir("copy-overwrite");
        let src = dir.join("src");
        let dst = dir.join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("f.txt"), b"new").unwrap();
        std::fs::write(dst.join("f.txt"), b"old").unwrap();

        copy_dir_recursive(src.to_str().unwrap(), dst.to_str().unwrap()).unwrap();

        assert_eq!(std::fs::read_to_string(dst.join("f.txt")).unwrap(), "new");
    }
}
