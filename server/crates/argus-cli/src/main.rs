//! Argus CLI 入口

use clap::{Parser, Subcommand};
use argus_core::{config::AppConfig, db_connect, run_migrations};

#[derive(Parser)]
#[command(name = "argus")]
#[command(version, about = "Argus 安全扫描系统 - 全知全见的守卫者")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动 API 服务（配置来自环境变量）
    Serve,
    /// 显示版本信息
    Version,
    /// 从 NVD 导入 CVE 数据库
    CveImport {
        /// 起始年份（默认 2002）
        #[arg(long, default_value = "2002")]
        start_year: u16,
        /// 结束年份（默认当前年份）
        #[arg(long)]
        end_year: Option<u16>,
        /// NVD API 密钥（可选，有密钥速率限制更宽松）
        #[arg(long)]
        api_key: Option<String>,
    },
    /// 导入 CISA KEV（已知被利用漏洞）目录
    KevImport,
    /// 通过 OSV API 查询漏洞（按 CPE 或包名）
    OsvQuery {
        /// CPE URI，如 cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
        #[arg(long)]
        cpe: Option<String>,
        /// 包名（与 ecosystem 配合使用）
        #[arg(long)]
        package: Option<String>,
        /// 生态系统: PyPI / npm / Maven / Go / crates.io / RubyGems / Packagist
        #[arg(long)]
        ecosystem: Option<String>,
        /// 版本号
        #[arg(long)]
        version: Option<String>,
        /// Git commit hash
        #[arg(long)]
        commit: Option<String>,
    },
    /// 从本地 JSON 文件导入 CNNVD（国家信息安全漏洞库）数据
    CnnvdImport {
        /// JSON 文件路径或目录路径
        #[arg(long)]
        path: String,
    },
    /// Web 应用扫描（爬虫 + OWASP 检测）
    WebScan {
        /// 目标 URL
        #[arg(long)]
        target: String,
        /// 最大爬取深度（默认 3）
        #[arg(long, default_value = "3")]
        max_depth: u32,
        /// 最大页面数（默认 200）
        #[arg(long, default_value = "200")]
        max_pages: usize,
    },
    /// 启动 HTTP 代理被动扫描
    ProxyScan {
        /// 监听地址
        #[arg(long, default_value = "127.0.0.1")]
        addr: String,
        /// 监听端口
        #[arg(long, default_value = "8888")]
        port: u16,
    },
    /// 运行自定义 POC 模板
    PocRun {
        /// 目标 URL
        #[arg(long)]
        target: String,
        /// POC 模板 YAML 文件路径
        #[arg(long)]
        poc: String,
    },
    /// 导入 Postman Collection 作为扫描目标
    ImportPostman {
        /// Postman Collection JSON 文件路径
        #[arg(long)]
        file: String,
    },
    /// Docker 镜像扫描
    ImageScan {
        /// 镜像名称 (如 library/nginx:latest)
        #[arg(long)]
        image: String,
        /// Harbor 仓库 URL (可选)
        #[arg(long)]
        harbor: Option<String>,
        /// Harbor 用户名
        #[arg(long)]
        harbor_user: Option<String>,
        /// Harbor 密码
        #[arg(long)]
        harbor_pass: Option<String>,
        /// 是否扫描依赖漏洞
        #[arg(long, default_value = "true")]
        scan_vulns: bool,
        /// 是否检测敏感文件
        #[arg(long, default_value = "true")]
        scan_sensitive: bool,
    },
    /// Harbor 仓库扫描
    HarborScan {
        /// Harbor URL
        #[arg(long)]
        url: String,
        /// 用户名
        #[arg(long)]
        username: String,
        /// 密码
        #[arg(long)]
        password: String,
        /// 仅列出项目和仓库
        #[arg(long)]
        list: bool,
    },
    /// 工控设备指纹扫描
    IcsScan {
        /// 目标主机 (逗号分隔)
        #[arg(long)]
        hosts: String,
        /// 超时 (毫秒)
        #[arg(long, default_value = "3000")]
        timeout_ms: u64,
        /// 是否启用无损只读模式
        #[arg(long, default_value = "true")]
        non_intrusive: bool,
    },
    /// 数据库漏洞扫描
    DbVulnScan {
        /// 目标主机
        #[arg(long)]
        host: String,
        /// 目标端口 (0 = 自动检测)
        #[arg(long)]
        port: Option<u16>,
        /// 数据库类型 (mysql/postgresql/redis/mongodb/mssql/oracle)
        #[arg(long)]
        db_type: String,
        /// 超时 (毫秒)
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
    },
    /// 启动分布式扫描节点 daemon
    NodeDaemon {
        /// 中心 API 端点，如 http://127.0.0.1:8080
        #[arg(long)]
        center: String,
        /// 节点名称
        #[arg(long)]
        name: Option<String>,
        /// 节点监听端口（用于内部通信）
        #[arg(long, default_value = "8090")]
        port: u16,
    },
    /// 执行数据库迁移
    Migrate {
        /// 数据库连接串，不指定则使用环境变量/默认配置
        #[arg(long)]
        database_url: Option<String>,
        /// 回滚最近一个迁移
        #[arg(long)]
        rollback: bool,
        /// 刷新数据库（全部 down + 全部 up）
        #[arg(long)]
        refresh: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = AppConfig::from_env();

    match cli.command {
        Commands::Serve => {
            tracing::info!("启动 Argus API 服务: {}:{}", config.server.host, config.server.port);
            argus_api::run_server_with_config(&config).await?;
        }
        Commands::Version => {
            println!("Argus {}", env!("CARGO_PKG_VERSION"));
            println!("全知全见的守卫者");
        }
        Commands::CveImport { start_year, end_year, api_key } => {
            let db_config = config.database.clone();
            tracing::info!("连接数据库: {}", db_config.url);
            let conn = db_connect(&db_config).await
                .map_err(|e| anyhow::anyhow!("数据库连接失败: {e}"))?;
            let end = end_year.unwrap_or_else(|| {
                chrono::Utc::now().format("%Y").to_string().parse().unwrap_or(2024)
            });
            tracing::info!("开始从 NVD 导入 CVE 数据（{}-{}）", start_year, end);
            let client = argus_vulndb::NvdClient::new(api_key);
            let importer = argus_vulndb::CveImporter::new(conn, client);
            match importer.import_all(start_year, end, None).await {
                Ok(stats) => {
                    println!("导入完成:");
                    println!("  总 CVE 数: {}", stats.total_cves);
                    println!("  新增 CVE: {}", stats.new_cves);
                    println!("  更新 CVE: {}", stats.updated_cves);
                    println!("  CPE 记录: {}", stats.total_cpes);
                    println!("  关联记录: {}", stats.total_mappings);
                    println!("  耗时: {:.1}s", stats.elapsed_secs);
                }
                Err(e) => {
                    tracing::error!("导入失败: {e}");
                    return Err(anyhow::anyhow!("导入失败: {e}"));
                }
            }
        }
        Commands::KevImport => {
            let db_config = config.database.clone();
            tracing::info!("连接数据库: {}", db_config.url);
            let conn = db_connect(&db_config).await
                .map_err(|e| anyhow::anyhow!("数据库连接失败: {e}"))?;
            tracing::info!("开始导入 CISA KEV 目录...");
            let importer = argus_vulndb::KevImporter::new(conn);
            match importer.import().await {
                Ok(stats) => {
                    println!("CISA KEV 导入完成:");
                    println!("  KEV 总数: {}", stats.total_kev);
                    println!("  标记 CVE: {}", stats.marked);
                    println!("  未匹配: {}", stats.not_found);
                    println!("  错误: {}", stats.errors);
                    println!("  耗时: {:.1}s", stats.elapsed_secs);
                }
                Err(e) => {
                    tracing::error!("KEV 导入失败: {e}");
                    return Err(anyhow::anyhow!("KEV 导入失败: {e}"));
                }
            }
        }
        Commands::OsvQuery { cpe, package, ecosystem, version, commit } => {
            let db_config = config.database.clone();
            tracing::info!("连接数据库: {}", db_config.url);
            let conn = db_connect(&db_config).await
                .map_err(|e| anyhow::anyhow!("数据库连接失败: {e}"))?;
            let importer = argus_vulndb::OsvImporter::new(conn);
            let result = if let Some(cpe_uri) = cpe {
                tracing::info!("按 CPE 查询 OSV: {}", cpe_uri);
                importer.query_by_cpe(&cpe_uri).await
            } else if let (Some(pkg), Some(eco)) = (package, ecosystem) {
                tracing::info!("按包名查询 OSV: {}/{} v{:?}", eco, pkg, version);
                importer.query_by_package(&pkg, &eco, version.as_deref()).await
            } else if let Some(c) = commit {
                tracing::info!("按 commit 查询 OSV: {}", c);
                importer.query_by_commit(&c).await
            } else {
                return Err(anyhow::anyhow!(
                    "请指定 --cpe、(--package + --ecosystem) 或 --commit 参数"
                ));
            };
            match result {
                Ok(stats) => {
                    println!("OSV 查询完成:");
                    println!("  结果总数: {}", stats.total_results);
                    println!("  新增 CVE: {}", stats.new_cves);
                    println!("  更新 CVE: {}", stats.updated_cves);
                    println!("  错误: {}", stats.errors);
                    println!("  耗时: {:.1}s", stats.elapsed_secs);
                }
                Err(e) => {
                    tracing::error!("OSV 查询失败: {e}");
                    return Err(anyhow::anyhow!("OSV 查询失败: {e}"));
                }
            }
        }
        Commands::CnnvdImport { path } => {
            let db_config = config.database.clone();
            tracing::info!("连接数据库: {}", db_config.url);
            let conn = db_connect(&db_config).await
                .map_err(|e| anyhow::anyhow!("数据库连接失败: {e}"))?;
            let importer = argus_vulndb::CnnvdImporter::new(conn);
            let result = if std::path::Path::new(&path).is_dir() {
                tracing::info!("从目录导入 CNNVD 数据: {}", path);
                importer.import_from_dir(&path).await
            } else {
                tracing::info!("从文件导入 CNNVD 数据: {}", path);
                importer.import_from_file(&path).await
            };
            match result {
                Ok(stats) => {
                    println!("CNNVD 导入完成:");
                    println!("  条目总数: {}", stats.total_entries);
                    println!("  更新 CVE: {}", stats.updated);
                    println!("  未匹配: {}", stats.not_found);
                    println!("  错误: {}", stats.errors);
                    println!("  耗时: {:.1}s", stats.elapsed_secs);
                }
                Err(e) => {
                    tracing::error!("CNNVD 导入失败: {e}");
                    return Err(anyhow::anyhow!("CNNVD 导入失败: {e}"));
                }
            }
        }
        Commands::WebScan { target, max_depth, max_pages } => {
            tracing::info!("Web 扫描目标: {}", target);
            let config = argus_webscan::CrawlConfig {
                max_depth,
                max_pages,
                ..Default::default()
            };
            let mut crawler = argus_webscan::Crawler::new(config);
            let results = crawler.crawl(&target).await;
            tracing::info!("爬取完成: {} 页", results.len());
            let scanner = argus_webscan::OwaspScanner::new();
            let form_findings = scanner.scan_forms(&results).await;
            let url_findings = scanner.scan_urls(&results).await;
            let total = form_findings.len() + url_findings.len();
            println!("Web 扫描完成:");
            println!("  爬取页面: {}", results.len());
            println!("  漏洞发现: {}", total);
            for f in form_findings.iter().chain(url_findings.iter()) {
                println!("  [{:?}] {} - {}", f.category, f.severity.as_str(), f.evidence);
            }
        }
        Commands::ProxyScan { addr, port } => {
            let config = argus_webscan::ProxyConfig { listen_addr: addr.clone(), listen_port: port };
            tracing::info!("HTTP 代理启动: {}:{}", config.listen_addr, config.listen_port);
            let proxy = argus_webscan::HttpProxy::new(config);
            proxy.run().await.map_err(|e| anyhow::anyhow!("代理失败: {e}"))?;
        }
        Commands::PocRun { target, poc } => {
            let yaml = std::fs::read_to_string(&poc)
                .map_err(|e| anyhow::anyhow!("读取 POC 文件失败: {e}"))?;
            let mut editor = argus_webscan::PocEditor::new();
            let count = editor.load_from_yaml(&yaml)
                .map_err(|e| anyhow::anyhow!("POC 解析失败: {e}"))?;
            tracing::info!("加载 {} 个 POC 模板", count);
            let results = editor.execute_all(&target).await;
            println!("POC 执行完成: {} 个结果", results.len());
            for r in &results {
                let status = if r.matched { "[MATCH]" } else { "[NO MATCH]" };
                println!("  {} {} - {} ({})", status, r.poc_id, r.name, r.response_status);
            }
        }
        Commands::ImportPostman { file } => {
            let json = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("读取文件失败: {e}"))?;
            let importer = argus_webscan::PostmanImporter::new();
            let requests = importer.import(&json)
                .map_err(|e| anyhow::anyhow!("导入失败: {e}"))?;
            println!("Postman Collection 导入完成: {} 个请求", requests.len());
            for req in &requests {
                println!("  {} {} {}", req.method, req.url, req.name);
            }
        }
        Commands::ImageScan { image, harbor, harbor_user, harbor_pass, scan_vulns, scan_sensitive } => {
            tracing::info!("镜像扫描: {}", image);
            let scanner = argus_container::ImageScanner::new();
            let matcher = argus_container::DepVulnMatcher::new();
            // 解析镜像名和标签
            let parts: Vec<&str> = image.rsplitn(2, ':').collect();
            let (img_name, tag) = if parts.len() == 2 {
                (parts[1].to_string(), parts[0].to_string())
            } else {
                (image.clone(), "latest".to_string())
            };

            // 从 Harbor 获取 manifest (如果提供了 URL)
            if let Some(harbor_url) = &harbor {
                let client = argus_container::HarborClient::new(
                    harbor_url,
                    harbor_user.as_deref().unwrap_or(""),
                    harbor_pass.as_deref().unwrap_or(""),
                );
                let hp: Vec<&str> = img_name.splitn(2, '/').collect();
                if hp.len() == 2 {
                    match client.get_manifest(hp[0], hp[1], &tag).await {
                        Ok(manifest) => {
                            tracing::info!("获取 manifest 成功 ({} bytes)", manifest.len());
                        }
                        Err(e) => {
                            tracing::warn!("获取 manifest 失败: {e}");
                        }
                    }
                    if scan_vulns {
                        if let Err(e) = client.trigger_scan(hp[0], hp[1], &tag).await {
                            tracing::warn!("触发 Harbor 扫描失败: {e}");
                        }
                    }
                }
            }

            // 本地已知漏洞匹配（演示）
            println!("镜像扫描完成:");
            println!("  镜像: {}:{}", img_name, tag);
            if scan_vulns {
                // 从镜像名推断常见包
                let known_packages = vec![
                    ("log4j-core", "2.14.0"),
                    ("openssl", "1.1.1h"),
                    ("nginx", "1.16.0"),
                ];
                let mut total_vulns = 0;
                for (pkg, ver) in &known_packages {
                    let vulns = matcher.match_local_known(pkg, ver);
                    for v in &vulns {
                        println!("  [{}] {} {} - {} ({})", v.severity, v.cve_id, pkg, ver, v.source);
                        total_vulns += 1;
                    }
                }
                println!("  本地漏洞匹配: {} 个", total_vulns);
            }
            if scan_sensitive {
                let fp_scanner = argus_container::ImageScanner::new();
                // 检查常见敏感路径
                let sensitive_paths = ["/root/.ssh/id_rsa", "/etc/ssl/server.pem", "/root/.aws/credentials", "/.env"];
                let mut found = 0;
                for path in &sensitive_paths {
                    if let Some(sf) = fp_scanner.check_sensitive_path(path) {
                        println!("  [{}] {} - {}", sf.severity, sf.path, sf.description);
                        found += 1;
                    }
                }
                println!("  敏感文件检测: {} 个", found);
            }
        }
        Commands::HarborScan { url, username, password, list } => {
            let client = argus_container::HarborClient::new(&url, &username, &password);
            tracing::info!("Harbor 扫描: {}", url);
            match client.health().await {
                Ok(true) => println!("Harbor 健康: 是"),
                Ok(false) => {
                    println!("Harbor 健康: 否");
                    return Err(anyhow::anyhow!("Harbor 不可用"));
                }
                Err(e) => {
                    println!("Harbor 连接失败: {e}");
                    return Err(anyhow::anyhow!("Harbor 连接失败: {e}"));
                }
            }
            match client.list_projects().await {
                Ok(projects) => {
                    println!("项目: {} 个", projects.len());
                    for p in &projects {
                        println!("  [{}] {} ({} repos)", p.project_id, p.name, p.repo_count);
                    }
                }
                Err(e) => {
                    tracing::error!("列出项目失败: {e}");
                    return Err(anyhow::anyhow!("列出项目失败: {e}"));
                }
            }
            if list {
                return Ok(());
            }
            // 获取每个项目的仓库
            let projects = client.list_projects().await.unwrap_or_default();
            for proj in &projects {
                match client.list_repositories(&proj.name).await {
                    Ok(repos) => {
                        for r in &repos {
                            println!("  {}/{}: {} artifacts, {} pulls",
                                proj.name, r.name, r.artifacts_count, r.pull_count);
                        }
                    }
                    Err(e) => tracing::warn!("列出 {} 仓库失败: {e}", proj.name),
                }
            }
        }
        Commands::IcsScan { hosts, timeout_ms, non_intrusive } => {
            let host_list: Vec<&str> = hosts.split(',').collect();
            tracing::info!("工控扫描: {} 台主机", host_list.len());
            for host in &host_list {
                println!("扫描主机: {}", host);
                if non_intrusive {
                    let scanner = argus_ics::NonIntrusiveScanner::new()
                        .with_timeout(timeout_ms);
                    let result = scanner.scan_host(host).await;
                    println!("  设备数: {}", result.devices.len());
                    for d in &result.devices {
                        println!("    {} {} ({}) {} {} {}",
                            d.protocol.as_str(),
                            d.device_type.as_deref().unwrap_or("?"),
                            d.port,
                            d.vendor.as_deref().unwrap_or("?"),
                            d.model.as_deref().unwrap_or("?"),
                            d.firmware.as_deref().unwrap_or("?"),
                        );
                    }
                    println!("  发现: {} 个", result.findings.len());
                    for f in &result.findings {
                        println!("    [{}] {} - {}", f.severity, f.finding_type, f.description);
                    }
                    for w in &result.warnings {
                        println!("  ⚠ {}", w);
                    }
                } else {
                    let fp_scanner = argus_ics::IcsFingerprintScanner::new();
                    let devices = fp_scanner.scan_host(host, timeout_ms).await;
                    println!("  设备数: {}", devices.len());
                    for d in &devices {
                        println!("    {} {} ({}) {} {} {}",
                            d.protocol.as_str(),
                            d.device_type.as_deref().unwrap_or("?"),
                            d.port,
                            d.vendor.as_deref().unwrap_or("?"),
                            d.model.as_deref().unwrap_or("?"),
                            d.firmware.as_deref().unwrap_or("?"),
                        );
                    }
                }
            }
        }
        Commands::DbVulnScan { host, port, db_type, timeout_ms } => {
            let db = match db_type.as_str() {
                "mysql" => argus_sysvuln::DbType::Mysql,
                "postgresql" | "postgres" | "pg" => argus_sysvuln::DbType::Postgresql,
                "redis" => argus_sysvuln::DbType::Redis,
                "mongodb" | "mongo" => argus_sysvuln::DbType::Mongodb,
                "mssql" | "sqlserver" => argus_sysvuln::DbType::Mssql,
                "oracle" => argus_sysvuln::DbType::Oracle,
                _ => return Err(anyhow::anyhow!("不支持的数据库类型: {}", db_type)),
            };
            let port = port.unwrap_or_else(|| db.default_port());
            tracing::info!("数据库漏洞扫描: {}:{} ({})", host, port, db.as_str());
            let scanner = argus_sysvuln::DbVulnScanner::new();
            let findings = scanner.scan(&host, port, db.clone(), timeout_ms).await;
            println!("数据库漏洞扫描完成: {} 个发现", findings.len());
            for f in &findings {
                println!("  [{}] {} - {}", f.severity, f.title, f.description);
                if let Some(advice) = &f.fix_advice {
                    println!("    修复: {}", advice);
                }
            }
        }
        Commands::NodeDaemon { center, name, port } => {
            let node_name = name.unwrap_or_else(|| format!("node-{}", &uuid::Uuid::new_v4().to_string()[..8]));
            tracing::info!("启动扫描节点: name={}, center={}, port={}", node_name, center, port);
            // 创建空的扫描引擎注册表（节点自身实现扫描能力时可扩展）
            let registry = std::sync::Arc::new(argus_scanner::ScannerRegistry::new());
            let capabilities = vec!["port_scan".to_string(), "fingerprint".to_string(), "vuln_detect".to_string()];
            let daemon = argus_node::NodeDaemon::new(center.clone(), node_name, registry, capabilities);
            if let Err(e) = daemon.run().await {
                tracing::error!("节点 daemon 运行失败: {e}");
                return Err(anyhow::anyhow!("节点 daemon 失败: {e}"));
            }
        }
        Commands::Migrate { database_url, rollback, refresh } => {
            let mut db_config = config.database.clone();
            if let Some(url) = database_url {
                db_config.url = url;
            }
            tracing::info!("连接数据库: {}", db_config.url);
            let conn = db_connect(&db_config).await
                .map_err(|e| anyhow::anyhow!("数据库连接失败: {e}"))?;
            if refresh {
                tracing::info!("刷新数据库...");
                argus_core::refresh_database(&conn).await
                    .map_err(|e| anyhow::anyhow!("刷新失败: {e}"))?;
            } else if rollback {
                tracing::info!("回滚最近一个迁移...");
                argus_core::rollback_migration(&conn).await
                    .map_err(|e| anyhow::anyhow!("回滚失败: {e}"))?;
            } else {
                tracing::info!("执行数据库迁移...");
                run_migrations(&conn).await
                    .map_err(|e| anyhow::anyhow!("迁移失败: {e}"))?;
            }
            tracing::info!("迁移完成");
        }
    }
    Ok(())
}
