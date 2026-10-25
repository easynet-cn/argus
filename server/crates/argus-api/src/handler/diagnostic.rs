//! 阶段8 第四批：网络诊断工具 + 辅助工具 API
//!
//! 提供 ping / telnet / http / dig / nslookup / traceroute / whois / nmap / 抓包
//! 以及编码 / 解码 / 哈希 / 加密 / 解密 / 子网计算等辅助工具。

use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::OsRng;

// ==================== 网络诊断请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct PingRequest {
    pub host: String,
    #[serde(default = "default_ping_count")]
    pub count: u32,
    #[serde(default = "default_ping_timeout")]
    pub timeout: u64, // ms
}

fn default_ping_count() -> u32 {
    4
}
fn default_ping_timeout() -> u64 {
    2000
}

#[derive(Debug, Deserialize)]
pub struct TelnetRequest {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_telnet_timeout")]
    pub timeout: u64,
}
fn default_telnet_timeout() -> u64 {
    3000
}

#[derive(Debug, Deserialize)]
pub struct HttpRequest {
    pub url: String,
    #[serde(default = "default_http_timeout")]
    pub timeout: u64,
}
fn default_http_timeout() -> u64 {
    5000
}

#[derive(Debug, Deserialize)]
pub struct DnsRequest {
    pub domain: String,
    #[serde(default = "default_record_type")]
    pub record_type: String,
    pub dns_server: Option<String>,
}
fn default_record_type() -> String {
    "A".to_string()
}

#[derive(Debug, Deserialize)]
pub struct TracerouteRequest {
    pub host: String,
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    #[serde(default = "default_trace_timeout")]
    pub timeout: u64,
}
fn default_max_hops() -> u32 {
    30
}
fn default_trace_timeout() -> u64 {
    2000
}

#[derive(Debug, Deserialize)]
pub struct WhoisRequest {
    pub query: String,
}

#[derive(Debug, Deserialize)]
pub struct NmapRequest {
    pub target: String,
    #[serde(default = "default_nmap_ports")]
    pub ports: String, // "top100" / "top1000" / "1-1000" / "80,443"
}
fn default_nmap_ports() -> String {
    "top100".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CaptureRequest {
    pub interface: String,
    #[serde(default = "default_capture_duration")]
    pub duration: u64, // 秒
    pub filter: Option<String>,
}
fn default_capture_duration() -> u64 {
    30
}

// ==================== 辅助工具请求结构 ====================

#[derive(Debug, Deserialize)]
pub struct EncodeRequest {
    pub text: String,
    #[serde(default = "default_encode_type")]
    pub r#type: String,
}
fn default_encode_type() -> String {
    "base64".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DecodeRequest {
    pub text: String,
    #[serde(default = "default_encode_type")]
    pub r#type: String,
}

#[derive(Debug, Deserialize)]
pub struct HashRequest {
    pub text: String,
    #[serde(default = "default_hash_type")]
    pub r#type: String,
}
fn default_hash_type() -> String {
    "sha256".to_string()
}

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub text: String,
    pub key: String,
    #[serde(default = "default_cipher_type")]
    pub r#type: String,
}
fn default_cipher_type() -> String {
    "aes".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub key: String,
    #[serde(default = "default_cipher_type")]
    pub r#type: String,
}

#[derive(Debug, Deserialize)]
pub struct SubnetRequest {
    pub cidr: String,
}

// ==================== 网络诊断 API ====================

/// Ping 检测：调用系统 ping 命令（跨平台）
pub async fn ping(body: web::Json<PingRequest>) -> impl Responder {
    let host = body.host.clone();
    let count = body.count;
    let timeout_secs = (body.timeout as f64 / 1000.0).max(1.0) as u64;

    // 跨平台 ping 参数
    let args: Vec<String> = if cfg!(target_os = "windows") {
        vec![
            "-n".to_string(),
            count.to_string(),
            "-w".to_string(),
            body.timeout.to_string(),
            host.clone(),
        ]
    } else {
        vec![
            "-c".to_string(),
            count.to_string(),
            "-W".to_string(),
            timeout_secs.to_string(),
            host.clone(),
        ]
    };

    let output = tokio::task::spawn_blocking(move || {
        Command::new("ping").args(&args).output()
    })
    .await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let success = out.status.success();
            HttpResponse::Ok().json(serde_json::json!({
                "host": host,
                "success": success,
                "stdout": stdout,
                "stderr": stderr,
            }))
        }
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "host": host,
            "success": false,
            "error": format!("执行 ping 命令失败: {e}"),
            "hint": "系统可能未安装 ping 命令或无权限",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("ping 任务异常: {e}")
        })),
    }
}

/// Telnet 端口检测：用 tokio TcpStream 连接
pub async fn telnet(body: web::Json<TelnetRequest>) -> impl Responder {
    let addr = format!("{}:{}", body.host, body.port);
    let timeout = Duration::from_millis(body.timeout);

    let result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await;

    match result {
        Ok(Ok(_stream)) => HttpResponse::Ok().json(serde_json::json!({
            "host": body.host,
            "port": body.port,
            "open": true,
            "message": "端口开放",
        })),
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "host": body.host,
            "port": body.port,
            "open": false,
            "error": e.to_string(),
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "host": body.host,
            "port": body.port,
            "open": false,
            "error": format!("连接超时 ({}ms)", body.timeout),
        })),
    }
}

/// HTTP GET 请求：用 reqwest
pub async fn http_get(body: web::Json<HttpRequest>) -> impl Responder {
    let url = body.url.clone();
    let timeout = Duration::from_millis(body.timeout);

    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("创建 HTTP 客户端失败: {e}")
            }));
        }
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers: serde_json::Value = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>()
                .into();
            let body_text = resp.text().await.unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "url": url,
                "status": status,
                "headers": headers,
                "body": body_text,
                "body_length": body_text.len(),
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "url": url,
            "status": 0,
            "error": e.to_string(),
        })),
    }
}

/// DNS 查询（dig）：优先使用 tokio::net::lookup_host
pub async fn dig(body: web::Json<DnsRequest>) -> impl Responder {
    let domain = body.domain.clone();
    let record_type = body.record_type.to_uppercase();

    // 当前仅支持 A / AAAA 记录（通过系统解析器）
    if record_type != "A" && record_type != "AAAA" {
        // 尝试调用系统 dig 命令
        let domain_clone = domain.clone();
        let rt = record_type.clone();
        let dns_server = body.dns_server.clone();
        let output = tokio::task::spawn_blocking(move || {
            let mut args = vec!["+short".to_string(), "-t".to_string(), rt.clone(), domain_clone.clone()];
            if let Some(srv) = &dns_server {
                args.push(format!("@{}", srv));
            }
            Command::new("dig").args(&args).output()
        })
        .await;

        return match output {
            Ok(Ok(out)) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                HttpResponse::Ok().json(serde_json::json!({
                    "domain": domain,
                    "record_type": record_type,
                    "dns_server": body.dns_server,
                    "answers": stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect::<Vec<_>>(),
                    "raw": stdout,
                }))
            }
            Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
                "domain": domain,
                "record_type": record_type,
                "error": format!("dig 命令执行失败: {e}"),
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("dig 任务异常: {e}")
            })),
        };
    }

    // A/AAAA 记录：用 tokio lookup_host
    match tokio::net::lookup_host(format!("{}:0", domain)).await {
        Ok(addrs) => {
            let ips: Vec<String> = addrs
                .map(|a| a.ip().to_string())
                .filter(|ip| {
                    if record_type == "A" {
                        ip.parse::<Ipv4Addr>().is_ok()
                    } else {
                        ip.parse::<Ipv4Addr>().is_err()
                    }
                })
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "domain": domain,
                "record_type": record_type,
                "dns_server": body.dns_server,
                "answers": ips,
            }))
        }
        Err(e) => HttpResponse::Ok().json(serde_json::json!({
            "domain": domain,
            "record_type": record_type,
            "error": format!("DNS 解析失败: {e}"),
        })),
    }
}

/// 域名查询（nslookup）：与 dig 类似，返回更详细信息
pub async fn nslookup(body: web::Json<DnsRequest>) -> impl Responder {
    let domain = body.domain.clone();
    let record_type = body.record_type.to_uppercase();

    let domain_clone = domain.clone();
    let rt = record_type.clone();
    let dns_server = body.dns_server.clone();
    let output = tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("nslookup");
        cmd.arg(format!("-type={}", rt)).arg(&domain_clone);
        if let Some(srv) = &dns_server {
            cmd.arg(srv);
        }
        cmd.output()
    })
    .await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "domain": domain,
                "record_type": record_type,
                "dns_server": body.dns_server,
                "output": stdout,
                "stderr": stderr,
            }))
        }
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "domain": domain,
            "record_type": record_type,
            "error": format!("nslookup 命令执行失败: {e}"),
            "hint": "系统可能未安装 nslookup",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("nslookup 任务异常: {e}")
        })),
    }
}

/// 路由跟踪（traceroute）：调用系统 traceroute / tracert
pub async fn traceroute(body: web::Json<TracerouteRequest>) -> impl Responder {
    let host = body.host.clone();
    let max_hops = body.max_hops;
    let timeout_secs = (body.timeout as f64 / 1000.0).max(1.0) as u64;

    let args: Vec<String> = if cfg!(target_os = "windows") {
        vec![
            "-d".to_string(),
            "-h".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            timeout_secs.to_string(),
            host.clone(),
        ]
    } else {
        vec![
            "-n".to_string(),
            "-m".to_string(),
            max_hops.to_string(),
            "-w".to_string(),
            timeout_secs.to_string(),
            host.clone(),
        ]
    };

    let cmd_name = if cfg!(target_os = "windows") {
        "tracert"
    } else {
        "traceroute"
    };

    let output = tokio::task::spawn_blocking(move || {
        Command::new(cmd_name).args(&args).output()
    })
    .await;

    match output {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "host": host,
                "max_hops": max_hops,
                "output": stdout,
            }))
        }
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "host": host,
            "error": format!("traceroute 命令执行失败: {e}"),
            "hint": "系统可能未安装 traceroute，或需要 root 权限",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("traceroute 任务异常: {e}")
        })),
    }
}

/// Whois 查询：连接 whois 服务器（TCP 43 端口）
pub async fn whois(body: web::Json<WhoisRequest>) -> impl Responder {
    let query = body.query.clone();

    // 选择 whois 服务器（简化处理）
    let whois_server = if query.ends_with(".com") || query.ends_with(".net") {
        "whois.verisign-grs.com"
    } else if query.ends_with(".org") {
        "whois.pir.org"
    } else if query.ends_with(".cn") {
        "whois.cnnic.cn"
    } else {
        "whois.iana.org"
    };

    let addr = format!("{}:43", whois_server);
    let timeout = Duration::from_secs(10);

    let result = tokio::time::timeout(timeout, async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(&addr).await?;
        stream.write_all(format!("{}\r\n", query).as_bytes()).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
    })
    .await;

    match result {
        Ok(Ok(text)) => HttpResponse::Ok().json(serde_json::json!({
            "query": query,
            "whois_server": whois_server,
            "result": text,
        })),
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "query": query,
            "whois_server": whois_server,
            "error": format!("Whois 查询失败: {e}"),
        })),
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "query": query,
            "whois_server": whois_server,
            "error": "Whois 查询超时",
        })),
    }
}

/// Nmap 快速端口扫描：调用 argus-portscanner
pub async fn nmap(body: web::Json<NmapRequest>) -> impl Responder {
    let target = body.target.clone();

    // 解析目标主机
    let ip = match argus_portscanner::host::resolve_host(&target).await {
        Some(ip) => ip,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("无法解析目标主机: {target}")
            }));
        }
    };

    // 解析端口列表
    let ports = match body.ports.as_str() {
        "top100" => argus_portscanner::port_list::top100_tcp_ports(),
        "top1000" => argus_portscanner::port_list::top1000_tcp_ports(),
        "full" => (1..=65535).collect::<Vec<u16>>(),
        other => match argus_portscanner::port_list::parse_port_range(other) {
            Ok(p) => p,
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("端口解析失败: {e}")
                }));
            }
        },
    };

    // 执行 TCP Connect 扫描
    let results =
        argus_portscanner::tcp::scan_tcp_ports_connect(&ip, &ports, 1000, 200, None).await;

    let open: Vec<serde_json::Value> = results
        .iter()
        .filter(|r| r.state == argus_portscanner::types::PortState::Open)
        .map(|r| {
            serde_json::json!({
                "port": r.port,
                "protocol": r.protocol.to_string(),
                "state": "open",
                "service": r.service,
                "banner": r.banner,
                "response_time_ms": r.response_time_ms,
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "target": target,
        "ip": ip,
        "ports_scanned": ports.len(),
        "open_count": open.len(),
        "open_ports": open,
    }))
}

/// 抓包：复用 argus-portscanner 的 PcapCapture
pub async fn capture(body: web::Json<CaptureRequest>) -> impl Responder {
    use argus_portscanner::pcap_capture::PcapCapture;

    let interface = body.interface.clone();
    let duration = Duration::from_secs(body.duration);
    let filter = body.filter.clone();

    // 抓包是阻塞操作，放在 spawn_blocking 中
    let interface_clone = interface.clone();
    let output_path = format!("/tmp/argus_diagnostic_capture_{}.pcap", uuid::Uuid::new_v4());
    let output_path_clone = output_path.clone();

    let capture_result = tokio::task::spawn_blocking(move || {
        let mut cap = PcapCapture::new(&interface_clone, filter.as_deref()).max_duration(duration);
        cap.start()?;
        // 等待 duration 时间（抓包线程内部已根据 max_duration 自动停止，
        // 但 start 是非阻塞的，这里 join 等待线程结束）
        std::thread::sleep(duration + Duration::from_millis(500));
        cap.stop();
        cap.save(&output_path_clone)?;
        Ok::<(usize, String), argus_portscanner::pcap_capture::CaptureError>((
            cap.packet_count(),
            output_path_clone,
        ))
    })
    .await;

    match capture_result {
        Ok(Ok((count, path))) => HttpResponse::Ok().json(serde_json::json!({
            "interface": interface,
            "duration_secs": body.duration,
            "filter": body.filter,
            "packet_count": count,
            "pcap_file": path,
        })),
        Ok(Err(e)) => HttpResponse::Ok().json(serde_json::json!({
            "interface": interface,
            "error": format!("抓包失败: {e}"),
            "hint": "可能需要 root 权限或接口名错误",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("抓包任务异常: {e}")
        })),
    }
}

// ==================== 辅助工具 API ====================

/// 编码（base64 / url / hex）
pub async fn encode(body: web::Json<EncodeRequest>) -> impl Responder {
    let result = match body.r#type.as_str() {
        "base64" => B64.encode(body.text.as_bytes()),
        "url" => urlencoding::encode(&body.text).to_string(),
        "hex" => hex::encode(body.text.as_bytes()),
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("不支持的编码类型: {other}，支持: base64, url, hex")
            }));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "type": body.r#type,
        "encoded": result,
    }))
}

/// 解码（base64 / url / hex）
pub async fn decode(body: web::Json<DecodeRequest>) -> impl Responder {
    let result = match body.r#type.as_str() {
        "base64" => match B64.decode(body.text.as_bytes()) {
            Ok(v) => String::from_utf8_lossy(&v).to_string(),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("base64 解码失败: {e}")
                }));
            }
        },
        "url" => match urlencoding::decode(&body.text) {
            Ok(s) => s.to_string(),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("URL 解码失败: {e}")
                }));
            }
        },
        "hex" => match hex::decode(&body.text) {
            Ok(v) => String::from_utf8_lossy(&v).to_string(),
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("hex 解码失败: {e}")
                }));
            }
        },
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("不支持的解码类型: {other}，支持: base64, url, hex")
            }));
        }
    };
    HttpResponse::Ok().json(serde_json::json!({
        "type": body.r#type,
        "decoded": result,
    }))
}

/// 哈希散列（md5 / sha1 / sha256 / sha512）
pub async fn hash(body: web::Json<HashRequest>) -> impl Responder {
    use md5::{Digest, Md5};
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Digest as Sha2Digest, Sha256, Sha512};

    let (hash_hex, hash_type) = match body.r#type.as_str() {
        "md5" => {
            let mut h = Md5::new();
            h.update(body.text.as_bytes());
            (hex::encode(h.finalize()), "md5".to_string())
        }
        "sha1" => {
            let mut h = Sha1::new();
            h.update(body.text.as_bytes());
            (hex::encode(h.finalize()), "sha1".to_string())
        }
        "sha256" => {
            let mut h = Sha256::new();
            h.update(body.text.as_bytes());
            (hex::encode(h.finalize()), "sha256".to_string())
        }
        "sha512" => {
            let mut h = Sha512::new();
            h.update(body.text.as_bytes());
            (hex::encode(h.finalize()), "sha512".to_string())
        }
        other => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("不支持的哈希类型: {other}，支持: md5, sha1, sha256, sha512")
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "type": hash_type,
        "hash": hash_hex,
    }))
}

/// 加密（AES-256-GCM）
pub async fn encrypt(body: web::Json<EncryptRequest>) -> impl Responder {
    if body.r#type != "aes" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("不支持的加密类型: {}，当前仅支持 aes", body.r#type)
        }));
    }

    // 密钥需要 32 字节（AES-256），不足则填充，过长则截断
    let key_bytes = body.key.as_bytes();
    let mut key = [0u8; 32];
    let len = key_bytes.len().min(32);
    key[..len].copy_from_slice(&key_bytes[..len]);

    use rand_core::RngCore;

    let cipher = Aes256Gcm::new(&key.into());
    // 生成 12 字节随机 nonce（AES-GCM 推荐 nonce 长度）
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = *Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(&nonce, body.text.as_bytes()) {
        Ok(ct) => ct,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("加密失败: {e}")
            }));
        }
    };

    // 输出格式: base64(nonce + ciphertext)
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    let encoded = B64.encode(&combined);

    HttpResponse::Ok().json(serde_json::json!({
        "type": "aes-256-gcm",
        "ciphertext": encoded,
    }))
}

/// 解密（AES-256-GCM）
pub async fn decrypt(body: web::Json<DecryptRequest>) -> impl Responder {
    if body.r#type != "aes" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("不支持的解密类型: {}，当前仅支持 aes", body.r#type)
        }));
    }

    let key_bytes = body.key.as_bytes();
    let mut key = [0u8; 32];
    let len = key_bytes.len().min(32);
    key[..len].copy_from_slice(&key_bytes[..len]);

    // 解析 base64 并分离 nonce (前 12 字节) 和 ciphertext
    let combined = match B64.decode(body.ciphertext.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("ciphertext base64 解码失败: {e}")
            }));
        }
    };

    if combined.len() < 12 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "密文格式错误，长度不足"
        }));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(&key.into());
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => pt,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("解密失败: {e}，密钥或密文可能不正确")
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "type": "aes-256-gcm",
        "plaintext": String::from_utf8_lossy(&plaintext).to_string(),
    }))
}

/// 子网掩码计算（IPv4）
pub async fn subnet(body: web::Json<SubnetRequest>) -> impl Responder {
    let cidr = body.cidr.trim();

    // 解析 CIDR: a.b.c.d/n
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "CIDR 格式错误，应为 a.b.c.d/n"
        }));
    }

    let ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("无效的 IPv4 地址: {}", parts[0])
            }));
        }
    };

    let prefix: u32 = match parts[1].parse() {
        Ok(n) if n <= 32 => n,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("无效的前缀长度: {} (0-32)", parts[1])
            }));
        }
    };

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0u32
    } else {
        (!0u32) << (32 - prefix)
    };
    let network = ip_u32 & mask;
    let broadcast = if prefix == 32 {
        network
    } else if prefix == 0 {
        !0u32
    } else {
        network | !mask
    };
    let wildcard = !mask;
    let netmask = Ipv4Addr::from(mask);
    let network_addr = Ipv4Addr::from(network);
    let broadcast_addr = Ipv4Addr::from(broadcast);

    // 可用主机范围
    let total_hosts = if prefix >= 31 {
        1u64 << (32 - prefix)
    } else {
        (1u64 << (32 - prefix)) - 2
    };
    let first_host = if prefix >= 31 {
        network_addr
    } else {
        Ipv4Addr::from(network + 1)
    };
    let last_host = if prefix >= 31 {
        broadcast_addr
    } else {
        Ipv4Addr::from(broadcast - 1)
    };

    HttpResponse::Ok().json(serde_json::json!({
        "cidr": cidr,
        "ip_address": ip.to_string(),
        "network_address": network_addr.to_string(),
        "broadcast_address": broadcast_addr.to_string(),
        "netmask": netmask.to_string(),
        "wildcard": Ipv4Addr::from(wildcard).to_string(),
        "prefix_length": prefix,
        "total_hosts": total_hosts,
        "first_host": first_host.to_string(),
        "last_host": last_host.to_string(),
        "ip_class": match ip.octets()[0] {
            0..=127 => "A",
            128..=191 => "B",
            192..=223 => "C",
            224..=239 => "D (组播)",
            _ => "E (保留)",
        },
    }))
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_cidr_24() {
        let req = SubnetRequest {
            cidr: "192.168.1.0/24".to_string(),
        };
        // 通过 actix handler 不易直接测，直接测核心逻辑
        let parts: Vec<&str> = req.cidr.split('/').collect();
        let ip: Ipv4Addr = parts[0].parse().unwrap();
        let prefix: u32 = parts[1].parse().unwrap();
        let ip_u32 = u32::from(ip);
        let mask = (!0u32) << (32 - prefix);
        let network = ip_u32 & mask;
        assert_eq!(Ipv4Addr::from(network).to_string(), "192.168.1.0");
        assert_eq!(Ipv4Addr::from(mask).to_string(), "255.255.255.0");
    }

    #[test]
    fn test_subnet_cidr_30() {
        let parts: Vec<&str> = "10.0.0.0/30".split('/').collect();
        let ip: Ipv4Addr = parts[0].parse().unwrap();
        let prefix: u32 = parts[1].parse().unwrap();
        let ip_u32 = u32::from(ip);
        let mask = (!0u32) << (32 - prefix);
        let broadcast = (ip_u32 & mask) | !mask;
        assert_eq!(Ipv4Addr::from(broadcast).to_string(), "10.0.0.3");
    }

    #[test]
    fn test_base64_encode_decode() {
        let text = "hello argus";
        let encoded = B64.encode(text.as_bytes());
        let decoded = B64.decode(encoded.as_bytes()).unwrap();
        assert_eq!(String::from_utf8_lossy(&decoded), text);
    }

    #[test]
    fn test_hex_encode_decode() {
        let text = "test";
        let encoded = hex::encode(text.as_bytes());
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(String::from_utf8_lossy(&decoded), text);
    }

    #[test]
    fn test_sha256_hash() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"hello");
        let result = hex::encode(h.finalize());
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_md5_hash() {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(b"hello");
        let result = hex::encode(h.finalize());
        assert_eq!(result, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        use rand_core::RngCore;
        let key = "this-is-a-32-byte-secret-key!!!!".as_bytes();
        let mut key_arr = [0u8; 32];
        let len = key.len().min(32);
        key_arr[..len].copy_from_slice(&key[..len]);

        let cipher = Aes256Gcm::new(&key_arr.into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = *Nonce::from_slice(&nonce_bytes);
        let plaintext = b"secret data";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
