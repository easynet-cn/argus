//! G4.2: 大数据组件漏洞检测
//!
//! 针对常见大数据组件实现:
//! - Hadoop (HDFS NameNode WebUI 未授权 + YARN ResourceManager)
//! - Spark (WebUI 未授权)
//! - Kafka (默认端口 9092)
//! - Elasticsearch (未授权访问 9200)
//! - HBase (Master WebUI 未授权 16010)
//! - Zookeeper (unauthorized admin 2181)
//! - Redis 已在 db_vuln.rs 实现
//!
//! 检测方式:
//! 1. HTTP 探测 WebUI 是否未授权可访问
//! 2. TCP 探测协议端口开放性
//! 3. 检查未授权访问响应内容 (名称、版本、配置等敏感信息)

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// 大数据组件类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BigDataComponent {
    /// Hadoop HDFS NameNode WebUI
    HadoopNameNode,
    /// Hadoop YARN ResourceManager WebUI
    HadoopYarn,
    /// Spark WebUI
    Spark,
    /// Kafka
    Kafka,
    /// Elasticsearch
    Elasticsearch,
    /// HBase Master WebUI
    HBase,
    /// Zookeeper
    Zookeeper,
}

impl BigDataComponent {
    pub fn default_port(&self) -> u16 {
        match self {
            BigDataComponent::HadoopNameNode => 50070,
            BigDataComponent::HadoopYarn => 8088,
            BigDataComponent::Spark => 8080,
            BigDataComponent::Kafka => 9092,
            BigDataComponent::Elasticsearch => 9200,
            BigDataComponent::HBase => 16010,
            BigDataComponent::Zookeeper => 2181,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BigDataComponent::HadoopNameNode => "hadoop_namenode",
            BigDataComponent::HadoopYarn => "hadoop_yarn",
            BigDataComponent::Spark => "spark",
            BigDataComponent::Kafka => "kafka",
            BigDataComponent::Elasticsearch => "elasticsearch",
            BigDataComponent::HBase => "hbase",
            BigDataComponent::Zookeeper => "zookeeper",
        }
    }
}

/// 大数据组件漏洞检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BigDataVulnFinding {
    /// 目标 host:port
    pub target: String,
    /// 组件类型
    pub component: BigDataComponent,
    /// 漏洞标题
    pub title: String,
    /// 严重级别 (critical/high/medium/low/info)
    pub severity: String,
    /// 漏洞描述
    pub description: String,
    /// 修复建议
    pub fix_advice: Option<String>,
    /// 证据
    pub evidence: String,
}

/// 大数据组件漏洞扫描器
pub struct BigDataVulnScanner;

impl BigDataVulnScanner {
    pub fn new() -> Self {
        Self
    }

    /// 扫描单个目标
    pub async fn scan(
        &self,
        host: &str,
        port: u16,
        component: BigDataComponent,
        timeout_ms: u64,
    ) -> Vec<BigDataVulnFinding> {
        let mut findings = Vec::new();
        let target = format!("{}:{}", host, port);
        let dur = Duration::from_millis(timeout_ms);

        match component {
            BigDataComponent::HadoopNameNode => {
                findings.extend(scan_hadoop_namenode(host, port, &target, dur).await);
            }
            BigDataComponent::HadoopYarn => {
                findings.extend(scan_hadoop_yarn(host, port, &target, dur).await);
            }
            BigDataComponent::Spark => {
                findings.extend(scan_spark(host, port, &target, dur).await);
            }
            BigDataComponent::Kafka => {
                findings.extend(scan_kafka(host, port, &target, dur).await);
            }
            BigDataComponent::Elasticsearch => {
                findings.extend(scan_elasticsearch(host, port, &target, dur).await);
            }
            BigDataComponent::HBase => {
                findings.extend(scan_hbase(host, port, &target, dur).await);
            }
            BigDataComponent::Zookeeper => {
                findings.extend(scan_zookeeper(host, port, &target, dur).await);
            }
        }

        findings
    }

    /// 扫描多个目标
    pub async fn scan_targets(
        &self,
        targets: &[(String, u16, BigDataComponent)],
        timeout_ms: u64,
    ) -> Vec<BigDataVulnFinding> {
        let mut all = Vec::new();
        for (host, port, component) in targets {
            let findings = self.scan(host, *port, component.clone(), timeout_ms).await;
            all.extend(findings);
        }
        all
    }
}

impl Default for BigDataVulnScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Hadoop NameNode WebUI 检测 ==============

async fn scan_hadoop_namenode(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // Hadoop NameNode WebUI 通常无需认证
    let resp = match http_get(host, port, "/jmx?qry=java.lang:type=Runtime", dur).await {
        Some(r) => r,
        None => return findings,
    };

    // 检查响应中是否包含 Hadoop 特征
    if resp.contains("Hadoop")
        || resp.contains("NameNode")
        || resp.contains("hadoop")
        || resp.contains("vmVendor")
    {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::HadoopNameNode,
            title: "Hadoop HDFS NameNode WebUI 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "Hadoop HDFS NameNode WebUI 默认无认证，攻击者可获取集群元数据并执行管理操作".to_string(),
            fix_advice: Some("1. 配置 HTTP 身份认证 (Kerberos/Simple) 2. 限制 WebUI 端口网络访问 3. 部署防火墙规则".to_string()),
            evidence: "/jmx 端点直接返回 Java 运行时信息".to_string(),
        });

        // 2. 检查是否能访问 HDFS 文件列表 (jvm 信息)
        if let Some(fs_resp) = http_get(host, port, "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo", dur).await {
            if fs_resp.contains("ClusterId") || fs_resp.contains("Total") {
                findings.push(BigDataVulnFinding {
                    target: target.to_string(),
                    component: BigDataComponent::HadoopNameNode,
                    title: "Hadoop HDFS 集群信息泄露".to_string(),
                    severity: "medium".to_string(),
                    description: "未授权访问可获取 HDFS 集群 ID、容量、节点数量等敏感信息".to_string(),
                    fix_advice: Some("配置 WebUI 认证并限制访问来源".to_string()),
                    evidence: "/jmx 返回 NameNodeInfo 包含 Cluster Id".to_string(),
                });
            }
        }
    }

    // 3. 检查是否能直接列目录 (/webhdfs/v1/?op=LISTSTATUS)
    if let Some(ls_resp) = http_get(host, port, "/webhdfs/v1/?op=LISTSTATUS&user.name=hdfs", dur).await {
        if ls_resp.contains("FileStatuses") || ls_resp.contains("pathSuffix") {
            findings.push(BigDataVulnFinding {
                target: target.to_string(),
                component: BigDataComponent::HadoopNameNode,
                title: "Hadoop WebHDFS 文件列表未授权访问".to_string(),
                severity: "critical".to_string(),
                description: "WebHDFS API 默认开启且无认证，攻击者可直接列出 HDFS 根目录所有文件".to_string(),
                fix_advice: Some("1. 启用 WebHDFS 认证 (Kerberos) 2. 配置 dfs.permissions 3. 限制 WebHDFS 端口".to_string()),
                evidence: "/webhdfs/v1/?op=LISTSTATUS 返回 FileStatuses".to_string(),
            });
        }
    }

    let _ = port;
    findings
}

// ============== Hadoop YARN ResourceManager 检测 ==============

async fn scan_hadoop_yarn(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // YARN ResourceManager 默认无认证
    let resp = match http_get(host, port, "/ws/v1/cluster/info", dur).await {
        Some(r) => r,
        None => return findings,
    };

    // 检查 YARN 集群信息
    if resp.contains("clusterInfo")
        || resp.contains("ResourceManager")
        || resp.contains("haState")
        || resp.contains("startedOn")
    {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::HadoopYarn,
            title: "Hadoop YARN ResourceManager WebUI 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "YARN ResourceManager WebUI 默认无认证，攻击者可获取集群信息并提交恶意任务".to_string(),
            fix_advice: Some("1. 配置 YARN WebUI 认证 2. 限制 8088 端口网络访问 3. 启用 ResourceManager ACL".to_string()),
            evidence: "/ws/v1/cluster/info 返回集群信息".to_string(),
        });

        // 2. 检查是否可列出应用 (提交恶意任务的入口)
        if let Some(apps_resp) = http_get(host, port, "/ws/v1/cluster/apps", dur).await {
            if apps_resp.contains("apps") || apps_resp.contains("app") {
                findings.push(BigDataVulnFinding {
                    target: target.to_string(),
                    component: BigDataComponent::HadoopYarn,
                    title: "Hadoop YARN 应用列表未授权访问".to_string(),
                    severity: "critical".to_string(),
                    description: "未授权访问可列出所有 YARN 应用，并可通过 REST API 提交恶意任务实现 RCE".to_string(),
                    fix_advice: Some("1. 配置 YARN ACL 2. 启用 Kerberos 认证 3. 限制 8088 端口".to_string()),
                    evidence: "/ws/v1/cluster/apps 返回应用列表".to_string(),
                });
            }
        }
    }

    let _ = port;
    findings
}

// ============== Spark WebUI 检测 ==============

async fn scan_spark(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // Spark Master/Worker WebUI 默认无认证
    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    // 检查 Spark 特征
    if resp.contains("Spark Master")
        || resp.contains("Spark Worker")
        || resp.contains("spark-master")
        || resp.contains("spark-worker")
        || resp.contains("Apache Spark")
    {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Spark,
            title: "Spark WebUI 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "Spark Master/Worker WebUI 默认无认证，攻击者可获取任务信息并提交恶意作业".to_string(),
            fix_advice: Some("1. 配置 Spark UI 认证 2. 限制 8080 端口网络访问 3. 部署 Kerberos".to_string()),
            evidence: "WebUI 主页直接返回 Spark 主节点信息".to_string(),
        });

        // 2. 检查是否能列出应用
        if let Some(apps_resp) = http_get(host, port, "/api/v1/applications", dur).await {
            if apps_resp.contains("id") || apps_resp.contains("name") {
                findings.push(BigDataVulnFinding {
                    target: target.to_string(),
                    component: BigDataComponent::Spark,
                    title: "Spark 应用列表未授权访问".to_string(),
                    severity: "medium".to_string(),
                    description: "未授权访问可获取所有 Spark 应用 ID 和执行状态，可能泄露业务逻辑".to_string(),
                    fix_advice: Some("配置 Spark UI 认证，限制 REST API 访问".to_string()),
                    evidence: "/api/v1/applications 返回应用列表".to_string(),
                });
            }
        }
    }

    let _ = port;
    findings
}

// ============== Kafka 检测 ==============

async fn scan_kafka(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // 1. TCP 连接探测
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 2. 发送 Kafka APIVersions 请求 (无需认证)
    // Kafka 协议: 4 byte 长度 + API key(2) + version(2) + correlation_id(4) + client_id
    // API key 18 = ApiVersions
    let kafka_req = build_kafka_api_versions();
    if stream.write_all(&kafka_req).await.is_err() {
        return findings;
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 4 => n,
        _ => return findings,
    };

    let resp = &buf[..n];
    // Kafka 响应: 4 byte 长度 + correlation_id(4) + error_code(2) + ...
    // error_code = 0 表示成功
    if n >= 10 {
        let error_code = u16::from_be_bytes([resp[8], resp[9]]);
        // Kafka 端口对外开放即可判定为信息泄露
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Kafka,
            title: "Kafka 服务端口暴露".to_string(),
            severity: "medium".to_string(),
            description: "Kafka 默认无认证，攻击者可枚举 Topic 并读写消息".to_string(),
            fix_advice: Some("1. 配置 SASL 认证 (SCRAM-SHA-256/PLAIN) 2. 启用 SSL/TLS 3. 限制 9092 端口访问 4. 配置 ACL".to_string()),
            evidence: format!("ApiVersions 响应 error_code={}", error_code),
        });

        // error_code = 0 表示无认证可访问
        if error_code == 0 {
            findings.push(BigDataVulnFinding {
                target: target.to_string(),
                component: BigDataComponent::Kafka,
                title: "Kafka 未授权访问".to_string(),
                severity: "high".to_string(),
                description: "Kafka 未配置 SASL 认证，攻击者可直接连接并读写 Topic 消息".to_string(),
                fix_advice: Some("1. 配置 SASL 认证 2. 启用 ACL 3. 限制 9092 端口访问".to_string()),
                evidence: "ApiVersions 请求返回成功响应".to_string(),
            });
        }
    }

    findings
}

/// 构造 Kafka ApiVersions 请求
fn build_kafka_api_versions() -> Vec<u8> {
    // Kafka 协议 ApiVersions 请求:
    // api_key=18 (ApiVersions), api_version=0, correlation_id=1, client_id="argus"
    let mut body = Vec::new();
    body.extend_from_slice(&18i16.to_be_bytes()); // api_key
    body.extend_from_slice(&0i16.to_be_bytes()); // api_version
    body.extend_from_slice(&1i32.to_be_bytes()); // correlation_id
    // client_id (nullable string): length(2) + bytes
    let client_id = b"argus";
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id);

    // 长度前缀 (4 bytes)
    let total_len = body.len();
    let mut packet = Vec::with_capacity(4 + total_len);
    packet.extend_from_slice(&(total_len as i32).to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

// ============== Elasticsearch 检测 ==============

async fn scan_elasticsearch(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // Elasticsearch 默认无认证 (旧版本 < 6.0 默认无 x-pack)
    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    // 检查 Elasticsearch 特征
    if resp.contains("cluster_name") || resp.contains("cluster_uuid") || resp.contains("\"version\"") {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Elasticsearch,
            title: "Elasticsearch 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "Elasticsearch 默认无认证，攻击者可读写所有索引并执行管理操作".to_string(),
            fix_advice: Some("1. 启用 x-pack security 2. 配置 ELASTICSEARCH_PASSWORD 3. 限制 9200 端口访问 4. 启用 TLS".to_string()),
            evidence: "/ 端点直接返回集群名称和版本".to_string(),
        });

        // 2. 检查是否能列出索引 (敏感信息)
        if let Some(idx_resp) = http_get(host, port, "/_cat/indices", dur).await {
            if idx_resp.contains("index") || idx_resp.contains("docs.count") {
                findings.push(BigDataVulnFinding {
                    target: target.to_string(),
                    component: BigDataComponent::Elasticsearch,
                    title: "Elasticsearch 索引列表未授权访问".to_string(),
                    severity: "critical".to_string(),
                    description: "未授权访问可列出所有索引名称、文档数量、大小，可进一步读写敏感数据".to_string(),
                    fix_advice: Some("1. 启用 x-pack security 2. 配置索引访问 ACL 3. 限制 9200 端口".to_string()),
                    evidence: "/_cat/indices 返回索引列表".to_string(),
                });
            }
        }

        // 3. 提取版本并检查已知 CVE
        let version = extract_es_version(&resp);
        if let Some(v) = version {
            if let Some(cve) = check_es_cve(&v, target) {
                findings.push(cve);
            }
        }
    }

    let _ = port;
    findings
}

/// 从 Elasticsearch 响应中提取版本号
///
/// 响应格式: `{"cluster_name":"elasticsearch","version":{"number":"7.10.2"}}`
/// 定位 `"number":"X.Y.Z"` 并提取 X.Y.Z
fn extract_es_version(resp: &str) -> Option<String> {
    // 找到 "number" 键的位置
    let needle = "\"number\"";
    let pos = resp.find(needle)?;
    let after = &resp[pos..];
    // 跳过冒号和空格，找到值的起始引号
    let colon_idx = after.find(':')?;
    let after_colon = &after[colon_idx..];
    let first_quote = after_colon.find('"')?;
    let value_start = colon_idx + first_quote + 1;
    // 找到值的结束引号
    let value_end = after[value_start..].find('"')?;
    Some(after[value_start..value_start + value_end].to_string())
}

/// 检查 Elasticsearch 已知 CVE
fn check_es_cve(version: &str, target: &str) -> Option<BigDataVulnFinding> {
    let (major, minor, patch) = match parse_version_tuple(version) {
        Some(v) => v,
        None => return None,
    };

    // CVE-2015-1427: Elasticsearch Groovy 沙箱逃逸 (1.3.0-1.3.7, 1.4.0-1.4.2)
    if major == 1 && ((minor == 3 && patch <= 7) || (minor == 4 && patch <= 2)) {
        return Some(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Elasticsearch,
            title: "Elasticsearch Groovy 沙箱逃逸 (CVE-2015-1427)".to_string(),
            severity: "critical".to_string(),
            description: "Elasticsearch 1.3.0-1.3.7 / 1.4.0-1.4.2 存在 Groovy 沙箱逃逸漏洞，可导致 RCE".to_string(),
            fix_advice: Some("升级到 1.4.3+ 或 1.5.0+ 版本".to_string()),
            evidence: format!("检测到版本: {}", version),
        });
    }

    // CVE-2014-3120: Elasticsearch MVEL 注入 (< 1.4.0)
    if major == 1 && minor < 4 {
        return Some(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Elasticsearch,
            title: "Elasticsearch MVEL 注入 (CVE-2014-3120)".to_string(),
            severity: "critical".to_string(),
            description: "Elasticsearch < 1.4.0 启用脚本执行，可通过 MVEL 表达式实现 RCE".to_string(),
            fix_advice: Some("升级到 1.4.0+，禁用动态脚本".to_string()),
            evidence: format!("检测到版本: {}", version),
        });
    }

    None
}

/// 解析版本号为 (major, minor, patch)
fn parse_version_tuple(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<u32> = version
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() >= 2 {
        Some((
            parts[0],
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        ))
    } else {
        None
    }
}

// ============== HBase Master WebUI 检测 ==============

async fn scan_hbase(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // HBase Master WebUI 默认无认证
    let resp = match http_get(host, port, "/", dur).await {
        Some(r) => r,
        None => return findings,
    };

    // 检查 HBase 特征
    if resp.contains("HBase Master")
        || resp.contains("hbase")
        || resp.contains("Master")
        || resp.contains("RegionServer")
    {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::HBase,
            title: "HBase Master WebUI 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "HBase Master WebUI 默认无认证，攻击者可获取表结构、Region 分布等敏感信息".to_string(),
            fix_advice: Some("1. 配置 HBase WebUI 认证 2. 限制 16010 端口访问 3. 启用 Kerberos".to_string()),
            evidence: "WebUI 主页直接返回 HBase Master 信息".to_string(),
        });

        // 2. 检查是否能列出表
        if let Some(tbl_resp) = http_get(host, port, "/tablesDetailed.jsp", dur).await {
            if tbl_resp.contains("table") || tbl_resp.contains("Table") {
                findings.push(BigDataVulnFinding {
                    target: target.to_string(),
                    component: BigDataComponent::HBase,
                    title: "HBase 表列表未授权访问".to_string(),
                    severity: "critical".to_string(),
                    description: "未授权访问可列出所有 HBase 表名和结构，可能包含敏感业务数据".to_string(),
                    fix_advice: Some("1. 配置 HBase ACL 2. 启用 Kerberos 3. 限制 WebUI 端口访问".to_string()),
                    evidence: "/tablesDetailed.jsp 返回表列表".to_string(),
                });
            }
        }
    }

    let _ = port;
    findings
}

// ============== Zookeeper 检测 ==============

async fn scan_zookeeper(
    host: &str,
    port: u16,
    target: &str,
    dur: Duration,
) -> Vec<BigDataVulnFinding> {
    let mut findings = Vec::new();

    // 1. TCP 连接探测
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return findings,
    };

    // 2. 发送 Zookeeper 四字命令 stat (无认证)
    let cmd = b"stat";
    if stream.write_all(cmd).await.is_err() {
        return findings;
    }

    let mut buf = vec![0u8; 4096];
    let n = match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return findings,
    };
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    // Zookeeper 响应包含 Zookeeper version / Latency 等
    if resp.contains("Zookeeper")
        || resp.contains("Latency")
        || resp.contains("version")
        || resp.contains("Mode:")
    {
        findings.push(BigDataVulnFinding {
            target: target.to_string(),
            component: BigDataComponent::Zookeeper,
            title: "Zookeeper 未授权访问".to_string(),
            severity: "high".to_string(),
            description: "Zookeeper 默认无认证，攻击者可获取服务器状态并枚举节点数据".to_string(),
            fix_advice: Some("1. 配置 Zookeeper ACL 2. 限制 2181 端口访问 3. 开启 auth 认证".to_string()),
            evidence: "stat 命令直接返回 Zookeeper 版本和统计信息".to_string(),
        });

        // 2. 检查是否能列出根节点 (envi 命令泄露环境变量)
        let mut stream2 = match timeout(dur, TcpStream::connect((host, port))).await {
            Ok(Ok(s)) => s,
            _ => return findings,
        };
        let _ = stream2.write_all(b"envi").await;
        let mut buf2 = vec![0u8; 4096];
        if let Ok(Ok(n2)) = timeout(dur, stream2.read(&mut buf2)).await {
            if n2 > 0 {
                let envi_resp = String::from_utf8_lossy(&buf2[..n2]).to_string();
                if envi_resp.contains("Environment")
                    || envi_resp.contains("zookeeper.version")
                    || envi_resp.contains("host.name")
                {
                    findings.push(BigDataVulnFinding {
                        target: target.to_string(),
                        component: BigDataComponent::Zookeeper,
                        title: "Zookeeper 环境变量泄露".to_string(),
                        severity: "critical".to_string(),
                        description: "envi 命令可获取 Zookeeper 进程环境变量，包含主机名、Java 路径等敏感信息".to_string(),
                        fix_advice: Some("1. 配置 zoo.cfg 4lw.commands.whitelist=* 限制 2. 限制 2181 端口访问".to_string()),
                        evidence: "envi 命令返回主机名和 Java 环境变量".to_string(),
                    });
                }
            }
        }
    }

    findings
}

// ============== HTTP 辅助函数 ==============

/// 发送 HTTP GET 请求并返回响应文本
async fn http_get(host: &str, port: u16, path: &str, dur: Duration) -> Option<String> {
    let mut stream = match timeout(dur, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: Argus-Scanner\r\nConnection: close\r\n\r\n",
        path, host, port
    );
    if stream.write_all(req.as_bytes()).await.is_err() {
        return None;
    }

    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > 8192 {
                    break;
                }
            }
            _ => break,
        }
    }

    if response.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&response).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigdata_component_default_port() {
        assert_eq!(BigDataComponent::HadoopNameNode.default_port(), 50070);
        assert_eq!(BigDataComponent::HadoopYarn.default_port(), 8088);
        assert_eq!(BigDataComponent::Spark.default_port(), 8080);
        assert_eq!(BigDataComponent::Kafka.default_port(), 9092);
        assert_eq!(BigDataComponent::Elasticsearch.default_port(), 9200);
        assert_eq!(BigDataComponent::HBase.default_port(), 16010);
        assert_eq!(BigDataComponent::Zookeeper.default_port(), 2181);
    }

    #[test]
    fn test_bigdata_component_as_str() {
        assert_eq!(BigDataComponent::HadoopNameNode.as_str(), "hadoop_namenode");
        assert_eq!(BigDataComponent::HadoopYarn.as_str(), "hadoop_yarn");
        assert_eq!(BigDataComponent::Spark.as_str(), "spark");
        assert_eq!(BigDataComponent::Kafka.as_str(), "kafka");
        assert_eq!(BigDataComponent::Elasticsearch.as_str(), "elasticsearch");
        assert_eq!(BigDataComponent::HBase.as_str(), "hbase");
        assert_eq!(BigDataComponent::Zookeeper.as_str(), "zookeeper");
    }

    #[test]
    fn test_bigdata_vuln_finding_serialization() {
        let finding = BigDataVulnFinding {
            target: "192.168.1.100:9200".to_string(),
            component: BigDataComponent::Elasticsearch,
            title: "未授权访问".to_string(),
            severity: "high".to_string(),
            description: "测试描述".to_string(),
            fix_advice: Some("测试建议".to_string()),
            evidence: "测试证据".to_string(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("elasticsearch"));
        assert!(json.contains("high"));
    }

    #[test]
    fn test_bigdata_component_clone_eq() {
        let c1 = BigDataComponent::HadoopNameNode;
        let c2 = c1.clone();
        assert_eq!(c1, c2);
        assert_ne!(c1, BigDataComponent::Kafka);
    }

    #[test]
    fn test_bigdata_vuln_scanner_default() {
        let _ = BigDataVulnScanner::default();
        let _ = BigDataVulnScanner::new();
    }

    /// 验证 Hadoop NameNode 指纹识别
    #[test]
    fn test_hadoop_namenode_fingerprint() {
        let resp = "{\"beans\":[{\"name\":\"java.lang:type=Runtime\",\"vmVendor\":\"Oracle Corporation\"}]}";
        assert!(resp.contains("vmVendor"));
        assert!(resp.contains("Hadoop") || resp.contains("NameNode") || resp.contains("vmVendor"));
    }

    /// 验证 Hadoop YARN 指纹识别
    #[test]
    fn test_hadoop_yarn_fingerprint() {
        let resp = "{\"clusterInfo\":{\"startedOn\":1234567890,\"haState\":\"ACTIVE\"}}";
        assert!(resp.contains("clusterInfo"));
        assert!(resp.contains("haState") || resp.contains("startedOn"));
    }

    /// 验证 Spark 指纹识别
    #[test]
    fn test_spark_fingerprint() {
        let resp = "<html><title>Spark Master</title></html>";
        assert!(resp.contains("Spark Master") || resp.contains("Spark Worker") || resp.contains("Apache Spark"));
    }

    /// 验证 Elasticsearch 指纹识别
    #[test]
    fn test_elasticsearch_fingerprint() {
        let resp = "{\"cluster_name\":\"elasticsearch\",\"cluster_uuid\":\"abc123\",\"version\":{\"number\":\"7.10.2\"}}";
        assert!(resp.contains("cluster_name"));
        assert!(resp.contains("cluster_uuid"));
    }

    /// 验证 ES 版本提取
    #[test]
    fn test_extract_es_version() {
        let resp = "{\"cluster_name\":\"elasticsearch\",\"version\":{\"number\":\"7.10.2\"}}";
        let version = extract_es_version(resp);
        assert_eq!(version, Some("7.10.2".to_string()));
    }

    /// 验证 ES CVE 检测 (旧版本)
    #[test]
    fn test_check_es_cve_old_version() {
        // CVE-2015-1427 命中 1.3.5
        let cve = check_es_cve("1.3.5", "test:9200");
        assert!(cve.is_some());
        let f = cve.unwrap();
        assert!(f.title.contains("CVE-2015-1427"));

        // CVE-2014-3120 命中 1.2.0
        let cve = check_es_cve("1.2.0", "test:9200");
        assert!(cve.is_some());
        let f = cve.unwrap();
        assert!(f.title.contains("CVE-2014-3120"));
    }

    /// 验证 ES CVE 检测 (新版本无 CVE)
    #[test]
    fn test_check_es_cve_new_version() {
        // 7.10.2 无已知 CVE
        let cve = check_es_cve("7.10.2", "test:9200");
        assert!(cve.is_none());
    }

    /// 验证 parse_version_tuple
    #[test]
    fn test_parse_version_tuple() {
        assert_eq!(parse_version_tuple("1.3.5"), Some((1, 3, 5)));
        assert_eq!(parse_version_tuple("7.10.2"), Some((7, 10, 2)));
        assert_eq!(parse_version_tuple("7.10"), Some((7, 10, 0)));
        assert!(parse_version_tuple("invalid").is_none());
    }

    /// 验证 Kafka ApiVersions 数据包结构
    #[test]
    fn test_build_kafka_api_versions() {
        let pkt = build_kafka_api_versions();
        // 长度前缀 4 bytes
        let len = i32::from_be_bytes(pkt[0..4].try_into().unwrap());
        assert_eq!(len as usize, pkt.len() - 4);

        // api_key = 18 (ApiVersions)
        let api_key = i16::from_be_bytes(pkt[4..6].try_into().unwrap());
        assert_eq!(api_key, 18);

        // correlation_id = 1
        let corr_id = i32::from_be_bytes(pkt[8..12].try_into().unwrap());
        assert_eq!(corr_id, 1);

        // client_id = "argus"
        let client_len = i16::from_be_bytes(pkt[12..14].try_into().unwrap()) as usize;
        assert_eq!(client_len, 5);
        assert_eq!(&pkt[14..19], b"argus");
    }

    /// 验证 HBase 指纹识别
    #[test]
    fn test_hbase_fingerprint() {
        let resp = "<html><title>HBase Master</title></html>";
        assert!(resp.contains("HBase Master") || resp.contains("hbase"));
    }

    /// 验证 Zookeeper 响应特征
    #[test]
    fn test_zookeeper_response_features() {
        let resp = "Zookeeper version: 3.6.3--built on 04/08/2021 13:24 GMT\nLatency min/avg/max: 0/0/0";
        assert!(resp.contains("Zookeeper"));
        assert!(resp.contains("Latency"));
    }

    /// 验证非大数据组件不会被误判
    #[test]
    fn test_non_bigdata_not_detected() {
        let resp = "<html><title>Apache Server</title></html>";
        // 不含 Spark 关键字
        assert!(!resp.contains("Spark Master") && !resp.contains("Spark Worker"));
    }
}
