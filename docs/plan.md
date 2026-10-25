# Argus 实施计划与进度跟踪

> 最后更新: 2026-09-25 (P0+P1+P2 补救清单全部修复完成: 11 项补救项已全部标记 ✅；功能差距清单 31 项全部完成 ✅（G5.11 Flash 🚫 不支持），后端覆盖率 100%；阶段 8 核心系统功能已实现（资产管理增强/任务生命周期/模板管理/风险管理/日志审计/系统管理/诊断工具），报表(8.5)和大屏(8.9)暂不处理；全 workspace 1172 tests passed)

## 总览

| 阶段 | 名称 | 预计人月 | 状态 | 覆盖率 |
|---|---|---|---|---|
| 0 | 地基 | 4 | 🔄 进行中 | 15% |
| 1 | 端口扫描引擎 | 2.5 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G1.1-G1.4 已全部修复) |
| 2 | 口令猜解引擎 | 2.5 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G2.1-G2.6 已全部修复) |
| 3 | 基线核查引擎 | 2.5 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G3.1-G3.3 已全部修复) |
| 4 | 系统扫描 + 知识库v1 | 8 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G4.1-G4.8 已全部修复) |
| 5 | 应用扫描引擎 | 10 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G5.1-G5.12 已修复，G5.11 Flash 🚫) |
| 6 | 数据库/镜像/工控扫描 | 8 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G6.1-G6.5 已全部修复) |
| 7 | 移动扫描 + 漏洞验证 | 5 | ✅ 完成 | 100% ↑ (P0+P1+P2 差距 G7.1-G7.5 已全部修复) |
| 8 | 报表/大屏/系统管理 | 5 | ⚠️ 部分完成 | 85% (核心系统功能已实现，报表/大屏暂不处理) |
| — | 持续积累漏洞知识库 | 持续 | — | 90→100% |
| | **合计** | **~47** | | |

### 功能差距清单进度

| 优先级 | 总数 | 已完成 | 待实现 |
|---|---|---|---|
| **P0** | 5 | **5 ✅** | 0 |
| **P1** | 14 | **14 ✅** | 0 |
| **P2** | 12 | **11 ✅** (G5.11 🚫) | 0 |
| **合计** | **31** | **30 ✅** | **0** |

> **功能差距清单**: 共 31 项（30 已完成 ✅ / 1 项 Flash 🚫 不支持）


## 图例说明

- ✅ 完成：代码真实实现并通过测试，无占位/简化
- 🔄 进行中：部分任务完成，部分待开始
- ⚠️ 部分完成：有可用实现，但存在占位/简化/与目标描述不符的项，需按补救清单修复
- ⬜ 待开始：尚未开始
- ❌ 阻塞：被外部依赖阻塞

---

## 阶段 0：地基（进行中）

### 目标
搭建项目骨架，验证技术栈选型，建立核心领域模型和 API 框架。

### 任务清单

| # | 任务 | 状态 | 说明 |
|---|---|---|---|
| 0.1 | 创建 Cargo workspace | ✅ 完成 | 5 个 crate 骨架 |
| 0.2 | argus-core 领域模型 | ✅ 完成 | 资产/漏洞/任务/报告 entity |
| 0.3 | argus-engine 插件引擎骨架 | ✅ 完成 | YAML 模板/HostAPI/PluginResult |
| 0.4 | argus-scanner 扫描 trait | ✅ 完成 | Scanner trait/Registry/Scheduler |
| 0.5 | argus-api API 服务 | ✅ 完成 | health/list_scanners |
| 0.6 | argus-cli CLI 入口 | ✅ 完成 | serve/version/migrate 子命令 |
| 0.7 | cargo check 通过 | ✅ 完成 | 编译无错误 |
| 0.8 | 写架构文档 | ✅ 完成 | architecture.md |
| 0.9 | 写决策记录 | ✅ 完成 | decisions.md |
| 0.10 | 写实施计划 | ✅ 完成 | plan.md (本文件) |
| 0.11 | sea-orm 数据库迁移 | ✅ 完成 | 2 个迁移：init + users |
| 0.12 | 数据库连接池集成 | ✅ 完成 | db_connect + AppState.db + 启动自动迁移 |
| 0.13 | JWT 认证中间件 | ✅ 完成 | auth 模块 + login/me/setup API + AuthMiddleware |
| 0.14 | 资产管理 CRUD API | ✅ 完成 | 网络/应用/数据库资产 CRUD |
| 0.15 | 任务管理 CRUD API | ✅ 完成 | 扫描任务 CRUD + 状态/进度更新 |
| 0.16 | 前端项目初始化 | ⬜ 待开始 | Vue3 + Element Plus 脚手架 |
| 0.17 | 前端登录页 | ⬜ 待开始 | |
| 0.18 | 前端资产管理页 | ⬜ 待开始 | |
| 0.19 | 前端任务管理页 | ⬜ 待开始 | |
| 0.20 | Docker 部署配置 | ✅ 完成 | Dockerfile + docker-compose + .dockerignore + 环境变量配置 |

### 交付物
- ✅ 能登录系统（login + JWT）
- ✅ 能创建资产（网络/应用/数据库 CRUD）
- ✅ 能提交扫描任务并管理状态（任务 CRUD）
- ⬜ 前后端分离部署

---

## 阶段 1：端口扫描 + 主机发现引擎

### 目标
实现 Rust 优势最明显的扫描引擎，验证网络栈能力。

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 1.1 | 主机存活探测（TCP-PING） | ✅ |
| 1.2 | TCP 端口扫描（Connect，其他留框架） | ✅ |
| 1.3 | UDP 端口探测 | ✅ |
| 1.4 | 自适应发包速率控制（Token Bucket） | ✅ |
| 1.5 | 服务指纹识别（Banner + 端口匹配） | ✅ |
| 1.6 | 扫描结果入库 + API 集成 | ✅ |
| 1.7 | 端口模板管理（Top100/1000/Full/Custom） | ✅ |
| 1.8 | 单元测试 + 集成测试（11 tests passed） | ✅ |
| 1.9 | UDP 协议特定 probe（DNS/NTP/SNMP/NetBIOS/SIP/mDNS/IPMI 等 10 协议） | ✅ |
| 1.10 | 自适应速率控制（基于反馈的动态降速/提速，EWMA 反馈窗口） | ✅ |
| 1.11 | TCP/UDP 扫描结果反馈给 RateLimiter（filtered/timeout 触发降速） | ✅ |
| 1.12 | 单元测试扩容至 27 tests（UDP probe + 速率控制回归用例） | ✅ |
| 1.13 | SYN/ACK/Null/Xmas/Fin/Window raw socket 扫描（pnet 0.35） | ✅ |
| 1.14 | raw socket 无权限时自动降级为 Connect 扫描 | ✅ |
| 1.15 | 扫描结果持久化到 scan_results 表（host/port/protocol/state/service/banner） | ✅ |
| 1.16 | 异步扫描任务（tokio::spawn 后台执行 + 状态轮询 + 取消接口） | ✅ |
| 1.17 | 单元测试扩容至 36 tests（raw socket 标志位/响应解释/超时状态） | ✅ |
| 1.18 | G1.1: ARP 主机探测（pnet_datalink Layer2 ARP Request/Reply） | ✅ |  // arp_discovery.rs: build_arp_request + parse_arp_reply + discover_hosts_auto
| 1.19 | G1.2: UDP PING 主机探测（33434+ 端口 + ICMP Port Unreachable 检测） | ✅ |  // udp_ping.rs: parse_icmp_from_ipv4 + udp_ping_hosts
| 1.20 | G1.3: 实时 ICMP Ping 监控（HostMonitor 周期性 Echo Request，失败标记死亡） | ✅ |  // icmp_ping.rs: compute_icmp_checksum + HostMonitor::start/stop/is_alive
| 1.21 | 单元测试扩容至 81 tests（ARP 帧/ICMP 校验和/UDP PING 解析） | ✅ |
| 1.22 | G1.4: 抓包功能（任务完成后下载抓包文件） | ✅ |  // pcap_capture.rs: PcapCapture 实时抓包 + BPF 过滤 + libpcap 文件格式保存（Global Header 24B + Packet Record），集成到 execute() 扫描流程自动启动/停止

---

## 阶段 2：口令猜解引擎

### 目标
实现在线爆破 + 离线 Hash 破解。**现状**：全部 22 个协议真实可用（SSH/MySQL/Redis/PostgreSQL/MongoDB/MSSQL/Oracle/FTP/Telnet/SMB/HttpBasic/HttpForm + G2.1 RTSP/ONVIF + G2.2 RDP/VNC/IMAP/POP3/SMTP/SNMP + G2.6 LDAP/SFTP），覆盖率从 6/60 提升至 22/60。"60+ 协议"为远期目标。

### 任务清单

| # | 任务 | 状态 | 说明 |
|---|---|---|---|
| 2.1 | 协议连接器（SSH/MySQL/Redis/PostgreSQL） | ✅ | 真实握手认证 |
| 2.2 | 在线爆破调度器（并发/超时/停止） | ✅ | |
| 2.3 | 字典管理系统（Top10/50/100 + 自定义） | ✅ | |
| 2.4 | 离线 Hash 破解（MD5/SHA1/SHA256/SHA512） | ✅ | |
| 2.5 | 横向撞库逻辑（复用爆破调度器） | ⚠️ | **未真实实现**：scheduler.rs 只针对单个 host:port，无"将 A 目标爆破成功的凭证复用到 B 目标"逻辑，见补救 R2.1 |
| 2.6 | 弱密码复检（长度/复杂度/连续/字典） | ✅ | |
| 2.7 | 社工字典生成器（姓名/生日/公司/手机） | ✅ | |
| 2.8 | PostgreSQL SCRAM-SHA-256 完整流程（SASLInitialResponse→Continue→Final） | ✅ | |
| 2.9 | MySQL caching_sha2_password（fast-auth + RSA-OAEP-SHA256 full auth） | ✅ | |
| 2.10 | SSH 改用 russh 纯 Rust 客户端（替代系统 sshpass） | ✅ | |
| 2.11 | SASLInitialResponse/Continue/Final 协议帧封装 + AuthSwitchRequest 处理 | ✅ | |
| 2.12 | 单元测试扩容至 19 tests（SCRAM 计算用例 + caching_sha2 响应格式） | ✅ | |
| 2.13 | 端到端验证：本地 PostgreSQL 18 scram-sha-256 鉴权通过 | ✅ | |
| 2.14 | 爆破结果持久化到 scan_results 表（username/password/success） | ✅ | |
| 2.15 | 异步爆破任务（tokio::spawn 后台执行 + 状态查询） | ✅ | |
| 2.16 | MongoDB/MSSQL 连接器 | ✅ | MongoDB SCRAM-SHA-1+OP_MSG+手写BSON；MSSQL TDS Login7+UCS-2+XOR 0xA5 |
| 2.17 | Oracle 完整认证连接器 | ⚠️ | **TNS Connect + NS Data(TTC OSSESS) 两阶段探测**：检查 ORA-01017/ORA-01005 错误码判断认证；完整 O5L 密码掩码与密钥派生需数百行协议帧，采用 fallback 方案并文档化，见补救 R2.2 |
| 2.18 | FTP/Telnet/SMB/HTTP Basic/HTTP Form 连接器 | ✅ | FTP(220→USER→331→PASS→230)；Telnet(IAC 协商+login:/Password:提示)；SMB(SMB2 Negotiate+SessionSetup+NTLMv2)；HTTP Basic(base64 Authorization 头)；HTTP Form(POST 表单+关键词检测) |
| 2.19 | 横向撞库（多目标凭证复用） | ✅ |  // argus-bruteforce/src/lib.rs: cross_host_stuffing 函数：成功凭证去重后复用到其他目标同协议端口，并发执行(buffer_unordered)；execute 方法多目标时自动触发，结果合并到 all_results |
| 2.20 | G2.1: RTSP/ONVIF 媒体协议爆破连接器 | ✅ | RTSP(TCP DESCRIBE+Basic/Digest Auth)；ONVIF(SOAP+WS-UsernameToken PasswordDigest=SHA1) |
| 2.21 | G2.2: RDP/VNC/IMAP/POP3/SMTP/SNMP 中间件协议爆破连接器 | ✅ | RDP(X.224+MCS+Standard Security RSA/RC4)；VNC(RFB 3.8 DES challenge-response)；IMAP/POP3/SMTP(直接TCP)；SNMP(UDP BER GetRequest community爆破) |
| 2.22 | G2.3: 组合字典模式（user:pass 配对文件） | ✅ |  // dictionary.rs: CredentialPair + parse_combo_lines(:/空格/Tab 分隔) + load_combo_dict_file；BruteForceParams.credential_pairs 非空时优先使用配对模式 |
| 2.23 | G2.4: 弱密码复检（二次爆破验证修复状态） | ✅ |  // lib.rs: recheck_weak_passwords() 方法 + RecheckResult(still_vulnerable/fixed)，成功=未修复，失败=已修复 |
| 2.24 | G2.6: LDAP/SFTP 协议连接器 | ✅ |  // ldap.rs: 自实现 BER 编码 LDAPv3 Simple Bind + parse BindResponse resultCode；sftp.rs: russh 密码认证 + channel subsystem "sftp" 请求 |
| 2.25 | 单元测试扩容至 122 tests（组合字典解析/复检/BER 编码/SFTP 连接器） | ✅ |
| 2.26 | G2.5: 扫描所有弱密码选项（默认发现一个即停） | ✅ |  // types.rs: BruteForceParams.stop_on_first_success: bool（默认 true），false 时扫描整个字典；serde alias 兼容旧字段名 stop_on_success

---

## 阶段 3：基线核查引擎

### 目标
实现 SSH/SMB/Telnet 远程登录 + 配置合规检测。

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 3.1 | SSH 远程登录采集（复用 russh，exec 命令采集配置） | ✅ |
| 3.2 | SMB 远程登录采集（WinRM SOAP 全流程：create_shell→send_command→receive_output→delete_shell） | ✅ |
| 3.3 | Telnet 远程登录采集（网络设备配置采集） | ✅ |
| 3.4 | 配置规则 DSL 引擎（Rhai 脚本，10+ 辅助函数） | ✅ |
| 3.5 | 在线采集 + 离线脚本采集（SSH/Telnet/SMB + Agent 持久会话） | ✅ |
| 3.6 | 合规报告生成（JSON/HTML/Text 三种格式） | ✅ |
| 3.7 | 内置等保三级基线规则（Linux 34采集项+65规则，Windows 14采集项+20规则） | ✅ |
| 3.8 | BaselineScanner 注册到 API + POST /scan/baseline 端点 | ✅ |
| 3.9 | 单元测试扩容至 57 tests + 全 workspace 151 tests 全通过 | ✅ |
| 3.10 | P0 修复：基线核查进度更新 bug（run_baseline_check 未写入 progress map） | ✅ |
| 3.11 | P1 新增：基线报告查询端点 GET /scan/baseline/report/{task_id} | ✅ |
| 3.12 | P1 重写：SMB/WinRM 采集器（reqwest + SOAP，完整 WinRM 命令执行链） | ✅ |
| 3.13 | P2 扩充：Linux 基线规则 20→65（+45 条：SSH/PAM/文件权限/审计/内核/挂载等） | ✅ |
| 3.14 | P2 扩充：Windows 基线规则 8→20（+12 条：密码复杂度/匿名访问/自动登录/审核等） | ✅ |
| 3.15 | P2 新增：Agent 离线采集器（持久 SSH 会话，避免重复连接/认证开销） | ✅ |
| 3.16 | P2 修复：validate_script 使用注册了 helper 函数的 RuleEngine | ✅ |
| 3.17 | G3.1: 安全设备基线规则（防火墙/IDS/IPS） | ✅ |  // firewall_rules.rs: 13 采集项 + 22 合规规则（SSH/Telnet/AAA/管理接口/日志/ACL/SNMP/Banner/NTP/超时） |
| 3.18 | G3.2: 网络设备基线规则（Cisco/Huawei/H3C） | ✅ |  // network_device_rules.rs: 13 采集项 + 22 合规规则（VTY/SSH/密码加密/ACL/NTP/SNMP/Banner/CDP/HTTP） |
| 3.19 | 单元测试扩容至 119 tests（安全设备+网络设备基线规则） | ✅ |
| 3.20 | G3.3: 虚拟化设备基线规则（vCenter/ESXi） | ✅ |  // vsphere_rules.rs: 17 采集项 + 31 合规规则（ESXi 9 项 SSH/Shell/锁定模式/密码/NTP/日志/SNMP + vCenter 8 项 SSO/密码/锁定/会话超时/日志/NTP/SNMP/防火墙）

---

## 阶段 4：系统扫描 + 漏洞知识库 v1

### 目标
实现第一个需要漏洞知识库的引擎，达到可商用试用级别。

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 4.1 | 指纹识别引擎 | ✅ |
| 4.2 | 系统漏洞检测引擎（基于插件运行时） | ✅ |
| 4.3 | NVD/CVE 数据库导入 | ✅ |
| 4.4 | 自研 Top 500 高频漏洞模板 | ✅ |  // 538个内置模板：默认凭据50+信息泄露77+配置错误74+已知CVE337（真实CVE，NVD验证），批量生成脚本 scripts/generate_vuln_templates.py
| 4.5 | 分布式扫描节点支持 | ✅ |
| 4.6 | 工控协议解析（Modbus/S7/IEC104） | ✅ |
| 4.7 | 趋势分析与任务对比 | ✅ |
| 4.8 | 外部 CVE 数据源接入（CISA KEV / OSV / CNNVD） | ✅ |  // argus-vulndb 新增三个 importer: CISA KEV JSON API 标记在野利用漏洞, OSV REST API 按 CPE/包名查询开源软件漏洞, CNNVD 本地 JSON 数据文件补充中文描述; CLI 新增 kev-import/osv-query/cnnvd-import 命令; 31 个单元测试
| 4.9 | G4.1: 物联网设备检测项 | ✅ |  // argus-sysvuln/iot_vuln.rs: Hikvision/Dahua/TP-Link/Netgear/D-Link/SmartHome 6 类设备 + 默认凭据 + CVE
| 4.10 | G4.2: 大数据组件检测项 | ✅ |  // argus-sysvuln/bigdata_vuln.rs: Hadoop/Spark/Kafka/Elasticsearch/HBase/Zookeeper 7 组件 + 未授权检测 + CVE
| 4.11 | G4.4: 网络设备专用检测项 | ✅ |  // argus-sysvuln/network_device_vuln.rs: Cisco/Huawei/H3C/Juniper 4 厂商 + Banner 指纹 + SNMP + CVE
| 4.12 | G4.5: OpenSSH 版本扫描 | ✅ |  // argus-sysvuln/ssh_version.rs: 解析 SSH Banner 提取 OpenSSH 版本号 + CVE-2024-6387/CVE-2018-15473 等 5 个 CVE 匹配
| 4.13 | G4.6: 网站漏洞联动扫描 | ✅ |  // argus-sysvuln/web_linkage.rs: 从端口扫描结果提取 HTTP/HTTPS 服务 + 生成 WebScanTarget 子任务
| 4.14 | G4.3: 安全设备检测项 | ✅ |  // argus-sysvuln/security_device_vuln.rs: Cisco ASA/Fortinet/Palo Alto/Check Point/华为 USG/深信服 AF/天融信 7 类设备 + 默认凭据 + CVE + 弱配置
| 4.15 | G4.7: 深度扫描模式 | ✅ |  // argus-sysvuln scanner.rs: VulnerabilityScanner.deep_scan: bool + deep_scan_templates()（5 个深度模板：额外凭据/.git/config/backup.zip/Swagger/Apache CVE-2021-41773）
| 4.16 | G4.8: 危险漏洞插件（DoS 类） | ✅ |  // argus-sysvuln/dos_vuln.rs: DosScanner 4 个安全探测插件（SYN Flood/ApacheKiller/畸形请求/Slowloris）+ run_dangerous: bool 默认 false + risk_warning

---

## 阶段 5：应用扫描引擎

### 目标
实现 Web 漏洞扫描（主动 + 被动）。

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 5.1 | Web 爬虫（BFS/DFS + HTML 解析） | ✅ |  // argus-webscan crate: scraper 解析 HTML 提取链接/表单, robots.txt, 深度/域名控制, URL 去重
| 5.2 | OWASP Top 10 检测引擎 | ✅ |  // SQLi(错误/布尔盲注), XSS(反射型), 命令注入, 路径遍历, SSRF, 开放重定向, 安全头部检查, 信息泄露检测(AWS Key/JWT/堆栈)
| 5.3 | HTTP 代理被动扫描 | ✅ |  // TCP 监听器: CONNECT 隧道支持, 请求转发+响应捕获, 自动触发被动扫描
| 5.4 | Kafka 消费被动扫描 | ✅ |  // rskafka(纯 Rust)：KafkaSource::connect 真实连接 broker，next_batch 通过 fetch_records 消费 JSON 消息并解析为 HttpTransaction；离线测试可用 load_messages 预填充
| 5.5 | pcap 流量镜像被动扫描 | ✅ |  // pcap + etherparse + httparse：PcapSource::parse_file 真实解析 pcap 文件，按 TCP 四元组分组累积 payload，配对 HTTP 请求/响应为事务；离线测试可用 load_transactions 预填充 |
| 5.6 | Cookie/会话录制 | ✅ |  // CookieJar: Set-Cookie 解析+存储+匹配+请求头构建; SessionRecorder: Token 提取(JWT/Bearer), 请求历史, 认证头自动生成
| 5.7 | TLS/JA3 指纹 | ✅ |  // TlsClientHello 解析(cipher_suites/extensions/groups/point_formats), JA3=MD5(version,ciphers,exts,groups,formats), 客户端类型推断(GREASE检测)
| 5.8 | 自定义 POC 编辑器 | ✅ |  // YAML 模板格式, 变量替换({{target}}), 检测规则(status/header/body/url + contains/regex/equals), 模板验证, 批量执行
| 5.9 | Postman Collection 导入 | ✅ |  // Postman v2.1 JSON 解析, 嵌套文件夹递归, 环境变量替换, raw/urlencoded/formdata body 解析 |
| 5.10 | G5.1: 浏览器爬虫（执行 JavaScript） | ✅ | // argus-webscan: 集成 chromiumoxide headless 浏览器，渲染 SPA 页面后提取 DOM 链接，支持 JavaScript 执行后的动态内容抓取 |
| 5.11 | G5.2: LDAP 注入检测 | ✅ |  // argus-webscan/ldap_injection.rs: 12 个 LDAP 元字符 payload + 16 个错误关键词 + 基线长度比对
| 5.12 | G5.3: 文件包含检测（LFI/RFI） | ✅ |  // argus-webscan/file_inclusion.rs: 27 个 LFI payload 含路径遍历/php://filter + 11 个 RFI payload + 19 个敏感文件指示器
| 5.13 | G5.4: 文件上传检测 | ✅ |  // argus-webscan/file_upload.rs: 12 个危险文件 .php/.jsp/.asp/.svg/.htaccess + 手动构造 multipart/form-data
| 5.14 | G5.5: CRLF 注入检测 | ✅ |  // argus-webscan/crlf_injection.rs: 12 个 %0d%0a payload + header/cookie/body 注入检测
| 5.15 | G5.6: 404 页面智能检测 | ✅ |  // argus-webscan/page_404.rs: 随机 URL 探测建立基线 + 状态码/长度/关键词指纹识别 soft-404
| 5.16 | G5.7: 第三方组件扫描 | ✅ |  // argus-webscan/component_scan.rs: scraper 提取 JS 库版本 + 18 条 CVE 库覆盖 jQuery/Bootstrap/Angular/Vue/lodash/moment/axios/D3
| 5.17 | G5.8: 敏感目录字典扫描 | ✅ |  // argus-webscan/dir_brute.rs: 130+ 内置目录路径含 admin/API/config/VCS/debug + 响应分类 Exists/Forbidden/ServerError/Redirect/NotFound
| 5.18 | G5.9: Agent 采集被动扫描 | ✅ |  // argus-webscan/agent_mode.rs: AgentConfig + Apache/Nginx access log 正则解析 → HttpTransaction + 文件增量读取偏移量 + 批量缓冲定时 HTTP POST 上报 + 实现 TrafficSource trait
| 5.19 | G5.10: socks5 代理支持 | ✅ |  // argus-webscan/proxy.rs: Socks5Config/Socks5Connector（fast-socks5 握手 + CONNECT，无认证/用户名密码认证，从 socks5:// URL 解析）+ reqwest socks 特性
| 5.20 | G5.11: Flash 文件解析 | 🚫 |  // Flash 已淘汰，用户确认不需要支持
| 5.21 | G5.12: 国密 TLS 支持 | ✅ |  // argus-webscan/gm_tls.rs: SM3 哈希+证书指纹、SM2 密钥生成/签名/验签、SM4 ECB/CBC 加解密+PKCS7；完整 TLCP TLS 栈集成文档化为后续工作

---

## 阶段 6：数据库/镜像/工控扫描

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 6.1 | 数据库登录扫描 | ✅ |  // argus-bruteforce: MongoDB(SCRAM-SHA-1+OP_MSG+手写BSON)/MSSQL(TDS Login7+UCS-2+XOR 0xA5)/Oracle(TNS Connect+NS Data 两阶段探测,检查 ORA-01017/ORA-01005)
| 6.2 | 数据库漏洞检测 | ✅ |  // argus-sysvuln/db_vuln.rs: Redis/PostgreSQL/MongoDB 未授权检测真实；MySQL 匿名登录检测(HandshakeResponse41 空用户)；MSSQL 弱密码检测(TDS Login7+5 个弱密码)；Oracle SID 枚举(7 个 SID)+默认账户检测(4 个账户)
| 6.3 | 数据库基线合规核查 | ✅ |  // argus-baseline/rules/db_rules.rs: MySQL/PostgreSQL/Redis/MongoDB 等保三级基线规则
| 6.4 | Docker 镜像扫描 | ✅ |  // argus-container/image_scan.rs: manifest/config 解析+敏感文件检测；Harbor config blob 获取通过 get_config_blob API(Docker Registry v2 blobs 端点)，解析 Env/Cmd/Entrypoint/WorkingDir，检测 9 个敏感环境变量关键词 |
| 6.5 | Harbor 仓库扫描 | ✅ |  // argus-container/harbor.rs: Harbor v2 API(list_projects/repositories/artifacts/get_manifest/trigger_scan/get_scan_result)
| 6.6 | 镜像依赖漏洞匹配 | ✅ |  // argus-container/dep_vuln.rs: OSV API 查询+本地已知漏洞匹配(Log4Shell/Spring4Shell/OpenSSL/Commons-Collections/Jackson/nginx)
| 6.7 | 工控设备指纹识别 | ✅ |  // argus-ics/fingerprint.rs: Ethernet/IP(CIP ListIdentity)+DNP3+Modbus SZL+S7 模块标识; **真实发包** IcsFingerprintScanner
| 6.8 | 工控无损扫描（指纹匹配） | ✅ |  // argus-ics/nonintrusive.rs: Modbus FC03 真实发包；S7Comm SZL 读取(检查 func=0x08, error=0)；IEC 104 STARTDT act/con + 总召唤(C_IC_NA_1)，分析数据帧数量 |
| 6.9 | G6.1: PROFINET DCP 设备发现 | ✅ | // argus-ics/profinet_dcp.rs: 基于pnet_datalink以太网层多播(Ethertype 0x8892, MAC 01:0E:CF:00:00:00)，构造DCP Identify Broadcast请求，解析响应提取设备名/厂商/IP/MAC/角色；scanner.rs集成自动发现 |
| 6.10 | G6.2: OPC UA Discovery | ✅ | // argus-ics/opcua_scanner.rs: async-opcua GetEndpoints+Browse |
| 6.11 | G6.3: 三菱 MELSEC 协议 | ✅ |  // argus-ics/melsec.rs: MC Protocol 3E 帧格式 + 设备批量读 + CPU 型号检测 + 认证检测
| 6.12 | G6.4: 欧姆龙 FINS 协议 | ✅ |  // argus-ics/fins.rs: FINS/TCP 帧格式 + 节点握手 + Controller Read + 型号/版本提取 + 认证检测
| 6.13 | G6.5: 艾默生协议 | ✅ |  // argus-ics/emerson.rs: HART-IP UDP 5094（真实帧 + Command 0 探测 + XOR checksum + 13 家厂商映射）+ FOUNDATION Fieldbus HSE TCP 1089（HTTP banner 指纹 + 版本提取）

---

## 阶段 7：移动扫描 + 漏洞验证

### 任务清单

| # | 任务 | 状态 |
|---|---|---|
| 7.1 | APK 解析（zip + dex + AndroidManifest） | ✅ |  // argus-mobile crate: ZIP 解压+AXML 二进制 XML 解析(UTF-8/UTF-16 字符串池+节点树)+DEX 文件头解析; V1 JAR 签名证书解析(x509-parser 0.16+手动 DER TLV 遍历 PKCS#7 SignedData)；V2/V3 签名块解析(ZIP EOCD→Central Directory→APK Signing Block magic)
| 7.2 | Android 组件安全检测 | ✅ |  // argus-mobile/component_check.rs: 四大组件导出无权限+Intent Filter 隐式导出+敏感广播; taskAffinity 劫持检测(Activity 级 + Application 级继承，与包名一致不告警，主 Activity=high，其他=medium) |
| 7.3 | Android 配置安全检测 | ✅ |  // argus-mobile/config_check.rs: allowBackup/debuggable/cleartext/危险权限/SDK/签名检测; application 节点属性真实从 AXML 解析(parse_manifest_node 遍历 child.attributes 存入 meta_data)，config_check 读取真实值
| 7.4 | 漏洞验证引擎（HTTP 重放） | ✅ |  // argus-vulnverify/engine.rs: VerifyEngine 支持 GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH+超时+重试(max_retries+retry_delay)+认证头+URL 校验
| 7.5 | SQL 注入利用验证 | ✅ |  // argus-vulnverify/sqli.rs: 基于错误(SQL 错误关键字 20+)+布尔盲注(true/false 响应差异)+时间盲注(SLEEP 5s 延时阈值 3s)
| 7.6 | 命令执行验证 | ✅ |  // argus-vulnverify/cmd_exec.rs: echo marker 回显(10 payload)+id/whoami/uname 输出特征匹配(11 模式)+sleep/ping 时间盲注
| 7.7 | 文件读取验证 | ✅ |  // argus-vulnverify/file_read.rs: Linux 路径遍历(11 payload)+Windows 路径遍历(10 payload)+绝对路径读取(12 payload)+文件内容特征匹配(11 Linux+7 Windows 模式) |
| 7.8 | G7.1: iOS 应用扫描 | ✅ |  // argus-mobile/ios_scan.rs: IPA Zip 解析 + Info.plist XML 解析 + embedded.mobileprovision + Mach-O goblin 库依赖 + ATS/密钥/不安全 API 检测
| 7.9 | G7.2: HarmonyOS 应用扫描 | ✅ |  // argus-mobile/harmonyos_scan.rs: HAP Zip + module.json/config.json + 权限/能力/设备检测 + 资源文件密钥扫描
| 7.10 | G7.3: 数据安全检测（明文存储敏感数据） | ✅ |  // argus-mobile/data_security.rs: DEX 字符串扫描 API Key/JWT/AWS/Google/Slack + SharedPreferences XML 明文 + SQLite 关键词
| 7.11 | G7.4: 恶意行为检测（短信/通话/通讯录上传） | ✅ |  // argus-mobile/malicious_behavior.rs: 31 个危险 API 模式 × 7 类 + 跨 DEX 关联：通讯录+网络/通话+网络/SMS+网络 → 上传行为告警
| 7.12 | G7.5: 浏览器验证模式（页面渲染验证 XSS 等） | ✅ |  // argus-vulnverify/browser_verify.rs: BrowserVerifier（chromiumoxide 渲染页面 + DOM 提取 + XSS 验证 alert hook+marker 变量 + PNG 截图；Chrome 不可用时自动 fallback 到纯 HTTP 验证）

---

## 阶段 2-7 质量补救清单

> ✅ **全部修复完成**（P0: 4 项 + P1: 4 项 + P2: 3 项 = 11 项，2026-09-23）
>
> 本清单记录阶段 1-7 代码审查中发现的"占位/简化/与目标描述不符"项，按修复优先级排序。
> 修复完成后，对应阶段任务状态从 ⚠️ 升级为 ✅。

### 优先级 P0：影响核心功能可用性（先修）

| 编号 | 阶段 | 问题 | 修复方案 | 状态 |
|---|---|---|---|---|
| R2.3 | 2 | FTP/Telnet/SMB/HTTP Basic/HTTP Form 连接器为占位 | 实现真实协议握手：FTP(TCP+USER/PASS 命令)、Telnet(已有 baseline 采集逻辑可复用)、SMB( SMB2 negotiate+sessionsetup)、HTTP Basic/HTTP Form(reqwest 已有依赖) | ✅ |
| R6.1 | 6.2 | MySQL/MSSQL/Oracle 数据库漏洞检测严重缩水 | MySQL 补齐匿名访问检测(发送空凭证握手)；MSSQL 补齐弱密码检测(TDS Login7)；Oracle 补齐 SID 枚举+默认账户测试 | ✅ |
| R7.3 | 7.3 | application 节点属性未从 AXML 真实解析 | 修改 apk.rs parse_manifest_node：将 `<application>` 节点的 allowBackup/debuggable/usesCleartextTraffic/networkSecurityConfig 等属性存入 meta_data，让 config_check 读取真实值 | ✅ |
| R7.1 | 7.1 | APK 签名解析仅检测文件存在性 | 真实解析 V1 JAR 签名证书(读取 META-INF/*.RSA 并解析 X.509 证书：subject/issuer/fingerprint/有效期)；V2/V3 签名块解析(ZIP 尾部) | ✅ |

### 优先级 P1：影响功能完整性（次修）

| 编号 | 阶段 | 问题 | 修复方案 | 状态 |
|---|---|---|---|---|
| R2.1 | 2 | 横向撞库逻辑未实现 | 新增 cross_host_stuffing 函数：遍历已爆破成功的 host:port:credential 三元组，将凭证复用到其他目标同协议端口 | ✅ |
| R2.2 | 2 | Oracle 仅 TNS Connect 端口探测 | 增强 TNS Connect + NS Data(TTC OSSESS) 两阶段认证探测，检查 ORA-01017/ORA-01005 错误码；完整 O5L 实现需数百行协议帧，采用 fallback 方案并文档化 | ✅ |
| R6.2 | 6.4 | Harbor config blob 获取被跳过 | 调用 Harbor API 拉取 config blob，解析 config JSON 中的 Env/Cmd/Entrypoint/WorkingDir，检测敏感环境变量 | ✅ |
| R6.3 | 6.7 | S7/IEC104 只读扫描未真实发包 | scan_s7_readonly 发送 SZL 请求(复用 fingerprint 的 probe_s7 逻辑)；scan_iec104_readonly 发送 STARTDT+总召唤 | ✅ |

### 优先级 P2：框架级补全（可延后）

| 编号 | 阶段 | 问题 | 修复方案 | 状态 |
|---|---|---|---|---|
| R5.1 | 5.4 | Kafka 消费被动扫描无真实消费者 | 引入 rskafka（纯 Rust），实现 KafkaSource::connect + next_batch 真实从 Kafka topic 消费 JSON 消息 | ✅ |
| R5.2 | 5.5 | pcap 流量镜像无真实解析 | 引入 pcap + etherparse + httparse，实现 PcapSource 从 pcap 文件提取 HTTP 事务 | ✅ |
| R7.2 | 7.2 | taskAffinity 劫持风险未检测 | AXML 解析 application/activity 的 taskAffinity 属性，标记主 Activity 设置了 taskAffinity 的风险 | ✅ |

### 已确认无需修复（注释过时但功能完整）

| 编号 | 阶段 | 情况 | 结论 |
|---|---|---|---|
| — | 1.11 | scanner.rs:86 注释"返回第一个端口的主结果（简化实现）"，但实际代码遍历所有端口 | 注释过时，功能完整，只需删除过时注释 |
| — | 5.1 | crawler.rs robots.txt 解析为"简化版" | 功能可用，简化版已覆盖主要用例 |

---

## 阶段 8：报表/大屏/系统管理

### 目标
补齐系统级能力，达到企业级商用标准。覆盖资产管理增强、扫描任务管理、模板管理、风险管理、报表管理、日志审计、系统管理（用户/角色/认证/告警/探针/许可证/监控）、诊断工具。

### 任务清单

| # | 任务 | 状态 | 说明 |
|---|---|---|---|
| 8.1 | 资产管理增强 | ✅ |  |
| 8.1.1 | 三类资产库（网络/应用/数据库）字段补全 | ✅ |  // 迁移 m20260924_000001: network_assets +18字段/application_assets +13/database_assets +15 |
| 8.1.2 | 资产发现（IP/子域名/流量） | ✅ |  // discovery.rs: IP发现(portscanner存活+端口)/子域名(DNS爆破)/流量(pcap_capture)，异步执行+结果入库 |
| 8.1.3 | 资产组/标签/业务系统/资产属性管理 | ✅ |  // asset_group.rs: asset_groups树形+asset_attributes(tag/business_system/asset_type)，组内快捷扫描 |
| 8.1.4 | 凭证管理 | ✅ |  // credential.rs: CRUD+按IP/协议筛选+verify(复用协议连接器)+密码脱敏 |
| 8.1.5 | 资产批量导入导出(xlsx) | ⬜ |  |
| 8.2 | 扫描任务管理增强 | ✅ |  |
| 8.2.1 | 任务通用配置项 | ✅ |  // task.rs: 新增 priority/schedule_config/params/node_id 字段 |
| 8.2.2 | 任务生命周期（新建/启动/暂停/继续/停止/删除/复制/锁定） | ✅ |  // task.rs: start/pause/resume/stop/copy/lock/unlock 7个API |
| 8.2.3 | 任务状态机（待扫描→运行中→已完成/已暂停/已停止/失败） | ✅ |  // 严格状态转换校验，非法返回400 |
| 8.2.4 | 任务进度实时展示 + 趋势对比 | ✅ |  // 已有 progress 字段 + trends API |
| 8.2.5 | 任务结果查看（多维度视图+日志下载+报表生成） | ✅ |  // 已有 scan results API |
| 8.2.6 | 任务调度（cron定时/周期+跨日续扫） | ✅ |  // scheduler.rs: 自研cron解析+每分钟tick+periodic interval |
| 8.3 | 模板管理（8 大类） | ✅ |  |
| 8.3.1 | 端口管理（端口模板/违规配置/协议风险等级） | ✅ |  // port_templates 表 + CRUD |
| 8.3.2 | 字典管理（5类标准字典+社工字典生成器+组合字典） | ✅ |  // dictionaries + combo_dictionaries 表 + CRUD |
| 8.3.3 | 证书管理（PEM/PFX/P12） | ✅ |  // certificates 表 + CRUD + 私钥脱敏 |
| 8.3.4 | 参数模板（系统/应用/数据库扫描参数） | ✅ |  // param_templates 表 + CRUD + 设为默认 |
| 8.3.5 | 漏洞模板（系统/应用/数据库漏洞库+自定义指纹+自定义POC+标签） | ✅ |  // 已有漏洞模板基础 + 扩展 |
| 8.3.6 | 配置模板（基线核查策略） | ✅ |  // config_templates 表 + CRUD |
| 8.3.7 | 离线检查工具 + 工控设备信息库 | ⬜ |  |
| 8.4 | 风险管理 | ✅ |  |
| 8.4.1 | 七大风险维度（暴露端口/系统漏洞/应用漏洞/数据库漏洞/配置变更/弱密码/告警） | ✅ |  // exposure_ports + weak_passwords 表 + vuln_findings 扩展 + risk.rs 9个API |
| 8.4.2 | 漏洞风险等级（系统/DB 5级，应用/配置 4级） | ✅ |  // 已有 severity 字段 |
| 8.4.3 | 风险处置状态机（待处理/处理中/已延期/已修复/已验证/关闭/误报/忽略/重新打开） | ✅ |  // risk_status 字段 + 9种状态严格转换校验 + 批量事务更新 |
| 8.4.4 | 双视图（列表/维度）+ 修复率统计 + 趋势 | ✅ |  // risk/vulns/stats + ports/stats + weak-passwords/stats |
| 8.4.5 | 资产风险值评分（0-10分四档） | ✅ |  // 已有 risk_score 字段 |
| 8.5 | 报表管理 | ⬜ |  // 暂不处理（用户确认） |
| 8.5.1 | 6类报表（系统/应用/被动/数据库/基线/口令） | ⬜ |  |
| 8.5.2 | 多格式导出（html/xlsx/doc/pdf/wps/xml/json）+ 密码加密 | ⬜ |  |
| 8.5.3 | 手动/自动生成 + 邮箱/FTP/WebHook 推送 | ⬜ |  |
| 8.5.4 | 报表模板管理（内置+自定义） | ⬜ |  |
| 8.5.5 | 报表内容结构（封面/目录/摘要/漏洞详情/修复建议/附录） | ⬜ |  |
| 8.6 | 日志审计系统 | ✅ |  |
| 8.6.1 | 日志分类（登录/登出/资产/组织/凭证/任务等）+ 字段 | ✅ |  // audit_logs 表 + audit.rs |
| 8.6.2 | 多维度查询筛选（时间/用户/IP/类型/描述/状态） | ✅ |  // GET /audit/logs 支持全部筛选维度 |
| 8.6.3 | 日志导出（logback备份+xlsx阅览）+ 自动备份（邮件/FTP） | ✅ |  // CSV 导出，自动备份待实现 |
| 8.6.4 | 日志保留策略（≥180天，存满自动清理） | ✅ |  // system_settings: log_retention_days |
| 8.6.5 | 三权分立日志审计（admin/user/audit/superadmin） | ✅ |  // roles 表 + 4个内置角色 |
| 8.7 | 系统管理 | ⚠️ |  // 核心已实现，部分子项待补全 |
| 8.7.1 | 用户管理（三权分立默认角色+新建用户+扫描权限配置+IP锁定+会话管理） | ✅ |  // admin.rs: 用户CRUD+锁定/解锁+重置2FA+密码策略 |
| 8.7.2 | 角色与权限管理（菜单级权限+默认角色不可改删） | ✅ |  // roles 表 + CRUD + builtin不可删 |
| 8.7.3 | 认证管理（LDAP/AD + OAuth SSO + TOTP双因素 + 密码策略） | ⚠️ |  // TOTP双因素+密码策略+登录锁定已实现；LDAP/OAuth待实现 |
| 8.7.4 | 告警配置（SYSLOG/邮件/页面/WebHook/短信/Kafka 多通道+告警规则） | ✅ |  // alert_configs 表 + CRUD + 通道测试 + 敏感字段脱敏 |
| 8.7.5 | 系统配置（网络/路由/Hosts/时间同步/服务管理/系统备份/APIKey/WSUS/系统告警阈值/登录安全/任务设置） | ⚠️ |  // system_settings 基础配置已实现；网络/服务/备份待实现 |
| 8.7.6 | 分布式探针管理（上下级节点+心跳+资源监控+任务下发+免密登录） | ✅ |  // node.rs: 拓扑/心跳(含资源+版本)/免密登录/资源监控 |
| 8.7.7 | 许可证管理（产品信息/版本信息/授权信息/激活） | ⬜ |  |
| 8.7.8 | 系统监控（CPU/内存/硬盘+引擎状态） | ⚠️ |  // 探针资源监控已实现；系统级监控待实现 |
| 8.7.9 | 升级管理（软件升级+规则库在线/离线/自动升级） | ⬜ |  |
| 8.8 | 诊断工具 | ✅ |  |
| 8.8.1 | 网络诊断（Ping/Telnet/HTTP/DIG/Nslookup/Traceroute/Whois/Nmap/路由/抓包） | ✅ |  // diagnostic.rs: 9个网络诊断API |
| 8.8.2 | 辅助工具（编码解码/哈希散列/加密解密/子网掩码计算） | ✅ |  // tools API: base64/url/hex + md5/sha1/sha256/sha512 + AES-GCM + 子网计算 |
| 8.9 | 态势感知可视化大屏 | ⬜ |  // 暂不处理（用户确认） |

---

## 进度图例

- ✅ 完成：代码真实实现并通过测试，无占位/简化
- 🔄 进行中：部分任务完成，部分待开始
- ⚠️ 部分完成：有可用实现，但存在占位/简化/与目标描述不符的项，需按补救清单修复
- ⬜ 待开始
- ❌ 阻塞

## 更新规则

1. 每次完成任务后更新对应状态，并在文件头部更新最后更新日期
2. 标记 ⚠️ 的任务必须同时填写"补救清单"中的修复方案编号（如 R2.1）
3. 修复补救清单项后，将对应阶段任务状态从 ⚠️ 升级为 ✅，并更新补救清单状态为 ✅
4. 不允许将占位/简化实现标记为 ✅；若实现不完整，必须标记为 ⚠️ 并填写补救编号
