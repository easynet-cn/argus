# Argus 架构设计

> 全知全见的守卫者 —— 纯 Rust 安全扫描系统

## 一、系统定位

构建纯 Rust 商业级漏洞发现与管理平台。覆盖 9 大扫描引擎，分阶段实现，最终达到商业产品级别。

## 二、技术栈

| 层 | 选型 | 版本 |
|---|---|---|
| 语言 | Rust | Edition 2024 |
| Web 框架 | actix-web | 4 |
| ORM | sea-orm | 1.x |
| 异步运行时 | tokio | 1 |
| 数据库 | PostgreSQL | 16+ |
| 缓存 | Redis | 7+ |
| 前端 | Vue3 + Element Plus | — |
| 浏览器自动化 | chromiumoxide（Chrome CDP） | — |
| 原始网络包 | pnet (libpnet) | — |

## 三、分层架构

```
┌─────────────────────────────────────────────────────┐
│  前端（Vue3 + Element Plus）                          │
├─────────────────────────────────────────────────────┤
│  API 网关层（actix-web + JWT + RBAC 三权分立）         │
├─────────────┬───────────────┬───────────────────────┤
│  编排层      │  引擎层        │  知识库层              │
│  - 任务调度  │  - 9大扫描引擎 │  - 漏洞规则库          │
│  - 资产管理  │  - 插件运行时   │  - 指纹库              │
│  - 风险管理  │  - 协议栈      │  - 基线规则库          │
│  - 报表引擎  │  - 加密/哈希   │  - 字典库              │
│  - 分布式调度 │               │  - POC 模板库          │
├─────────────┴───────────────┴───────────────────────┤
│  存储层（PostgreSQL + Redis + 对象存储）              │
└─────────────────────────────────────────────────────┘
```

## 四、Cargo Workspace 结构

```
argus/
├── Cargo.toml              # workspace 根配置
├── crates/
│   ├── argus-core/         # 核心领域模型 + 数据库
│   ├── argus-engine/       # 插件引擎（YAML + Rhai + WASM）
│   ├── argus-scanner/      # 扫描引擎 trait + 调度 + 注册
│   ├── argus-api/          # actix-web API 服务
│   └── argus-cli/          # CLI 入口
├── docs/                   # 文档
│   ├── architecture.md     # 本文件
│   ├── decisions.md        # 关键决策记录
│   └── plan.md             # 实施计划与进度
└── templates/              # 插件模板（YAML/Rhai/WASM）
```

后续阶段将新增：
- `argus-portscanner` — 端口扫描引擎
- `argus-bruteforce` — 口令猜解引擎
- `argus-baseline` — 基线核查引擎
- `argus-sysvuln` — 系统漏洞扫描引擎
- `argus-webscanner` — Web 应用扫描引擎
- `argus-dbscanner` — 数据库扫描引擎
- `argus-imagescan` — 镜像扫描引擎
- `argus-mobilescan` — 移动应用扫描引擎
- `argus-vulnverify` — 漏洞验证引擎

## 五、插件引擎架构

### 三层混合设计

| 层 | 格式 | 适用场景 | 占比(预期) |
|---|---|---|---|
| YAML 模板 | 声明式（HTTP请求+响应匹配） | 简单检测 | ~80% |
| Rhai 脚本 | 条件逻辑、多步骤 | 中等检测 | ~15% |
| WASM 插件 | Rust 编译，复杂协议交互 | 复杂检测 | ~5% |

### 核心组件

- **PluginRegistry**：插件注册/发现/版本管理
- **PluginLoader**：加载 YAML/Rhai/WASM 到运行时
- **PluginExecutor**：调度执行、超时控制、资源限制
- **PluginSandbox**：沙箱隔离、能力控制（网络/文件/CPU/内存）
- **HostAPI**：注入给插件的安全能力接口（HTTP 请求、TCP 连接、DNS 查询）

### 设计原则

- 插件不直接访问网络/文件系统，必须通过 HostAPI
- WASM 插件用 wasmtime 运行，天然沙箱
- YAML 和 Rhai 支持热加载、在线编辑、版本管理
- 统一输出格式：`PluginResult { vuln_id, name, severity, evidence, cvss, cve, fix_advice, target, port, service, timestamp }`

## 六、扫描引擎接口

所有引擎实现统一 `Scanner` trait：

```rust
#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    async fn execute(&self, config: &ScanConfig) -> Result<ScanResult, ScannerError>;
    async fn progress(&self, task_id: &str) -> Result<f32, ScannerError>;
    async fn cancel(&self, task_id: &str) -> Result<(), ScannerError>;
}
```

引擎之间互不依赖，可独立开发、独立部署、独立升级。每个引擎内部调用 `argus-engine` 执行检测插件。

## 七、actix-web Actor 模型

每个扫描引擎可以设计为一个 Actor，通过消息传递调度：

- `TaskScheduler` Actor：接收扫描请求，分发到对应引擎
- `PortScanner` Actor：端口扫描引擎
- `BruteForce` Actor：口令猜解引擎
- ...

Actor 模型天然支持分布式和隔离，适合扫描引擎编排场景。

## 八、功能模块映射

| 模块 | Argus crate | 阶段 |
|---|---|---|
| 登录管理 + 系统首页 | argus-api + 前端 | 阶段 0 |
| 资产管理 | argus-core | 阶段 0 |
| 风险管理 | argus-core | 阶段 0 |
| 系统扫描（含工控） | argus-portscanner → argus-sysvuln | 阶段 1, 4 |
| 应用扫描（主动） | argus-webscanner | 阶段 5 |
| 应用扫描（被动） | argus-webscanner | 阶段 5 |
| 数据库扫描 | argus-dbscanner | 阶段 6 |
| 基线核查 | argus-baseline | 阶段 3 |
| 口令猜解 | argus-bruteforce | 阶段 2 |
| 移动扫描 | argus-mobilescan | 阶段 7 |
| 镜像扫描 | argus-imagescan | 阶段 6 |
| 漏洞验证 | argus-vulnverify | 阶段 7 |
| 模板管理 | argus-engine + argus-core | 阶段 0, 4 |
| 报表管理 | argus-core (report) | 阶段 8 |
| 日志管理 | argus-core + 中间件 | 阶段 0, 8 |
| 系统管理 | argus-api + 前端 | 阶段 0, 8 |
| 探针管理（分布式） | argus-scanner + gRPC | 阶段 8 |
