# Argus

> 全知全见的守卫者 —— 纯 Rust 实现的安全扫描平台

Argus 是一个纯 Rust 安全扫描平台，覆盖系统扫描、应用扫描、数据库扫描、基线核查、口令猜解、移动扫描、镜像扫描、漏洞验证等 9 大扫描引擎。

## ⚠️ 安全与法律声明（务必先读）

Argus 是**安全测试工具**，具备主动扫描、口令猜解、漏洞验证等能力，不当使用可能对目标系统造成损害或违反法律。

- **仅限授权目标**：你只能对**拥有合法授权**的资产进行扫描与测试。未经授权对任何第三方系统进行扫描，可能违反《网络安全法》《刑法》及所在国家/地区的法律。
- **禁止恶意使用**：严禁将本工具用于入侵、破坏、数据窃取等非法目的。
- **风险自负**：使用者须自行评估扫描对目标系统的影响（如拒绝服务、业务中断），后果由使用者自行承担。
- **责任限制**：本软件按「原样」提供，作者与贡献者不对任何使用后果承担责任。

如发现安全漏洞，请按 [SECURITY.md](SECURITY.md) 的流程私下报告。

## 特点

- **纯 Rust**：核心引擎全部 Rust 原生实现，单二进制部署，无运行时依赖
- **高性能**：利用 Rust 异步并发能力，扫描与爆破性能优异
- **插件引擎**：YAML 模板 + Rhai 脚本 + WASM 插件三层混合架构
- **分布式**：基于 Actor 模型的任务调度，支持多节点部署
- **安全隔离**：插件沙箱化，通过 HostAPI 控制能力边界

## 系统架构

```
┌─────────────┐     ┌──────────────────────────┐     ┌─────────────────┐
│  Frontend   │────▶│  argus-api (Actix-Web)   │────▶│  argus-engine   │
│  (Vue 3)    │     │  ├─ 认证 / 授权 (JWT)    │     │  ├─ 插件引擎     │
└─────────────┘     │  ├─ 任务调度             │     │  ├─ HostAPI 沙箱 │
                    │  └─ 资产管理 / 报表       │     │  └─ 扫描模板     │
                    └──────────────────────────┘     └────────┬────────┘
                              │                               │
                              ▼                               ▼
                    ┌─────────────────┐            ┌──────────────────────┐
                    │  PostgreSQL     │            │  扫描引擎 (crates)   │
                    │  Redis          │            │  portscan/bruteforce │
                    └─────────────────┘            │  baseline/webscan/   │
                                                    │  container/mobile/   │
                                                    │  vulnverify/ics ...  │
                                                    └──────────────────────┘
```

| 层 | 组件 | 说明 |
|---|---|---|
| 接入层 | `frontend/` | Vue 3 + TypeScript 管理控制台 |
| 服务层 | `server/crates/argus-api` | Web API、认证授权、任务调度、资产管理 |
| 引擎层 | `server/crates/argus-engine` | 插件加载与执行、HostAPI 沙箱 |
| 引擎层 | `server/crates/argus-scanner` | 扫描框架与注册表 |
| 能力层 | `argus-portscanner` `argus-bruteforce` `argus-baseline` `argus-fingerprint` `argus-vulndb` `argus-sysvuln` `argus-ics` `argus-node` `argus-webscan` `argus-container` `argus-mobile` `argus-vulnverify` | 各扫描引擎 |

## 项目结构

```
argus/
├── server/
│   └── crates/           # Rust 后端 workspace
│       ├── argus-core/   # 核心领域模型与配置
│       ├── argus-engine/ # 插件引擎
│       ├── argus-scanner/# 扫描引擎框架
│       ├── argus-api/    # Web API
│       └── argus-cli/    # CLI 入口
├── frontend/             # Vue 3 前端
├── docker/               # Dockerfile 与 docker-compose
├── docs/
│   ├── architecture.md   # 架构设计
│   ├── decisions.md      # 关键决策记录
│   └── plan.md           # 实施计划与进度
└── templates/            # 插件模板
```

## 快速开始（源码构建）

前置条件：Rust 2024 工具链（edition 2024）、Node.js 18+、PostgreSQL 16、Redis 7。

```bash
# 1. 启动依赖（PostgreSQL + Redis），并创建数据库
createdb argus

# 2. 配置环境变量（至少设置 JWT_SECRET）
export DATABASE_URL="postgresql://argus:argus@localhost:5432/argus"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="$(openssl rand -hex 32)"   # 生产务必使用强随机值

# 3. 构建并运行（自动执行数据库迁移）
cargo build --release
./target/release/argus serve --host 0.0.0.0 --port 8080

# 查看版本
./target/release/argus version
```

### 首次初始化管理员

服务启动后，调用一次性初始化接口创建管理员账号（仅可成功一次，且要求强口令）：

```bash
curl -X POST http://localhost:8080/api/v1/auth/setup \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"请使用强口令","email":"admin@example.com"}'
```

## 快速开始（Docker Compose）

```bash
cd docker
cp .env.example .env          # 修改 .env 中的口令与密钥
podman compose --env-file .env up -d
```

访问 `http://localhost:8080`，按上述「首次初始化管理员」创建账号。

## 配置说明

服务通过环境变量配置，关键变量如下：

| 变量 | 说明 | 默认值（仅开发） |
|---|---|---|
| `ARGUS_ENV` | 运行环境：`development` / `production` | 未设置（按开发处理） |
| `ARGUS_HOST` / `ARGUS_PORT` | 监听地址与端口 | `0.0.0.0` / `8080` |
| `DATABASE_URL` | PostgreSQL 连接串 | `postgresql://argus:argus@localhost:5432/argus` |
| `REDIS_URL` | Redis 连接串 | `redis://localhost:6379` |
| `JWT_SECRET` | JWT 签名密钥 | 开发默认（**生产缺失则启动失败**） |
| `JWT_EXPIRATION_HOURS` | 令牌有效期（小时） | `24` |
| `ARGUS_LICENSE_SECRET` | 许可证 HMAC 签名密钥 | 开发默认（缺失会告警） |

## 安全须知

发布与部署时务必遵守以下要求：

1. **必须设置 `JWT_SECRET`**：生产环境（`ARGUS_ENV=production`）下若未设置 `JWT_SECRET`，服务将**启动失败**（fail-fast），以防止使用公开可预测的默认密钥伪造登录令牌。
2. **修改数据库口令**：默认 `argus/argus` 仅用于本地开发，生产必须替换为强口令。
3. **一次性强口令**：`/api/v1/auth/setup` 创建的管理员口令需满足强度要求，且只能成功一次。
4. **网络暴露**：API 默认监听 `0.0.0.0`，生产环境请置于反向代理与防火墙之后，启用 HTTPS。
5. **许可证密钥**：若启用商业许可证校验，需通过 `ARGUS_LICENSE_SECRET` 设置自有密钥，避免默认密钥被利用伪造许可证。

## 文档

- [架构设计](docs/architecture.md)
- [关键决策记录](docs/decisions.md)
- [实施计划与进度](docs/plan.md)

## 许可证

本项目基于 [MIT 许可证](LICENSE) 开源。
