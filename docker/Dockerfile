# ===== 构建阶段 =====
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# 先拷贝依赖清单，利用 Docker 层缓存
COPY Cargo.toml Cargo.lock ./
COPY server/crates ./server/crates

# 安装必要的编译依赖（sea-orm 用 rustls，不需要 openssl）
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 编译 release 版本（单二进制）
RUN cargo build --release --bin argus

# ===== 运行阶段 =====
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 从构建阶段拷贝编译产物
COPY --from=builder /app/target/release/argus /usr/local/bin/argus

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

EXPOSE 8080

# 启动时自动执行数据库迁移，然后启动 API 服务
# 迁移由 argus-api 的 run_server 自动处理，这里直接 serve
CMD ["argus", "serve", "--host", "0.0.0.0", "--port", "8080"]
