# 贡献指南

感谢你关注 Argus！在提交贡献前，请阅读以下约定。

## 行为准则

参与本项目的所有成员均须遵守 [行为准则](CODE_OF_CONDUCT.md)。

## 如何开始

1. Fork 本仓库并克隆到本地。
2. 从 `main`（或 `master`）创建特性分支：`git checkout -b feat/your-feature`。
3. 安装依赖并本地验证（见 [README](README.md) 的「快速开始」）。
4. 提交前确保通过本地检查（见下方「提交前检查」）。

## 开发约定

- **语言**：项目主语言为中文。注释、提交信息、文档优先使用中文；代码标识符使用英文。
- **代码风格**：Rust 遵循 `cargo fmt` 与 `cargo clippy`；前端遵循项目既有 ESLint/Prettier（如有）。
- **提交信息**：建议采用约定式提交（如 `feat:`、`fix:`、`docs:`、`refactor:`、`test:`），并用中文简述。
- **密钥安全**：**严禁**在代码中提交任何真实密钥、令牌或个人数据。所有敏感配置通过环境变量注入，模板见 `docker/.env.example`。

## 提交前检查

```bash
# 后端
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- -D warnings
cargo build --release --workspace
cargo test --workspace

# 前端
cd frontend && npm ci && npm run build
```

## Pull Request

- 一个 PR 聚焦一个明确目标，描述「做了什么 / 为什么 / 如何验证」。
- 关联相关的 Issue（如 `close #123`）。
- 确保 CI 全部通过。
- 大型改动请先开 Issue 或讨论，避免重复劳动。

## 许可证

提交即表示你同意以 [MIT 许可证](LICENSE) 发布你的贡献。
