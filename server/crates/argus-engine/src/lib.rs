//! Argus 插件引擎
//!
//! 三层插件架构：YAML 模板 / Rhai 脚本 / WASM 插件

pub mod template;
pub mod host_api;
pub mod result;
pub mod error;
pub mod runtime;

pub use error::EngineError;
pub use result::PluginResult;
pub use template::PluginTemplate;
pub use runtime::PluginRuntime;
pub use template::TemplateMetadata;
