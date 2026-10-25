//! 扫描引擎注册表
//!
//! 管理所有已注册的扫描引擎实例

use std::collections::HashMap;
use std::sync::Arc;
use crate::scanner::Scanner;

pub struct ScannerRegistry {
    scanners: HashMap<String, Arc<dyn Scanner>>,
}

impl ScannerRegistry {
    pub fn new() -> Self {
        Self {
            scanners: HashMap::new(),
        }
    }

    pub fn register(&mut self, scanner: Arc<dyn Scanner>) {
        let name = scanner.name().to_string();
        tracing::info!("注册扫描引擎: {}", name);
        self.scanners.insert(name, scanner);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Scanner>> {
        self.scanners.get(name).cloned()
    }

    pub fn list(&self) -> Vec<&str> {
        self.scanners.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
