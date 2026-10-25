//! Argus Web 扫描引擎
//!
//! Phase 5: 应用扫描引擎
//! - Web 爬虫 (BFS/DFS + HTML 解析)
//! - G5.1 浏览器爬虫 (headless Chrome，执行 JavaScript)
//! - OWASP Top 10 检测引擎
//! - G5.2 LDAP 注入检测
//! - G5.3 文件包含 (LFI/RFI) 检测
//! - G5.4 文件上传检测
//! - G5.5 CRLF 注入检测
//! - G5.6 404 页面智能检测
//! - G5.7 第三方组件漏洞扫描
//! - G5.8 敏感目录字典扫描
//! - G5.9 Agent 模式被动扫描（采集本地 HTTP 日志并上报）
//! - G5.10 SOCKS5 代理支持（无认证/用户名密码认证）
//! - HTTP 代理被动扫描
//! - Kafka/pcap 被动扫描框架
//! - Cookie/会话录制
//! - TLS/JA3 指纹
//! - G5.12 国密 SM2/SM3/SM4 密码学支持
//! - 自定义 POC 编辑器
//! - Postman Collection 导入

pub mod types;
pub mod crawler;
pub mod browser;
pub mod owasp;
pub mod scanner;
pub mod ldap_injection;
pub mod file_inclusion;
pub mod file_upload;
pub mod crlf_injection;
pub mod page_404;
pub mod component_scan;
pub mod dir_brute;
pub mod proxy;
pub mod passive;
pub mod agent_mode;
pub mod gm_tls;
pub mod session;
pub mod tls_ja3;
pub mod poc;
pub mod postman;

pub use types::{
    CrawlConfig, CrawlResult, FormData, FormField, VulnCategory, Severity,
    VulnFinding, HttpRequest, HttpResponse, HttpTransaction, Cookie, SessionState,
    PocTemplate as PocTemplateType, ScanStats,
};
pub use crawler::Crawler;
pub use browser::{BrowserCrawler, BrowserCrawlConfig};
pub use owasp::OwaspScanner;
pub use scanner::WebScanner;
pub use ldap_injection::LdapScanner;
pub use file_inclusion::FileInclusionScanner;
pub use file_upload::{FileUploadScanner, UploadTestFile};
pub use crlf_injection::CrlfScanner;
pub use page_404::{Page404Detector, Page404Baseline};
pub use component_scan::{ComponentScanner, ComponentVersion, VulnerableComponent};
pub use dir_brute::{DirBruteScanner, DirEntry, DirStatus, Method as DirBruteMethod};
pub use proxy::{HttpProxy, ProxyConfig, parse_http_request, parse_http_response, Socks5Config, Socks5Auth, Socks5Connector, build_socks5_client};
pub use passive::{PassiveScanner, KafkaSource, PcapSource, TrafficSource};
pub use agent_mode::{AgentConfig, AgentCollector, AccessLogEntry};
pub use gm_tls::{Sm2KeyPair, sm3_hash, sm3_hash_hex, cert_fingerprint_sm3, cert_fingerprint_sm3_hex, sm2_verify, sm4_ecb_encrypt, sm4_ecb_decrypt, sm4_cbc_encrypt, sm4_cbc_decrypt, SM2_DEFAULT_USER_ID, SM3_DIGEST_LEN, SM4_KEY_LEN, SM4_BLOCK_LEN};
pub use session::{CookieJar, SessionRecorder, parse_set_cookie};
pub use tls_ja3::{TlsClientHello, Ja3Fingerprint, fingerprint_tls_record};
pub use poc::{PocEditor, PocTemplate, PocRequest, PocDetect, PocResult};
pub use postman::{PostmanImporter, PostmanCollection, PostmanItem, PostmanRequest, ScanRequest};
