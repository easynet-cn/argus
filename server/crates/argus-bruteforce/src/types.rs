//! 口令猜解相关数据类型

use serde::{Deserialize, Serialize};

/// 支持的协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Mysql,
    Redis,
    Postgresql,
    Ftp,
    Telnet,
    Smb,
    Mongodb,
    Mssql,
    Oracle,
    HttpBasic,
    HttpForm,
    // G2.1: RTSP / ONVIF 媒体协议爆破
    Rtsp,
    Onvif,
    // G2.2: 远程桌面 / 工控 / 邮件 / SNMP 协议爆破
    Rdp,
    Vnc,
    Imap,
    Pop3,
    Smtp,
    Snmp,
    // G2.6: LDAP / SFTP 协议爆破
    Ldap,
    Sftp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Ssh => "ssh",
            Protocol::Mysql => "mysql",
            Protocol::Redis => "redis",
            Protocol::Postgresql => "postgresql",
            Protocol::Ftp => "ftp",
            Protocol::Telnet => "telnet",
            Protocol::Smb => "smb",
            Protocol::Mongodb => "mongodb",
            Protocol::Mssql => "mssql",
            Protocol::Oracle => "oracle",
            Protocol::HttpBasic => "http-basic",
            Protocol::HttpForm => "http-form",
            Protocol::Rtsp => "rtsp",
            Protocol::Onvif => "onvif",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::Smtp => "smtp",
            Protocol::Snmp => "snmp",
            Protocol::Ldap => "ldap",
            Protocol::Sftp => "sftp",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Mysql => 3306,
            Protocol::Redis => 6379,
            Protocol::Postgresql => 5432,
            Protocol::Ftp => 21,
            Protocol::Telnet => 23,
            Protocol::Smb => 445,
            Protocol::Mongodb => 27017,
            Protocol::Mssql => 1433,
            Protocol::Oracle => 1521,
            Protocol::HttpBasic => 80,
            Protocol::HttpForm => 80,
            Protocol::Rtsp => 554,
            Protocol::Onvif => 80, // ONVIF 走 HTTP SOAP，默认 80/37017
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
            Protocol::Imap => 143,
            Protocol::Pop3 => 110,
            Protocol::Smtp => 25,
            Protocol::Snmp => 161, // UDP
            Protocol::Ldap => 389,
            Protocol::Sftp => 22, // SFTP 走 SSH，默认 22
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ssh" => Some(Protocol::Ssh),
            "mysql" => Some(Protocol::Mysql),
            "redis" => Some(Protocol::Redis),
            "postgresql" | "postgres" | "pg" => Some(Protocol::Postgresql),
            "ftp" => Some(Protocol::Ftp),
            "telnet" => Some(Protocol::Telnet),
            "smb" => Some(Protocol::Smb),
            "mongodb" | "mongo" => Some(Protocol::Mongodb),
            "mssql" | "sqlserver" => Some(Protocol::Mssql),
            "oracle" | "ora" => Some(Protocol::Oracle),
            "http-basic" | "httpbasic" => Some(Protocol::HttpBasic),
            "http-form" | "httpform" => Some(Protocol::HttpForm),
            "rtsp" => Some(Protocol::Rtsp),
            "onvif" => Some(Protocol::Onvif),
            "rdp" => Some(Protocol::Rdp),
            "vnc" => Some(Protocol::Vnc),
            "imap" => Some(Protocol::Imap),
            "pop3" | "pop" => Some(Protocol::Pop3),
            "smtp" => Some(Protocol::Smtp),
            "snmp" => Some(Protocol::Snmp),
            "ldap" => Some(Protocol::Ldap),
            "sftp" => Some(Protocol::Sftp),
            _ => None,
        }
    }

    /// 是否已实现爆破连接器
    ///
    /// 仅返回 true 的协议才有真实实现，其余协议调用 create_connector
    /// 会得到 UnsupportedConnector（login 直接报错，不产出误导性结果）。
    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            Protocol::Ssh
            | Protocol::Mysql
            | Protocol::Redis
            | Protocol::Postgresql
            | Protocol::Mongodb
            | Protocol::Mssql
            | Protocol::Oracle
            | Protocol::Ftp
            | Protocol::Telnet
            | Protocol::Smb
            | Protocol::HttpBasic
            | Protocol::HttpForm
            | Protocol::Rtsp
            | Protocol::Onvif
            | Protocol::Rdp
            | Protocol::Vnc
            | Protocol::Imap
            | Protocol::Pop3
            | Protocol::Smtp
            | Protocol::Snmp
            | Protocol::Ldap
            | Protocol::Sftp
        )
    }
}

/// 凭证（用户名 + 密码）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// 爆破结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceResult {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub credential: Credential,
    pub success: bool,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

/// 爆破参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceParams {
    /// 目标主机
    #[serde(default)]
    pub host: String,
    /// 目标协议
    pub protocol: Protocol,
    /// 目标端口，None 则用协议默认端口
    #[serde(default)]
    pub port: Option<u16>,
    /// 用户名字典
    #[serde(default)]
    pub usernames: Vec<String>,
    /// 密码字典
    #[serde(default)]
    pub passwords: Vec<String>,
    /// 并发数
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// 超时（毫秒）
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// 每个目标最大尝试次数，0 表示不限
    #[serde(default)]
    pub max_attempts: usize,
    /// G2.5: 发现第一个成功凭证后是否立即停止扫描整个字典。
    /// 默认 true（当前行为：发现一个即停）；false 时即使发现成功凭证也继续尝试剩余凭证，
    /// 用于穷举所有弱口令。
    /// serde alias 保留对旧字段名 `stop_on_success` 的向后兼容。
    #[serde(default = "default_true", alias = "stop_on_success")]
    pub stop_on_first_success: bool,
    /// 重试次数
    #[serde(default = "default_one")]
    pub retries: u32,
    /// G2.3: 组合字典模式 — user:pass 配对文件，逐行使用（非笛卡尔积）。
    /// 非空时优先使用，忽略 usernames × passwords 笛卡尔积。
    #[serde(default)]
    pub credential_pairs: Vec<crate::dictionary::CredentialPair>,
}

fn default_concurrency() -> usize { 100 }
fn default_timeout() -> u64 { 5000 }
fn default_true() -> bool { true }
fn default_one() -> u32 { 1 }

impl Default for BruteForceParams {
    fn default() -> Self {
        Self {
            host: String::new(),
            protocol: Protocol::Ssh,
            port: None,
            usernames: Vec::new(),
            passwords: Vec::new(),
            concurrency: 100,
            timeout_ms: 5000,
            max_attempts: 0,
            stop_on_first_success: true,
            retries: 1,
            credential_pairs: Vec::new(),
        }
    }
}

/// 离线 Hash 破解结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCrackResult {
    pub hash: String,
    pub plaintext: Option<String>,
    pub hash_type: String,
    pub cracked: bool,
}

/// 弱密码检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPasswordResult {
    pub password: String,
    pub is_weak: bool,
    pub reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stop_on_first_success_defaults_to_true() {
        // G2.5: 默认行为是发现第一个成功凭证即停止
        let params = BruteForceParams::default();
        assert!(params.stop_on_first_success);
    }

    #[test]
    fn test_serde_stop_on_first_success_field() {
        // 新字段名可正常反序列化
        let json = r#"{"protocol":"ssh","stop_on_first_success":false}"#;
        let params: BruteForceParams = serde_json::from_str(json).unwrap();
        assert!(!params.stop_on_first_success);
    }

    #[test]
    fn test_serde_backward_compat_stop_on_success_alias() {
        // 旧字段名 stop_on_success 通过 serde alias 继续生效，
        // 保证 argus-api 等上游无需改动即可控制该行为
        let json = r#"{"protocol":"ssh","stop_on_success":false}"#;
        let params: BruteForceParams = serde_json::from_str(json).unwrap();
        assert!(!params.stop_on_first_success);
    }

    #[test]
    fn test_serde_stop_on_first_success_true() {
        let json = r#"{"protocol":"ssh","stop_on_first_success":true}"#;
        let params: BruteForceParams = serde_json::from_str(json).unwrap();
        assert!(params.stop_on_first_success);
    }
}
