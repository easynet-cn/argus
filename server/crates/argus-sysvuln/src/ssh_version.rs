//! G4.5: OpenSSH 版本扫描
//!
//! 通过读取 SSH Banner 获取版本号，与已知 CVE 版本范围比对
//! 1. TCP 连接目标 22 端口
//! 2. 读取服务器主动发送的 SSH 协议版本标识（"SSH-2.0-OpenSSH_8.9p1 ..."）
//! 3. 解析 OpenSSH 版本号
//! 4. 匹配已知 CVE 版本范围

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// SSH 版本扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshVersionFinding {
    pub target: String,
    pub banner: String,
    pub product: String,
    pub version: String,
    /// 匹配到的 CVE 列表
    pub cves: Vec<SshCveInfo>,
    /// 修复建议
    pub fix_advice: Option<String>,
}

/// SSH CVE 信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCveInfo {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub affected_versions: String,
}

/// 扫描 SSH 版本
pub async fn scan_ssh_version(host: &str, port: u16, timeout_ms: u64) -> Option<SshVersionFinding> {
    let dur = Duration::from_millis(timeout_ms);
    let target = format!("{}:{}", host, port);

    // 1. TCP 连接
    let mut stream = timeout(dur, TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;

    // 2. 读取 SSH Banner（服务器主动发送）
    let mut buf = vec![0u8; 256];
    let n = timeout(dur, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }

    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
    let banner = banner.lines().next()?.trim().to_string();

    // SSH Banner 格式: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    if !banner.starts_with("SSH-") {
        return None;
    }

    // 3. 解析产品名和版本号
    let (product, version) = parse_ssh_banner(&banner)?;

    // 4. 匹配已知 CVE
    let cves = match_ssh_cves(&product, &version);

    let fix_advice = if cves.is_empty() {
        None
    } else {
        Some(format!(
            "升级 OpenSSH 到最新版本，当前版本 {} 存在 {} 个已知漏洞",
            version,
            cves.len()
        ))
    };

    Some(SshVersionFinding {
        target,
        banner,
        product,
        version,
        cves,
        fix_advice,
    })
}

/// 解析 SSH Banner
///
/// 格式: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`
/// 返回: ("OpenSSH", "8.9p1")
fn parse_ssh_banner(banner: &str) -> Option<(String, String)> {
    // SSH-2.0-Product_Version Comments
    let parts: Vec<&str> = banner.splitn(3, '-').collect();
    if parts.len() < 3 {
        return None;
    }
    let product_version = parts[2].split_whitespace().next()?;

    // 分离产品名和版本号
    if let Some(idx) = product_version.find('_') {
        let product = product_version[..idx].to_string();
        let version = product_version[idx + 1..].to_string();
        return Some((product, version));
    }
    // 有些实现不用下划线分隔（如 LibsshSSH_0.8.1 → 可能是 "libssh-0.8.1"）
    if let Some(idx) = product_version.find(|c: char| c.is_ascii_digit()) {
        let product = product_version[..idx].trim_end_matches('-').to_string();
        let version = product_version[idx..].to_string();
        return Some((product, version));
    }
    None
}

/// 从版本字符串中提取主版本号 (major, minor, patch)
fn parse_version_num(version: &str) -> Option<(u32, u32, u32)> {
    let cleaned: String = version
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Vec<u32> = cleaned.split('.').filter_map(|s| s.parse().ok()).collect();
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

/// 匹配 OpenSSH 已知 CVE
fn match_ssh_cves(product: &str, version: &str) -> Vec<SshCveInfo> {
    let product_lower = product.to_lowercase();
    if !product_lower.contains("openssh") {
        return Vec::new();
    }

    let (major, minor, patch) = match parse_version_num(version) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut cves = Vec::new();

    // CVE-2023-38446: OpenSSH ssh-agent 远程代码执行（7.0-9.3p1）
    if (major == 7 && (minor >= 0 && minor <= 9))
        || (major == 8)
        || (major == 9 && (minor <= 3))
    {
        cves.push(SshCveInfo {
            cve_id: "CVE-2023-38446".to_string(),
            severity: "high".to_string(),
            description: "OpenSSH ssh-agent 中的签名原语可能被泄露，可导致远程代码执行".to_string(),
            affected_versions: "OpenSSH 7.0 - 9.3p1".to_string(),
        });
    }

    // CVE-2023-28531: OpenSSH ssh-agent 被利用提权（6.0-9.2p1）
    if (major == 6) || (major == 7) || (major == 8) || (major == 9 && minor <= 2) {
        cves.push(SshCveInfo {
            cve_id: "CVE-2023-28531".to_string(),
            severity: "medium".to_string(),
            description: "OpenSSH ssh-agent 在某些情况下可能被利用进行本地权限提升".to_string(),
            affected_versions: "OpenSSH 6.0 - 9.2p1".to_string(),
        });
    }

    // CVE-2018-15473: OpenSSH 用户名枚举（5.0-7.7）
    if (major == 5) || (major == 6) || (major == 7 && minor <= 7) {
        cves.push(SshCveInfo {
            cve_id: "CVE-2018-15473".to_string(),
            severity: "medium".to_string(),
            description: "OpenSSH 允许通过延迟响应枚举有效用户名".to_string(),
            affected_versions: "OpenSSH 5.0 - 7.7".to_string(),
        });
    }

    // CVE-2016-6210: OpenSSH 用户名枚举（5.0-7.2）
    if (major == 5) || (major == 6) || (major == 7 && minor <= 2) {
        cves.push(SshCveInfo {
            cve_id: "CVE-2016-6210".to_string(),
            severity: "medium".to_string(),
            description: "OpenSSH 允许通过认证响应时间差异枚举用户名".to_string(),
            affected_versions: "OpenSSH 5.0 - 7.2".to_string(),
        });
    }

    // CVE-2024-6387: regreSSHion — OpenSSH 远程代码执行（8.5p1-9.7p1）
    if (major == 8 && minor >= 5) || (major == 9 && minor <= 7) {
        cves.push(SshCveInfo {
            cve_id: "CVE-2024-6387".to_string(),
            severity: "critical".to_string(),
            description: "regreSSHion: OpenSSH sshd 信号处理竞态条件，可导致未认证远程代码执行".to_string(),
            affected_versions: "OpenSSH 8.5p1 - 9.7p1".to_string(),
        });
    }

    let _ = patch; // patch 暂未使用，预留扩展
    cves
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_banner_openssh() {
        let (product, version) = parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1").unwrap();
        assert_eq!(product, "OpenSSH");
        assert_eq!(version, "8.9p1");
    }

    #[test]
    fn test_parse_ssh_banner_without_comment() {
        let (product, version) = parse_ssh_banner("SSH-2.0-OpenSSH_7.4").unwrap();
        assert_eq!(product, "OpenSSH");
        assert_eq!(version, "7.4");
    }

    #[test]
    fn test_parse_ssh_banner_invalid() {
        assert!(parse_ssh_banner("not-ssh").is_none());
        assert!(parse_ssh_banner("SSH-2.0-").is_none());
    }

    #[test]
    fn test_parse_version_num() {
        assert_eq!(parse_version_num("8.9p1"), Some((8, 9, 0)));
        assert_eq!(parse_version_num("7.4"), Some((7, 4, 0)));
        assert_eq!(parse_version_num("9.7p1"), Some((9, 7, 0)));
    }

    #[test]
    fn test_match_ssh_cves_cve_2024_6387() {
        // OpenSSH 8.5 应匹配 CVE-2024-6387
        let cves = match_ssh_cves("OpenSSH", "8.5p1");
        assert!(cves.iter().any(|c| c.cve_id == "CVE-2024-6387"));
    }

    #[test]
    fn test_match_ssh_cves_cve_2018_15473() {
        // OpenSSH 7.4 应匹配 CVE-2018-15473
        let cves = match_ssh_cves("OpenSSH", "7.4");
        assert!(cves.iter().any(|c| c.cve_id == "CVE-2018-15473"));
    }

    #[test]
    fn test_match_ssh_cves_no_match() {
        // OpenSSH 10.0 无已知 CVE
        let cves = match_ssh_cves("OpenSSH", "10.0p1");
        // 10.0 可能匹配 CVE-2023-38446 的条件（major==10 不满足任何分支）
        // 实际上 major==10 不满足任何 CVE 条件
        assert!(cves.is_empty());
    }

    #[test]
    fn test_match_ssh_cves_non_openssh() {
        let cves = match_ssh_cves("libssh", "0.8.1");
        assert!(cves.is_empty());
    }

    #[test]
    fn test_match_ssh_cves_9_7() {
        // OpenSSH 9.7p1 应匹配 CVE-2024-6387
        let cves = match_ssh_cves("OpenSSH", "9.7p1");
        assert!(cves.iter().any(|c| c.cve_id == "CVE-2024-6387"));
    }

    #[test]
    fn test_match_ssh_cves_8_4_no_regreshion() {
        // OpenSSH 8.4p1 不应匹配 CVE-2024-6387（8.5 才开始）
        let cves = match_ssh_cves("OpenSSH", "8.4p1");
        assert!(!cves.iter().any(|c| c.cve_id == "CVE-2024-6387"));
    }
}
