//! 字典管理系统

use serde::{Deserialize, Serialize};

/// 内置用户名模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsernameDict {
    /// 空（不指定用户名，适用于 Redis 等无用户场景）
    Empty,
    /// Top 10 常见用户名
    Top10,
    /// Top 50 常见用户名
    Top50,
    /// 自定义用户名列表
    Custom(Vec<String>),
}

/// 内置密码模板
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordDict {
    /// Top 10 弱密码
    Top10,
    /// Top 50 弱密码
    Top50,
    /// Top 100 弱密码
    Top100,
    /// 自定义密码列表
    Custom(Vec<String>),
}

/// Top 10 常见用户名
pub fn top10_usernames() -> Vec<String> {
    vec![
        "root", "admin", "test", "guest", "user",
        "mysql", "postgres", "redis", "ftp", "www",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// Top 50 常见用户名
pub fn top50_usernames() -> Vec<String> {
    let mut users = top10_usernames();
    users.extend(vec![
        "administrator", "oracle", "sa", "sybase", "nobody",
        "mail", "ftpuser", "apache", "nginx", "tomcat",
        "jenkins", "git", "svn", "docker", "vagrant",
        "ubuntu", "centos", "debian", "pi", "oracle",
        "mongodb", "rabbitmq", "zookeeper", "elastic", "kibana",
        "grafana", "prometheus", "nagios", "zabbix", "cacti",
        "backup", "support", "sales", "info", "contact",
        "webmaster", "postmaster", "abuse", "spam", "hostmaster",
        "dev", "ops", "dba", "sec", "audit",
    ].into_iter().map(|s| s.to_string()));
    users
}

/// Top 10 弱密码
pub fn top10_passwords() -> Vec<String> {
    vec![
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// Top 50 弱密码
pub fn top50_passwords() -> Vec<String> {
    let mut passwords = top10_passwords();
    passwords.extend(vec![
        "123123", "baseball", "iloveyou", "trustno1", "sunshine",
        "princess", "football", "charlie", "shadow", "superman",
        "michael", "ninja", "mustang", "password1", "1234567890",
        "123456789", "1234567", "123456", "12345", "1234",
        "123456789", "admin", "letmein", "welcome", "monkey",
        "654321", "666666", "abc123", "qazwsx", "000000",
        "123321", "iloveyou", "a123456", "123456a", "11111111",
        "12341234", "123123123", "pass@123", "P@ssw0rd", "Password1",
        "qwerty123", "abc123456", "password123", "1q2w3e4r", "1qaz2wsx",
        "woaini", "woaini1314", "5201314", "1314520", "520520",
    ].into_iter().map(|s| s.to_string()));
    passwords
}

/// Top 100 弱密码
pub fn top100_passwords() -> Vec<String> {
    let mut passwords = top50_passwords();
    passwords.extend(vec![
        "asdfgh", "asdfghjkl", "zxcvbnm", "qwer1234", "q1w2e3r4",
        "1qazxsw2", "zaq12wsx", "!QAZ2wsx", "1q2w3e4r5t", "qazwsxedc",
        "plokijuh", "asdf1234", "asdf123456", "1234asdf", "pass1234",
        "pass123456", "test1234", "test123456", "root1234", "root123456",
        "admin123", "admin1234", "admin123456", "admin@123", "Admin123",
        "root@123", "toor", "passw0rd", "passw0rd123", "Passw0rd",
        "Pa$$w0rd", "Abcd1234", "Abcd@1234", "abcd1234", "abcd@1234",
        "123456789a", "123456789b", "a123456789", "a1b2c3d4", "a1b2c3d4e5",
        "woaini1314520", "1314520woaini", "5201314520", "521521", "201314",
        "1314520", "5201314", "123123123123", "112233", "11223344",
        "223344", "aabbcc", "abcabc", "111222", "111222333",
    ].into_iter().map(|s| s.to_string()));
    passwords
}

/// 获取用户名列表
pub fn get_usernames(dict: &UsernameDict) -> Vec<String> {
    match dict {
        UsernameDict::Empty => vec![String::new()],
        UsernameDict::Top10 => top10_usernames(),
        UsernameDict::Top50 => top50_usernames(),
        UsernameDict::Custom(users) => users.clone(),
    }
}

/// 获取密码列表
pub fn get_passwords(dict: &PasswordDict) -> Vec<String> {
    match dict {
        PasswordDict::Top10 => top10_passwords(),
        PasswordDict::Top50 => top50_passwords(),
        PasswordDict::Top100 => top100_passwords(),
        PasswordDict::Custom(pwds) => pwds.clone(),
    }
}

/// 加载字典文件（每行一个条目）
pub fn load_dict_file(path: &str) -> Result<Vec<String>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取字典文件失败: {e}"))?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

// G2.3: 组合字典模式 — 用户上传 user:pass 配对文件，逐行使用

/// 凭证对（用户名 + 密码配对，非笛卡尔积）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialPair {
    pub username: String,
    pub password: String,
}

/// 加载组合字典文件（每行 `username:password` 或 `username password`）
///
/// 支持分隔符: `:`、`空格`、`Tab`。第一个分隔符前的部分为用户名，之后为密码。
/// 空行和以 `#` 开头的注释行被跳过。
pub fn load_combo_dict_file(path: &str) -> Result<Vec<CredentialPair>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取组合字典文件失败: {e}"))?;
    parse_combo_lines(&content)
}

/// 解析组合字典文本（公开以便测试）
pub fn parse_combo_lines(content: &str) -> Result<Vec<CredentialPair>, String> {
    let mut pairs = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 找第一个分隔符（: 或 空格 或 Tab）
        let sep_pos = line
            .find(|c: char| c == ':' || c == ' ' || c == '\t')
            .ok_or_else(|| format!("第 {} 行缺少分隔符（: 或空格）: `{}`", i + 1, line))?;
        let username = line[..sep_pos].trim().to_string();
        let password = line[sep_pos..].trim_start_matches([':', ' ', '\t']).to_string();
        if username.is_empty() || password.is_empty() {
            return Err(format!("第 {} 行用户名或密码为空: `{}`", i + 1, line));
        }
        pairs.push(CredentialPair { username, password });
    }
    Ok(pairs)
}
