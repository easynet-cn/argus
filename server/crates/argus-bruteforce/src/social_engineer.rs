//! 社工字典生成器

use serde::{Deserialize, Serialize};

/// 社工目标信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialTarget {
    pub name: Option<String>,
    pub english_name: Option<String>,
    pub company: Option<String>,
    pub domain: Option<String>,
    pub birthday: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub keywords: Vec<String>,
}

impl Default for SocialTarget {
    fn default() -> Self {
        Self {
            name: None,
            english_name: None,
            company: None,
            domain: None,
            birthday: None,
            phone: None,
            email: None,
            keywords: Vec::new(),
        }
    }
}

/// 社工字典生成器
pub struct SocialEngineer;

impl SocialEngineer {
    /// 基于目标信息生成密码字典
    pub fn generate_passwords(target: &SocialTarget) -> Vec<String> {
        let mut passwords = Vec::new();
        let mut base_words: Vec<String> = Vec::new();

        // 收集基础词
        if let Some(name) = &target.name {
            base_words.push(name.clone());
            base_words.push(name.to_lowercase());
        }
        if let Some(en_name) = &target.english_name {
            base_words.push(en_name.clone());
            base_words.push(en_name.to_lowercase());
            base_words.push(en_name.to_uppercase());
        }
        if let Some(company) = &target.company {
            base_words.push(company.clone());
            base_words.push(company.to_lowercase());
        }
        if let Some(domain) = &target.domain {
            base_words.push(domain.clone());
            base_words.push(domain.to_lowercase());
        }
        for kw in &target.keywords {
            base_words.push(kw.clone());
            base_words.push(kw.to_lowercase());
        }

        // 常见后缀数字
        let suffixes = ["", "123", "1234", "12345", "123456", "1", "111", "000", "666", "888"];
        let special = ["", "!", "@", "#", "$", ".", "_"];

        // 基础词 + 后缀
        for word in &base_words {
            for suffix in suffixes.iter() {
                for sp in special.iter() {
                    let pwd = format!("{word}{suffix}{sp}");
                    if !pwd.is_empty() {
                        passwords.push(pwd);
                    }
                }
            }
            // 首字母大写 + 后缀
            let capitalized = capitalize(word);
            if capitalized != *word {
                for suffix in suffixes.iter() {
                    for sp in special.iter() {
                        let pwd = format!("{capitalized}{suffix}{sp}");
                        if !pwd.is_empty() {
                            passwords.push(pwd);
                        }
                    }
                }
            }
        }

        // 生日相关组合
        if let Some(birthday) = &target.birthday {
            // 提取年、月、日
            let parts: Vec<&str> = birthday.split(|c| c == '-' || c == '/' || c == '.').collect();
            if parts.len() == 3 {
                let year = parts[0];
                let month = parts[1];
                let day = parts[2];
                let year_short = &year[year.len().saturating_sub(2)..];

                let birthday_combos = [
                    format!("{year}{month}{day}"),
                    format!("{year_short}{month}{day}"),
                    format!("{month}{day}{year_short}"),
                    format!("{day}{month}{year_short}"),
                    format!("{year}.{month}.{day}"),
                    format!("{year}_{month}_{day}"),
                    format!("{month}{day}"),
                ];
                passwords.extend(birthday_combos.into_iter());

                // 基础词 + 生日
                for word in &base_words {
                    passwords.push(format!("{word}{year}"));
                    passwords.push(format!("{word}{year_short}"));
                    passwords.push(format!("{word}{month}{day}"));
                }
            }
        }

        // 手机号相关
        if let Some(phone) = &target.phone {
            passwords.push(phone.clone());
            if phone.len() >= 6 {
                passwords.push(phone[phone.len() - 6..].to_string());
            }
            if phone.len() >= 4 {
                passwords.push(phone[phone.len() - 4..].to_string());
            }
            for word in &base_words {
                passwords.push(format!("{word}{}", phone[phone.len().saturating_sub(4)..].to_string()));
            }
        }

        // 邮箱用户名部分
        if let Some(email) = &target.email {
            if let Some(at) = email.find('@') {
                let username = &email[..at];
                passwords.push(username.to_string());
                passwords.push(format!("{username}123"));
                passwords.push(format!("{username}123456"));
            }
        }

        // 去重
        passwords.sort();
        passwords.dedup();
        passwords
    }

    /// 基于目标信息生成用户名字典
    pub fn generate_usernames(target: &SocialTarget) -> Vec<String> {
        let mut usernames = Vec::new();

        if let Some(name) = &target.name {
            usernames.push(name.clone());
            usernames.push(name.to_lowercase());
            // 拼音首字母（仅中文名有效）
            let initials = pinyin_initial(name);
            if !initials.is_empty() {
                usernames.push(initials);
            }
        }
        if let Some(en_name) = &target.english_name {
            usernames.push(en_name.clone());
            usernames.push(en_name.to_lowercase());
            usernames.push(en_name.to_uppercase());
            // 全名缩写
            let parts: Vec<&str> = en_name.split_whitespace().collect();
            if parts.len() > 1 {
                let initials: String = parts.iter().map(|p| p.chars().next().unwrap_or(' ')).collect();
                usernames.push(initials.to_lowercase());
                usernames.push(format!("{}{}", parts[0].to_lowercase(), parts[1].to_lowercase()));
            }
        }
        if let Some(company) = &target.company {
            usernames.push(company.to_lowercase());
            usernames.push(format!("{}@admin", company.to_lowercase()));
        }
        if let Some(email) = &target.email {
            if let Some(at) = email.find('@') {
                usernames.push(email[..at].to_string());
            }
        }

        usernames.sort();
        usernames.dedup();
        usernames
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// 提取中文名的拼音首字母
///
/// 仅处理 CJK 汉字，每个汉字取拼音首字母（如 "张三" → "zs"）
/// 非汉字字符跳过，无汉字时返回空字符串
fn pinyin_initial(s: &str) -> String {
    use pinyin::ToPinyin;

    s.chars()
        .filter_map(|ch| {
            if ('\u{4e00}'..='\u{9fff}').contains(&ch) {
                // CJK 统一汉字：转为拼音后取首字母
                ch.to_pinyin().and_then(|p| p.plain().chars().next())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinyin_initial_chinese() {
        assert_eq!(pinyin_initial("张三"), "zs");
        assert_eq!(pinyin_initial("李四"), "ls");
        assert_eq!(pinyin_initial("王五"), "ww");
        assert_eq!(pinyin_initial("赵"), "z");
    }

    #[test]
    fn test_pinyin_initial_ascii_returns_empty() {
        // ASCII 名字不产生拼音首字母
        assert_eq!(pinyin_initial("admin"), "");
        assert_eq!(pinyin_initial("Test"), "");
    }

    #[test]
    fn test_pinyin_initial_mixed() {
        // 混合字符串只提取中文部分的拼音首字母
        assert_eq!(pinyin_initial("张三test"), "zs");
        assert_eq!(pinyin_initial("Admin张"), "z");
    }

    #[test]
    fn test_pinyin_initial_empty_and_symbols() {
        assert_eq!(pinyin_initial(""), "");
        assert_eq!(pinyin_initial("   "), "");
        assert_eq!(pinyin_initial("123"), "");
        assert_eq!(pinyin_initial("@#$"), "");
    }

    #[test]
    fn test_username_generation_with_chinese_name() {
        let target = SocialTarget {
            name: Some("张三".to_string()),
            ..Default::default()
        };
        let usernames = SocialEngineer::generate_usernames(&target);
        assert!(
            usernames.iter().any(|u| u == "zs"),
            "用户名应包含拼音首字母 zs: {:?}",
            usernames
        );
    }

    #[test]
    fn test_username_generation_with_ascii_name_no_pinyin() {
        let target = SocialTarget {
            name: Some("admin".to_string()),
            ..Default::default()
        };
        let usernames = SocialEngineer::generate_usernames(&target);
        // ASCII 名字不应产生空字符串用户名
        assert!(
            !usernames.iter().any(|u| u.is_empty()),
            "不应包含空字符串用户名: {:?}",
            usernames
        );
    }
}
