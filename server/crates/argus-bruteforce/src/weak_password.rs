//! 弱密码检测模块

use crate::dictionary::top100_passwords;
use crate::types::WeakPasswordResult;

/// 弱密码检测器
pub struct WeakPasswordChecker;

impl WeakPasswordChecker {
    /// 检测单个密码是否为弱密码
    pub fn check(password: &str) -> WeakPasswordResult {
        let mut reasons = Vec::new();

        // 1. 长度检查
        if password.len() < 8 {
            reasons.push(format!("密码长度 {} < 8", password.len()));
        }

        // 2. 复杂度检查
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

        let complexity = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .filter(|&&c| c)
            .count();

        if complexity < 3 {
            reasons.push(format!("复杂度不足: 仅包含 {} 种字符类型", complexity));
        }

        // 3. 是否全为同一字符
        if password.len() > 1 && password.chars().all(|c| c == password.chars().next().unwrap()) {
            reasons.push("所有字符相同".to_string());
        }

        // 4. 是否连续字符（如 abcdef, 123456）
        if is_consecutive(password) {
            reasons.push("连续字符序列".to_string());
        }

        // 5. 是否为键盘序列（如 qwerty, asdfgh）
        if is_keyboard_pattern(password) {
            reasons.push("键盘连续序列".to_string());
        }

        // 6. 是否在常见弱密码列表中
        let weak_list = top100_passwords();
        if weak_list.contains(&password.to_lowercase()) {
            reasons.push("在常见弱密码字典中".to_string());
        }

        // 7. 重复模式（如 123123, abcabc）
        if has_repeated_pattern(password) {
            reasons.push("重复模式".to_string());
        }

        WeakPasswordResult {
            password: password.to_string(),
            is_weak: !reasons.is_empty(),
            reasons,
        }
    }

    /// 批量检测
    pub fn check_batch(passwords: &[String]) -> Vec<WeakPasswordResult> {
        passwords.iter().map(|p| Self::check(p)).collect()
    }
}

/// 检测是否为连续字符序列
fn is_consecutive(s: &str) -> bool {
    if s.len() < 3 {
        return false;
    }
    let chars: Vec<u8> = s.bytes().collect();
    let diffs: Vec<i8> = chars.windows(2).map(|w| w[1] as i8 - w[0] as i8).collect();
    diffs.iter().all(|&d| d == 1) || diffs.iter().all(|&d| d == -1)
}

/// 检测是否为键盘序列
fn is_keyboard_pattern(s: &str) -> bool {
    let patterns = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "!@#$%^&*()",
        "qazwsx", "edc", "qweasd", "1qaz2wsx",
    ];
    let lower = s.to_lowercase();
    patterns.iter().any(|p| p.contains(&lower) || lower.contains(p))
}

/// 检测是否有重复模式
fn has_repeated_pattern(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let len = s.len();
    for size in 1..=len / 2 {
        if len % size == 0 {
            let pattern = &s[..size];
            if s.chars().collect::<Vec<char>>().chunks(size).all(|chunk| {
                chunk.iter().collect::<String>() == pattern
            }) {
                return true;
            }
        }
    }
    false
}
