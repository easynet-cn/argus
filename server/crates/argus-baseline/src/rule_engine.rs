//! 配置规则 DSL 引擎
//!
//! 基于 Rhai 脚本引擎，对采集到的配置输出执行合规判定
//! 每条规则的 check_script 是一个 Rhai 表达式，上下文变量 `output` 为采集命令输出
//! 脚本返回 true 表示合规，false 表示不合规

use rhai::{Engine, Scope};
use crate::types::{CheckResult, ComplianceLevel, ComplianceRule};

pub struct RuleEngine {
    engine: Engine,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // 注册辅助函数，便于规则脚本调用

        // contains(output, keyword) - 判断输出是否包含关键词
        let _ = engine.register_fn("contains", |output: &str, keyword: &str| {
            output.contains(keyword)
        });

        // not_contains(output, keyword) - 判断输出是否不包含关键词
        let _ = engine.register_fn("not_contains", |output: &str, keyword: &str| {
            !output.contains(keyword)
        });

        // matches_regex(output, pattern) - 正则匹配
        let _ = engine.register_fn("matches_regex", |output: &str, pattern: &str| {
            match regex::Regex::new(pattern) {
                Ok(re) => re.is_match(output),
                Err(_) => false,
            }
        });

        // starts_with(output, prefix)
        let _ = engine.register_fn("starts_with", |output: &str, prefix: &str| {
            output.starts_with(prefix)
        });

        // ends_with(output, suffix)
        let _ = engine.register_fn("ends_with", |output: &str, suffix: &str| {
            output.ends_with(suffix)
        });

        // equals(output, expected) - 完全相等
        let _ = engine.register_fn("equals", |output: &str, expected: &str| {
            output.trim() == expected.trim()
        });

        // contains_line(output, keyword) - 判断某一行包含关键词（用于多行配置）
        let _ = engine.register_fn("contains_line", |output: &str, keyword: &str| {
            output.lines().any(|line| line.contains(keyword))
        });

        // not_contains_line(output, keyword) - 没有任何一行包含关键词
        let _ = engine.register_fn("not_contains_line", |output: &str, keyword: &str| {
            !output.lines().any(|line| line.contains(keyword))
        });

        // is_empty(output) - 判断输出是否为空
        let _ = engine.register_fn("is_empty", |output: &str| output.trim().is_empty());

        // line_count(output) - 统计行数
        let _ = engine.register_fn("line_count", |output: &str| {
            output.lines().count() as i64
        });

        // to_int(output) - 将输出转为整数
        let _ = engine.register_fn("to_int", |output: &str| {
            output.trim().parse::<i64>().unwrap_or(-1)
        });

        Self { engine }
    }

    /// 对单条规则执行合规判定
    ///
    /// `output` 为采集命令的输出文本
    /// 返回 CheckResult 包含合规级别
    pub fn evaluate(&self, rule: &ComplianceRule, output: &str) -> CheckResult {
        let mut scope = Scope::new();
        scope.push("output", output.to_string());

        // Rhai 使用双引号字符串，预处理：
        // 1. 将反斜杠加倍（Rhai 字符串字面量会处理 \ 转义，如 \s -> s，需加倍保持正则 \s）
        // 2. 将单引号替换为双引号（Rhai 不支持单引号字符串）
        let script = rule.check_script.replace("\\", "\\\\").replace("'", "\"");
        let result = self.engine.eval_with_scope::<bool>(&mut scope, &script);

        let (compliance, message) = match result {
            Ok(true) => (ComplianceLevel::Compliant, None),
            Ok(false) => (
                ComplianceLevel::NonCompliant,
                Some(format!(
                    "规则判定不合规: 期望{}",
                    rule.expected.as_deref().unwrap_or("满足条件")
                )),
            ),
            Err(e) => {
                tracing::warn!("规则 {} 脚本执行失败: {e}", rule.id);
                (
                    ComplianceLevel::Unknown,
                    Some(format!("规则脚本执行异常: {e}")),
                )
            }
        };

        CheckResult {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            category: rule.category.clone(),
            requirement_id: rule.requirement_id.clone(),
            severity: rule.severity.clone(),
            compliance,
            collected_output: Some(output.to_string()),
            message,
            fix_advice: rule.fix_advice.clone(),
        }
    }

    /// 批量评估规则
    ///
    /// `output` 为同一采集项的输出，`rules` 为关联的合规规则列表
    pub fn evaluate_batch<'a>(
        &self,
        output: &str,
        rules: impl Iterator<Item = &'a ComplianceRule>,
    ) -> Vec<CheckResult> {
        rules.map(|r| self.evaluate(r, output)).collect()
    }

    /// 验证规则脚本语法（不实际执行）
    ///
    /// 用于在导入规则集时预检
    pub fn validate_script(script: &str) -> Result<(), String> {
        // 使用 RuleEngine::new() 以注册所有 helper 函数（contains, matches_regex 等）
        let re = Self::new();
        let mut scope = Scope::new();
        scope.push("output", String::new());
        // 同样预处理：反斜杠加倍 + 单引号转双引号
        let processed = script.replace("\\", "\\\\").replace("'", "\"");
        re.engine
            .eval_with_scope::<bool>(&mut scope, &processed)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, script: &str) -> ComplianceRule {
        ComplianceRule {
            id: id.to_string(),
            name: format!("rule-{id}"),
            category: "test".to_string(),
            requirement_id: "8.1.1".to_string(),
            severity: "high".to_string(),
            collect_item_id: "c1".to_string(),
            check_script: script.to_string(),
            expected: None,
            fix_advice: None,
        }
    }

    #[test]
    fn test_contains_compliant() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "contains(output, 'PermitRootLogin no')");
        let result = engine.evaluate(&rule, "PermitRootLogin no\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_contains_non_compliant() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "contains(output, 'PermitRootLogin no')");
        let result = engine.evaluate(&rule, "PermitRootLogin yes\n");
        assert_eq!(result.compliance, ComplianceLevel::NonCompliant);
    }

    #[test]
    fn test_not_contains() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "not_contains(output, 'PermitRootLogin yes')");
        let result = engine.evaluate(&rule, "PermitRootLogin no\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_matches_regex() {
        let engine = RuleEngine::new();
        // 密码最小长度 >= 8
        let rule = make_rule("r1", "matches_regex(output, 'minlen\\s*=?\\s*([8-9]|[1-9][0-9]+)')");
        let result = engine.evaluate(&rule, "minlen = 8\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_matches_regex_non_compliant() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "matches_regex(output, 'minlen\\s*=?\\s*([8-9]|[1-9][0-9]+)')");
        let result = engine.evaluate(&rule, "minlen = 6\n");
        assert_eq!(result.compliance, ComplianceLevel::NonCompliant);
    }

    #[test]
    fn test_equals() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "equals(output, 'yes')");
        let result = engine.evaluate(&rule, "yes\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_contains_line() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "contains_line(output, 'password    requisite')");
        let output = "# pam config\npassword    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=\n";
        let result = engine.evaluate(&rule, output);
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_not_contains_line() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "not_contains_line(output, 'PermitRootLogin yes')");
        let result = engine.evaluate(&rule, "PermitRootLogin no\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_is_empty() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "is_empty(output)");
        let result = engine.evaluate(&rule, "   \n  ");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_line_count() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "line_count(output) >= 2");
        let result = engine.evaluate(&rule, "line1\nline2\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_to_int() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "to_int(output) >= 8");
        let result = engine.evaluate(&rule, "8\n");
        assert_eq!(result.compliance, ComplianceLevel::Compliant);
    }

    #[test]
    fn test_script_error() {
        let engine = RuleEngine::new();
        let rule = make_rule("r1", "invalid_syntax {{{");
        let result = engine.evaluate(&rule, "test\n");
        assert_eq!(result.compliance, ComplianceLevel::Unknown);
    }

    #[test]
    fn test_validate_script_ok() {
        assert!(RuleEngine::validate_script("contains(output, 'test')").is_ok());
    }

    #[test]
    fn test_validate_script_error() {
        assert!(RuleEngine::validate_script("invalid {{{").is_err());
    }

    #[test]
    fn test_evaluate_batch() {
        let engine = RuleEngine::new();
        let rules = vec![
            make_rule("r1", "contains(output, 'a')"),
            make_rule("r2", "contains(output, 'b')"),
        ];
        let results = engine.evaluate_batch("ab\n", rules.iter());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].compliance, ComplianceLevel::Compliant);
        assert_eq!(results[1].compliance, ComplianceLevel::Compliant);
    }
}
