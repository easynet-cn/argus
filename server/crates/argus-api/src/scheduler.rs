//! 任务调度器（定时 / 周期）
//!
//! 启动后在后台周期性检查 `launch_mode` 为 `scheduled` / `periodic` 的任务，
//! 当调度条件满足时将任务状态置为 `running`（交由扫描执行流程消费）。
//!
//! 配置通过任务的 `schedule_config` JSONB 字段传入，支持两种模式：
//!
//! ```json
//! {"type": "periodic", "interval_minutes": 60}
//! {"type": "cron", "cron": "0 2 * * *"}
//! ```
//!
//! 调度器会在 `schedule_config` 中写入 `last_run_at`（RFC3339）用于去重与间隔判断。

use std::time::Duration;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, ActiveValue::Set};
use argus_core::entity::task::{self, Entity as ScanTaskEntity, LaunchMode, TaskStatus};

/// 解析单个 cron 字段为分钟集合（0..max）。
/// 支持 `*`、数字、`a,b,c`、`a-b`、`*/n`、`a-b/n`。
fn parse_cron_field(field: &str, min: u32, max: u32) -> Option<std::collections::BTreeSet<u32>> {
    let mut result = std::collections::BTreeSet::new();
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() { return None; }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (r, s.parse::<u32>().ok()?),
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)
        } else {
            let v = range.parse::<u32>().ok()?;
            (v, v)
        };
        if lo < min || hi > max || lo > hi || step == 0 { return None; }
        let mut v = lo;
        while v <= hi {
            result.insert(v);
            v += step;
        }
    }
    Some(result)
}

/// 解析 5 字段 cron 表达式：分 时 日 月 周
struct CronSchedule {
    minutes: std::collections::BTreeSet<u32>,
    hours: std::collections::BTreeSet<u32>,
    days: std::collections::BTreeSet<u32>,
    months: std::collections::BTreeSet<u32>,
    dows: std::collections::BTreeSet<u32>,
}

impl CronSchedule {
    fn parse(expr: &str) -> Option<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 { return None; }
        Some(Self {
            minutes: parse_cron_field(fields[0], 0, 59)?,
            hours: parse_cron_field(fields[1], 0, 23)?,
            days: parse_cron_field(fields[2], 1, 31)?,
            months: parse_cron_field(fields[3], 1, 12)?,
            dows: parse_cron_field(fields[4], 0, 6)?,
        })
    }

    fn matches(&self, dt: &chrono::DateTime<chrono::Utc>) -> bool {
        let minute = dt.format("%M").to_string().parse::<u32>().unwrap_or(99);
        let hour = dt.format("%H").to_string().parse::<u32>().unwrap_or(99);
        let day = dt.format("%d").to_string().parse::<u32>().unwrap_or(0);
        let month = dt.format("%m").to_string().parse::<u32>().unwrap_or(0);
        let dow = dt.format("%u").to_string().parse::<u32>().unwrap_or(0) % 7; // 周一=1..周日=0
        self.minutes.contains(&minute)
            && self.hours.contains(&hour)
            && self.days.contains(&day)
            && self.months.contains(&month)
            && self.dows.contains(&dow)
    }
}

/// 调度配置
enum Schedule {
    Periodic { interval_minutes: i64 },
    Cron(CronSchedule),
}

impl Schedule {
    fn from_config(cfg: &serde_json::Value) -> Option<Self> {
        let typ = cfg.get("type")?.as_str()?;
        match typ {
            "periodic" => {
                let mins = cfg.get("interval_minutes").and_then(|v| v.as_i64()).unwrap_or(60);
                Some(Schedule::Periodic { interval_minutes: mins.max(1) })
            }
            "cron" => {
                let expr = cfg.get("cron")?.as_str()?;
                CronSchedule::parse(expr).map(Schedule::Cron)
            }
            _ => None,
        }
    }
}

/// 判断任务是否该调度执行
fn should_run(
    schedule: &Schedule,
    last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match schedule {
        Schedule::Periodic { interval_minutes } => {
            match last_run_at {
                None => true,
                Some(last) => {
                    let elapsed = (now - last).num_minutes();
                    elapsed >= *interval_minutes
                }
            }
        }
        Schedule::Cron(cron) => {
            if !cron.matches(&now) {
                return false;
            }
            // 同一分钟内不重复触发
            match last_run_at {
                None => true,
                Some(last) => (now - last).num_seconds().abs() >= 60,
            }
        }
    }
}

/// 后台调度循环
pub async fn run_scheduler(db: sea_orm::DatabaseConnection) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    // 第一次立即 tick，后续每分钟一次
    interval.tick().await;
    loop {
        interval.tick().await;
        let now = chrono::Utc::now();

        // 加载所有 scheduled / periodic 任务
        let tasks = match ScanTaskEntity::find()
            .filter(task::Column::LaunchMode.is_in([LaunchMode::Scheduled, LaunchMode::Periodic]))
            .all(&db)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("调度器加载任务失败: {e}");
                continue;
            }
        };

        for t in tasks {
            // 仅在非运行状态时触发；已完成/失败/停止的可按周期重新调度
            if matches!(t.status, TaskStatus::Running | TaskStatus::Paused) {
                continue;
            }
            let cfg = match &t.schedule_config {
                Some(c) => c.clone(),
                None => continue,
            };
            let schedule = match Schedule::from_config(&cfg) {
                Some(s) => s,
                None => continue,
            };
            let last_run_at = cfg
                .get("last_run_at")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));

            if !should_run(&schedule, last_run_at, now) {
                continue;
            }

            // 更新 schedule_config.last_run_at
            let mut new_cfg = cfg;
            new_cfg["last_run_at"] = serde_json::Value::String(now.to_rfc3339());

            let mut active: task::ActiveModel = t.clone().into();
            active.status = Set(TaskStatus::Running);
            active.started_at = Set(Some(now));
            active.finished_at = Set(None);
            active.schedule_config = Set(Some(new_cfg));
            if let Err(e) = active.update(&db).await {
                tracing::error!("调度器启动任务 {} 失败: {e}", t.id);
            } else {
                tracing::info!("调度器启动任务 {} ({:?})", t.id, t.launch_mode);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cron_all() {
        let c = CronSchedule::parse("* * * * *").unwrap();
        assert_eq!(c.minutes.len(), 60);
        assert_eq!(c.hours.len(), 24);
        assert_eq!(c.days.len(), 31);
        assert_eq!(c.months.len(), 12);
        assert_eq!(c.dows.len(), 7);
    }

    #[test]
    fn test_parse_cron_specific() {
        let c = CronSchedule::parse("0 2 * * *").unwrap();
        assert!(c.minutes.contains(&0));
        assert!(c.hours.contains(&2));
    }

    #[test]
    fn test_parse_cron_step() {
        let c = CronSchedule::parse("*/15 * * * *").unwrap();
        assert!(c.minutes.contains(&0));
        assert!(c.minutes.contains(&15));
        assert!(c.minutes.contains(&30));
        assert!(c.minutes.contains(&45));
        assert!(!c.minutes.contains(&10));
    }

    #[test]
    fn test_parse_cron_range_list() {
        let c = CronSchedule::parse("1,3,5-7 * * * *").unwrap();
        for m in [1, 3, 5, 6, 7] {
            assert!(c.minutes.contains(&m));
        }
    }

    #[test]
    fn test_parse_cron_invalid() {
        assert!(CronSchedule::parse("* * *").is_none());
        assert!(CronSchedule::parse("60 * * * *").is_none());
        assert!(CronSchedule::parse("0 24 * * *").is_none());
    }

    #[test]
    fn test_schedule_periodic() {
        let s = Schedule::from_config(&serde_json::json!({"type": "periodic", "interval_minutes": 30})).unwrap();
        let now = chrono::Utc::now();
        assert!(should_run(&s, None, now));
        let last = now - chrono::Duration::minutes(31);
        assert!(should_run(&s, Some(last), now));
        let last = now - chrono::Duration::minutes(10);
        assert!(!should_run(&s, Some(last), now));
    }

    #[test]
    fn test_schedule_cron_dedup() {
        let s = Schedule::from_config(&serde_json::json!({"type": "cron", "cron": "* * * * *"})).unwrap();
        let now = chrono::Utc::now();
        assert!(should_run(&s, None, now));
        // 同一分钟内不重复
        assert!(!should_run(&s, Some(now), now));
    }
}
