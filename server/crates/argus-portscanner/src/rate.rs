//! 自适应发包速率控制
//!
//! 实现：
//! - Token Bucket 限流
//! - 基于反馈（成功/失败）的动态速率调整
//!   - 连续失败达到阈值 → 降速（×0.5，下限 = 1）
//!   - 连续成功达到阈值 → 提速（×1.1，上限 = 原始 rate）
//!   - unlimited 模式下不启用动态调整

use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 连续失败多少次后触发降速
const FAILURE_THRESHOLD: u64 = 10;
/// 连续成功多少次后触发提速
const SUCCESS_THRESHOLD: u64 = 100;
/// 降速因子（除以 2）
const BACKOFF_DIVISOR: u64 = 2;
/// 提速乘数 / 1000（× 1.1）
const RECOVERY_MULTIPLIER_X1000: u64 = 1100;

/// 令牌桶限流器（带自适应速率调整）
pub struct RateLimiter {
    /// 当前令牌数
    tokens: Mutex<u64>,
    /// 桶容量
    capacity: u64,
    /// 基础速率（包/秒）—— 用户配置的初始值，提速上限
    base_rate_per_sec: u64,
    /// 当前实际速率（包/秒）—— 动态调整后的值
    current_rate_per_sec: AtomicU64,
    /// 上次补充令牌时间
    last_refill: Mutex<Instant>,
    /// 已发送总包数
    total_sent: AtomicU64,
    /// 连续成功计数
    consecutive_success: AtomicU64,
    /// 连续失败计数
    consecutive_failure: AtomicU64,
    /// 降速次数（统计用）
    backoff_count: AtomicU32,
    /// 提速次数（统计用）
    recovery_count: AtomicU32,
}

impl RateLimiter {
    /// 创建限流器
    /// - rate_per_sec: 每秒允许的包数，0 表示不限速
    pub fn new(rate_per_sec: u32) -> Arc<Self> {
        let capacity = rate_per_sec.max(1) as u64;
        Arc::new(Self {
            tokens: Mutex::new(capacity),
            capacity,
            base_rate_per_sec: capacity,
            current_rate_per_sec: AtomicU64::new(capacity),
            last_refill: Mutex::new(Instant::now()),
            total_sent: AtomicU64::new(0),
            consecutive_success: AtomicU64::new(0),
            consecutive_failure: AtomicU64::new(0),
            backoff_count: AtomicU32::new(0),
            recovery_count: AtomicU32::new(0),
        })
    }

    /// 不限速
    pub fn unlimited() -> Arc<Self> {
        Arc::new(Self {
            tokens: Mutex::new(u64::MAX),
            capacity: u64::MAX,
            base_rate_per_sec: u64::MAX,
            current_rate_per_sec: AtomicU64::new(u64::MAX),
            last_refill: Mutex::new(Instant::now()),
            total_sent: AtomicU64::new(0),
            consecutive_success: AtomicU64::new(0),
            consecutive_failure: AtomicU64::new(0),
            backoff_count: AtomicU32::new(0),
            recovery_count: AtomicU32::new(0),
        })
    }

    /// 尝试获取一个令牌，如果没有则等待
    pub async fn acquire(&self) {
        if self.capacity == u64::MAX {
            self.total_sent.fetch_add(1, Ordering::Relaxed);
            return;
        }

        loop {
            let mut tokens = self.tokens.lock().await;
            let mut last_refill = self.last_refill.lock().await;

            let now = Instant::now();
            let elapsed = now.duration_since(*last_refill);
            // 使用当前实际速率（动态调整后）补充令牌
            let current_rate = self.current_rate_per_sec.load(Ordering::Relaxed);
            let refill = (elapsed.as_secs_f64() * current_rate as f64) as u64;
            if refill > 0 {
                *tokens = (*tokens + refill).min(self.capacity);
                *last_refill = now;
            }

            if *tokens > 0 {
                *tokens -= 1;
                drop(last_refill);
                drop(tokens);
                self.total_sent.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // 没有令牌，等待一个令牌周期
            let wait_nanos = 1_000_000_000u64 / current_rate.max(1);
            drop(last_refill);
            drop(tokens);
            tokio::time::sleep(Duration::from_nanos(wait_nanos)).await;
        }
    }

    /// 反馈成功（用于自适应提速）
    pub async fn record_success(&self) {
        if self.capacity == u64::MAX {
            return;
        }
        // 失败计数清零
        self.consecutive_failure.store(0, Ordering::Relaxed);
        let succ = self.consecutive_success.fetch_add(1, Ordering::Relaxed) + 1;

        if succ >= SUCCESS_THRESHOLD {
            // 重置并尝试提速
            self.consecutive_success.store(0, Ordering::Relaxed);
            let current = self.current_rate_per_sec.load(Ordering::Relaxed);
            let new_rate = (current * RECOVERY_MULTIPLIER_X1000 / 1000)
                .min(self.base_rate_per_sec)
                .max(1);
            if new_rate != current {
                self.current_rate_per_sec.store(new_rate, Ordering::Relaxed);
                self.recovery_count.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    "RateLimiter 提速: {current} -> {new_rate} (base={})",
                    self.base_rate_per_sec
                );
            }
        }
    }

    /// 反馈失败（用于自适应降速）
    pub async fn record_failure(&self) {
        if self.capacity == u64::MAX {
            return;
        }
        self.consecutive_success.store(0, Ordering::Relaxed);
        let fail = self.consecutive_failure.fetch_add(1, Ordering::Relaxed) + 1;

        if fail >= FAILURE_THRESHOLD {
            // 重置并降速
            self.consecutive_failure.store(0, Ordering::Relaxed);
            let current = self.current_rate_per_sec.load(Ordering::Relaxed);
            // 下限 1 包/秒，避免完全停摆
            let new_rate = (current / BACKOFF_DIVISOR).max(1).min(self.base_rate_per_sec);
            if new_rate != current {
                self.current_rate_per_sec.store(new_rate, Ordering::Relaxed);
                self.backoff_count.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "RateLimiter 降速: {current} -> {new_rate} (base={})",
                    self.base_rate_per_sec
                );
            }
        }
    }

    /// 获取已发送的总包数
    pub fn total_sent(&self) -> u64 {
        self.total_sent.load(Ordering::Relaxed)
    }

    /// 当前实际速率（包/秒）
    pub fn current_rate(&self) -> u64 {
        self.current_rate_per_sec.load(Ordering::Relaxed)
    }

    /// 基础速率（用户配置的上限）
    pub fn base_rate(&self) -> u64 {
        self.base_rate_per_sec
    }

    /// 降速次数
    pub fn backoff_count(&self) -> u32 {
        self.backoff_count.load(Ordering::Relaxed)
    }

    /// 提速次数
    pub fn recovery_count(&self) -> u32 {
        self.recovery_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_acquire_never_blocks() {
        let rl = RateLimiter::unlimited();
        for _ in 0..1000 {
            rl.acquire().await;
        }
        assert_eq!(rl.total_sent(), 1000);
        assert_eq!(rl.current_rate(), u64::MAX);
    }

    #[tokio::test]
    async fn test_limited_acquire_releases_tokens() {
        let rl = RateLimiter::new(1000);
        for _ in 0..10 {
            rl.acquire().await;
        }
        assert!(rl.total_sent() >= 10);
    }

    #[tokio::test]
    async fn test_record_failure_reduces_rate() {
        let rl = RateLimiter::new(1000);
        for _ in 0..FAILURE_THRESHOLD {
            rl.record_failure().await;
        }
        // 一次降速：1000 / 2 = 500
        assert_eq!(rl.current_rate(), 500);
        assert_eq!(rl.backoff_count(), 1);
    }

    #[tokio::test]
    async fn test_record_success_increases_rate() {
        let rl = RateLimiter::new(1000);
        // 先降速
        for _ in 0..FAILURE_THRESHOLD {
            rl.record_failure().await;
        }
        assert_eq!(rl.current_rate(), 500);
        // 再连续成功 -> 提速
        for _ in 0..SUCCESS_THRESHOLD {
            rl.record_success().await;
        }
        // 500 * 1.1 = 550
        assert_eq!(rl.current_rate(), 550);
        assert_eq!(rl.recovery_count(), 1);
    }

    #[tokio::test]
    async fn test_recovery_caps_at_base_rate() {
        let rl = RateLimiter::new(1000);
        // 大量成功，应到上限 1000 不超过
        for _ in 0..SUCCESS_THRESHOLD * 20 {
            rl.record_success().await;
        }
        assert!(rl.current_rate() <= rl.base_rate());
    }

    #[tokio::test]
    async fn test_backoff_floor_is_one() {
        let rl = RateLimiter::new(2);
        // 多次降速，不应低于 1
        for _ in 0..100 {
            rl.record_failure().await;
        }
        assert!(rl.current_rate() >= 1);
    }
}
