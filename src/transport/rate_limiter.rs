use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::config::ProcessingBudgetConfig;

const MIN_RATE_WINDOW: Duration = Duration::from_millis(1);
const MIN_BLOCK_DURATION: Duration = Duration::from_millis(1);
const MIN_PROCESSING_IDLE_TTL: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    RateExceeded,
    Manual,
    HandshakeHeuristic,
    CookieMismatchGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allow,
    GlobalLimit,
    IpBlocked {
        newly_blocked: bool,
        reason: BlockReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingBudgetDecision {
    Allow,
    IpExhausted,
    GlobalExhausted,
}

#[derive(Debug, Clone, Copy, Default)]
struct IpWindowState {
    count: usize,
}

#[derive(Debug, Clone, Copy)]
struct BlockState {
    blocked_until: Option<Instant>,
    reason: BlockReason,
}

#[derive(Debug, Clone, Copy, Default)]
struct RateLimiterMetrics {
    global_limit_hits: u64,
    ip_block_hits: u64,
    ip_block_hits_rate_exceeded: u64,
    ip_block_hits_manual: u64,
    ip_block_hits_handshake_heuristic: u64,
    ip_block_hits_cookie_mismatch_guard: u64,
    addresses_blocked: u64,
    addresses_blocked_rate_exceeded: u64,
    addresses_blocked_manual: u64,
    addresses_blocked_handshake_heuristic: u64,
    addresses_blocked_cookie_mismatch_guard: u64,
    addresses_unblocked: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessingBudgetMetrics {
    drops_total: u64,
    drops_ip_exhausted: u64,
    drops_global_exhausted: u64,
    consumed_units_total: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessingTokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl ProcessingTokenBucket {
    fn with_full_tokens(now: Instant, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant, refill_per_sec: u32, burst: u32) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        let refill = elapsed * (refill_per_sec as f64);
        self.tokens = (self.tokens + refill).clamp(0.0, burst as f64);
    }

    fn can_consume(&self, cost: u32) -> bool {
        self.tokens >= cost as f64
    }

    fn consume(&mut self, cost: u32) {
        self.tokens = (self.tokens - cost as f64).max(0.0);
    }
}

struct ProcessingBudgetState {
    config: ProcessingBudgetConfig,
    global_bucket: ProcessingTokenBucket,
    per_ip_buckets: HashMap<IpAddr, ProcessingTokenBucket>,
    metrics: ProcessingBudgetMetrics,
}

impl ProcessingBudgetState {
    fn new(config: ProcessingBudgetConfig, now: Instant) -> Self {
        let config = normalize_processing_budget_config(config);
        Self {
            global_bucket: ProcessingTokenBucket::with_full_tokens(now, config.global_burst_units),
            config,
            per_ip_buckets: HashMap::new(),
            metrics: ProcessingBudgetMetrics::default(),
        }
    }

    fn set_config(&mut self, config: ProcessingBudgetConfig, now: Instant) {
        let config = normalize_processing_budget_config(config);
        self.config = config;
        self.global_bucket =
            ProcessingTokenBucket::with_full_tokens(now, self.config.global_burst_units);
        self.per_ip_buckets.clear();
    }

    fn tick(&mut self, now: Instant) {
        if !self.config.enabled {
            self.per_ip_buckets.clear();
            return;
        }

        self.per_ip_buckets.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_refill) <= self.config.bucket_idle_ttl
        });
    }

    fn consume(&mut self, ip: IpAddr, cost_units: usize, now: Instant) -> ProcessingBudgetDecision {
        if !self.config.enabled {
            return ProcessingBudgetDecision::Allow;
        }

        let max_cost = self
            .config
            .per_ip_burst_units
            .min(self.config.global_burst_units)
            .max(1);
        let cost_units = cost_units.max(1).min(max_cost as usize) as u32;

        self.global_bucket.refill(
            now,
            self.config.global_refill_units_per_sec,
            self.config.global_burst_units,
        );
        if !self.global_bucket.can_consume(cost_units) {
            self.metrics.drops_total = self.metrics.drops_total.saturating_add(1);
            self.metrics.drops_global_exhausted =
                self.metrics.drops_global_exhausted.saturating_add(1);
            return ProcessingBudgetDecision::GlobalExhausted;
        }

        let bucket = self.per_ip_buckets.entry(ip).or_insert_with(|| {
            ProcessingTokenBucket::with_full_tokens(now, self.config.per_ip_burst_units)
        });
        bucket.refill(
            now,
            self.config.per_ip_refill_units_per_sec,
            self.config.per_ip_burst_units,
        );
        if !bucket.can_consume(cost_units) {
            self.metrics.drops_total = self.metrics.drops_total.saturating_add(1);
            self.metrics.drops_ip_exhausted = self.metrics.drops_ip_exhausted.saturating_add(1);
            return ProcessingBudgetDecision::IpExhausted;
        }

        self.global_bucket.consume(cost_units);
        bucket.consume(cost_units);
        self.metrics.consumed_units_total = self
            .metrics
            .consumed_units_total
            .saturating_add(cost_units as u64);
        ProcessingBudgetDecision::Allow
    }

    fn metrics_snapshot(&self) -> ProcessingBudgetMetricsSnapshot {
        ProcessingBudgetMetricsSnapshot {
            drops_total: self.metrics.drops_total,
            drops_ip_exhausted: self.metrics.drops_ip_exhausted,
            drops_global_exhausted: self.metrics.drops_global_exhausted,
            consumed_units_total: self.metrics.consumed_units_total,
            active_ip_buckets: self.per_ip_buckets.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RateLimiterMetricsSnapshot {
    pub global_limit_hits: u64,
    pub ip_block_hits: u64,
    pub ip_block_hits_rate_exceeded: u64,
    pub ip_block_hits_manual: u64,
    pub ip_block_hits_handshake_heuristic: u64,
    pub ip_block_hits_cookie_mismatch_guard: u64,
    pub addresses_blocked: u64,
    pub addresses_blocked_rate_exceeded: u64,
    pub addresses_blocked_manual: u64,
    pub addresses_blocked_handshake_heuristic: u64,
    pub addresses_blocked_cookie_mismatch_guard: u64,
    pub addresses_unblocked: u64,
    pub blocked_addresses: usize,
    pub exception_addresses: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessingBudgetMetricsSnapshot {
    pub drops_total: u64,
    pub drops_ip_exhausted: u64,
    pub drops_global_exhausted: u64,
    pub consumed_units_total: u64,
    pub active_ip_buckets: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimiterConfigSnapshot {
    pub per_ip_limit: usize,
    pub global_limit: usize,
    pub window: Duration,
    pub block_duration: Duration,
}

pub struct RateLimiter {
    window_start: Instant,
    window_count: usize,
    per_ip_limit: usize,
    global_limit: usize,
    window: Duration,
    block_duration: Duration,
    ip_state: HashMap<IpAddr, IpWindowState>,
    blocked: HashMap<IpAddr, BlockState>,
    exceptions: HashSet<IpAddr>,
    metrics: RateLimiterMetrics,
    processing_budget: ProcessingBudgetState,
}

impl RateLimiter {
    pub fn new(
        per_ip_limit: usize,
        global_limit: usize,
        window: Duration,
        block_duration: Duration,
    ) -> Self {
        Self::new_with_processing_budget(
            per_ip_limit,
            global_limit,
            window,
            block_duration,
            ProcessingBudgetConfig::default(),
        )
    }

    pub fn new_with_processing_budget(
        per_ip_limit: usize,
        global_limit: usize,
        window: Duration,
        block_duration: Duration,
        processing_budget_config: ProcessingBudgetConfig,
    ) -> Self {
        let (per_ip_limit, global_limit, window, block_duration) =
            normalize_limits(per_ip_limit, global_limit, window, block_duration);
        let now = Instant::now();
        Self {
            window_start: now,
            window_count: 0,
            per_ip_limit,
            global_limit,
            window,
            block_duration,
            ip_state: HashMap::new(),
            blocked: HashMap::new(),
            exceptions: HashSet::new(),
            metrics: RateLimiterMetrics::default(),
            processing_budget: ProcessingBudgetState::new(processing_budget_config, now),
        }
    }

    pub fn tick(&mut self, now: Instant) {
        self.rotate_window_if_needed(now);
        self.prune_expired_blocks(now);
        self.processing_budget.tick(now);
    }

    pub fn check(&mut self, ip: IpAddr, now: Instant) -> RateLimitDecision {
        self.tick(now);

        if self.exceptions.contains(&ip) {
            self.window_count += 1;
            return RateLimitDecision::Allow;
        }

        if let Some(reason) = self.blocked.get(&ip).map(|state| state.reason) {
            self.record_ip_block_hit(reason);
            return RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason,
            };
        }

        if self.window_count >= self.global_limit {
            self.metrics.global_limit_hits = self.metrics.global_limit_hits.saturating_add(1);
            return RateLimitDecision::GlobalLimit;
        }

        let state = self.ip_state.entry(ip).or_default();
        if state.count >= self.per_ip_limit {
            let reason = BlockReason::RateExceeded;
            let newly_blocked =
                self.block_address_for_with_reason(ip, now, self.block_duration, reason);
            self.record_ip_block_hit(reason);
            return RateLimitDecision::IpBlocked {
                newly_blocked,
                reason,
            };
        }

        state.count += 1;
        self.window_count += 1;
        RateLimitDecision::Allow
    }

    pub fn add_exception(&mut self, ip: IpAddr) {
        self.exceptions.insert(ip);
        if self.blocked.remove(&ip).is_some() {
            self.metrics.addresses_unblocked = self.metrics.addresses_unblocked.saturating_add(1);
        }
    }

    pub fn remove_exception(&mut self, ip: IpAddr) {
        self.exceptions.remove(&ip);
    }

    pub fn is_exception(&self, ip: IpAddr) -> bool {
        self.exceptions.contains(&ip)
    }

    pub fn set_per_ip_limit(&mut self, per_ip_limit: usize) {
        self.per_ip_limit = per_ip_limit.max(1);
        self.reset_window_state(Instant::now());
    }

    pub fn set_global_limit(&mut self, global_limit: usize) {
        self.global_limit = global_limit.max(1);
        self.reset_window_state(Instant::now());
    }

    pub fn set_window(&mut self, window: Duration) {
        self.window = normalize_duration(window, MIN_RATE_WINDOW);
        self.reset_window_state(Instant::now());
    }

    pub fn set_block_duration(&mut self, block_duration: Duration) {
        self.block_duration = normalize_duration(block_duration, MIN_BLOCK_DURATION);
    }

    pub fn update_limits(
        &mut self,
        per_ip_limit: usize,
        global_limit: usize,
        window: Duration,
        block_duration: Duration,
    ) {
        let (per_ip_limit, global_limit, window, block_duration) =
            normalize_limits(per_ip_limit, global_limit, window, block_duration);
        self.per_ip_limit = per_ip_limit;
        self.global_limit = global_limit;
        self.window = window;
        self.block_duration = block_duration;
        self.reset_window_state(Instant::now());
    }

    pub fn config_snapshot(&self) -> RateLimiterConfigSnapshot {
        RateLimiterConfigSnapshot {
            per_ip_limit: self.per_ip_limit,
            global_limit: self.global_limit,
            window: self.window,
            block_duration: self.block_duration,
        }
    }

    pub fn processing_budget_config(&self) -> ProcessingBudgetConfig {
        self.processing_budget.config
    }

    pub fn set_processing_budget_config(&mut self, config: ProcessingBudgetConfig) {
        self.processing_budget.set_config(config, Instant::now());
    }

    pub fn consume_processing_budget(
        &mut self,
        ip: IpAddr,
        cost_units: usize,
        now: Instant,
    ) -> ProcessingBudgetDecision {
        self.tick(now);
        self.processing_budget.consume(ip, cost_units, now)
    }

    pub fn processing_budget_metrics_snapshot(&self) -> ProcessingBudgetMetricsSnapshot {
        self.processing_budget.metrics_snapshot()
    }

    pub fn block_address(&mut self, ip: IpAddr) -> bool {
        self.block_address_with_reason(ip, BlockReason::Manual)
    }

    pub fn block_address_with_reason(&mut self, ip: IpAddr, reason: BlockReason) -> bool {
        if self.exceptions.contains(&ip) {
            return false;
        }

        let newly_blocked = !self.blocked.contains_key(&ip);
        self.blocked.insert(
            ip,
            BlockState {
                blocked_until: None,
                reason,
            },
        );
        if newly_blocked {
            self.record_new_block(reason);
        }
        newly_blocked
    }

    pub fn block_address_for(&mut self, ip: IpAddr, now: Instant, duration: Duration) -> bool {
        self.block_address_for_with_reason(ip, now, duration, BlockReason::Manual)
    }

    pub fn block_address_for_with_reason(
        &mut self,
        ip: IpAddr,
        now: Instant,
        duration: Duration,
        reason: BlockReason,
    ) -> bool {
        if self.exceptions.contains(&ip) {
            return false;
        }

        let duration = normalize_duration(duration, MIN_BLOCK_DURATION);
        let newly_blocked = !self.blocked.contains_key(&ip);
        self.blocked.insert(
            ip,
            BlockState {
                blocked_until: Some(now + duration),
                reason,
            },
        );
        if newly_blocked {
            self.record_new_block(reason);
        }
        newly_blocked
    }

    pub fn unblock_address(&mut self, ip: IpAddr) -> bool {
        if self.blocked.remove(&ip).is_some() {
            self.metrics.addresses_unblocked = self.metrics.addresses_unblocked.saturating_add(1);
            return true;
        }
        false
    }

    pub fn metrics_snapshot(&self) -> RateLimiterMetricsSnapshot {
        RateLimiterMetricsSnapshot {
            global_limit_hits: self.metrics.global_limit_hits,
            ip_block_hits: self.metrics.ip_block_hits,
            ip_block_hits_rate_exceeded: self.metrics.ip_block_hits_rate_exceeded,
            ip_block_hits_manual: self.metrics.ip_block_hits_manual,
            ip_block_hits_handshake_heuristic: self.metrics.ip_block_hits_handshake_heuristic,
            ip_block_hits_cookie_mismatch_guard: self.metrics.ip_block_hits_cookie_mismatch_guard,
            addresses_blocked: self.metrics.addresses_blocked,
            addresses_blocked_rate_exceeded: self.metrics.addresses_blocked_rate_exceeded,
            addresses_blocked_manual: self.metrics.addresses_blocked_manual,
            addresses_blocked_handshake_heuristic: self
                .metrics
                .addresses_blocked_handshake_heuristic,
            addresses_blocked_cookie_mismatch_guard: self
                .metrics
                .addresses_blocked_cookie_mismatch_guard,
            addresses_unblocked: self.metrics.addresses_unblocked,
            blocked_addresses: self.blocked.len(),
            exception_addresses: self.exceptions.len(),
        }
    }

    fn record_ip_block_hit(&mut self, reason: BlockReason) {
        self.metrics.ip_block_hits = self.metrics.ip_block_hits.saturating_add(1);
        match reason {
            BlockReason::RateExceeded => {
                self.metrics.ip_block_hits_rate_exceeded =
                    self.metrics.ip_block_hits_rate_exceeded.saturating_add(1);
            }
            BlockReason::Manual => {
                self.metrics.ip_block_hits_manual =
                    self.metrics.ip_block_hits_manual.saturating_add(1);
            }
            BlockReason::HandshakeHeuristic => {
                self.metrics.ip_block_hits_handshake_heuristic = self
                    .metrics
                    .ip_block_hits_handshake_heuristic
                    .saturating_add(1);
            }
            BlockReason::CookieMismatchGuard => {
                self.metrics.ip_block_hits_cookie_mismatch_guard = self
                    .metrics
                    .ip_block_hits_cookie_mismatch_guard
                    .saturating_add(1);
            }
        }
    }

    fn record_new_block(&mut self, reason: BlockReason) {
        self.metrics.addresses_blocked = self.metrics.addresses_blocked.saturating_add(1);
        match reason {
            BlockReason::RateExceeded => {
                self.metrics.addresses_blocked_rate_exceeded = self
                    .metrics
                    .addresses_blocked_rate_exceeded
                    .saturating_add(1);
            }
            BlockReason::Manual => {
                self.metrics.addresses_blocked_manual =
                    self.metrics.addresses_blocked_manual.saturating_add(1);
            }
            BlockReason::HandshakeHeuristic => {
                self.metrics.addresses_blocked_handshake_heuristic = self
                    .metrics
                    .addresses_blocked_handshake_heuristic
                    .saturating_add(1);
            }
            BlockReason::CookieMismatchGuard => {
                self.metrics.addresses_blocked_cookie_mismatch_guard = self
                    .metrics
                    .addresses_blocked_cookie_mismatch_guard
                    .saturating_add(1);
            }
        }
    }

    fn rotate_window_if_needed(&mut self, now: Instant) {
        if now.duration_since(self.window_start) < self.window {
            return;
        }

        self.reset_window_state(now);
    }

    fn reset_window_state(&mut self, now: Instant) {
        self.window_start = now;
        self.window_count = 0;
        self.ip_state.clear();
    }

    fn prune_expired_blocks(&mut self, now: Instant) {
        let mut unblocked = 0u64;
        self.blocked.retain(|_, state| {
            let Some(until) = state.blocked_until else {
                return true;
            };
            if now >= until {
                unblocked = unblocked.saturating_add(1);
                return false;
            }
            true
        });

        self.metrics.addresses_unblocked =
            self.metrics.addresses_unblocked.saturating_add(unblocked);
    }
}

fn normalize_limits(
    per_ip_limit: usize,
    global_limit: usize,
    window: Duration,
    block_duration: Duration,
) -> (usize, usize, Duration, Duration) {
    (
        per_ip_limit.max(1),
        global_limit.max(1),
        normalize_duration(window, MIN_RATE_WINDOW),
        normalize_duration(block_duration, MIN_BLOCK_DURATION),
    )
}

fn normalize_duration(value: Duration, minimum: Duration) -> Duration {
    if value.is_zero() { minimum } else { value }
}

fn normalize_processing_budget_config(
    mut config: ProcessingBudgetConfig,
) -> ProcessingBudgetConfig {
    if !config.enabled {
        return config;
    }

    config.per_ip_refill_units_per_sec = config.per_ip_refill_units_per_sec.max(1);
    config.per_ip_burst_units = config.per_ip_burst_units.max(1);
    config.global_refill_units_per_sec = config.global_refill_units_per_sec.max(1);
    config.global_burst_units = config.global_burst_units.max(1);
    config.bucket_idle_ttl = normalize_duration(config.bucket_idle_ttl, MIN_PROCESSING_IDLE_TTL);
    config
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{BlockReason, ProcessingBudgetDecision, RateLimitDecision, RateLimiter};
    use crate::transport::config::ProcessingBudgetConfig;

    #[test]
    fn per_ip_limit_transitions_to_blocked() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(5));
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );
        assert_eq!(
            limiter.check(ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::RateExceeded,
            }
        );
    }

    #[test]
    fn global_limit_applies_across_ips() {
        let mut limiter = RateLimiter::new(10, 1, Duration::from_secs(1), Duration::from_secs(5));
        let now = Instant::now();

        assert_eq!(
            limiter.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), now),
            RateLimitDecision::Allow
        );
        assert_eq!(
            limiter.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), now),
            RateLimitDecision::GlobalLimit
        );
    }

    #[test]
    fn exception_bypasses_per_ip_limit() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(5));
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        limiter.add_exception(ip);

        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
        let metrics = limiter.metrics_snapshot();
        assert_eq!(metrics.exception_addresses, 1);
        assert_eq!(metrics.blocked_addresses, 0);
    }

    #[test]
    fn scheduled_unblock_happens_on_tick() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(2));
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );
        assert_eq!(limiter.metrics_snapshot().blocked_addresses, 1);

        limiter.tick(now + Duration::from_secs(3));
        assert_eq!(limiter.metrics_snapshot().blocked_addresses, 0);
    }

    #[test]
    fn explicit_unblock_clears_block_state() {
        let mut limiter = RateLimiter::new(10, 100, Duration::from_secs(1), Duration::from_secs(5));
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9));

        assert!(limiter.block_address_for(ip, now, Duration::from_secs(30)));
        assert_eq!(limiter.metrics_snapshot().blocked_addresses, 1);
        assert!(limiter.unblock_address(ip));
        assert_eq!(limiter.metrics_snapshot().blocked_addresses, 0);
    }

    #[test]
    fn window_rotation_resets_global_and_per_ip_counters() {
        let mut limiter =
            RateLimiter::new(1, 3, Duration::from_secs(1), Duration::from_millis(400));
        let start = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3));

        assert_eq!(limiter.check(ip_a, start), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip_b, start), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(ip_b, start),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );

        let next_window = start + Duration::from_secs(2);
        assert_eq!(limiter.check(ip_b, next_window), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip_c, next_window), RateLimitDecision::Allow);
    }

    #[test]
    fn removing_exception_restores_per_ip_enforcement() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(5));
        let start = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 9));

        limiter.add_exception(ip);
        assert_eq!(limiter.check(ip, start), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip, start), RateLimitDecision::Allow);

        limiter.remove_exception(ip);
        let next_window = start + Duration::from_secs(2);
        assert_eq!(limiter.check(ip, next_window), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(ip, next_window),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );
    }

    #[test]
    fn adding_exception_unblocks_address_and_updates_metrics() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(30));
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );

        limiter.add_exception(ip);
        let metrics = limiter.metrics_snapshot();
        assert_eq!(metrics.blocked_addresses, 0);
        assert_eq!(metrics.exception_addresses, 1);
        assert_eq!(metrics.addresses_blocked, 1);
        assert_eq!(metrics.addresses_unblocked, 1);

        assert_eq!(limiter.check(ip, now), RateLimitDecision::Allow);
    }

    #[test]
    fn update_limits_clamps_zero_values_and_resets_window_state() {
        let mut limiter =
            RateLimiter::new(100, 100, Duration::from_secs(2), Duration::from_secs(5));
        let start = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));

        assert_eq!(limiter.check(ip, start), RateLimitDecision::Allow);

        limiter.update_limits(0, 0, Duration::ZERO, Duration::ZERO);
        let cfg = limiter.config_snapshot();
        assert_eq!(cfg.per_ip_limit, 1);
        assert_eq!(cfg.global_limit, 1);
        assert_eq!(cfg.window, Duration::from_millis(1));
        assert_eq!(cfg.block_duration, Duration::from_millis(1));

        assert_eq!(limiter.check(ip, start), RateLimitDecision::Allow);
        assert_eq!(limiter.check(ip, start), RateLimitDecision::GlobalLimit);
    }

    #[test]
    fn permanent_block_stays_until_explicit_unblock() {
        let mut limiter =
            RateLimiter::new(10, 10, Duration::from_millis(10), Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let now = Instant::now();

        assert!(limiter.block_address(ip));
        assert_eq!(
            limiter.check(ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::Manual,
            }
        );

        limiter.tick(now + Duration::from_secs(60));
        assert_eq!(
            limiter.check(ip, now + Duration::from_secs(61)),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::Manual,
            }
        );

        assert!(limiter.unblock_address(ip));
        assert_eq!(
            limiter.check(ip, now + Duration::from_secs(62)),
            RateLimitDecision::Allow
        );
    }

    #[test]
    fn reason_specific_block_metrics_are_tracked() {
        let mut limiter = RateLimiter::new(1, 100, Duration::from_secs(1), Duration::from_secs(5));
        let now = Instant::now();

        let rate_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1));
        let manual_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 2));
        let handshake_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 3));
        let cookie_ip = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 4));

        assert_eq!(limiter.check(rate_ip, now), RateLimitDecision::Allow);
        assert_eq!(
            limiter.check(rate_ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: true,
                reason: BlockReason::RateExceeded,
            }
        );

        assert!(limiter.block_address(manual_ip));
        assert_eq!(
            limiter.check(manual_ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::Manual,
            }
        );

        assert!(limiter.block_address_for_with_reason(
            handshake_ip,
            now,
            Duration::from_secs(30),
            BlockReason::HandshakeHeuristic
        ));
        assert_eq!(
            limiter.check(handshake_ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::HandshakeHeuristic,
            }
        );

        assert!(limiter.block_address_for_with_reason(
            cookie_ip,
            now,
            Duration::from_secs(30),
            BlockReason::CookieMismatchGuard
        ));
        assert_eq!(
            limiter.check(cookie_ip, now),
            RateLimitDecision::IpBlocked {
                newly_blocked: false,
                reason: BlockReason::CookieMismatchGuard,
            }
        );

        let metrics = limiter.metrics_snapshot();
        assert_eq!(metrics.ip_block_hits, 4);
        assert_eq!(metrics.ip_block_hits_rate_exceeded, 1);
        assert_eq!(metrics.ip_block_hits_manual, 1);
        assert_eq!(metrics.ip_block_hits_handshake_heuristic, 1);
        assert_eq!(metrics.ip_block_hits_cookie_mismatch_guard, 1);
        assert_eq!(metrics.addresses_blocked, 4);
        assert_eq!(metrics.addresses_blocked_rate_exceeded, 1);
        assert_eq!(metrics.addresses_blocked_manual, 1);
        assert_eq!(metrics.addresses_blocked_handshake_heuristic, 1);
        assert_eq!(metrics.addresses_blocked_cookie_mismatch_guard, 1);
    }

    #[test]
    fn processing_budget_exhausts_and_refills_per_ip_tokens() {
        let mut limiter = RateLimiter::new_with_processing_budget(
            1000,
            1000,
            Duration::from_secs(1),
            Duration::from_secs(1),
            ProcessingBudgetConfig {
                enabled: true,
                per_ip_refill_units_per_sec: 100,
                per_ip_burst_units: 100,
                global_refill_units_per_sec: 1_000,
                global_burst_units: 1_000,
                bucket_idle_ttl: Duration::from_secs(5),
            },
        );
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

        assert_eq!(
            limiter.consume_processing_budget(ip, 80, now),
            ProcessingBudgetDecision::Allow
        );
        assert_eq!(
            limiter.consume_processing_budget(ip, 30, now),
            ProcessingBudgetDecision::IpExhausted
        );
        assert_eq!(
            limiter.consume_processing_budget(ip, 30, now + Duration::from_secs(1)),
            ProcessingBudgetDecision::Allow
        );
    }

    #[test]
    fn processing_budget_enforces_global_bucket() {
        let mut limiter = RateLimiter::new_with_processing_budget(
            1000,
            1000,
            Duration::from_secs(1),
            Duration::from_secs(1),
            ProcessingBudgetConfig {
                enabled: true,
                per_ip_refill_units_per_sec: 10_000,
                per_ip_burst_units: 10_000,
                global_refill_units_per_sec: 100,
                global_burst_units: 100,
                bucket_idle_ttl: Duration::from_secs(5),
            },
        );
        let now = Instant::now();
        let ip_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

        assert_eq!(
            limiter.consume_processing_budget(ip_a, 80, now),
            ProcessingBudgetDecision::Allow
        );
        assert_eq!(
            limiter.consume_processing_budget(ip_b, 30, now),
            ProcessingBudgetDecision::GlobalExhausted
        );
        let metrics = limiter.processing_budget_metrics_snapshot();
        assert_eq!(metrics.drops_global_exhausted, 1);
    }

    #[test]
    fn processing_budget_bypasses_exception_addresses() {
        let mut limiter = RateLimiter::new_with_processing_budget(
            1000,
            1000,
            Duration::from_secs(1),
            Duration::from_secs(1),
            ProcessingBudgetConfig {
                enabled: true,
                per_ip_refill_units_per_sec: 1,
                per_ip_burst_units: 1,
                global_refill_units_per_sec: 1,
                global_burst_units: 1,
                bucket_idle_ttl: Duration::from_secs(5),
            },
        );
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        limiter.add_exception(ip);
        assert!(limiter.is_exception(ip));

        // Caller is expected to bypass consumption for exception IPs.
        let decision = if limiter.is_exception(ip) {
            ProcessingBudgetDecision::Allow
        } else {
            limiter.consume_processing_budget(ip, 10_000, now)
        };
        assert_eq!(decision, ProcessingBudgetDecision::Allow);
    }
}
