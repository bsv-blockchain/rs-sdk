//! Host reputation tracking for overlay service hosts.
//!
//! Translates the TS SDK HostReputationTracker.ts. Tracks per-host latency,
//! failure counts, and backoff state to rank hosts by reliability. In-memory
//! only (no localStorage equivalent in Rust).

use std::collections::HashMap;

/// Default assumed latency (ms) for hosts with no measurements.
const DEFAULT_LATENCY_MS: f64 = 1500.0;
/// Smoothing factor for exponential moving average of latency.
const LATENCY_SMOOTHING_FACTOR: f64 = 0.25;
/// Penalty per consecutive failure (ms) added to score.
const FAILURE_PENALTY_MS: f64 = 400.0;
/// Bonus per total success (ms) subtracted from score, capped at latency/2.
const SUCCESS_BONUS_MS: f64 = 30.0;
/// Base backoff duration (ms) before exponential scaling.
const BASE_BACKOFF_MS: u64 = 1000;
/// Maximum backoff duration (ms).
const MAX_BACKOFF_MS: u64 = 60_000;
/// Number of consecutive failures before backoff begins.
const FAILURE_BACKOFF_GRACE: u32 = 2;

/// Reputation data for a single host.
#[derive(Debug, Clone)]
pub struct HostReputationEntry {
    /// Host identifier (URL).
    pub host: String,
    /// Total successful requests.
    pub total_successes: u32,
    /// Total failed requests.
    pub total_failures: u32,
    /// Current streak of consecutive failures.
    pub consecutive_failures: u32,
    /// Exponentially smoothed average latency (ms).
    pub avg_latency_ms: Option<f64>,
    /// Most recent latency measurement (ms).
    pub last_latency_ms: Option<f64>,
    /// Timestamp (ms) until which this host should be avoided.
    pub backoff_until: u64,
    /// Last time this entry was updated (ms since epoch).
    pub last_updated_at: u64,
    /// Last error message, if any.
    pub last_error: Option<String>,
}

/// A host with its computed reputation score.
#[derive(Debug, Clone)]
pub struct RankedHost {
    /// The host URL.
    pub host: String,
    /// Computed reputation score (lower is better).
    pub score: f64,
    /// Timestamp until which the host is in backoff.
    pub backoff_until: u64,
}

/// Tracks host reputation for overlay service discovery.
///
/// Records success/failure for each host, computes latency-based scores,
/// and applies exponential backoff for unreliable hosts.
#[derive(Debug)]
pub struct HostReputationTracker {
    stats: HashMap<String, HostReputationEntry>,
}

impl HostReputationTracker {
    /// Create a new empty reputation tracker.
    pub fn new() -> Self {
        HostReputationTracker {
            stats: HashMap::new(),
        }
    }

    /// Reset all reputation data.
    pub fn reset(&mut self) {
        self.stats.clear();
    }

    /// Record a successful request to a host with the observed latency.
    pub fn record_success(&mut self, host: &str, latency_ms: f64) {
        let entry = self.get_or_create(host);
        let now = current_time_ms();
        let safe_latency = if latency_ms.is_finite() && latency_ms >= 0.0 {
            latency_ms
        } else {
            DEFAULT_LATENCY_MS
        };
        entry.avg_latency_ms = Some(match entry.avg_latency_ms {
            None => safe_latency,
            Some(avg) => {
                (1.0 - LATENCY_SMOOTHING_FACTOR) * avg + LATENCY_SMOOTHING_FACTOR * safe_latency
            }
        });
        entry.last_latency_ms = Some(safe_latency);
        entry.total_successes += 1;
        entry.consecutive_failures = 0;
        entry.backoff_until = 0;
        entry.last_updated_at = now;
        entry.last_error = None;
    }

    /// Record a failed request to a host.
    pub fn record_failure(&mut self, host: &str, reason: Option<&str>) {
        let entry = self.get_or_create(host);
        let now = current_time_ms();
        entry.total_failures += 1;
        entry.consecutive_failures += 1;

        // Immediate backoff for DNS/network failures.
        let is_immediate = reason
            .map(|r| {
                r.contains("ERR_NAME_NOT_RESOLVED")
                    || r.contains("ENOTFOUND")
                    || r.contains("getaddrinfo")
                    || r.contains("Failed to fetch")
            })
            .unwrap_or(false);

        if is_immediate && entry.consecutive_failures < FAILURE_BACKOFF_GRACE + 1 {
            entry.consecutive_failures = FAILURE_BACKOFF_GRACE + 1;
        }

        let penalty_level = entry
            .consecutive_failures
            .saturating_sub(FAILURE_BACKOFF_GRACE);
        if penalty_level == 0 {
            entry.backoff_until = 0;
        } else {
            let backoff_duration =
                BASE_BACKOFF_MS.saturating_mul(1u64 << (penalty_level - 1).min(30));
            let backoff_duration = backoff_duration.min(MAX_BACKOFF_MS);
            entry.backoff_until = now + backoff_duration;
        }
        entry.last_updated_at = now;
        entry.last_error = reason.map(|s| s.to_string());
    }

    /// Rank a list of hosts by reputation score (lower is better).
    ///
    /// Hosts in backoff are sorted after available hosts. Within each group,
    /// hosts are sorted by score ascending, then by total successes descending.
    pub fn rank_hosts(&mut self, hosts: &[String], now: u64) -> Vec<RankedHost> {
        // Deduplicate while preserving order.
        let mut seen = HashMap::new();
        for (idx, host) in hosts.iter().enumerate() {
            if host.is_empty() {
                continue;
            }
            seen.entry(host.as_str()).or_insert(idx);
        }

        let mut ordered: Vec<(&str, usize)> = seen.into_iter().collect();
        ordered.sort_by_key(|&(_, idx)| idx);

        let mut ranked: Vec<(RankedHost, usize)> = ordered
            .into_iter()
            .map(|(host, original_order)| {
                let entry = self.get_or_create(host);
                let score = compute_score(entry, now);
                let backoff_until = entry.backoff_until;
                (
                    RankedHost {
                        host: host.to_string(),
                        score,
                        backoff_until,
                    },
                    original_order,
                )
            })
            .collect();

        ranked.sort_by(|(a, a_order), (b, b_order)| {
            let a_in_backoff = a.backoff_until > now;
            let b_in_backoff = b.backoff_until > now;
            if a_in_backoff != b_in_backoff {
                return if a_in_backoff {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Less
                };
            }
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a_order.cmp(b_order))
        });

        ranked.into_iter().map(|(rh, _)| rh).collect()
    }

    /// Get a snapshot of a host's reputation entry.
    pub fn snapshot(&self, host: &str) -> Option<HostReputationEntry> {
        self.stats.get(host).cloned()
    }

    fn get_or_create(&mut self, host: &str) -> &mut HostReputationEntry {
        self.stats
            .entry(host.to_string())
            .or_insert_with(|| HostReputationEntry {
                host: host.to_string(),
                total_successes: 0,
                total_failures: 0,
                consecutive_failures: 0,
                avg_latency_ms: None,
                last_latency_ms: None,
                backoff_until: 0,
                last_updated_at: 0,
                last_error: None,
            })
    }
}

impl Default for HostReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the reputation score for a host entry.
///
/// Score = latency + failure_penalty + backoff_penalty - success_bonus
/// Lower scores are better.
fn compute_score(entry: &HostReputationEntry, now: u64) -> f64 {
    let latency = entry.avg_latency_ms.unwrap_or(DEFAULT_LATENCY_MS);
    let failure_penalty = entry.consecutive_failures as f64 * FAILURE_PENALTY_MS;
    let success_bonus = (entry.total_successes as f64 * SUCCESS_BONUS_MS).min(latency / 2.0);
    let backoff_penalty = if entry.backoff_until > now {
        (entry.backoff_until - now) as f64
    } else {
        0.0
    };
    latency + failure_penalty + backoff_penalty - success_bonus
}

/// Get current time in milliseconds since epoch.
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_host_gets_default_score() {
        let mut tracker = HostReputationTracker::new();
        let hosts = vec!["https://host1.example.com".to_string()];
        let ranked = tracker.rank_hosts(&hosts, 1000);
        assert_eq!(ranked.len(), 1);
        // Default score = DEFAULT_LATENCY_MS = 1500
        assert!((ranked[0].score - DEFAULT_LATENCY_MS).abs() < 0.01);
    }

    #[test]
    fn test_success_lowers_score() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://fast.example.com";
        tracker.record_success(host, 200.0);
        let entry = tracker.snapshot(host).unwrap();
        // avg_latency should be 200 (first measurement)
        assert!((entry.avg_latency_ms.unwrap() - 200.0).abs() < 0.01);
        assert_eq!(entry.total_successes, 1);
        assert_eq!(entry.consecutive_failures, 0);
    }

    #[test]
    fn test_failure_increases_score() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://flaky.example.com";
        tracker.record_failure(host, Some("timeout"));
        let entry = tracker.snapshot(host).unwrap();
        assert_eq!(entry.consecutive_failures, 1);
        assert_eq!(entry.total_failures, 1);
        // Under grace period, no backoff yet
        assert_eq!(entry.backoff_until, 0);
    }

    #[test]
    fn test_backoff_kicks_in_after_grace() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://failing.example.com";
        // Failures 1 and 2 are within grace
        tracker.record_failure(host, Some("error"));
        assert_eq!(tracker.snapshot(host).unwrap().backoff_until, 0);
        tracker.record_failure(host, Some("error"));
        assert_eq!(tracker.snapshot(host).unwrap().backoff_until, 0);
        // Failure 3 triggers backoff
        tracker.record_failure(host, Some("error"));
        assert!(tracker.snapshot(host).unwrap().backoff_until > 0);
    }

    #[test]
    fn test_ranking_puts_healthy_hosts_first() {
        let mut tracker = HostReputationTracker::new();
        let fast = "https://fast.example.com".to_string();
        let slow = "https://slow.example.com".to_string();
        tracker.record_success(&fast, 100.0);
        tracker.record_success(&slow, 2000.0);
        let ranked = tracker.rank_hosts(&[fast.clone(), slow.clone()], current_time_ms());
        assert_eq!(ranked[0].host, fast);
        assert_eq!(ranked[1].host, slow);
    }

    #[test]
    fn test_ranking_puts_backed_off_hosts_last() {
        let mut tracker = HostReputationTracker::new();
        let good = "https://good.example.com".to_string();
        let bad = "https://bad.example.com".to_string();
        tracker.record_success(&good, 500.0);
        // Push bad past grace
        for _ in 0..5 {
            tracker.record_failure(&bad, Some("error"));
        }
        let now = current_time_ms();
        let ranked = tracker.rank_hosts(&[bad.clone(), good.clone()], now);
        assert_eq!(ranked[0].host, good);
        assert_eq!(ranked[1].host, bad);
    }

    #[test]
    fn test_success_resets_consecutive_failures() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://recovering.example.com";
        tracker.record_failure(host, None);
        tracker.record_failure(host, None);
        tracker.record_failure(host, None);
        assert_eq!(tracker.snapshot(host).unwrap().consecutive_failures, 3);
        tracker.record_success(host, 300.0);
        assert_eq!(tracker.snapshot(host).unwrap().consecutive_failures, 0);
        assert_eq!(tracker.snapshot(host).unwrap().backoff_until, 0);
    }

    #[test]
    fn test_latency_smoothing() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://varying.example.com";
        tracker.record_success(host, 100.0); // avg = 100
        tracker.record_success(host, 500.0); // avg = 0.75*100 + 0.25*500 = 200
        let avg = tracker.snapshot(host).unwrap().avg_latency_ms.unwrap();
        assert!((avg - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_score_formula() {
        let entry = HostReputationEntry {
            host: "test".to_string(),
            total_successes: 10,
            total_failures: 0,
            consecutive_failures: 0,
            avg_latency_ms: Some(400.0),
            last_latency_ms: Some(400.0),
            backoff_until: 0,
            last_updated_at: 0,
            last_error: None,
        };
        let score = compute_score(&entry, 0);
        // latency(400) + failure_penalty(0) + backoff(0) - success_bonus(min(300, 200))
        // success_bonus = min(10*30, 400/2) = min(300, 200) = 200
        assert!((score - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_deduplication_in_rank() {
        let mut tracker = HostReputationTracker::new();
        let host = "https://dup.example.com".to_string();
        let ranked = tracker.rank_hosts(&[host.clone(), host.clone(), host.clone()], 0);
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn test_reset_clears_all() {
        let mut tracker = HostReputationTracker::new();
        tracker.record_success("host1", 100.0);
        tracker.record_success("host2", 200.0);
        tracker.reset();
        assert!(tracker.snapshot("host1").is_none());
        assert!(tracker.snapshot("host2").is_none());
    }
}
