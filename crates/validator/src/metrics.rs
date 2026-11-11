// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's metrics, mirroring `dag::metrics` conventions: one `Arc`-shared front
//! type, metric names as adjacent constants, registration into a caller-provided registry.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use checkpoint::{certifier::CheckpointTimings, checkpoint::Outcome};
use prometheus::{
    Histogram, HistogramVec, IntCounter, IntGauge, Registry,
    core::{Collector, Desc},
    proto::{Counter, LabelPair, Metric, MetricFamily, MetricType},
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_with_registry, register_int_gauge_with_registry,
};

// Metric names, public for scrapers. The counters are prefixed because the replica already
// registers a `submitted_transactions` in the same registry.
pub const SUBMITTED_TRANSACTIONS: &str = "validator_submitted_transactions";
pub const EXECUTED_TRANSACTIONS: &str = "validator_executed_transactions";
/// Unlike mysticeti's `latency_s`, which observes every committed payload, votes and
/// certificates included.
pub const CLIENT_COMMIT_LATENCY_S: &str = "client_commit_latency_s";
pub const SUBDAG_EXECUTION_LATENCY_S: &str = "subdag_execution_latency_s";
pub const CHECKPOINT_CERTIFICATION_LATENCY_S: &str = "checkpoint_certification_latency_s";
pub const END_TO_END_LATENCY_S: &str = "end_to_end_latency_s";
pub const CHECKPOINT_FINALITY_LATENCY_S: &str = "checkpoint_finality_latency_s";
pub const CHECKPOINT_PENDING_HEIGHTS: &str = "checkpoint_pending_heights";
pub const CHECKPOINT_DECISION_ACCOUNTING: &str = "checkpoint_decision_accounting_total";

/// The `outcome` label of [`CHECKPOINT_CERTIFICATION_LATENCY_S`] and
/// [`CHECKPOINT_FINALITY_LATENCY_S`], and its values.
pub const LABEL_OUTCOME: &str = "outcome";
pub const FINALIZE: &str = "finalize";
pub const SKIP: &str = "skip";

/// The `path` label of [`CHECKPOINT_CERTIFICATION_LATENCY_S`], what decided the checkpoint,
/// and its values.
pub const LABEL_PATH: &str = "path";
/// Votes or certificates as their blocks entered the local DAG.
pub const FAST: &str = "fast";
/// The commit sequence.
pub const SLOW: &str = "slow";

/// The `quantity` label of [`CHECKPOINT_DECISION_ACCOUNTING`] and its values: the number of
/// decisions, and the sum of their decision latencies in seconds.
pub const LABEL_QUANTITY: &str = "quantity";
pub const DECISIONS: &str = "decisions";
pub const DECISION_LATENCY_S: &str = "latency_s";

/// Mysticeti's consensus-latency buckets: dense around the expected commit latency.
const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.1, 0.2, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1., 1.25, 1.5, 1.75, 2., 3.0, 5., 10.,
];

pub struct ValidatorMetrics {
    submitted_transactions: IntCounter,
    executed_transactions: IntCounter,
    client_commit_latency_s: Histogram,
    subdag_execution_latency_s: Histogram,
    checkpoint_certification_latency_s: HistogramVec,
    checkpoint_finality_latency_s: HistogramVec,
    checkpoint_pending_heights: IntGauge,
    end_to_end_latency_s: Histogram,
    decision_accounting: DecisionAccounting,
}

impl ValidatorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let decision_accounting = DecisionAccounting::new();
        registry
            .register(Box::new(decision_accounting.clone()))
            .unwrap();
        Arc::new(Self {
            submitted_transactions: register_int_counter_with_registry!(
                SUBMITTED_TRANSACTIONS,
                "Transactions submitted by the load generator",
                registry,
            )
            .unwrap(),
            executed_transactions: register_int_counter_with_registry!(
                EXECUTED_TRANSACTIONS,
                "Client transactions executed",
                registry,
            )
            .unwrap(),
            client_commit_latency_s: register_histogram_with_registry!(
                CLIENT_COMMIT_LATENCY_S,
                "Client transaction submission to commit delivery latency (s)",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            subdag_execution_latency_s: register_histogram_with_registry!(
                SUBDAG_EXECUTION_LATENCY_S,
                "Commit delivery to execution and checkpoint inclusion latency per sub-dag (s)",
                // Local execution is sub-millisecond but commit-channel queueing under
                // backpressure can reach seconds: ~100 µs to ~13 s, exponential.
                prometheus::exponential_buckets(1e-4, 2.0, 18).unwrap(),
                registry,
            )
            .unwrap(),
            checkpoint_certification_latency_s: register_histogram_vec_with_registry!(
                CHECKPOINT_CERTIFICATION_LATENCY_S,
                "Checkpoint creation to decision (finalize or skip) latency (s)",
                &[LABEL_OUTCOME, LABEL_PATH],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            checkpoint_finality_latency_s: register_histogram_vec_with_registry!(
                CHECKPOINT_FINALITY_LATENCY_S,
                "Checkpoint creation to contiguous decision (the watermark passing it) latency (s)",
                &[LABEL_OUTCOME],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            checkpoint_pending_heights: register_int_gauge_with_registry!(
                CHECKPOINT_PENDING_HEIGHTS,
                "Minted checkpoints not yet contiguously decided",
                registry,
            )
            .unwrap(),
            end_to_end_latency_s: register_histogram_with_registry!(
                END_TO_END_LATENCY_S,
                "Submission to contiguously finalized checkpoint latency (s)",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            decision_accounting,
        })
    }

    pub fn inc_submitted_transactions(&self, count: u64) {
        self.submitted_transactions.inc_by(count);
    }

    pub(crate) fn inc_executed_transactions(&self, count: u64) {
        self.executed_transactions.inc_by(count);
    }

    pub(crate) fn observe_subdag_execution_latency(&self, latency: Duration) {
        self.subdag_execution_latency_s
            .observe(latency.as_secs_f64());
    }

    /// Closes the decision metrics of a checkpoint decided at `now` on `path` ([`FAST`] or
    /// [`SLOW`]).
    pub(crate) fn observe_decision(
        &self,
        now: Duration,
        outcome: Outcome,
        path: &'static str,
        timings: CheckpointTimings,
    ) {
        let label = match outcome {
            Outcome::Finalize(_) => FINALIZE,
            Outcome::Skip => SKIP,
        };
        let latency_s = now.saturating_sub(timings.minted_at).as_secs_f64();
        self.checkpoint_certification_latency_s(label, path)
            .observe(latency_s);
        self.decision_accounting.record(label, path, latency_s);
    }

    /// Closes the latency metrics of a checkpoint that became contiguously decided at `now`.
    /// Skipped transactions are never finalized, so only finalized checkpoints close end to end.
    pub(crate) fn observe_contiguous(
        &self,
        now: Duration,
        outcome: Outcome,
        timings: CheckpointTimings,
    ) {
        let label = match outcome {
            Outcome::Finalize(_) => FINALIZE,
            Outcome::Skip => SKIP,
        };
        self.checkpoint_finality_latency_s(label)
            .observe(now.saturating_sub(timings.minted_at).as_secs_f64());
        if let Outcome::Finalize(_) = outcome {
            let submitted = Duration::from_millis(timings.mean_timestamp_ms);
            self.end_to_end_latency_s
                .observe(now.saturating_sub(submitted).as_secs_f64());
        }
    }

    pub(crate) fn set_pending_heights(&self, pending: usize) {
        self.checkpoint_pending_heights.set(pending as i64);
    }

    /// The raw metrics, for test assertions (`get`/`get_sample_count`/`get_sample_sum`).
    pub fn submitted_transactions(&self) -> &IntCounter {
        &self.submitted_transactions
    }

    pub fn executed_transactions(&self) -> &IntCounter {
        &self.executed_transactions
    }

    pub fn client_commit_latency_s(&self) -> &Histogram {
        &self.client_commit_latency_s
    }

    pub fn subdag_execution_latency_s(&self) -> &Histogram {
        &self.subdag_execution_latency_s
    }

    /// The decision latency of one `outcome` and `path` label pair.
    pub fn checkpoint_certification_latency_s(&self, outcome: &str, path: &str) -> Histogram {
        self.checkpoint_certification_latency_s
            .with_label_values(&[outcome, path])
    }

    /// The contiguous-decision latency of one `outcome` label.
    pub fn checkpoint_finality_latency_s(&self, outcome: &str) -> Histogram {
        self.checkpoint_finality_latency_s
            .with_label_values(&[outcome])
    }

    pub fn checkpoint_pending_heights(&self) -> &IntGauge {
        &self.checkpoint_pending_heights
    }

    pub fn end_to_end_latency_s(&self) -> &Histogram {
        &self.end_to_end_latency_s
    }

    /// The decision count and latency sum of one `outcome` and `path` label pair.
    pub fn decision_accounting(&self, outcome: &'static str, path: &'static str) -> (u64, f64) {
        let totals = self.decision_accounting.totals.lock().unwrap();
        totals.get(&(outcome, path)).copied().unwrap_or_default()
    }
}

/// Decision counts and latency sums by outcome and path, exported as one counter family whose
/// every scrape pairs them coherently: a decision updates both under one lock, and collection
/// copies them under it. A `CounterVec` reads its children one at a time, so a scrape could
/// pair a count and a sum from either side of a decision.
#[derive(Clone)]
struct DecisionAccounting {
    desc: Desc,
    totals: Arc<Mutex<DecisionTotals>>,
}

/// The decision count and latency sum by `(outcome, path)`.
type DecisionTotals = BTreeMap<(&'static str, &'static str), (u64, f64)>;

impl DecisionAccounting {
    fn new() -> Self {
        let desc = Desc::new(
            CHECKPOINT_DECISION_ACCOUNTING.into(),
            "Checkpoint decisions and their summed decision latency (s)".into(),
            vec![
                LABEL_OUTCOME.into(),
                LABEL_PATH.into(),
                LABEL_QUANTITY.into(),
            ],
            HashMap::new(),
        )
        .unwrap();
        Self {
            desc,
            totals: Arc::default(),
        }
    }

    fn record(&self, outcome: &'static str, path: &'static str, latency_s: f64) {
        let mut totals = self.totals.lock().unwrap();
        let (decisions, sum) = totals.entry((outcome, path)).or_default();
        *decisions += 1;
        *sum += latency_s;
    }
}

impl Collector for DecisionAccounting {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let totals = self.totals.lock().unwrap().clone();
        let label = |name: &str, value: &str| {
            let mut pair = LabelPair::default();
            pair.set_name(name.into());
            pair.set_value(value.into());
            pair
        };
        let mut family = MetricFamily::default();
        family.set_name(CHECKPOINT_DECISION_ACCOUNTING.into());
        family.set_help(self.desc.help.clone());
        family.set_field_type(MetricType::COUNTER);
        for ((outcome, path), (decisions, latency_s)) in totals {
            for (quantity, value) in [
                (DECISIONS, decisions as f64),
                (DECISION_LATENCY_S, latency_s),
            ] {
                let mut metric = Metric::from_label(vec![
                    label(LABEL_OUTCOME, outcome),
                    label(LABEL_PATH, path),
                    label(LABEL_QUANTITY, quantity),
                ]);
                let mut counter = Counter::default();
                counter.set_value(value);
                metric.set_counter(counter);
                family.mut_metric().push(metric);
            }
        }
        vec![family]
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Duration,
    };

    use checkpoint::{certifier::CheckpointTimings, checkpoint::Outcome};
    use prometheus::Registry;

    use crate::metrics::{
        CHECKPOINT_DECISION_ACCOUNTING, DECISION_LATENCY_S, DECISIONS, SKIP, SLOW, ValidatorMetrics,
    };

    /// The accounting family's skip-on-the-slow-path quantities in one scrape of `registry`:
    /// the decisions and their latency sum.
    fn scrape(registry: &Registry) -> (f64, f64) {
        let quantities: BTreeMap<_, _> = registry
            .gather()
            .into_iter()
            .filter(|family| family.name() == CHECKPOINT_DECISION_ACCOUNTING)
            .flat_map(|family| family.get_metric().to_vec())
            .map(|metric| {
                let labels: Vec<_> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                (labels.join(","), metric.get_counter().value())
            })
            .collect();
        let quantity = |name: &str| {
            let key = format!("outcome={SKIP},path={SLOW},quantity={name}");
            quantities.get(&key).copied().unwrap_or_default()
        };
        (quantity(DECISIONS), quantity(DECISION_LATENCY_S))
    }

    #[test]
    fn every_scrape_pairs_decision_counts_with_their_latency_sums() {
        const SCRAPES: usize = 1_000;
        let registry = Registry::new();
        let metrics = ValidatorMetrics::new(&registry);
        let done = AtomicBool::new(false);
        // Every decision takes exactly two seconds, so a coherent scrape has a latency sum of
        // twice its count, exactly.
        let minted_at_zero = CheckpointTimings::default();
        let now = Duration::from_secs(2);
        let incoherent = thread::scope(|scope| {
            let recorder = scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    metrics.observe_decision(now, Outcome::Skip, SLOW, minted_at_zero);
                }
            });
            // Scrape only while recording.
            while metrics.decision_accounting(SKIP, SLOW).0 == 0 && !recorder.is_finished() {
                thread::yield_now();
            }
            let incoherent = (0..SCRAPES)
                .filter(|_| {
                    let (decisions, latency_s) = scrape(&registry);
                    latency_s != 2.0 * decisions
                })
                .count();
            done.store(true, Ordering::Relaxed);
            incoherent
        });
        assert_eq!(incoherent, 0, "of {SCRAPES} scrapes");
        let (decisions, latency_s) = scrape(&registry);
        assert!(decisions > 0.0);
        assert_eq!(decisions, metrics.decision_accounting(SKIP, SLOW).0 as f64);
        assert_eq!(latency_s, 2.0 * decisions);
    }
}
