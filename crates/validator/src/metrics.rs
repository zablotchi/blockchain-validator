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
    Histogram, HistogramVec, IntCounter, IntGauge, IntGaugeVec, Registry,
    core::{Collector, Desc},
    proto::{Counter, Gauge, LabelPair, Metric, MetricFamily, MetricType},
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};

use crate::episode::{EpisodeRecord, Role};

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
pub const VALIDATOR_HALTED: &str = "validator_halted";
pub const VALIDATOR_RETAINED_BYTES: &str = "validator_retained_bytes";
pub const PROTOCOL_SUBMISSIONS_DEFERRED: &str = "validator_protocol_submissions_deferred_total";
pub const PROTOCOL_PAYLOADS_SUBMITTED: &str = "validator_protocol_payloads_submitted_total";
pub const MAX_PROPOSAL_BYTES: &str = "validator_max_proposal_bytes";
pub const MAX_PROPOSAL_PROTOCOL_BYTES: &str = "validator_max_proposal_protocol_bytes";
pub const CHECKPOINT_RELEASE_WAITS: &str = "checkpoint_release_waits_total";
pub const VALIDATOR_SKIPPED_TRANSACTIONS: &str = "validator_skipped_transactions";
pub const FORK_RECOVERY_ACCOUNTING: &str = "fork_recovery_accounting_total";
pub const FORK_RECOVERY_EPISODE: &str = "fork_recovery_episode";
pub const FORK_RECOVERY_STALL_S: &str = "fork_recovery_stall_s";
pub const FORK_RECOVERY_RE_EXECUTED_HEIGHTS: &str = "fork_recovery_re_executed_heights";

/// [`FORK_RECOVERY_EPISODE`] holds the records of the schedule's first this many episodes;
/// [`FORK_RECOVERY_ACCOUNTING`] covers every episode.
pub const MAX_EXPORTED_EPISODES: u64 = 32;

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

/// The `reason` label of [`VALIDATOR_HALTED`] and its values.
pub const LABEL_REASON: &str = "reason";
/// The retained state exceeded the evidence budget.
pub const EVIDENCE_BUDGET: &str = "evidence_budget";
/// No candidate state matches a finalized commitment this validator lost to.
pub const NO_MATCHING_CANDIDATE: &str = "no_matching_candidate";
/// The executed heights not yet released reached the window cap.
pub const UNSTABLE_HEIGHTS: &str = "unstable_heights";

/// The `role` label of the fork-recovery metrics and its values ([`SKIP`] and these): see
/// [`Role`].
pub const LABEL_ROLE: &str = "role";
pub const ADOPT: &str = "adopt";
pub const WINNER: &str = "winner";

/// The `episode` label of [`FORK_RECOVERY_EPISODE`]: the episode's index in the fork schedule,
/// from 1.
pub const LABEL_EPISODE: &str = "episode";

/// The `quantity` values of [`FORK_RECOVERY_ACCOUNTING`], summed over episodes, and all but
/// `episodes` of [`FORK_RECOVERY_EPISODE`]: the fields of [`EpisodeRecord`], durations in seconds.
pub const EPISODES: &str = "episodes";
pub const DETECTION_S: &str = "detection_s";
pub const STALL_S: &str = "stall_s";
pub const RE_EXECUTED_HEIGHTS: &str = "re_executed_heights";
pub const RE_EXECUTED_TRANSACTIONS: &str = "re_executed_transactions";
pub const SKIPPED_TRANSACTIONS: &str = "skipped_transactions";
pub const RE_VOTES: &str = "re_votes";
pub const RECOVERY_S: &str = "recovery_s";
/// The further `quantity` values of [`FORK_RECOVERY_EPISODE`]: the forked height, and the role
/// as its [`code`](Role::code).
pub const HEIGHT: &str = "height";
pub const ROLE: &str = "role";

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
    halted: IntGaugeVec,
    retained_bytes: IntGauge,
    protocol_submissions_deferred: IntCounter,
    protocol_payloads_submitted: IntCounter,
    max_proposal_bytes: IntGauge,
    max_proposal_protocol_bytes: IntGauge,
    release_waits: IntCounter,
    skipped_transactions: IntCounter,
    recovery: RecoveryExport,
    fork_recovery_stall_s: HistogramVec,
    fork_recovery_re_executed_heights: HistogramVec,
}

impl ValidatorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let decision_accounting = DecisionAccounting::new();
        registry
            .register(Box::new(decision_accounting.clone()))
            .unwrap();
        let halted = register_int_gauge_vec_with_registry!(
            VALIDATOR_HALTED,
            "1 once the validator halted, by reason: it keeps running consensus, but executes, \
                decides and submits nothing more",
            &[LABEL_REASON],
            registry,
        )
        .unwrap();
        // Exported at 0 from the start, so that every run's measurements hold it.
        halted.with_label_values(&[EVIDENCE_BUDGET]);
        let recovery = RecoveryExport::new();
        registry.register(Box::new(recovery.clone())).unwrap();
        let fork_recovery_stall_s = register_histogram_vec_with_registry!(
            FORK_RECOVERY_STALL_S,
            "Fork episodes' stalls, from the forked height's first mint until every height pending \
                at its release is released (s)",
            &[LABEL_ROLE],
            LATENCY_SEC_BUCKETS.to_vec(),
            registry,
        )
        .unwrap();
        let fork_recovery_re_executed_heights = register_histogram_vec_with_registry!(
            FORK_RECOVERY_RE_EXECUTED_HEIGHTS,
            "Fork episodes' height executions done again",
            &[LABEL_ROLE],
            // Up to the default window and twice over: 1 to 2048, exponential.
            prometheus::exponential_buckets(1.0, 2.0, 12).unwrap(),
            registry,
        )
        .unwrap();
        // Every role exported from the start, so that fork-free measurements hold them.
        for role in Role::ALL {
            fork_recovery_stall_s.with_label_values(&[role.label()]);
            fork_recovery_re_executed_heights.with_label_values(&[role.label()]);
        }
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
            halted,
            retained_bytes: register_int_gauge_with_registry!(
                VALIDATOR_RETAINED_BYTES,
                "Bytes of state retained against the evidence budget",
                registry,
            )
            .unwrap(),
            protocol_submissions_deferred: register_int_counter_with_registry!(
                PROTOCOL_SUBMISSIONS_DEFERRED,
                "Events whose own votes and certificates waited for the protocol byte budget",
                registry,
            )
            .unwrap(),
            protocol_payloads_submitted: register_int_counter_with_registry!(
                PROTOCOL_PAYLOADS_SUBMITTED,
                "Own votes and certificates submitted to consensus",
                registry,
            )
            .unwrap(),
            max_proposal_bytes: register_int_gauge_with_registry!(
                MAX_PROPOSAL_BYTES,
                "The largest own proposal, serialized (bytes)",
                registry,
            )
            .unwrap(),
            max_proposal_protocol_bytes: register_int_gauge_with_registry!(
                MAX_PROPOSAL_PROTOCOL_BYTES,
                "The most framed bytes of own votes and certificates in one own proposal",
                registry,
            )
            .unwrap(),
            release_waits: register_int_counter_with_registry!(
                CHECKPOINT_RELEASE_WAITS,
                "Checkpoints released later than concluded: they waited for a predecessor",
                registry,
            )
            .unwrap(),
            skipped_transactions: register_int_counter_with_registry!(
                VALIDATOR_SKIPPED_TRANSACTIONS,
                "Client transactions of skipped heights: executed, then undone",
                registry,
            )
            .unwrap(),
            recovery,
            fork_recovery_stall_s,
            fork_recovery_re_executed_heights,
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

    /// Marks the validator halted for `reason`, a [`LABEL_REASON`] value.
    pub(crate) fn set_halted(&self, reason: &str) {
        self.halted.with_label_values(&[reason]).set(1);
    }

    /// Sets the retained-bytes gauge, if the value changed.
    pub(crate) fn set_retained_bytes(&self, bytes: u64) {
        let bytes = bytes as i64;
        if self.retained_bytes.get() != bytes {
            self.retained_bytes.set(bytes);
        }
    }

    pub(crate) fn inc_protocol_submissions_deferred(&self) {
        self.protocol_submissions_deferred.inc();
    }

    pub(crate) fn inc_protocol_payloads_submitted(&self, count: u64) {
        self.protocol_payloads_submitted.inc_by(count);
    }

    pub(crate) fn inc_release_waits(&self) {
        self.release_waits.inc();
    }

    pub(crate) fn inc_skipped_transactions(&self, count: u64) {
        self.skipped_transactions.inc_by(count);
    }

    /// Exports the record of the episode at `index` of the schedule, in place of any earlier
    /// version, if it is among the first [`MAX_EXPORTED_EPISODES`].
    pub(crate) fn export_episode(&self, index: u64, record: &EpisodeRecord) {
        if index <= MAX_EXPORTED_EPISODES {
            let mut state = self.recovery.state.lock().unwrap();
            state.records.insert(index, *record);
        }
    }

    /// Adds a final episode record to the accounting and the histograms.
    pub(crate) fn account_episode(&self, record: &EpisodeRecord) {
        let role = [record.role.label()];
        self.recovery.account(record);
        if let Some(stall) = record.stall {
            let histogram = self.fork_recovery_stall_s.with_label_values(&role);
            histogram.observe(stall.as_secs_f64());
        }
        let histogram = self
            .fork_recovery_re_executed_heights
            .with_label_values(&role);
        histogram.observe(record.re_executed_heights as f64);
    }

    /// Raises the proposal-size gauges to an own proposal's serialized size and framed protocol
    /// bytes, where they are larger.
    pub(crate) fn observe_own_proposal(&self, bytes: u64, protocol_bytes: u64) {
        for (gauge, value) in [
            (&self.max_proposal_bytes, bytes),
            (&self.max_proposal_protocol_bytes, protocol_bytes),
        ] {
            if value as i64 > gauge.get() {
                gauge.set(value as i64);
            }
        }
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

    /// The halt gauge of one `reason` label.
    pub fn halted(&self, reason: &str) -> IntGauge {
        self.halted.with_label_values(&[reason])
    }

    pub fn retained_bytes(&self) -> &IntGauge {
        &self.retained_bytes
    }

    pub fn protocol_submissions_deferred(&self) -> &IntCounter {
        &self.protocol_submissions_deferred
    }

    pub fn protocol_payloads_submitted(&self) -> &IntCounter {
        &self.protocol_payloads_submitted
    }

    pub fn release_waits(&self) -> &IntCounter {
        &self.release_waits
    }

    pub fn max_proposal_bytes(&self) -> &IntGauge {
        &self.max_proposal_bytes
    }

    pub fn max_proposal_protocol_bytes(&self) -> &IntGauge {
        &self.max_proposal_protocol_bytes
    }

    pub fn skipped_transactions(&self) -> &IntCounter {
        &self.skipped_transactions
    }

    /// The exported episode records, by index in the schedule.
    pub fn episodes(&self) -> BTreeMap<u64, EpisodeRecord> {
        self.recovery.state.lock().unwrap().records.clone()
    }

    /// The accounted total of one `quantity` over the final episodes of `role`.
    pub fn recovery_accounting(&self, role: Role, quantity: &'static str) -> f64 {
        let state = self.recovery.state.lock().unwrap();
        let total = state.totals.get(&(role.label(), quantity));
        total.copied().unwrap_or_default()
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

/// A pair of labels, as exported.
fn label(name: &str, value: &str) -> LabelPair {
    let mut pair = LabelPair::default();
    pair.set_name(name.into());
    pair.set_value(value.into());
    pair
}

/// The summable quantities of `record`, the stall once it ended.
fn quantities(record: &EpisodeRecord) -> impl Iterator<Item = (&'static str, f64)> {
    [
        (DETECTION_S, Some(record.detection.as_secs_f64())),
        (STALL_S, record.stall.map(|stall| stall.as_secs_f64())),
        (RE_EXECUTED_HEIGHTS, Some(record.re_executed_heights as f64)),
        (
            RE_EXECUTED_TRANSACTIONS,
            Some(record.re_executed_transactions as f64),
        ),
        (
            SKIPPED_TRANSACTIONS,
            Some(record.skipped_transactions as f64),
        ),
        (RE_VOTES, Some(record.re_votes as f64)),
        (RECOVERY_S, Some(record.recovery.as_secs_f64())),
    ]
    .into_iter()
    .filter_map(|(quantity, value)| value.map(|value| (quantity, value)))
}

/// Fork-recovery episodes, exported as two families under one lock, F5's pattern: the
/// accounting, whose every scrape pairs the episode count of a role with its sums coherently,
/// and the records of the first [`MAX_EXPORTED_EPISODES`] episodes, as gauges.
#[derive(Clone)]
struct RecoveryExport {
    accounting: Desc,
    episodes: Desc,
    state: Arc<Mutex<RecoveryState>>,
}

struct RecoveryState {
    /// The sums by `(role, quantity)`, every pair present from the start.
    totals: BTreeMap<(&'static str, &'static str), f64>,
    /// The exported records by episode index.
    records: BTreeMap<u64, EpisodeRecord>,
}

impl RecoveryExport {
    fn new() -> Self {
        let accounting = Desc::new(
            FORK_RECOVERY_ACCOUNTING.into(),
            "Final fork-recovery episodes and their summed quantities, by role".into(),
            vec![LABEL_ROLE.into(), LABEL_QUANTITY.into()],
            HashMap::new(),
        )
        .unwrap();
        let episodes = Desc::new(
            FORK_RECOVERY_EPISODE.into(),
            "The first fork-recovery episodes' records; role 1 skip, 2 adopt, 3 winner".into(),
            vec![LABEL_EPISODE.into(), LABEL_QUANTITY.into()],
            HashMap::new(),
        )
        .unwrap();
        let summed = [
            EPISODES,
            DETECTION_S,
            STALL_S,
            RE_EXECUTED_HEIGHTS,
            RE_EXECUTED_TRANSACTIONS,
            SKIPPED_TRANSACTIONS,
            RE_VOTES,
            RECOVERY_S,
        ];
        let totals = Role::ALL
            .into_iter()
            .flat_map(|role| summed.map(|quantity| ((role.label(), quantity), 0.0)))
            .collect();
        let state = RecoveryState {
            totals,
            records: BTreeMap::new(),
        };
        Self {
            accounting,
            episodes,
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn account(&self, record: &EpisodeRecord) {
        let role = record.role.label();
        let mut state = self.state.lock().unwrap();
        let added = std::iter::once((EPISODES, 1.0)).chain(quantities(record));
        for (quantity, value) in added {
            *state.totals.entry((role, quantity)).or_default() += value;
        }
    }
}

impl Collector for RecoveryExport {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.accounting, &self.episodes]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let (totals, records) = {
            let state = self.state.lock().unwrap();
            (state.totals.clone(), state.records.clone())
        };
        let mut accounting = MetricFamily::default();
        accounting.set_name(FORK_RECOVERY_ACCOUNTING.into());
        accounting.set_help(self.accounting.help.clone());
        accounting.set_field_type(MetricType::COUNTER);
        for ((role, quantity), value) in totals {
            let mut metric = Metric::from_label(vec![
                label(LABEL_ROLE, role),
                label(LABEL_QUANTITY, quantity),
            ]);
            let mut counter = Counter::default();
            counter.set_value(value);
            metric.set_counter(counter);
            accounting.mut_metric().push(metric);
        }
        let mut episodes = MetricFamily::default();
        episodes.set_name(FORK_RECOVERY_EPISODE.into());
        episodes.set_help(self.episodes.help.clone());
        episodes.set_field_type(MetricType::GAUGE);
        for (index, record) in records {
            let index = index.to_string();
            let identity = [(HEIGHT, record.height as f64), (ROLE, record.role.code())];
            for (quantity, value) in identity.into_iter().chain(quantities(&record)) {
                let mut metric = Metric::from_label(vec![
                    label(LABEL_EPISODE, &index),
                    label(LABEL_QUANTITY, quantity),
                ]);
                let mut gauge = Gauge::default();
                gauge.set_value(value);
                metric.set_gauge(gauge);
                episodes.mut_metric().push(metric);
            }
        }
        vec![accounting, episodes]
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
    use prometheus::{Registry, proto::MetricType};

    use crate::{
        episode::{EpisodeRecord, Role},
        metrics::{
            CHECKPOINT_DECISION_ACCOUNTING, DECISION_LATENCY_S, DECISIONS, EPISODES,
            FORK_RECOVERY_ACCOUNTING, FORK_RECOVERY_EPISODE, FORK_RECOVERY_RE_EXECUTED_HEIGHTS,
            FORK_RECOVERY_STALL_S, MAX_EXPORTED_EPISODES, RE_EXECUTED_HEIGHTS, SKIP, SLOW, STALL_S,
            VALIDATOR_SKIPPED_TRANSACTIONS, ValidatorMetrics,
        },
    };

    /// The samples of family `name` in one scrape of `registry`, by their labels as
    /// comma-separated `name=value` pairs: histograms by sample count.
    fn samples(registry: &Registry, name: &str) -> BTreeMap<String, f64> {
        let families = registry.gather().into_iter();
        let mut families = families.filter(|family| family.name() == name);
        let Some(family) = families.next() else {
            return BTreeMap::new();
        };
        let kind = family.get_field_type();
        (family.get_metric().iter())
            .map(|metric| {
                let labels: Vec<_> = metric
                    .get_label()
                    .iter()
                    .map(|pair| format!("{}={}", pair.name(), pair.value()))
                    .collect();
                let value = match kind {
                    MetricType::COUNTER => metric.get_counter().value(),
                    MetricType::GAUGE => metric.get_gauge().value(),
                    _ => metric.get_histogram().get_sample_count() as f64,
                };
                (labels.join(","), value)
            })
            .collect()
    }

    /// The accounting family's skip-on-the-slow-path quantities in one scrape of `registry`:
    /// the decisions and their latency sum.
    fn scrape(registry: &Registry) -> (f64, f64) {
        let quantities = samples(registry, CHECKPOINT_DECISION_ACCOUNTING);
        let quantity = |name: &str| {
            let key = format!("outcome={SKIP},path={SLOW},quantity={name}");
            quantities.get(&key).copied().unwrap_or_default()
        };
        (quantity(DECISIONS), quantity(DECISION_LATENCY_S))
    }

    /// A final skip episode at `height` that stalled two seconds and executed three heights
    /// again.
    fn episode(height: u64) -> EpisodeRecord {
        EpisodeRecord {
            height,
            role: Role::Skip,
            detection: Duration::from_secs(1),
            stall: Some(Duration::from_secs(2)),
            re_executed_heights: 3,
            re_executed_transactions: 30,
            skipped_transactions: 10,
            re_votes: 3,
            recovery: Duration::ZERO,
        }
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

    #[test]
    fn episode_accounting_scrapes_are_coherent() {
        const SCRAPES: usize = 1_000;
        let registry = Registry::new();
        let metrics = ValidatorMetrics::new(&registry);
        let done = AtomicBool::new(false);
        let accounted = |quantity| metrics.recovery_accounting(Role::Skip, quantity);
        let incoherent = thread::scope(|scope| {
            let recorder = scope.spawn(|| {
                while !done.load(Ordering::Relaxed) {
                    metrics.account_episode(&episode(200));
                }
            });
            // Scrape only while recording.
            while accounted(EPISODES) == 0.0 && !recorder.is_finished() {
                thread::yield_now();
            }
            let incoherent = (0..SCRAPES)
                .filter(|_| {
                    let totals = samples(&registry, FORK_RECOVERY_ACCOUNTING);
                    let total = |quantity| totals[&format!("role={SKIP},quantity={quantity}")];
                    let episodes = total(EPISODES);
                    total(STALL_S) != 2.0 * episodes || total(RE_EXECUTED_HEIGHTS) != 3.0 * episodes
                })
                .count();
            done.store(true, Ordering::Relaxed);
            incoherent
        });
        assert_eq!(incoherent, 0, "of {SCRAPES} scrapes");
        assert!(accounted(EPISODES) > 0.0);
        assert_eq!(accounted(STALL_S), 2.0 * accounted(EPISODES));
    }

    /// Before any episode, as in a fork-free run, every recovery metric is exported at zero
    /// for every role, and no episode record.
    #[test]
    fn fork_free_runs_export_no_episode() {
        let registry = Registry::new();
        ValidatorMetrics::new(&registry);

        let accounting = samples(&registry, FORK_RECOVERY_ACCOUNTING);
        assert_eq!(accounting.len(), 3 * 8);
        assert!(accounting.values().all(|&total| total == 0.0));
        for histogram in [FORK_RECOVERY_STALL_S, FORK_RECOVERY_RE_EXECUTED_HEIGHTS] {
            let roles: Vec<_> = samples(&registry, histogram).into_iter().collect();
            let expected = ["adopt", "skip", "winner"].map(|role| (format!("role={role}"), 0.0));
            assert_eq!(roles, expected, "{histogram}");
        }
        let skipped = samples(&registry, VALIDATOR_SKIPPED_TRANSACTIONS);
        assert_eq!(skipped.into_values().collect::<Vec<_>>(), [0.0]);
        assert!(samples(&registry, FORK_RECOVERY_EPISODE).is_empty());
    }

    /// Records are exported for the schedule's first episodes only, each with its every
    /// quantity, and the accounting counts every final one.
    #[test]
    fn only_the_first_episodes_are_exported_and_every_one_is_accounted() {
        let registry = Registry::new();
        let metrics = ValidatorMetrics::new(&registry);
        for index in [MAX_EXPORTED_EPISODES, MAX_EXPORTED_EPISODES + 1] {
            metrics.export_episode(index, &episode(200 * index));
            metrics.account_episode(&episode(200 * index));
        }

        let exported = samples(&registry, FORK_RECOVERY_EPISODE);
        let prefix = format!("episode={MAX_EXPORTED_EPISODES},");
        assert!(exported.keys().all(|labels| labels.starts_with(&prefix)));
        let quantity = |quantity: &str| exported[&format!("{prefix}quantity={quantity}")];
        assert_eq!(exported.len(), 9);
        assert_eq!(quantity("height"), (200 * MAX_EXPORTED_EPISODES) as f64);
        assert_eq!(quantity("role"), Role::Skip.code());
        assert_eq!(quantity(STALL_S), 2.0);
        assert_eq!(metrics.episodes().len(), 1);
        assert_eq!(metrics.recovery_accounting(Role::Skip, EPISODES), 2.0);
        for histogram in [FORK_RECOVERY_STALL_S, FORK_RECOVERY_RE_EXECUTED_HEIGHTS] {
            let observed = samples(&registry, histogram)[&format!("role={SKIP}")];
            assert_eq!(observed, 2.0, "{histogram}");
        }
    }
}
