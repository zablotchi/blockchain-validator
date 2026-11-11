// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's metrics, mirroring `dag::metrics` conventions: one `Arc`-shared front
//! type, metric names as adjacent constants, registration into a caller-provided registry.

use std::{sync::Arc, time::Duration};

use checkpoint::{certifier::CheckpointTimings, checkpoint::Outcome};
use prometheus::{
    Histogram, HistogramVec, IntCounter, Registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, register_int_counter_with_registry,
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

/// The `outcome` label of [`CHECKPOINT_CERTIFICATION_LATENCY_S`] and its values.
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
    end_to_end_latency_s: Histogram,
}

impl ValidatorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
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
            end_to_end_latency_s: register_histogram_with_registry!(
                END_TO_END_LATENCY_S,
                "Submission to finalized-checkpoint inclusion latency (s)",
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
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

    /// Closes the latency metrics of a checkpoint decided at `now` on `path` ([`FAST`] or
    /// [`SLOW`]). Skipped transactions are never finalized, so only finalized checkpoints close
    /// end to end.
    pub(crate) fn observe_decision(
        &self,
        now: Duration,
        outcome: Outcome,
        path: &str,
        timings: CheckpointTimings,
    ) {
        let label = match outcome {
            Outcome::Finalize(_) => FINALIZE,
            Outcome::Skip => SKIP,
        };
        self.checkpoint_certification_latency_s(label, path)
            .observe(now.saturating_sub(timings.minted_at).as_secs_f64());
        if let Outcome::Finalize(_) = outcome {
            let submitted = Duration::from_millis(timings.mean_timestamp_ms);
            self.end_to_end_latency_s
                .observe(now.saturating_sub(submitted).as_secs_f64());
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

    pub fn end_to_end_latency_s(&self) -> &Histogram {
        &self.end_to_end_latency_s
    }
}
