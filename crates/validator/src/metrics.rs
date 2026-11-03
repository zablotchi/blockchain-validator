// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's metrics, mirroring `dag::metrics` conventions: one `Arc`-shared front
//! type, metric names as adjacent constants, registration into a caller-provided registry.

use std::{sync::Arc, time::Duration};

use checkpoint::checkpoint::Outcome;
use prometheus::{
    Histogram, HistogramVec, IntCounter, Registry, register_histogram_vec_with_registry,
    register_histogram_with_registry, register_int_counter_with_registry,
};

// Metric names, public for scrapers. The counter is prefixed because the replica already
// registers a `submitted_transactions` in the same registry.
pub const SUBMITTED_TRANSACTIONS: &str = "validator_submitted_transactions";
pub const SUBDAG_EXECUTION_LATENCY_S: &str = "subdag_execution_latency_s";
pub const CHECKPOINT_CERTIFICATION_LATENCY_S: &str = "checkpoint_certification_latency_s";
pub const END_TO_END_LATENCY_S: &str = "end_to_end_latency_s";

/// The `outcome` label of [`CHECKPOINT_CERTIFICATION_LATENCY_S`] and its values.
pub const LABEL_OUTCOME: &str = "outcome";
pub const FINALIZE: &str = "finalize";
pub const SKIP: &str = "skip";

/// Mysticeti's consensus-latency buckets: dense around the expected commit latency.
const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.1, 0.2, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1., 1.25, 1.5, 1.75, 2., 3.0, 5., 10.,
];

pub struct ValidatorMetrics {
    submitted_transactions: IntCounter,
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
                &[LABEL_OUTCOME],
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

    pub(crate) fn observe_subdag_execution_latency(&self, latency: Duration) {
        self.subdag_execution_latency_s
            .observe(latency.as_secs_f64());
    }

    pub(crate) fn observe_checkpoint_certification_latency(
        &self,
        outcome: Outcome,
        latency: Duration,
    ) {
        let label = match outcome {
            Outcome::Finalize(_) => FINALIZE,
            Outcome::Skip => SKIP,
        };
        self.checkpoint_certification_latency_s(label)
            .observe(latency.as_secs_f64());
    }

    pub(crate) fn observe_end_to_end_latency(&self, latency: Duration) {
        self.end_to_end_latency_s.observe(latency.as_secs_f64());
    }

    /// The raw metrics, for test assertions (`get`/`get_sample_count`/`get_sample_sum`).
    pub fn submitted_transactions(&self) -> &IntCounter {
        &self.submitted_transactions
    }

    pub fn subdag_execution_latency_s(&self) -> &Histogram {
        &self.subdag_execution_latency_s
    }

    /// The decision latency of one `outcome` label value.
    pub fn checkpoint_certification_latency_s(&self, outcome: &str) -> Histogram {
        self.checkpoint_certification_latency_s
            .with_label_values(&[outcome])
    }

    pub fn end_to_end_latency_s(&self) -> &Histogram {
        &self.end_to_end_latency_s
    }
}
