// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end validator test on the local tokio network.
//!
//! Port offsets across test binaries: mysticeti uses 0-500, this file uses 3000, and
//! recovery.rs uses 3100/3200.

mod common;

use checkpoint::checkpoint::Outcome;
use common::Testbed;
use execution::{
    fake::{FakeExecutor, FakeTransaction},
    object::{ObjectId, Version},
    store::StateView,
};
use validator::metrics::{
    CHECKPOINT_DECISION_ACCOUNTING, CLIENT_COMMIT_LATENCY_S, DECISION_LATENCY_S, DECISIONS,
    FINALIZE, SLOW,
};

#[tokio::test]
async fn submitted_transactions_execute_identically_on_all_validators() {
    let mut testbed = Testbed::start(3000).await;

    // One batch, so block order (and thus commit order) executes the creation before the
    // read-modify-write.
    let id = ObjectId::new(1);
    testbed
        .submit(
            0,
            vec![
                FakeTransaction::success(vec![], vec![id], vec![]).into(),
                FakeTransaction::success(vec![], vec![], vec![id]).into(),
            ],
        )
        .await;
    testbed.wait_for_transactions(2).await;
    testbed.wait_for_decided().await;
    // Metric (b) observes every delivered sub-dag with real durations on the tokio path;
    // certification and end-to-end observe once per certified checkpoint.
    for validator in testbed.validators() {
        let histogram = validator.metrics().subdag_execution_latency_s();
        assert!(histogram.get_sample_count() > 0);
        assert!(histogram.get_sample_sum() > 0.0);
        let certification = validator
            .metrics()
            .checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert!(certification.get_sample_count() > 0);
        assert!(certification.get_sample_sum() > 0.0);
        let end_to_end = validator.metrics().end_to_end_latency_s();
        assert_eq!(
            end_to_end.get_sample_count(),
            certification.get_sample_count()
        );
        assert!(end_to_end.get_sample_sum() > 0.0);
        // Client metrics count exactly the executed transactions, not the votes.
        let executed = validator.executed();
        assert_eq!(validator.metrics().executed_transactions().get(), executed);
        let client_commit = validator.metrics().client_commit_latency_s();
        assert_eq!(client_commit.get_sample_count(), executed);
        assert!(client_commit.get_sample_sum() > 0.0);
    }
    // The shared registry serves scraping: validator and replica metrics both land in it.
    for (registry, validator) in testbed.registries().iter().zip(testbed.validators()) {
        let families: Vec<_> = registry.gather();
        // The decision accounting exports every live decision and its latency.
        let accounting = families
            .iter()
            .find(|family| family.name() == CHECKPOINT_DECISION_ACCOUNTING)
            .expect("decision accounting must be registered");
        let quantity = |name: &str| {
            let metric = accounting.get_metric().iter().find(|metric| {
                let labels: Vec<_> = metric.get_label().iter().map(|pair| pair.value()).collect();
                labels == [FINALIZE, SLOW, name]
            });
            metric.expect("decided checkpoints").get_counter().value()
        };
        let certification = validator
            .metrics()
            .checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(quantity(DECISIONS), certification.get_sample_count() as f64);
        let latency_s = quantity(DECISION_LATENCY_S);
        assert!((latency_s - certification.get_sample_sum()).abs() < 1e-9);

        assert!(
            families
                .iter()
                .any(|family| family.name() == "subdag_execution_latency_s")
        );
        assert!(families.iter().any(|family| family.name() == "latency_s"));
        assert!(
            families
                .iter()
                .any(|family| family.name() == CLIENT_COMMIT_LATENCY_S)
        );
    }
    let results = testbed.shutdown().await;

    let (reference, certifier) = &results[0];
    let store = reference.store();
    let certified = certifier
        .highest_decided()
        .expect("everything executed is certified");
    assert_eq!(certified.outcome(), Outcome::Finalize(store.commitment()));
    // Certification is a deterministic function of the commit stream: every validator holds
    // the same byte-identical certificate and an empty pending window.
    for (scheduler, other) in &results {
        assert_eq!(scheduler.store(), store);
        assert_eq!(other.highest_decided(), Some(certified));
        assert!(other.pending().next().is_none());
    }
    let latest = store.latest(&id).expect("object must exist");
    assert_eq!(latest.version(), Version::new(2));
    assert_eq!(latest.contents(), FakeExecutor::NEW_OBJECT_CONTENT);
}
