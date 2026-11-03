// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Full-committee restart: execution state is rebuilt by replaying the consensus WAL.
//!
//! Port offsets across test binaries: mysticeti uses 0-500, smoke.rs uses 3000, and this file
//! uses 3100-3400 (a fresh offset per start avoids rebinding ports still in TIME_WAIT).

mod common;

use common::Testbed;
use execution::{
    fake::FakeTransaction,
    object::{ObjectId, Version},
    store::StateView,
};

const STATE_UPDATES: usize = 3;

#[tokio::test]
async fn restarted_committee_recovers_execution_state() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let id = ObjectId::new(1);
    let total = (STATE_UPDATES + 1) as u64;

    // First run: create an object and update it a few times.
    let mut testbed = Testbed::start_with_wal(dir.path(), 3100).await;
    let mut transactions = vec![FakeTransaction::success(vec![], vec![id], vec![]).into()];
    transactions.extend(
        (0..STATE_UPDATES).map(|_| FakeTransaction::success(vec![], vec![], vec![id]).into()),
    );
    testbed.submit(0, transactions).await;
    testbed.wait_for_transactions(total).await;
    // Halt only once everything is certified: the run then loses no in-flight votes, so
    // replay alone rebuilds the certified watermark (re-attestation is a separate concern).
    testbed.wait_for_certified().await;
    let references = testbed.shutdown().await;

    // Restart on the same WALs: replay must rebuild the executed count and the certified
    // watermark without new commits — the WAL's post-cut sub-dags carry only attestations,
    // which mint nothing.
    let mut testbed = Testbed::start_with_wal(dir.path(), 3200).await;
    testbed.wait_for_transactions(total).await;
    testbed.wait_for_certified().await;
    // Replay records nothing: the pre-restart certifications must not re-observe.
    for validator in testbed.validators() {
        let certification = validator.metrics().checkpoint_certification_latency_s();
        assert_eq!(certification.get_sample_count(), 0);
    }

    // The restarted committee stays live: one more update commits and executes everywhere.
    let update = FakeTransaction::success(vec![], vec![], vec![id]).into();
    testbed.submit(0, vec![update]).await;
    testbed.wait_for_transactions(total + 1).await;
    testbed.wait_for_certified().await;
    // Exactly the post-restart checkpoint observes.
    for validator in testbed.validators() {
        let certification = validator.metrics().checkpoint_certification_latency_s();
        assert_eq!(certification.get_sample_count(), 1);
    }
    let rebuilt = testbed.shutdown().await;

    assert_eq!(references.len(), rebuilt.len());
    for ((reference, reference_certifier), (rebuilt, rebuilt_certifier)) in
        references.iter().zip(&rebuilt)
    {
        // Replay reproduced the pre-restart history exactly...
        for version in 1..=total {
            assert_eq!(
                rebuilt.store().get(&id, Version::new(version)),
                reference.store().get(&id, Version::new(version)),
            );
        }
        // ...and the post-restart update landed on top of it.
        let latest = rebuilt.store().latest(&id).expect("object must exist");
        assert_eq!(latest.version(), Version::new(total + 1));
        // Replay rebuilt the certified watermark from the WAL's ordered votes, and the
        // post-restart checkpoint certified on top of it.
        let reference_certified = reference_certifier
            .highest_certified()
            .expect("first run halts certified");
        let rebuilt_certified = rebuilt_certifier
            .highest_certified()
            .expect("restarted run halts certified");
        assert_eq!(
            reference_certified.checkpoint().commitment(),
            reference.store().commitment()
        );
        assert_eq!(
            rebuilt_certified.checkpoint().commitment(),
            rebuilt.store().commitment()
        );
        assert!(rebuilt_certified.round() > reference_certified.round());
    }
    let (first, first_certifier) = &rebuilt[0];
    let store = first.store();
    for (scheduler, certifier) in &rebuilt {
        assert_eq!(scheduler.store(), store);
        assert_eq!(
            certifier.highest_certified(),
            first_certifier.highest_certified()
        );
        assert!(certifier.pending().next().is_none());
    }
}

#[tokio::test]
async fn restarted_committee_recertifies_lost_votes() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let id = ObjectId::new(1);
    let total = (STATE_UPDATES + 1) as u64;

    // First run: halt as soon as everything executed. Votes still in flight die with the
    // transaction queue, leaving checkpoints that can never certify without re-attestation.
    let mut testbed = Testbed::start_with_wal(dir.path(), 3300).await;
    let mut transactions = vec![FakeTransaction::success(vec![], vec![id], vec![]).into()];
    transactions.extend(
        (0..STATE_UPDATES).map(|_| FakeTransaction::success(vec![], vec![], vec![id]).into()),
    );
    testbed.submit(0, transactions).await;
    testbed.wait_for_transactions(total).await;
    let references = testbed.shutdown().await;
    // The scenario's precondition: at least one validator halted with an uncertified window,
    // so the restart below cannot certify from replay alone.
    assert!(
        references
            .iter()
            .any(|(_, certifier)| certifier.pending().next().is_some())
    );

    // Restart: replay rebuilds the pending window, and re-attestation certifies it — waiting
    // here stalls forever if any lost vote is not resubmitted.
    let mut testbed = Testbed::start_with_wal(dir.path(), 3400).await;
    testbed.wait_for_transactions(total).await;
    testbed.wait_for_certified().await;
    let rebuilt = testbed.shutdown().await;

    let (first, first_certifier) = &rebuilt[0];
    let store = first.store();
    let certified = first_certifier
        .highest_certified()
        .expect("everything executed is certified");
    assert_eq!(certified.checkpoint().commitment(), store.commitment());
    for (scheduler, certifier) in &rebuilt {
        assert_eq!(scheduler.store(), store);
        assert_eq!(
            certifier.highest_certified(),
            first_certifier.highest_certified()
        );
        assert!(certifier.pending().next().is_none());
    }
}
