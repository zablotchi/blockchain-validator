// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Full-committee restart: execution state is rebuilt by replaying the consensus WAL.
//!
//! Port offsets across test binaries: mysticeti uses 0-500, smoke.rs uses 3000, and this file
//! uses 3100-3400 and 3700-4600 (a fresh offset per start avoids rebinding ports still in
//! TIME_WAIT). Offset 3500 would bind port 5000, taken by macOS's AirPlay receiver.

mod common;

use std::num::NonZeroU64;

use checkpoint::{certifier::CheckpointCertifier, checkpoint::Outcome, finality::FinalityProtocol};
use common::{COMMITTEE_SIZE, Testbed};
use dag::{authority::Authority, block::BlockReference, context::TokioCtx};
use execution::{
    fake::{FakeExecutor, FakeTransaction},
    object::{ObjectId, Version},
    store::StateView,
};
use validator::{
    fork::ForkInjection,
    metrics::{FAST, FINALIZE, SLOW},
    parameters::ValidatorParameters,
    validator::ValidatorHandle,
};

const STATE_UPDATES: usize = 3;
/// Committed sub-dags after which anything submitted before has committed: a few rounds.
const COMMITS_TO_SETTLE: u64 = 10;

#[tokio::test]
async fn restarted_committee_recovers_execution_state() {
    recovers_execution_state(FinalityProtocol::Baseline, 3100).await;
}

/// Replay rebuilds B's decisions from the certificates in the WAL.
#[tokio::test]
async fn restarted_committee_recovers_execution_state_under_protocol_b() {
    recovers_execution_state(FinalityProtocol::B, 3900).await;
}

/// Replay rebuilds C's decisions on its slow path, from the certificates in the WAL.
#[tokio::test]
async fn restarted_committee_recovers_execution_state_under_protocol_c() {
    recovers_execution_state(FinalityProtocol::C, 4100).await;
}

/// The default parameters, deciding with `finality`.
fn deciding(finality: FinalityProtocol) -> ValidatorParameters {
    ValidatorParameters {
        finality,
        ..Default::default()
    }
}

/// The checkpoints a validator finalized since it started, on either path.
fn finalized(validator: &ValidatorHandle<TokioCtx, FakeExecutor>) -> u64 {
    [FAST, SLOW]
        .map(|path| {
            validator
                .metrics()
                .checkpoint_certification_latency_s(FINALIZE, path)
                .get_sample_count()
        })
        .iter()
        .sum()
}

/// The last decision, as validators agree on it: under C they may decide a height on
/// different paths, so with different proofs.
fn last_decision(
    finality: FinalityProtocol,
    certifier: &CheckpointCertifier,
) -> (BlockReference, Outcome, Option<Vec<BlockReference>>) {
    let decision = certifier.highest_decided().expect("decided checkpoint");
    let proof = (finality != FinalityProtocol::C).then(|| decision.proof().to_vec());
    (decision.anchor(), decision.outcome(), proof)
}

/// Runs a committee deciding with `finality` to quiescence, then restarts it on
/// `port_offset + 100`.
async fn recovers_execution_state(finality: FinalityProtocol, port_offset: u16) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let id = ObjectId::new(1);
    let total = (STATE_UPDATES + 1) as u64;
    let parameters = deciding(finality);

    // First run: create an object and update it a few times.
    let mut testbed = Testbed::start_with_wal(dir.path(), port_offset, &parameters).await;
    let mut transactions = vec![FakeTransaction::success(vec![], vec![id], vec![]).into()];
    transactions.extend(
        (0..STATE_UPDATES).map(|_| FakeTransaction::success(vec![], vec![], vec![id]).into()),
    );
    testbed.submit(0, transactions).await;
    testbed.wait_for_transactions(total).await;
    // Halt only once everything is certified and the certificates committed (C's fast path
    // decides before they do): the run then loses nothing in flight, so replay alone rebuilds
    // the certified watermark (re-attestation is a separate concern).
    testbed.wait_for_decided().await;
    testbed.wait_for_commits(COMMITS_TO_SETTLE).await;
    let references = testbed.shutdown().await;

    // Restart on the same WALs: replay must rebuild the executed count and the certified
    // watermark without new commits — the WAL's post-cut sub-dags carry only attestations,
    // which mint nothing.
    let mut testbed = Testbed::start_with_wal(dir.path(), port_offset + 100, &parameters).await;
    testbed.wait_for_transactions(total).await;
    testbed.wait_for_decided().await;
    // Replay records nothing: the pre-restart certifications must not re-observe.
    for validator in testbed.validators() {
        assert_eq!(finalized(validator), 0);
    }

    // The restarted committee stays live: one more update commits and executes everywhere.
    let update = FakeTransaction::success(vec![], vec![], vec![id]).into();
    testbed.submit(0, vec![update]).await;
    testbed.wait_for_transactions(total + 1).await;
    testbed.wait_for_decided().await;
    // Exactly the post-restart checkpoint observes, contiguity included: replay drained the
    // replayed heights into its discarded metrics.
    for validator in testbed.validators() {
        assert_eq!(finalized(validator), 1);
        let metrics = validator.metrics();
        let finality = metrics.checkpoint_finality_latency_s(FINALIZE);
        assert_eq!(finality.get_sample_count(), 1);
        assert_eq!(metrics.end_to_end_latency_s().get_sample_count(), 1);
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
            .highest_decided()
            .expect("first run halts certified");
        let rebuilt_certified = rebuilt_certifier
            .highest_decided()
            .expect("restarted run halts certified");
        assert_eq!(
            reference_certified.outcome(),
            Outcome::Finalize(reference.store().commitment())
        );
        assert_eq!(
            rebuilt_certified.outcome(),
            Outcome::Finalize(rebuilt.store().commitment())
        );
        assert!(rebuilt_certified.round() > reference_certified.round());
    }
    let (first, first_certifier) = &rebuilt[0];
    let store = first.store();
    for (scheduler, certifier) in &rebuilt {
        assert_eq!(scheduler.store(), store);
        assert_eq!(
            last_decision(finality, certifier),
            last_decision(finality, first_certifier)
        );
        assert!(certifier.pending().next().is_none());
    }
}

#[tokio::test]
async fn restarted_committee_recertifies_lost_votes() {
    recertifies_lost_votes(deciding(FinalityProtocol::Baseline), 3300).await;
}

/// Arrival tallies die with the process: certificates conclude again from re-attested votes.
#[tokio::test]
async fn restarted_committee_recertifies_lost_votes_under_protocol_b() {
    recertifies_lost_votes(deciding(FinalityProtocol::B), 3700).await;
}

/// As under B: without forks, the re-attested votes conclude without timing out.
#[tokio::test]
async fn restarted_committee_recertifies_lost_votes_under_protocol_c() {
    recertifies_lost_votes(deciding(FinalityProtocol::C), 4300).await;
}

/// With every height forked, the re-attested votes conclude only once timed out: the replayed
/// checkpoints' phase-one timeouts are re-armed, as no new mint will expire them.
#[tokio::test]
async fn restarted_committee_skips_lost_forked_heights_under_protocol_c() {
    // Every validator but the first forks alone at every height.
    let groups = (1..COMMITTEE_SIZE)
        .map(|index| vec![Authority::from(index)])
        .collect();
    let parameters = ValidatorParameters {
        fork: Some(ForkInjection {
            groups,
            period: NonZeroU64::MIN,
        }),
        ..deciding(FinalityProtocol::C)
    };
    recertifies_lost_votes(parameters, 4500).await;
}

/// Halts a committee running with `parameters` with votes in flight, then restarts it on
/// `port_offset + 100`.
async fn recertifies_lost_votes(parameters: ValidatorParameters, port_offset: u16) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let id = ObjectId::new(1);
    let total = (STATE_UPDATES + 1) as u64;

    // First run: halt as soon as everything executed. Votes still in flight die with the
    // transaction queue, leaving checkpoints that can never certify without re-attestation.
    let mut testbed = Testbed::start_with_wal(dir.path(), port_offset, &parameters).await;
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
    let mut testbed = Testbed::start_with_wal(dir.path(), port_offset + 100, &parameters).await;
    testbed.wait_for_transactions(total).await;
    testbed.wait_for_decided().await;
    let rebuilt = testbed.shutdown().await;

    let (first, first_certifier) = &rebuilt[0];
    let store = first.store();
    let certified = first_certifier
        .highest_decided()
        .expect("everything executed is certified");
    let expected = match parameters.fork {
        None => Outcome::Finalize(store.commitment()),
        // Forked runs fork every height.
        Some(_) => Outcome::Skip,
    };
    assert_eq!(certified.outcome(), expected);
    let finality = parameters.finality;
    for (scheduler, certifier) in &rebuilt {
        assert_eq!(scheduler.store(), store);
        assert_eq!(
            last_decision(finality, certifier),
            last_decision(finality, first_certifier)
        );
        assert!(certifier.pending().next().is_none());
    }
}
