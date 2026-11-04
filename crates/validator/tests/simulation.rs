// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Multi-replica convergence and determinism under the mysticeti discrete-event simulator.
//! Unlike the smoke test, every validator submits through its own replica, so the total order
//! of transactions is genuinely decided by consensus across concurrent proposers.

use std::{num::NonZeroU64, path::Path, sync::Arc, time::Duration};

use checkpoint::{certifier::CheckpointCertifier, checkpoint::Outcome, finality::FinalityProtocol};
use dag::{authority::Authority, block::BlockReference, context::Ctx, metrics::Metrics};
use execution::{
    fake::{FakeExecutor, FakeTransaction},
    object::{ObjectId, Version},
    scheduler::SequentialScheduler,
    store::StateView,
};
use futures::future::join_all;
use rand::{SeedableRng, rngs::StdRng};
use replica::{
    builder::StorageKind,
    config::{PrivateReplicaConfig, PublicReplicaConfig},
};
use simulator::{
    LatencyModel, SimulatedNetwork, SimulatorContext, SimulatorExecutor, UniformLatency,
};
use validator::{
    fork::ForkInjection,
    generator::LoadGeneratorConfig,
    metrics::{FAST, FINALIZE, SKIP, SLOW},
    parameters::ValidatorParameters,
    validator::{ValidatorBuilder, ValidatorHandle},
};

const COMMITTEE_SIZE: usize = 4;
/// Executed-transaction cut at which the load generators are stopped.
const TARGET_TRANSACTIONS: u64 = 1_000;
/// One quiescence window: long enough for any in-flight block to commit everywhere.
const DRAIN_INTERVAL: Duration = Duration::from_secs(5);
/// Modifications each validator makes to its coupled object (simulated time is free).
const COUPLED_UPDATES: usize = 20;
/// Spreads the coupled submissions across many consensus rounds.
const SUBMISSION_INTERVAL: Duration = Duration::from_millis(100);
/// A few generated transactions per consensus block, so the generator's block-splitting path
/// (mid-batch flushes plus a partial trailing block) is exercised on every tick.
const MAX_BLOCK_SIZE: usize = 512;
/// Fork injection fragments every this many checkpoint heights.
const FORK_PERIOD: u64 = 5;

/// A committee of validators running under the simulator.
struct SimulatedTestbed {
    /// Dropping the network silently severs all connections.
    _network: SimulatedNetwork,
    validators: Vec<ValidatorHandle<SimulatorContext, FakeExecutor>>,
    metrics: Vec<Arc<Metrics>>,
}

impl SimulatedTestbed {
    async fn start(parameters: ValidatorParameters) -> Self {
        let mut public_config = PublicReplicaConfig::new_for_tests(COMMITTEE_SIZE);
        public_config.parameters.dag.max_block_size = MAX_BLOCK_SIZE;
        let latency = LatencyModel::Uniform(UniformLatency { range_ms: 50..100 });
        let (network, node_networks) = SimulatedNetwork::new(&public_config.committee(), latency);
        let private_configs =
            PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), COMMITTEE_SIZE);

        let mut validators = Vec::with_capacity(COMMITTEE_SIZE);
        let mut metrics = Vec::with_capacity(COMMITTEE_SIZE);
        for (index, (node_network, private_config)) in
            node_networks.into_iter().zip(private_configs).enumerate()
        {
            let node_metrics = Metrics::new_for_test(COMMITTEE_SIZE);
            metrics.push(node_metrics.clone());
            let validator = ValidatorBuilder::new(
                FakeExecutor,
                Authority::from(index),
                public_config.clone(),
                private_config,
            )
            .with_storage(StorageKind::Ephemeral)
            .with_simulated_crypto()
            .with_parameters(parameters.clone())
            .with_metrics(node_metrics)
            .with_network(node_network)
            .build()
            .expect("validator must build")
            .start::<SimulatorContext>()
            .await
            .expect("validator must start");
            validators.push(validator);
        }
        network.connect_all().await;

        Self {
            _network: network,
            validators,
            metrics,
        }
    }

    fn validators(&self) -> &[ValidatorHandle<SimulatorContext, FakeExecutor>] {
        &self.validators
    }

    async fn wait_for_transactions(&mut self, count: u64) {
        for validator in &mut self.validators {
            validator.wait_for_transactions(count).await;
        }
    }

    /// Drains to a fixed point: submissions have stopped, but transactions already queued keep
    /// committing, and every validator must reach the same executed count and hold it for a
    /// full quiescence window before the stores are comparable.
    async fn drain(&mut self) {
        loop {
            let target = self.validators.iter().map(|v| v.executed()).max().unwrap();
            self.wait_for_transactions(target).await;
            SimulatorContext::sleep(DRAIN_INTERVAL).await;
            if self.validators.iter().all(|v| v.executed() == target) {
                break;
            }
        }
    }

    /// Waits until everything executed is decided; call after an executed-count cut.
    async fn wait_for_decided(&mut self) {
        for validator in &mut self.validators {
            validator.wait_for_decided().await;
        }
    }

    async fn shutdown(self) -> Vec<(SequentialScheduler<FakeExecutor>, CheckpointCertifier)> {
        let mut results = Vec::with_capacity(self.validators.len());
        for validator in self.validators {
            results.push(validator.shutdown().await);
        }
        results
    }
}

/// Every validator creates its own object, then modifies it while reading its neighbor's: the
/// read couples the Lamport versions across objects, so the final state encodes the commit
/// interleaving — an ordering oracle the conflict-free generator load cannot provide.
async fn coupled_workload(
    index: usize,
    validator: &ValidatorHandle<SimulatorContext, FakeExecutor>,
) {
    let id = ObjectId::new(index as u64);
    let neighbor = ObjectId::new(((index + 1) % COMMITTEE_SIZE) as u64);
    let create = FakeTransaction::success(vec![], vec![id], vec![]).into();
    validator
        .submit(vec![create])
        .await
        .expect("submission must succeed");
    for _ in 0..COUPLED_UPDATES {
        SimulatorContext::sleep(SUBMISSION_INTERVAL).await;
        // Aborts deterministically with a missing read until the neighbor's object is created.
        let modify = FakeTransaction::success(vec![neighbor], vec![], vec![id]).into();
        validator
            .submit(vec![modify])
            .await
            .expect("submission must succeed");
    }
}

/// Per-validator state, metrics, and delivered-sub-dag counts (the metric-(b) sample count).
type RunOutcome = (
    Vec<(SequentialScheduler<FakeExecutor>, CheckpointCertifier)>,
    Vec<Arc<Metrics>>,
    Vec<u64>,
);

fn run_once(seed: u64) -> RunOutcome {
    SimulatorExecutor::run(StdRng::seed_from_u64(seed), async move {
        let mut committee = SimulatedTestbed::start(ValidatorParameters::default()).await;
        let generators: Vec<_> = committee
            .validators()
            .iter()
            .map(|validator| validator.start_load_generator(LoadGeneratorConfig::new_for_test()))
            .collect();
        let workloads = committee
            .validators()
            .iter()
            .enumerate()
            .map(|(index, validator)| coupled_workload(index, validator));
        join_all(workloads).await;

        committee.wait_for_transactions(TARGET_TRANSACTIONS).await;
        for generator in &generators {
            SimulatorContext::abort(generator);
        }
        committee.drain().await;
        committee.wait_for_decided().await;
        // Metric (b) observes every delivered sub-dag. Values are zero under simulated time
        // (execution advances no simulated clock), so only population is meaningful.
        let mut delivered = Vec::with_capacity(COMMITTEE_SIZE);
        let mut certified_counts = Vec::with_capacity(COMMITTEE_SIZE);
        for validator in committee.validators() {
            assert!(validator.executed() >= TARGET_TRANSACTIONS);
            assert!(validator.metrics().submitted_transactions().get() > 0);
            let histogram = validator.metrics().subdag_execution_latency_s();
            assert!(histogram.get_sample_count() > 0);
            delivered.push(histogram.get_sample_count());

            // Certification and end-to-end latencies derive from simulated clocks, so their
            // magnitudes are meaningful; each certified checkpoint observes both once.
            let certification = validator
                .metrics()
                .checkpoint_certification_latency_s(FINALIZE, SLOW);
            let end_to_end = validator.metrics().end_to_end_latency_s();
            assert!(certification.get_sample_count() > 0);
            assert_eq!(
                end_to_end.get_sample_count(),
                certification.get_sample_count()
            );
            for (name, histogram) in [("certification", &certification), ("e2e", end_to_end)] {
                let mean = histogram.get_sample_sum() / histogram.get_sample_count() as f64;
                assert!(
                    mean > 0.0 && mean < 10.0,
                    "implausible {name} latency: {mean} s"
                );
            }
            certified_counts.push(certification.get_sample_count());
        }
        // Certified checkpoints are a deterministic function of the commit stream.
        assert!(certified_counts.iter().all(|c| *c == certified_counts[0]));
        let metrics = committee.metrics.clone();
        (committee.shutdown().await, metrics, delivered)
    })
}

#[test]
fn validators_converge_under_simulation() {
    let (results, metrics, _) = run_once(7);

    // Commit latency derives from the envelope timestamps: positive, and bounded well below
    // the several simulated seconds the submissions span — unstamped payloads would instead
    // record "commit time − epoch", which grows with the run.
    for metrics in &metrics {
        let p50 = metrics
            .collect()
            .transaction_latency_percentile_ms(0.5)
            .expect("commit-latency histogram must be populated");
        assert!(
            p50 > 0.0 && p50 < 2_000.0,
            "implausible commit latency: {p50} ms"
        );
    }

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
    // Every validator's coupled object was created and modified at least once.
    for index in 0..COMMITTEE_SIZE {
        let latest = store
            .latest(&ObjectId::new(index as u64))
            .expect("object must exist");
        assert!(latest.version() >= Version::new(2));
    }
}

#[test]
fn simulation_is_deterministic_per_seed() {
    for seed in [7, 42] {
        let (first, _, first_delivered) = run_once(seed);
        let (second, _, second_delivered) = run_once(seed);
        assert_eq!(
            first_delivered, second_delivered,
            "seed {seed} produced diverging delivery counts"
        );
        for ((a, a_certifier), (b, b_certifier)) in first.iter().zip(&second) {
            assert_eq!(
                a.store(),
                b.store(),
                "seed {seed} produced diverging stores"
            );
            assert_eq!(
                a_certifier.highest_decided(),
                b_certifier.highest_decided(),
                "seed {seed} produced diverging certificates"
            );
        }
    }
}

/// Every validator but the first forks into a group of its own at every [`FORK_PERIOD`]-th
/// height: one commitment per validator, so none reaches f+1 support.
fn fragmented(finality: FinalityProtocol) -> ValidatorParameters {
    let groups = (1..COMMITTEE_SIZE)
        .map(|index| vec![Authority::from(index)])
        .collect();
    let period = NonZeroU64::new(FORK_PERIOD).unwrap();
    ValidatorParameters {
        finality,
        fork: Some(ForkInjection { groups, period }),
        ..Default::default()
    }
}

/// Runs the load generators until every validator executed [`TARGET_TRANSACTIONS`], then
/// drains.
async fn generate_load(parameters: ValidatorParameters) -> SimulatedTestbed {
    let mut committee = SimulatedTestbed::start(parameters).await;
    let generators: Vec<_> = committee
        .validators()
        .iter()
        .map(|validator| validator.start_load_generator(LoadGeneratorConfig::new_for_test()))
        .collect();
    committee.wait_for_transactions(TARGET_TRANSACTIONS).await;
    for generator in &generators {
        SimulatorContext::abort(generator);
    }
    committee.drain().await;
    committee
}

/// The decision latency histograms of `outcome` on either path.
fn latencies(
    validator: &ValidatorHandle<SimulatorContext, FakeExecutor>,
    outcome: &str,
) -> [prometheus::Histogram; 2] {
    [FAST, SLOW].map(|path| {
        validator
            .metrics()
            .checkpoint_certification_latency_s(outcome, path)
    })
}

/// Each validator's count of finalized and skipped checkpoints.
fn decisions(committee: &SimulatedTestbed) -> Vec<(u64, u64)> {
    committee
        .validators()
        .iter()
        .map(|validator| {
            let count = |outcome| {
                let histograms = latencies(validator, outcome);
                histograms.iter().map(|h| h.get_sample_count()).sum()
            };
            (count(FINALIZE), count(SKIP))
        })
        .collect()
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

#[test]
fn skipping_protocols_skip_fragmented_heights_and_finalize_the_rest() {
    let protocols = [
        FinalityProtocol::A,
        FinalityProtocol::B,
        FinalityProtocol::C,
    ];
    for finality in protocols {
        SimulatorExecutor::run(StdRng::seed_from_u64(7), async move {
            let mut committee = generate_load(fragmented(finality)).await;
            committee.wait_for_decided().await;
            let decisions = decisions(&committee);
            // Skipped transactions are never finalized: only finalized heights close end to
            // end.
            for (validator, (finalized, _)) in committee.validators().iter().zip(&decisions) {
                let end_to_end = validator.metrics().end_to_end_latency_s();
                assert_eq!(end_to_end.get_sample_count(), *finalized, "{finality}");
                // C finalizes on the fast path here, and skips only by the commit sequence.
                if finality == FinalityProtocol::C {
                    let [fast, _] = latencies(validator, FINALIZE);
                    assert!(fast.get_sample_count() > 0);
                    let [fast, _] = latencies(validator, SKIP);
                    assert_eq!(fast.get_sample_count(), 0);
                }
            }
            let results = committee.shutdown().await;

            // Decisions follow the commit sequence, proofs included except under C.
            let (_, reference) = &results[0];
            for ((finalized, skipped), (_, certifier)) in decisions.into_iter().zip(&results) {
                let minted = finalized + skipped;
                assert!(
                    minted > FORK_PERIOD,
                    "the run must reach a fragmented height"
                );
                assert_eq!(skipped, minted / FORK_PERIOD, "{finality}");
                assert_eq!(
                    last_decision(finality, certifier),
                    last_decision(finality, reference),
                    "{finality}"
                );
            }
        });
    }
}

#[test]
fn baselines_stall_at_the_first_fragmented_height() {
    for finality in [FinalityProtocol::Baseline, FinalityProtocol::SuiBaseline] {
        SimulatorExecutor::run(StdRng::seed_from_u64(7), async move {
            let committee = generate_load(fragmented(finality)).await;
            let decisions = decisions(&committee);
            let results = committee.shutdown().await;

            for ((finalized, skipped), (_, certifier)) in decisions.into_iter().zip(&results) {
                assert_eq!(skipped, 0, "{finality}");
                // The watermark stops below the first fragmented height for good, and every
                // height from there on stays pending, although the ones without a fork
                // finalized.
                let minted = certifier.pending().count() as u64 + FORK_PERIOD - 1;
                assert!(
                    minted > FORK_PERIOD,
                    "the run must pass a fragmented height"
                );
                assert_eq!(finalized, minted - minted / FORK_PERIOD, "{finality}");
            }
        });
    }
}

/// Each validator's mean checkpoint certification latency, in seconds, over a fork-free run.
fn certification_latencies(finality: FinalityProtocol) -> Vec<f64> {
    SimulatorExecutor::run(StdRng::seed_from_u64(7), async move {
        let parameters = ValidatorParameters {
            finality,
            ..Default::default()
        };
        let mut committee = generate_load(parameters).await;
        committee.wait_for_decided().await;
        let latencies = committee
            .validators()
            .iter()
            .map(|validator| {
                let histograms = latencies(validator, FINALIZE);
                let sum: f64 = histograms.iter().map(|h| h.get_sample_sum()).sum();
                let count: u64 = histograms.iter().map(|h| h.get_sample_count()).sum();
                sum / count as f64
            })
            .collect();
        let results = committee.shutdown().await;

        // Validators see votes arrive in different orders, so proofs may differ, outcomes not.
        let (_, reference) = &results[0];
        let decided = |certifier: &CheckpointCertifier| {
            let decision = certifier.highest_decided().expect("decided checkpoint");
            (decision.anchor(), decision.outcome())
        };
        for (_, certifier) in &results {
            assert_eq!(decided(certifier), decided(reference), "{finality}");
        }
        latencies
    })
}

#[test]
fn the_sui_baseline_decides_on_arrival_ahead_of_the_baseline() {
    let baseline = certification_latencies(FinalityProtocol::Baseline);
    let sui = certification_latencies(FinalityProtocol::SuiBaseline);
    for (sui, baseline) in sui.iter().zip(&baseline) {
        assert!(
            sui < baseline,
            "the Sui-style baseline took {sui} s, the baseline {baseline} s"
        );
    }
}

/// C's fast path waits for one more dissemination step than the Sui-style baseline, where A
/// waits for f+1 votes to commit.
#[test]
fn protocol_c_decides_ahead_of_protocol_a() {
    let a = certification_latencies(FinalityProtocol::A);
    let c = certification_latencies(FinalityProtocol::C);
    for (c, a) in c.iter().zip(&a) {
        assert!(c < a, "C took {c} s, A {a} s");
    }
}

#[test]
fn protocol_c_skips_wait_out_the_phase_one_timeout_deterministically() {
    // Not the default, which the driver would fall back to if the setting never reached it.
    let timeout = Duration::from_secs(2);
    let run = || {
        SimulatorExecutor::run(StdRng::seed_from_u64(7), async move {
            let parameters = ValidatorParameters {
                phase_one_timeout: timeout,
                ..fragmented(FinalityProtocol::C)
            };
            let mut committee = generate_load(parameters).await;
            committee.wait_for_decided().await;
            // Skips decide only after the phase-one timeout: their latencies time it.
            let skips: Vec<_> = committee
                .validators()
                .iter()
                .map(|validator| {
                    let [_, slow] = latencies(validator, SKIP);
                    (slow.get_sample_count(), slow.get_sample_sum())
                })
                .collect();
            let results = committee.shutdown().await;
            (skips, results.into_iter().map(|(_, certifier)| certifier))
        })
    };
    let (first_skips, first) = run();
    // Other validators' timeouts start at their own mints, so a skip can decide a little under
    // one timeout after this validator's; committing the certificates more than makes up for
    // it on average.
    for &(count, sum) in &first_skips {
        assert!(count > 0);
        let mean = sum / count as f64;
        assert!(
            mean >= timeout.as_secs_f64(),
            "skips took {mean} s on average"
        );
    }
    let (second_skips, second) = run();
    assert_eq!(first_skips, second_skips);
    for (a, b) in first.zip(second) {
        assert_eq!(a.highest_decided(), b.highest_decided());
    }
}
