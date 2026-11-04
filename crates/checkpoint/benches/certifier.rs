// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks the certifier's hot paths: minting pending checkpoints and tallying votes.

use checkpoint::{
    certifier::{CheckpointCertifier, CheckpointTimings},
    checkpoint::Checkpoint,
    finality::FinalityProtocol,
};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use dag::{block::BlockReference, committee::Committee};

/// The pending window each benchmark works through.
const CHECKPOINTS: u64 = 100;
const COMMITTEE_SIZE: usize = 4;
/// Quorum for [`COMMITTEE_SIZE`] unit-stake validators: 2f + 1.
const QUORUM: u64 = 3;

/// Mints [`CHECKPOINTS`] checkpoints into a fresh certifier.
fn mint(c: &mut Criterion) {
    let mut group = c.benchmark_group("certifier");
    group.throughput(Throughput::Elements(CHECKPOINTS));
    group.bench_function("mint", |b| {
        b.iter_batched(
            || {
                let committee = Committee::new_test(vec![1; COMMITTEE_SIZE]);
                CheckpointCertifier::new(committee, FinalityProtocol::Baseline, QUORUM)
            },
            |mut certifier| {
                for n in 1..=CHECKPOINTS {
                    let checkpoint = Checkpoint::new_for_test(n);
                    certifier.push(
                        checkpoint.anchor(),
                        checkpoint.commitment(),
                        CheckpointTimings::default(),
                    );
                }
                certifier
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

/// Records a quorum of votes for each of [`CHECKPOINTS`] pending checkpoints, in commit order,
/// driving the full path: accumulate stake, certify, advance the watermark, prune the window.
fn certify(c: &mut Criterion) {
    let mut group = c.benchmark_group("certifier");
    group.throughput(Throughput::Elements(CHECKPOINTS * QUORUM));
    group.bench_function("certify", |b| {
        b.iter_batched(
            || {
                let stake = vec![1; COMMITTEE_SIZE];
                CheckpointCertifier::new_for_test(
                    FinalityProtocol::Baseline,
                    stake,
                    QUORUM,
                    CHECKPOINTS,
                )
            },
            |mut certifier| {
                for n in 1..=CHECKPOINTS {
                    // The blocks carrying the votes commit after the checkpointed sub-dags.
                    for authority in 0..QUORUM {
                        let block = BlockReference::new_test(authority, CHECKPOINTS + n);
                        certifier.record(block, Checkpoint::new_for_test(n));
                    }
                }
                let decided = certifier.highest_decided();
                assert!(decided.is_some_and(|decided| decided.round() == CHECKPOINTS));
                certifier
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, mint, certify);
criterion_main!(benches);
