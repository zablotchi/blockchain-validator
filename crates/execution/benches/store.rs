// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks the store's write path with the undo journal off and on, and undoing those writes.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use execution::{
    effects::ExecutionOutput,
    object::{Object, ObjectId, Version},
    store::InMemoryStore,
};

/// Writes per iteration, one fresh object per transaction, as the load generator's.
const WRITES: u64 = 1_000;
/// Object sizes: 512 bytes, and the 4 bytes of the fake engine's created objects (the AWS
/// workload's).
const OBJECT_BYTES: [usize; 2] = [512, 4];

fn outputs(bytes: usize) -> Vec<ExecutionOutput> {
    (0..WRITES)
        .map(|i| {
            let object = Object::new(ObjectId::new(i), Version::new(1), vec![i as u8; bytes]);
            ExecutionOutput::success(vec![object])
        })
        .collect()
}

/// A fresh store, with one open height if `journal`.
fn store(journal: bool) -> InMemoryStore {
    let mut store = InMemoryStore::default();
    if journal {
        store.enable_journal(1);
        store.begin_height(1);
    }
    store
}

/// Applies [`WRITES`] writes to a fresh store, with the journal off and on.
fn apply(c: &mut Criterion) {
    let mut group = c.benchmark_group("store");
    group.throughput(Throughput::Elements(WRITES));
    for bytes in OBJECT_BYTES {
        for (name, journal) in [("apply", false), ("apply_with_journal", true)] {
            group.bench_with_input(BenchmarkId::new(name, bytes), &bytes, |b, &bytes| {
                b.iter_batched(
                    || (store(journal), outputs(bytes)),
                    |(mut store, outputs)| {
                        for output in outputs {
                            store.apply(output);
                        }
                        store
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

/// Undoes a height of [`WRITES`] writes of 512-byte objects.
fn undo(c: &mut Criterion) {
    let mut group = c.benchmark_group("store");
    group.throughput(Throughput::Elements(WRITES));
    group.bench_function("undo", |b| {
        b.iter_batched(
            || {
                let mut store = store(true);
                for output in outputs(OBJECT_BYTES[0]) {
                    store.apply(output);
                }
                store
            },
            |mut store| {
                store.undo_from(1);
                store
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, apply, undo);
criterion_main!(benches);
