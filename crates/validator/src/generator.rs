// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A deterministic load generator, mirroring mysticeti's `replica::generator` — same pacing,
//! seeding, clock caching, and block chunking (by framed bytes, capped at
//! [`CLIENT_BATCH_BYTES`]) — but emitting valid [`FakeTransaction`] payloads in timestamped
//! [`Envelope`]s, so everything downstream of commit (execution, checkpoints, certification)
//! fires.

use std::{sync::Arc, time::Duration};

use dag::{
    authority::Authority, block::transaction::Transaction as ConsensusTransaction,
    config::ImportExport, context::Ctx,
};
use execution::{fake::FakeTransaction, object::ObjectId};
use rand::{Rng, SeedableRng, rngs::StdRng};
use replica::client::TransactionClient;
use serde::{Deserialize, Serialize};

use crate::{
    envelope::{Envelope, MAX_PAYLOAD_SIZE, Payload},
    limits::{CLIENT_BATCH_BYTES, split_batch},
    metrics::ValidatorMetrics,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct LoadGeneratorConfig {
    /// Transactions to submit per second.
    #[serde(default = "load_generator_defaults::default_load")]
    pub load: usize,
    /// Serialized envelope size per transaction, in bytes.
    #[serde(default = "load_generator_defaults::default_transaction_size")]
    pub transaction_size: usize,
    /// Delay before the first submission.
    /// Accepts humantime strings in YAML (e.g. `"0s"`, `"500ms"`, `"30s"`).
    #[serde(default = "load_generator_defaults::default_initial_delay")]
    #[serde(with = "humantime_serde")]
    pub initial_delay: Duration,
}

impl LoadGeneratorConfig {
    pub const DEFAULT_FILENAME: &'static str = "load-generator-config.yaml";

    pub fn new_for_test() -> Self {
        Self {
            load: 100,
            transaction_size: 128,
            initial_delay: Duration::ZERO,
        }
    }
}

impl Default for LoadGeneratorConfig {
    fn default() -> Self {
        Self {
            load: load_generator_defaults::default_load(),
            transaction_size: load_generator_defaults::default_transaction_size(),
            initial_delay: load_generator_defaults::default_initial_delay(),
        }
    }
}

impl ImportExport for LoadGeneratorConfig {}

mod load_generator_defaults {
    use std::time::Duration;

    pub fn default_load() -> usize {
        10
    }

    pub fn default_transaction_size() -> usize {
        512
    }

    pub fn default_initial_delay() -> Duration {
        Duration::from_secs(30)
    }
}

pub struct TransactionGenerator {
    client: TransactionClient,
    /// Where batches close: the replica's block-size cap or [`CLIENT_BATCH_BYTES`].
    batch_cap: u64,
    metrics: Arc<ValidatorMetrics>,
}

impl TransactionGenerator {
    const TARGET_BLOCK_INTERVAL: Duration = Duration::from_millis(100);
    /// Object-id split: authority in the top 8 bits, the random stream in the low 56, so
    /// streams from different authorities can never collide.
    const AUTHORITY_SHIFT: u32 = 56;
    const RANDOM_MASK: u64 = (1 << Self::AUTHORITY_SHIFT) - 1;

    /// Starts generating `config`'s load; `max_transaction_size` is the validator's
    /// proposal-size ceiling on client transactions.
    pub fn start<C: Ctx>(
        client: TransactionClient,
        seed: Authority,
        config: LoadGeneratorConfig,
        max_block_size: usize,
        max_transaction_size: u64,
        metrics: Arc<ValidatorMetrics>,
    ) -> C::JoinHandle<()> {
        assert!(config.load > 0, "load must be positive");
        // Envelope overhead is invariant across ids and timestamps, so padding the arguments
        // by the probed difference makes every serialized envelope exactly `transaction_size`
        // bytes — the analog of upstream's fixed raw payload size.
        let overhead = Self::transaction(0, ObjectId::new(0), Vec::new())
            .to_bytes()
            .len();
        assert!(
            config.transaction_size > overhead,
            "transaction_size must be greater than {overhead} bytes"
        );
        // Oversized envelopes fail to decode after commit and are silently skipped, so the
        // generator would exercise nothing downstream.
        assert!(
            config.transaction_size as u64 <= MAX_PAYLOAD_SIZE,
            "transaction_size must not exceed the {MAX_PAYLOAD_SIZE}-byte payload cap"
        );
        assert!(
            config.transaction_size as u64 <= max_transaction_size,
            "transaction_size must not exceed {max_transaction_size} bytes, or proposals could \
                outgrow the proposal budget"
        );
        let args_len = config.transaction_size - overhead;
        tracing::info!(
            "Starting generator with {} transactions per second, initial delay {:?}",
            config.load,
            config.initial_delay
        );
        let mut rng = StdRng::seed_from_u64(seed.as_u64());
        let random = rng.r#gen();
        C::spawn(
            Self {
                client,
                batch_cap: (max_block_size as u64).min(CLIENT_BATCH_BYTES),
                metrics,
            }
            .run::<C>(config, seed.as_u64(), args_len, random),
        )
    }

    /// One creation of a fresh object, padded with `args` and stamped into an envelope.
    fn transaction(timestamp_ms: u64, id: ObjectId, args: Vec<u8>) -> Envelope {
        let transaction = FakeTransaction::success_with_args(vec![], vec![id], vec![], args);
        Envelope::new(timestamp_ms, Payload::Execute(transaction.into()))
    }

    fn fill_batch(
        timestamp_ms: u64,
        transactions_per_interval: usize,
        args_len: usize,
        namespace: u64,
        counter: &mut u64,
        random: &mut u64,
    ) -> Vec<ConsensusTransaction> {
        let mut batch = Vec::with_capacity(transactions_per_interval);
        for _ in 0..transactions_per_interval {
            // Upstream's stream, wrapping: the initial `random` is uniform over `u64`, so a
            // checked add could overflow.
            *random = random.wrapping_add(*counter);
            *counter += 1;
            let id =
                ObjectId::new((namespace << Self::AUTHORITY_SHIFT) | (*random & Self::RANDOM_MASK));
            let envelope = Self::transaction(timestamp_ms, id, vec![0; args_len]);
            batch.push(ConsensusTransaction::new(envelope.to_bytes().into()));
        }
        batch
    }

    async fn ship_blocks(&self, batch: Vec<ConsensusTransaction>) -> bool {
        for block in split_batch(batch, self.batch_cap) {
            if self.client.submit(block).await.is_err() {
                return false;
            }
        }
        true
    }

    async fn run<C: Ctx>(
        self,
        config: LoadGeneratorConfig,
        namespace: u64,
        args_len: usize,
        mut random: u64,
    ) {
        let intervals_per_second = 1000 / Self::TARGET_BLOCK_INTERVAL.as_millis() as usize;
        let transactions_per_interval = config.load.div_ceil(intervals_per_second);

        let mut counter = 0u64;

        // Cache the context clock at startup and derive subsequent timestamps from a
        // monotonic instant, avoiding repeated clock reads in the hot loop. Works uniformly
        // under the real and the simulated clock.
        let base_system_time = C::timestamp_utc();
        let base_instant = C::now();

        // Under tokio missed ticks are skipped (no catch-up burst after the initial delay);
        // under the simulator the interval degrades to a fixed sleep between batches. Neither
        // backend bursts, though `div_ceil` rounds the effective rate up to the next multiple
        // of `intervals_per_second`, as upstream does.
        let mut interval = C::interval(Self::TARGET_BLOCK_INTERVAL);
        C::sleep(config.initial_delay).await;
        loop {
            C::interval_tick(&mut interval).await;
            let timestamp_ms = (base_system_time + C::elapsed(&base_instant)).as_millis() as u64;

            // Structured envelopes must be serialized per transaction, so the per-tick
            // allocations of upstream's reused flat buffer cannot be avoided here.
            let batch = Self::fill_batch(
                timestamp_ms,
                transactions_per_interval,
                args_len,
                namespace,
                &mut counter,
                &mut random,
            );

            if !self.ship_blocks(batch).await {
                tracing::info!("Transaction channel closed, stopping generator");
                return;
            }

            // Reported per tick, diverging from upstream's amortized flush: a counter must
            // not under-report, and ten atomic adds per second cost nothing.
            self.metrics
                .inc_submitted_transactions(transactions_per_interval as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use dag::crypto::AsBytes;
    use execution::transaction::AccessMode;

    use super::*;

    const TRANSACTION_SIZE: usize = 128;

    fn batch(seed: u64, namespace: u64, count: usize) -> Vec<ConsensusTransaction> {
        let overhead = TransactionGenerator::transaction(0, ObjectId::new(0), Vec::new())
            .to_bytes()
            .len();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut random = rng.r#gen();
        let mut counter = 0;
        TransactionGenerator::fill_batch(
            1234,
            count,
            TRANSACTION_SIZE - overhead,
            namespace,
            &mut counter,
            &mut random,
        )
    }

    #[test]
    fn payloads_decode_to_creations_of_exact_size() {
        for transaction in batch(1, 1, 10) {
            let bytes = transaction.as_bytes();
            assert_eq!(bytes.len(), TRANSACTION_SIZE);
            let envelope = Envelope::from_bytes(bytes).unwrap();
            assert_eq!(envelope.timestamp_ms(), 1234);
            let Payload::Execute(transaction) = envelope.into_payload() else {
                panic!("expected an execution payload");
            };
            assert!(matches!(transaction.inputs(), [(_, AccessMode::WriteOnly)]));
        }
    }

    /// Identical random streams under different namespaces stay disjoint: exactly the
    /// namespacing guarantee, since without the authority bits every id would collide.
    #[test]
    fn namespaces_separate_identical_random_streams() {
        let ids = |batch: Vec<ConsensusTransaction>| -> Vec<ObjectId> {
            batch
                .iter()
                .map(|transaction| {
                    let envelope = Envelope::from_bytes(transaction.as_bytes()).unwrap();
                    let Payload::Execute(transaction) = envelope.into_payload() else {
                        panic!("expected an execution payload");
                    };
                    transaction.inputs()[0].0
                })
                .collect()
        };
        let (first, other) = (ids(batch(1, 1, 100)), ids(batch(1, 2, 100)));
        assert!(first.iter().all(|id| !other.contains(id)));
    }

    #[test]
    fn config_roundtrips_through_yaml_files() {
        let config = LoadGeneratorConfig {
            load: 250,
            transaction_size: 256,
            initial_delay: Duration::from_secs(5),
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        config.print(file.path()).unwrap();
        // Hand-edited and orchestrator-uploaded configs rely on the humantime disk format.
        let written = std::fs::read_to_string(file.path()).unwrap();
        assert!(written.contains("initial_delay: 5s"), "{written}");
        let loaded = LoadGeneratorConfig::load(file.path()).unwrap();
        assert_eq!(loaded.load, config.load);
        assert_eq!(loaded.transaction_size, config.transaction_size);
        assert_eq!(loaded.initial_delay, config.initial_delay);
    }

    #[test]
    fn config_fills_defaults_and_parses_humantime_delays() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "initial_delay: 30s\n").unwrap();
        let loaded = LoadGeneratorConfig::load(file.path()).unwrap();
        assert_eq!(loaded.load, LoadGeneratorConfig::default().load);
        assert_eq!(
            loaded.transaction_size,
            LoadGeneratorConfig::default().transaction_size
        );
        assert_eq!(loaded.initial_delay, Duration::from_secs(30));
    }
}
