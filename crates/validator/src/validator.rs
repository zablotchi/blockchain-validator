// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator node: a mysticeti replica wired to an execution engine.

use std::{path::PathBuf, sync::Arc, time::Duration};

use checkpoint::{
    certifier::{CheckpointCertifier, CheckpointTimings},
    checkpoint::Checkpoint,
};
use dag::{
    authority::Authority, block::transaction::Transaction as ConsensusTransaction,
    consensus::CommittedSubDag, context::Ctx, crypto::AsBytes, metrics::Metrics, storage::Storage,
    sync::network::Network,
};
use execution::{
    crypto::Digest, engine::ExecutionEngine, scheduler::SequentialScheduler,
    transaction::Transaction,
};
use prometheus::Registry;
use replica::{
    builder::{ReplicaBuilder, StorageKind},
    config::{PrivateReplicaConfig, PublicReplicaConfig},
    replica::{Replica, ReplicaHandle},
};
use tokio::sync::{mpsc, watch};

#[cfg(any(test, feature = "benchmark"))]
use crate::generator::{LoadGeneratorConfig, TransactionGenerator};
use crate::{
    envelope::{Envelope, Payload},
    metrics::ValidatorMetrics,
};

/// Capacity of the commit stream; a bounded channel is mandatory — a slow consumer must
/// backpressure the replica rather than drop or reorder commits.
const COMMIT_CHANNEL_CAPACITY: usize = 1024;

/// Builds a [`Validator`], delegating replica options to the underlying [`ReplicaBuilder`].
///
/// Under the simulator, `with_network` and `with_metrics` are mandatory: the replica defaults
/// bind real TCP and spawn onto the tokio runtime, neither of which exists there.
pub struct ValidatorBuilder<E> {
    engine: E,
    authority: Authority,
    public_config: PublicReplicaConfig,
    /// The consensus WAL to replay on start; `None` for ephemeral storage.
    wal: Option<PathBuf>,
    registry: Registry,
    replica: ReplicaBuilder,
}

impl<E: ExecutionEngine + Send + 'static> ValidatorBuilder<E> {
    pub fn new(
        engine: E,
        authority: Authority,
        public_config: PublicReplicaConfig,
        private_config: PrivateReplicaConfig,
    ) -> Self {
        Self {
            engine,
            authority,
            public_config: public_config.clone(),
            // The replica defaults to WAL storage at this path when `with_storage` is not called.
            wal: Some(private_config.wal()),
            registry: Registry::new(),
            replica: ReplicaBuilder::new(authority, public_config, private_config),
        }
    }

    /// Share one Prometheus registry between the replica's and the validator's metrics.
    pub fn with_registry(mut self, registry: Registry) -> Self {
        self.registry = registry.clone();
        self.replica = self.replica.with_registry(registry);
        self
    }

    pub fn with_storage(mut self, storage: StorageKind) -> Self {
        self.wal = match &storage {
            StorageKind::Wal(path) => Some(path.clone()),
            StorageKind::Ephemeral => None,
        };
        self.replica = self.replica.with_storage(storage);
        self
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.replica = self.replica.with_network(network);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.replica = self.replica.with_metrics(metrics);
        self
    }

    pub fn with_simulated_crypto(mut self) -> Self {
        self.replica = self.replica.with_simulated_crypto();
        self
    }

    /// Assembles the validator: builds the scheduler, the certifier, and the replica with its
    /// commit consumer. No I/O happens until [`Validator::start`].
    pub fn build(self) -> eyre::Result<Validator<E>> {
        let (sender, receiver) = mpsc::channel(COMMIT_CHANNEL_CAPACITY);
        let committee = self.public_config.committee();
        let protocol = self
            .public_config
            .parameters
            .consensus
            .to_protocol(&committee)?;
        let certifier = CheckpointCertifier::new(committee, protocol.quorum_threshold);
        Ok(Validator {
            state: ExecutionState {
                scheduler: SequentialScheduler::new(self.engine),
                certifier,
            },
            authority: self.authority,
            public_config: self.public_config,
            wal: self.wal,
            metrics: ValidatorMetrics::new(&self.registry),
            replica: self.replica.with_commit_consumer(sender).build(),
            receiver,
        })
    }
}

/// A fully configured validator, ready to [`start`](Validator::start).
pub struct Validator<E> {
    state: ExecutionState<E>,
    authority: Authority,
    public_config: PublicReplicaConfig,
    wal: Option<PathBuf>,
    metrics: Arc<ValidatorMetrics>,
    replica: Replica,
    receiver: mpsc::Receiver<CommittedSubDag>,
}

/// The execution half of a validator — the scheduler and the certifier fed by the commit
/// stream — owned by the driver task once started.
struct ExecutionState<E> {
    scheduler: SequentialScheduler<E>,
    certifier: CheckpointCertifier,
}

impl<E: ExecutionEngine + Send + 'static> Validator<E> {
    /// Replays the consensus WAL (if any) to rebuild execution state, then starts the replica
    /// and the driver task feeding its committed transactions, in commit order, to the
    /// scheduler. The live stream never re-emits recovered commits, so replay and stream
    /// compose without overlap.
    pub async fn start<C: Ctx>(mut self) -> eyre::Result<ValidatorHandle<C, E>> {
        let replayed = self.replay()?;
        let max_block_size = self.public_config.parameters.dag.max_block_size;
        let Self {
            mut state,
            replica,
            mut receiver,
            metrics,
            ..
        } = self;

        let replica = replica.run::<C>().await?;
        let client = replica.transaction_client();
        let (executed_sender, executed) = watch::channel(replayed);
        let (certified_sender, certified) = watch::channel(state.certification_status());
        let driver_metrics = metrics.clone();
        let driver = C::spawn(async move {
            // Re-attest checkpoints uncertified at replay: votes in flight at shutdown died
            // with the transaction queue, and a validator otherwise attests only once, so an
            // uncertified checkpoint could stall forever. The certifier's per-author dedupe
            // makes resubmission idempotent — votes that did commit are simply ignored.
            let pending: Vec<_> = state.certifier.pending().cloned().collect();
            if !pending.is_empty() {
                let timestamp_ms = C::timestamp_utc().as_millis() as u64;
                let attestations = pending
                    .into_iter()
                    .map(|checkpoint| Self::attestation(timestamp_ms, checkpoint))
                    .collect();
                if client.submit(attestations).await.is_err() {
                    tracing::debug!("re-attestation failed; shutting down");
                }
            }

            let mut count = replayed;
            while let Some(subdag) = receiver.recv().await {
                // The clock starts at delivery (idle waiting is not latency) and stops after
                // execution, checkpoint minting, and vote recording.
                let start = C::now();
                let now = C::timestamp_utc();
                let (executed, minted) = state.execute_subdag(&driver_metrics, now, subdag);
                driver_metrics.observe_subdag_execution_latency(C::elapsed(&start));
                count += executed as u64;
                let _ = executed_sender.send(count);
                let _ = certified_sender.send(state.certification_status());
                // Attest to the minted checkpoint through consensus: the vote rides this
                // validator's own signed blocks. Failure is benign — the replica is shutting
                // down, and lost votes are resubmitted after replay.
                if let Some(checkpoint) = minted {
                    let attestation = Self::attestation(now.as_millis() as u64, checkpoint);
                    if client.submit(vec![attestation]).await.is_err() {
                        tracing::debug!("attestation submission failed; shutting down");
                    }
                }
            }
            (state.scheduler, state.certifier)
        });

        Ok(ValidatorHandle {
            replica,
            driver,
            executed,
            certified,
            metrics,
            max_block_size,
        })
    }

    /// Rebuilds execution state by replaying the WAL's committed sub-dags through the
    /// scheduler, exactly as the live stream delivered them. The storage handle only reads and
    /// is dropped before the replica re-opens the WAL (there is no file locking).
    fn replay(&mut self) -> eyre::Result<u64> {
        let Some(wal) = &self.wal else {
            return Ok(0);
        };
        let committee = self.public_config.committee();
        // Isolated metrics, discarded with these handles: replay records nothing.
        let metrics = Metrics::new_for_test(committee.len());
        let replay_metrics = ValidatorMetrics::new(&Registry::new());
        let (storage, _recovered) = Storage::open(self.authority, wal, metrics, &committee)?;

        let mut replayed = 0;
        for commit in storage.iter_commits() {
            let blocks = commit
                .sub_dag
                .iter()
                .map(|reference| {
                    storage.block_reader().get_block(*reference).ok_or_else(|| {
                        eyre::eyre!("committed block {reference} missing from the WAL")
                    })
                })
                .collect::<eyre::Result<_>>()?;
            let subdag = CommittedSubDag::new(commit.leader, blocks);
            // The minted checkpoint is dropped: replay never submits votes.
            let (executed, _) = self
                .state
                .execute_subdag(&replay_metrics, Duration::ZERO, subdag);
            replayed += executed as u64;
        }
        Ok(replayed)
    }

    /// Wraps a checkpoint as this validator's timestamped attestation payload.
    fn attestation(timestamp_ms: u64, checkpoint: Checkpoint) -> ConsensusTransaction {
        let envelope = Envelope::new(timestamp_ms, Payload::Attest(checkpoint));
        ConsensusTransaction::new(envelope.to_bytes().into())
    }
}

impl<E: ExecutionEngine> ExecutionState<E> {
    /// Executes every transaction of a committed sub-dag in canonical order, dispatches its
    /// checkpoint votes to the certifier, and returns how many transactions were executed
    /// together with the checkpoint this sub-dag minted, if any. Undecodable payloads are
    /// skipped; the choice is deterministic. Sub-dags that execute nothing are not
    /// checkpointed: their commitment is unchanged, and their count varies across validators
    /// at any executed-transaction cut. `now` stamps the mint and closes the latency metrics
    /// of checkpoints certified by this sub-dag's votes.
    fn execute_subdag(
        &mut self,
        metrics: &ValidatorMetrics,
        now: Duration,
        mut subdag: CommittedSubDag,
    ) -> (usize, Option<Checkpoint>) {
        let anchor = subdag.anchor;
        subdag.sort();
        // Votes are attributed to the block author: they ride their author's own signed
        // blocks, so no authority can forge another's vote.
        let mut votes = Vec::new();
        // Submission stamps reduce to their sum here, while the payloads are in hand.
        let mut stamp_sum_ms = 0u64;
        let transactions = subdag
            .blocks
            .iter()
            .flat_map(|block| {
                let author = block.author();
                block
                    .transactions()
                    .iter()
                    .map(move |payload| (author, payload))
            })
            .filter_map(|(author, payload)| {
                let envelope = Envelope::from_bytes(payload.as_bytes())
                    .inspect_err(|error| tracing::warn!(?error, "skipping undecodable payload"))
                    .ok()?;
                let stamp_ms = envelope.timestamp_ms();
                match envelope.into_payload() {
                    Payload::Execute(transaction) => {
                        stamp_sum_ms += stamp_ms;
                        Some(transaction)
                    }
                    Payload::Attest(vote) => {
                        votes.push((author, vote));
                        None
                    }
                }
            });
        let executed = self.scheduler.execute(transactions).len();
        let minted = (executed > 0).then(|| {
            let timings = CheckpointTimings {
                minted_at: now,
                mean_timestamp_ms: stamp_sum_ms / executed as u64,
            };
            self.certifier
                .push(anchor, self.scheduler.store().commitment(), timings)
                .clone()
        });
        // A vote can never reference its own delivering sub-dag's checkpoint (it is created
        // only after that sub-dag commits), so recording after minting loses nothing.
        for (author, vote) in votes {
            if let Some(timings) = self.certifier.record(anchor, author, vote) {
                metrics.observe_checkpoint_certification_latency(
                    now.saturating_sub(timings.minted_at),
                );
                let submitted = Duration::from_millis(timings.mean_timestamp_ms);
                metrics.observe_end_to_end_latency(now.saturating_sub(submitted));
            }
        }
        (executed, minted)
    }

    /// The pair consumed by [`ValidatorHandle::wait_for_certified`]: the highest certified
    /// commitment beside the store commitment at the same instant.
    fn certification_status(&self) -> (Option<Digest>, Digest) {
        let certified = self
            .certifier
            .highest_certified()
            .map(|certificate| certificate.checkpoint().commitment());
        (certified, self.scheduler.store().commitment())
    }
}

/// A handle to a running validator: a consensus replica whose committed transactions are
/// executed by an [`ExecutionEngine`] through a [`SequentialScheduler`].
///
/// The driver task owns the scheduler and every task is spawned through [`Ctx`], so the whole
/// node runs unchanged under tokio and under the mysticeti simulator.
pub struct ValidatorHandle<C: Ctx, E: ExecutionEngine + Send + 'static> {
    replica: ReplicaHandle<C>,
    driver: C::JoinHandle<(SequentialScheduler<E>, CheckpointCertifier)>,
    executed: watch::Receiver<u64>,
    certified: watch::Receiver<(Option<Digest>, Digest)>,
    metrics: Arc<ValidatorMetrics>,
    max_block_size: usize,
}

impl<C: Ctx, E: ExecutionEngine + Send + 'static> ValidatorHandle<C, E> {
    /// Submits transactions to the replica; resolves once they are queued for inclusion in a
    /// block, not once they are committed or executed. Every payload is stamped with the
    /// submission time (one clock read per batch), from which mysticeti derives its
    /// commit-latency metric.
    pub async fn submit(&self, transactions: Vec<Transaction>) -> eyre::Result<()> {
        let timestamp_ms = C::timestamp_utc().as_millis() as u64;
        let transactions = transactions
            .into_iter()
            .map(|transaction| {
                let envelope = Envelope::new(timestamp_ms, Payload::Execute(transaction));
                ConsensusTransaction::new(envelope.to_bytes().into())
            })
            .collect();
        self.replica.submit(transactions).await
    }

    /// The validator's metrics.
    pub fn metrics(&self) -> &Arc<ValidatorMetrics> {
        &self.metrics
    }

    /// The replica's block-size cap, which bounds every submitted batch.
    pub fn max_block_size(&self) -> usize {
        self.max_block_size
    }

    /// The number of transactions executed so far.
    pub fn executed(&self) -> u64 {
        *self.executed.borrow()
    }

    /// Starts the built-in load generator; its transactions share the replica's submission
    /// channel with [`submit`](ValidatorHandle::submit). Stop it with [`Ctx::abort`].
    #[cfg(any(test, feature = "benchmark"))]
    pub fn start_load_generator(&self, config: LoadGeneratorConfig) -> C::JoinHandle<()> {
        TransactionGenerator::start::<C>(
            self.replica.transaction_client(),
            self.replica.authority(),
            config,
            self.max_block_size,
            self.metrics.clone(),
        )
    }

    /// Waits until at least `count` transactions have been executed. Returns early if the
    /// driver has stopped.
    pub async fn wait_for_transactions(&mut self, count: u64) {
        while *self.executed.borrow_and_update() < count {
            if self.executed.changed().await.is_err() {
                return;
            }
        }
    }

    /// Waits until everything executed is certified: the highest certified commitment equals
    /// the store commitment. Equality is transient while submissions are in flight, so this is
    /// meaningful after an executed-count cut ([`wait_for_transactions`]
    /// (ValidatorHandle::wait_for_transactions) first). Returns early if the driver has
    /// stopped.
    pub async fn wait_for_certified(&mut self) {
        loop {
            let (certified, store) = *self.certified.borrow_and_update();
            if certified == Some(store) {
                return;
            }
            if self.certified.changed().await.is_err() {
                return;
            }
        }
    }

    /// Resolves when the replica crashes or stops; long-running deployments select on this.
    /// The driver task is detached and dies with the process.
    pub async fn await_completion(self) -> eyre::Result<()> {
        self.replica.await_completion().await
    }

    /// Stops the replica, waits for the driver to drain the remaining commits, and returns the
    /// scheduler with the executed state and the checkpoint certifier.
    pub async fn shutdown(self) -> (SequentialScheduler<E>, CheckpointCertifier) {
        // The returned syncer holds the consensus storage; the WAL outlives it on disk, which
        // is what replay on the next start relies on.
        let _syncer = self.replica.shutdown().await;
        self.driver.await.expect("driver task failed")
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use checkpoint::certifier::CheckpointCertifier;
    use dag::{
        authority::Authority,
        block::{Block, data::Data, transaction::Transaction as ConsensusTransaction},
        consensus::CommittedSubDag,
        crypto::CryptoEngine,
    };
    use execution::{
        fake::{FakeExecutor, FakeTransaction},
        object::ObjectId,
        scheduler::SequentialScheduler,
    };
    use prometheus::Registry;

    use crate::{
        envelope::{Envelope, Payload},
        metrics::ValidatorMetrics,
        validator::ExecutionState,
    };

    fn state() -> ExecutionState<FakeExecutor> {
        ExecutionState {
            scheduler: SequentialScheduler::new(FakeExecutor),
            certifier: CheckpointCertifier::new_for_test(vec![1; 4], 3, 0),
        }
    }

    fn metrics() -> Arc<ValidatorMetrics> {
        ValidatorMetrics::new(&Registry::new())
    }

    /// A sub-dag at `round` with one block per `(author, payloads)` entry, anchored at the
    /// first block.
    fn subdag_at(round: u64, blocks: Vec<(usize, Vec<Vec<u8>>)>) -> CommittedSubDag {
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|(author, payloads)| {
                let transactions = payloads
                    .into_iter()
                    .map(|bytes| ConsensusTransaction::new(bytes.into()))
                    .collect();
                let block = Block::new(
                    Authority::from(author),
                    round,
                    vec![],
                    transactions,
                    0,
                    &CryptoEngine::disabled(),
                );
                Data::new(block)
            })
            .collect();
        CommittedSubDag::new(*blocks[0].reference(), blocks)
    }

    /// A single-block sub-dag carrying the given raw payloads.
    fn subdag(payloads: Vec<Vec<u8>>) -> CommittedSubDag {
        subdag_at(1, vec![(0, payloads)])
    }

    #[test]
    fn undecodable_payloads_are_skipped() {
        let mut state = state();
        let transaction = FakeTransaction::success(vec![], vec![ObjectId::new(1)], vec![]);
        let valid = Envelope::new(0, Payload::Execute(transaction.into())).to_bytes();

        let (executed, minted) = state.execute_subdag(
            &metrics(),
            Duration::ZERO,
            subdag(vec![vec![0xFF; 16], valid]),
        );

        assert_eq!(executed, 1);
        assert!(minted.is_some());
        assert_eq!(state.certifier.pending().count(), 1);
    }

    #[test]
    fn subdags_with_only_undecodable_payloads_mint_no_checkpoint() {
        let mut state = state();

        let (executed, minted) =
            state.execute_subdag(&metrics(), Duration::ZERO, subdag(vec![vec![0xFF; 16]]));

        assert_eq!(executed, 0);
        assert!(minted.is_none());
        assert_eq!(state.certifier.pending().count(), 0);
    }

    #[test]
    fn a_quorum_of_attestations_certifies_and_mints_nothing() {
        let mut state = state();
        let metrics = metrics();
        // Two transactions with distinct stamps pin the mean reduction: (1000 + 3000) / 2.
        let executes = [1, 2]
            .map(ObjectId::new)
            .into_iter()
            .zip([1000, 3000])
            .map(|(id, stamp_ms)| {
                let transaction = FakeTransaction::success(vec![], vec![id], vec![]);
                Envelope::new(stamp_ms, Payload::Execute(transaction.into())).to_bytes()
            })
            .collect();
        let (_, minted) = state.execute_subdag(&metrics, Duration::from_secs(1), subdag(executes));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // A quorum of votes delivered in a later sub-dag, one block per author.
        let votes = (0..3)
            .map(|author| {
                let vote = Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes();
                (author, vec![vote])
            })
            .collect();
        let delivering = subdag_at(2, votes);
        let anchor = delivering.anchor;
        let (executed, minted) = state.execute_subdag(&metrics, Duration::from_secs(4), delivering);

        assert_eq!(executed, 0);
        assert!(minted.is_none());
        let certified = state
            .certifier
            .highest_certified()
            .expect("quorum must certify");
        assert_eq!(certified.checkpoint(), &checkpoint);
        // The proof records the delivering sub-dag's anchor per counted vote.
        assert_eq!(certified.proof(), [anchor; 3]);
        assert!(state.certifier.pending().next().is_none());
        // Certification closed the latency metrics: minted at 1s and certified at 4s, with a
        // mean submission stamp of 2s.
        let certification = metrics.checkpoint_certification_latency_s();
        assert_eq!(certification.get_sample_count(), 1);
        assert_eq!(certification.get_sample_sum(), 3.0);
        let end_to_end = metrics.end_to_end_latency_s();
        assert_eq!(end_to_end.get_sample_count(), 1);
        assert_eq!(end_to_end.get_sample_sum(), 2.0);
    }

    #[test]
    fn mixed_subdags_execute_mint_and_certify_together() {
        let mut state = state();
        let metrics = metrics();
        let create = FakeTransaction::success(vec![], vec![ObjectId::new(1)], vec![]);
        let execute = Envelope::new(0, Payload::Execute(create.into())).to_bytes();
        let (_, minted) = state.execute_subdag(&metrics, Duration::ZERO, subdag(vec![execute]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // Votes for the first checkpoint share the sub-dag with a fresh transaction; the vote
        // stamps must stay out of the new checkpoint's mean.
        let vote = || Envelope::new(7777, Payload::Attest(checkpoint.clone())).to_bytes();
        let update = FakeTransaction::success(vec![], vec![], vec![ObjectId::new(1)]);
        let update = Envelope::new(500, Payload::Execute(update.into())).to_bytes();
        let blocks = vec![
            (0, vec![vote(), update]),
            (1, vec![vote()]),
            (2, vec![vote()]),
        ];
        let (executed, minted) =
            state.execute_subdag(&metrics, Duration::from_secs(2), subdag_at(2, blocks));

        assert_eq!(executed, 1);
        let second = minted.expect("the update must mint a second checkpoint");
        let certified = state
            .certifier
            .highest_certified()
            .expect("quorum must certify");
        assert_eq!(certified.checkpoint(), &checkpoint);
        // The prior checkpoint certified and was reclaimed; only the new mint is pending.
        assert_eq!(state.certifier.pending().count(), 1);

        // Certifying the second checkpoint closes its metrics from the update's stamp alone:
        // minted at 2s from a 0.5s submission, certified at 6s.
        let votes = (0..3)
            .map(|author| {
                let vote = Envelope::new(0, Payload::Attest(second.clone())).to_bytes();
                (author, vec![vote])
            })
            .collect();
        state.execute_subdag(&metrics, Duration::from_secs(6), subdag_at(3, votes));
        let certification = metrics.checkpoint_certification_latency_s();
        assert_eq!(certification.get_sample_count(), 2);
        assert_eq!(certification.get_sample_sum(), 2.0 + 4.0);
        let end_to_end = metrics.end_to_end_latency_s();
        assert_eq!(end_to_end.get_sample_count(), 2);
        assert_eq!(end_to_end.get_sample_sum(), 2.0 + 5.5);
    }
}
