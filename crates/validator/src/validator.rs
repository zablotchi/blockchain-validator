// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator node: a mysticeti replica wired to an execution engine.

use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use checkpoint::{
    certifier::{CheckpointCertifier, CheckpointTimings},
    checkpoint::Checkpoint,
};
use dag::{
    authority::Authority,
    block::{Block, transaction::Transaction as ConsensusTransaction},
    consensus::CommittedSubDag,
    context::Ctx,
    crypto::AsBytes,
    metrics::Metrics,
    output::{DagConsumer, DagEvent},
    storage::Storage,
    sync::network::Network,
};
use execution::{
    engine::ExecutionEngine, scheduler::SequentialScheduler, transaction::Transaction,
};
use prometheus::{Registry, local::LocalHistogram};
use replica::{
    builder::{ReplicaBuilder, StorageKind},
    client::TransactionClient,
    config::{PrivateReplicaConfig, PublicReplicaConfig},
    replica::{Replica, ReplicaHandle},
};
use tokio::{
    select,
    sync::{mpsc, watch},
};

#[cfg(any(test, feature = "benchmark"))]
use crate::generator::{LoadGeneratorConfig, TransactionGenerator};
use crate::{
    envelope::{Envelope, Payload},
    fork::ForkInjection,
    limits::{self, CLIENT_BATCH_BYTES, split_batch},
    metrics::{EVIDENCE_BUDGET, FAST, SLOW, ValidatorMetrics},
    outbox::ProtocolOutbox,
    parameters::ValidatorParameters,
};

/// Capacity of the event stream, in rounds: each round streams about one block per validator
/// plus a commit. A bounded channel is mandatory — a slow consumer must backpressure the
/// replica rather than drop or reorder events.
const EVENT_CHANNEL_ROUNDS: usize = 1024;

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
    parameters: ValidatorParameters,
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
            parameters: ValidatorParameters::default(),
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

    pub fn with_parameters(mut self, parameters: ValidatorParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Assembles the validator: builds the scheduler, the certifier, and the replica with its
    /// event consumer. No I/O happens until [`Validator::start`].
    pub fn build(self) -> eyre::Result<Validator<E>> {
        let committee = self.public_config.committee();
        // Every protocol reads the full event stream, so all runs bear the same streaming cost.
        let (sender, receiver) = mpsc::channel(EVENT_CHANNEL_ROUNDS * (committee.len() + 1));
        let consensus = self
            .public_config
            .parameters
            .consensus
            .to_protocol(&committee)?;
        let quorum = consensus.quorum_threshold;
        let ValidatorParameters {
            finality,
            fork,
            phase_one_timeout,
            evidence_budget_bytes,
            protocol_bytes_in_flight,
        } = self.parameters;
        eyre::ensure!(
            !finality.needs_bft_quorum() || quorum == 2 * committee.total_stake() / 3 + 1,
            "finality protocol {finality} needs a 2f+1 consensus quorum (no hybrid protocols)"
        );
        eyre::ensure!(
            ValidatorParameters::EVIDENCE_BUDGET_BYTES.contains(&evidence_budget_bytes),
            "evidence_budget_bytes must be between 4 KiB and 64 GiB, not {evidence_budget_bytes}"
        );
        let largest_payload = limits::max_protocol_payload(committee.len());
        eyre::ensure!(
            (largest_payload..=ValidatorParameters::MAX_PROTOCOL_BYTES_IN_FLIGHT)
                .contains(&protocol_bytes_in_flight),
            "protocol_bytes_in_flight must be between {largest_payload} (the largest protocol \
                payload) and 4 MiB, not {protocol_bytes_in_flight}"
        );
        if let Some(fork) = &fork {
            let mut members = HashSet::new();
            for group in &fork.groups {
                eyre::ensure!(!group.is_empty(), "fork groups must not be empty");
                for &authority in group {
                    eyre::ensure!(
                        committee.known_authority(authority),
                        "fork group member {} is not in the committee",
                        authority.index()
                    );
                    eyre::ensure!(
                        members.insert(authority),
                        "authority {} appears in the fork groups twice",
                        authority.index()
                    );
                }
            }
        }
        let certifier =
            CheckpointCertifier::new(committee, finality, quorum, consensus.leader_count);
        Ok(Validator {
            state: ExecutionState {
                scheduler: SequentialScheduler::new(self.engine),
                certifier,
                authority: self.authority,
                fork,
                minted: 0,
                evidence_budget: evidence_budget_bytes,
            },
            authority: self.authority,
            public_config: self.public_config,
            wal: self.wal,
            phase_one_timeout,
            protocol_bytes_in_flight,
            metrics: ValidatorMetrics::new(&self.registry),
            replica: self
                .replica
                .with_consumer(DagConsumer::Events(sender))
                .build(),
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
    phase_one_timeout: Duration,
    protocol_bytes_in_flight: u64,
    metrics: Arc<ValidatorMetrics>,
    replica: Replica,
    receiver: mpsc::Receiver<DagEvent>,
}

/// The execution half of a validator — the scheduler and the certifier fed by the event
/// stream — owned by the driver task once started.
struct ExecutionState<E> {
    scheduler: SequentialScheduler<E>,
    certifier: CheckpointCertifier,
    authority: Authority,
    fork: Option<ForkInjection>,
    /// Checkpoints minted so far: the height of the latest one.
    minted: u64,
    /// The bytes the certifier may retain before the validator halts.
    evidence_budget: u64,
}

/// Why a validator halted: it keeps running consensus, so the replica never backs up and the
/// run completes, but it executes, decides and submits nothing more.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HaltReason {
    /// The certifier retained more than the evidence budget.
    EvidenceBudget { bytes: u64 },
}

impl HaltReason {
    /// The `reason` label of the halt gauge.
    fn label(self) -> &'static str {
        match self {
            Self::EvidenceBudget { .. } => EVIDENCE_BUDGET,
        }
    }
}

impl<E: ExecutionEngine + Send + 'static> Validator<E> {
    /// Replays the consensus WAL (if any) to rebuild execution state, then starts the replica
    /// and the driver task feeding its committed transactions, in commit order, to the
    /// scheduler, arriving votes and certificates to the certifier if the protocol counts
    /// them, and expired phase-one timeouts if it times out. The live stream never re-emits
    /// recovered commits, so replay and stream compose without overlap.
    pub async fn start<C: Ctx>(mut self) -> eyre::Result<ValidatorHandle<C, E>> {
        let replayed = self.replay()?;
        let max_block_size = self.public_config.parameters.dag.max_block_size;
        let Self {
            state,
            authority,
            replica,
            receiver,
            metrics,
            phase_one_timeout,
            protocol_bytes_in_flight,
            ..
        } = self;

        let replica = replica.run::<C>().await?;
        let (executed_sender, executed) = watch::channel(replayed);
        let (decided_sender, decided) = watch::channel(state.decided_everything());
        let (halted_sender, halted) = watch::channel(None);
        let driver = Driver {
            state,
            receiver,
            submitter: replica.transaction_client(),
            outbox: ProtocolOutbox::new(authority, protocol_bytes_in_flight),
            metrics: metrics.clone(),
            phase_one_timeout,
            executed: executed_sender,
            decided: decided_sender,
            halted: halted_sender,
        };
        let driver = C::spawn(driver.run::<C>());

        Ok(ValidatorHandle {
            replica,
            driver,
            executed,
            decided,
            halted,
            metrics,
            max_block_size,
            max_transaction_size: limits::max_transaction_size(protocol_bytes_in_flight),
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
        let replay_latency = replay_metrics.client_commit_latency_s().local();
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
            let (executed, _) =
                self.state
                    .execute_subdag(&replay_metrics, &replay_latency, Duration::ZERO, subdag);
            replayed += executed as u64;
        }
        Ok(replayed)
    }
}

/// Where the driver submits this validator's own votes and certificates.
trait Submitter: Send + Sync + 'static {
    /// Errors iff the replica shut down.
    fn submit(
        &self,
        payloads: Vec<ConsensusTransaction>,
    ) -> impl Future<Output = eyre::Result<()>> + Send;
}

impl Submitter for TransactionClient {
    fn submit(
        &self,
        payloads: Vec<ConsensusTransaction>,
    ) -> impl Future<Output = eyre::Result<()>> + Send {
        TransactionClient::submit(self, payloads)
    }
}

/// The task feeding the event stream to the execution state, once started.
struct Driver<E, S> {
    state: ExecutionState<E>,
    receiver: mpsc::Receiver<DagEvent>,
    submitter: S,
    outbox: ProtocolOutbox,
    metrics: Arc<ValidatorMetrics>,
    phase_one_timeout: Duration,
    /// The executed transaction count, starting from the replayed ones.
    executed: watch::Sender<u64>,
    decided: watch::Sender<bool>,
    halted: watch::Sender<Option<HaltReason>>,
}

impl<E: ExecutionEngine + Send + 'static, S: Submitter> Driver<E, S> {
    /// Runs until the event stream closes, then returns the scheduler and the certifier.
    async fn run<C: Ctx>(self) -> (SequentialScheduler<E>, CheckpointCertifier) {
        let Self {
            mut state,
            mut receiver,
            submitter: client,
            mut outbox,
            metrics: driver_metrics,
            phase_one_timeout,
            executed: executed_sender,
            decided: decided_sender,
            halted: halted_sender,
        } = self;
        let client_latency = driver_metrics.client_commit_latency_s().local();
        let times_out = state.certifier.protocol().times_out();
        // Re-attest checkpoints undecided at replay: votes in flight at shutdown died
        // with the transaction queue, and a validator otherwise attests only once, so an
        // undecided checkpoint could stall forever. The certifier's per-author dedupe
        // makes resubmission idempotent — votes that did commit are simply ignored.
        let pending: Vec<_> = state.certifier.pending().cloned().collect();
        // Phase-one timeouts by mint instant, in mint order; replayed checkpoints time
        // from now.
        let mut timeouts = VecDeque::new();
        if times_out {
            timeouts.extend(
                pending
                    .iter()
                    .map(|checkpoint| (C::now(), checkpoint.anchor())),
            );
        }
        if !pending.is_empty() {
            let timestamp_ms = C::timestamp_utc().as_millis() as u64;
            let attestations = pending
                .into_iter()
                .map(|checkpoint| Self::wrap(timestamp_ms, Payload::Attest(checkpoint)))
                .collect();
            Self::submit(&mut outbox, &client, &driver_metrics, attestations).await;
        }

        let mut count = *executed_sender.borrow();
        // Armed for the earliest timeout; it may outlive it, waking once for nothing.
        let mut timer = None;
        loop {
            if timer.is_none()
                && let Some((minted, _)) = timeouts.front()
            {
                let remaining = phase_one_timeout.saturating_sub(C::elapsed(minted));
                timer = Some(Box::pin(C::sleep(remaining)));
            }
            // Biased, so polling never depends on tokio's process-seeded RNG. Expired
            // timeouts apply before every event either way, so the order is not observable.
            let event = select! {
                biased;
                () = async { timer.as_mut().expect("guarded").await }, if timer.is_some() => {
                    timer = None;
                    None
                }
                event = receiver.recv() => match event {
                    Some(event) => Some(event),
                    None => break,
                },
            };
            // Expired timeouts are checked on every event too: a busy stream must not
            // starve them.
            while let Some((minted, anchor)) = timeouts.front()
                && C::elapsed(minted) >= phase_one_timeout
            {
                state.certifier.expire(*anchor);
                timeouts.pop_front();
            }
            let now = C::timestamp_utc();
            let minted = match event {
                None => None,
                Some(DagEvent::Block(block)) => {
                    if let Some(protocol_bytes) = outbox.observe_block(&block) {
                        let bytes = block.serialized_bytes().len() as u64;
                        driver_metrics.observe_own_proposal(bytes, protocol_bytes);
                    }
                    if state.count_arrivals(&driver_metrics, now, &block) {
                        let _ = decided_sender.send(state.decided_everything());
                    }
                    None
                }
                Some(DagEvent::Commit(subdag)) => {
                    // The clock starts at delivery (idle waiting is not latency) and stops
                    // after execution, checkpoint minting, and vote recording.
                    let start = C::now();
                    let (executed, minted) =
                        state.execute_subdag(&driver_metrics, &client_latency, now, subdag);
                    driver_metrics.observe_subdag_execution_latency(C::elapsed(&start));
                    count += executed as u64;
                    let _ = executed_sender.send(count);
                    let _ = decided_sender.send(state.decided_everything());
                    minted
                }
            };
            if times_out && let Some(checkpoint) = &minted {
                timeouts.push_back((C::now(), checkpoint.anchor()));
            }
            if let Some(reason) = state.check_budget(&driver_metrics) {
                tracing::error!(?reason, "validator halted: discarding events from now on");
                driver_metrics.set_halted(reason.label());
                let _ = halted_sender.send(Some(reason));
                // Receive without executing, deciding or submitting, so that the replica never
                // backs up behind a halted validator.
                while receiver.recv().await.is_some() {}
                break;
            }
            // Attest to the minted checkpoint and submit concluded certificates through
            // consensus: both ride this validator's own signed blocks, behind any payloads an
            // own proposal has made room for.
            let payloads: Vec<_> = minted
                .map(Payload::Attest)
                .into_iter()
                .chain(
                    state
                        .certifier
                        .take_certificates()
                        .into_iter()
                        .map(Payload::Certify),
                )
                .map(|payload| Self::wrap(now.as_millis() as u64, payload))
                .collect();
            Self::submit(&mut outbox, &client, &driver_metrics, payloads).await;
        }
        (state.scheduler, state.certifier)
    }

    /// Queues one event's payloads (possibly none) and submits, in one batch, the queued ones
    /// the protocol byte budget admits. Failure is benign: the replica is shutting down, lost
    /// votes are resubmitted after replay, and certificates conclude again from them.
    async fn submit(
        outbox: &mut ProtocolOutbox,
        client: &S,
        metrics: &ValidatorMetrics,
        payloads: Vec<ConsensusTransaction>,
    ) {
        let queued = !payloads.is_empty();
        outbox.enqueue(payloads);
        let batch = outbox.next_batch();
        if !batch.is_empty() {
            let count = batch.len() as u64;
            if client.submit(batch).await.is_err() {
                tracing::debug!("submission failed; shutting down");
                return;
            }
            metrics.inc_protocol_payloads_submitted(count);
        }
        if queued && !outbox.is_empty() {
            metrics.inc_protocol_submissions_deferred();
        }
    }

    /// Wraps this validator's own payload, timestamped, for submission through consensus.
    fn wrap(timestamp_ms: u64, payload: Payload) -> ConsensusTransaction {
        ConsensusTransaction::new(Envelope::new(timestamp_ms, payload).to_bytes().into())
    }
}

impl<E: ExecutionEngine> ExecutionState<E> {
    /// Executes every transaction of a committed sub-dag in canonical order, dispatches its
    /// checkpoint votes and certificates to the certifier, and returns how many transactions
    /// were executed together with the checkpoint this sub-dag minted, if any. Undecodable
    /// payloads are skipped; the choice is deterministic. Sub-dags that execute nothing are not
    /// checkpointed: their commitment is unchanged, and their count varies across validators
    /// at any executed-transaction cut. `now` stamps the mint and closes the latency metrics
    /// of checkpoints decided by the mint or this sub-dag's votes and certificates, and of
    /// every client transaction in `client_latency`, a local copy of `metrics`' histogram (so
    /// per-transaction observations stay off the shared one), flushed once per sub-dag.
    fn execute_subdag(
        &mut self,
        metrics: &ValidatorMetrics,
        client_latency: &LocalHistogram,
        now: Duration,
        mut subdag: CommittedSubDag,
    ) -> (usize, Option<Checkpoint>) {
        let anchor = subdag.anchor;
        subdag.sort();
        let mut votes = Vec::new();
        let mut certificates = Vec::new();
        // Submission stamps reduce to their sum here, while the payloads are in hand.
        let mut stamp_sum_ms = 0u64;
        let transactions: Vec<Transaction> = subdag
            .blocks
            .iter()
            .flat_map(|block| {
                let reference = *block.reference();
                block
                    .transactions()
                    .iter()
                    .map(move |payload| (reference, payload))
            })
            .filter_map(|(block, payload)| {
                let envelope = Envelope::from_bytes(payload.as_bytes())
                    .inspect_err(|error| tracing::warn!(?error, "skipping undecodable payload"))
                    .ok()?;
                let stamp_ms = envelope.timestamp_ms();
                match envelope.into_payload() {
                    Payload::Execute(transaction) => {
                        stamp_sum_ms += stamp_ms;
                        let submitted = Duration::from_millis(stamp_ms);
                        client_latency.observe(now.saturating_sub(submitted).as_secs_f64());
                        Some(transaction)
                    }
                    Payload::Attest(vote) => {
                        votes.push((block, vote));
                        None
                    }
                    Payload::Certify(certificate) => {
                        certificates.push((block, certificate));
                        None
                    }
                }
            })
            .collect();
        let executed = self.scheduler.execute(&transactions).len();
        metrics.inc_executed_transactions(executed as u64);
        client_latency.flush();
        let minted = (executed > 0).then(|| {
            self.minted += 1;
            let timings = CheckpointTimings {
                minted_at: now,
                mean_timestamp_ms: stamp_sum_ms / executed as u64,
            };
            let mut commitment = self.scheduler.store().commitment();
            if let Some(fork) = &self.fork {
                commitment = fork.commitment(self.authority, self.minted, commitment);
            }
            let (checkpoint, outcome) = self.certifier.push(anchor, commitment, timings);
            // Only arrivals held for the mint can decide it.
            if let Some(outcome) = outcome {
                metrics.observe_decision(now, outcome, FAST, timings);
            }
            checkpoint
        });
        if minted.is_none() {
            self.certifier.observe_unminted_commit(anchor);
        }
        // A vote can never reference its own delivering sub-dag's checkpoint (it is created
        // only after that sub-dag commits), so recording after minting loses nothing.
        for (block, vote) in votes {
            if let Some((outcome, timings)) = self.certifier.record(block, vote) {
                metrics.observe_decision(now, outcome, SLOW, timings);
            }
        }
        // Certificates cite votes from their causal history: committed by now, recorded above.
        for (block, certificate) in certificates {
            if let Some((outcome, timings)) = self.certifier.record_certificate(block, &certificate)
            {
                metrics.observe_decision(now, outcome, SLOW, timings);
            }
        }
        self.observe_contiguous(metrics, now, minted.is_some());
        (executed, minted)
    }

    /// Counts the checkpoint votes, and certificates if the protocol counts them, that `block`
    /// carries as it enters the local DAG, if the protocol counts arrivals, and returns whether
    /// one decided a checkpoint; `now` closes that checkpoint's latency metrics.
    fn count_arrivals(&mut self, metrics: &ValidatorMetrics, now: Duration, block: &Block) -> bool {
        let protocol = self.certifier.protocol();
        if !protocol.counts_arrivals() {
            return false;
        }
        let certificates = protocol.counts_arriving_certificates();
        let reference = *block.reference();
        let mut decided = false;
        for payload in block.transactions() {
            let bytes = payload.as_bytes();
            let counted = if let Some(vote) = Envelope::attestation_from_bytes(bytes) {
                self.certifier.record_arrival(reference, vote)
            } else if certificates
                && let Some(certificate) = Envelope::certificate_from_bytes(bytes)
            {
                self.certifier
                    .record_arriving_certificate(reference, certificate)
            } else {
                continue;
            };
            if let Some((outcome, timings)) = counted {
                metrics.observe_decision(now, outcome, FAST, timings);
                decided = true;
            }
        }
        if decided {
            self.observe_contiguous(metrics, now, false);
        }
        decided
    }

    /// Closes the latency metrics, at `now`, of the checkpoints that became contiguously
    /// decided, and updates the pending-heights gauge if the window changed (`minted` or
    /// popped).
    fn observe_contiguous(&mut self, metrics: &ValidatorMetrics, now: Duration, minted: bool) {
        let mut popped = false;
        for (outcome, timings) in self.certifier.take_contiguous() {
            metrics.observe_contiguous(now, outcome, timings);
            popped = true;
        }
        if minted || popped {
            metrics.set_pending_heights(self.certifier.pending().len());
        }
    }

    /// The reason to halt, if the certifier retains more than the evidence budget; updates the
    /// retained-bytes gauge.
    fn check_budget(&self, metrics: &ValidatorMetrics) -> Option<HaltReason> {
        let bytes = self.certifier.retained_bytes();
        metrics.set_retained_bytes(bytes);
        (bytes > self.evidence_budget).then_some(HaltReason::EvidenceBudget { bytes })
    }

    /// Whether every minted checkpoint is decided, once one was minted; consumed by
    /// [`ValidatorHandle::wait_for_decided`].
    fn decided_everything(&self) -> bool {
        self.minted > 0 && self.certifier.pending().next().is_none()
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
    decided: watch::Receiver<bool>,
    halted: watch::Receiver<Option<HaltReason>>,
    metrics: Arc<ValidatorMetrics>,
    max_block_size: usize,
    /// The largest client transaction (serialized envelope) the proposal budget admits.
    max_transaction_size: u64,
}

impl<C: Ctx, E: ExecutionEngine + Send + 'static> ValidatorHandle<C, E> {
    /// Submits transactions to the replica, in batches of at most about
    /// [`CLIENT_BATCH_BYTES`]; resolves once they are queued for inclusion in a block, not once
    /// they are committed or executed. Every payload is stamped with the submission time (one
    /// clock read per call), from which mysticeti derives its commit-latency metric. Fails,
    /// submitting nothing, if a stamped transaction exceeds the proposal budget's ceiling.
    pub async fn submit(&self, transactions: Vec<Transaction>) -> eyre::Result<()> {
        let timestamp_ms = C::timestamp_utc().as_millis() as u64;
        let batches =
            prepare_client_batches(timestamp_ms, transactions, self.max_transaction_size)?;
        for batch in batches {
            self.replica.submit(batch).await?;
        }
        Ok(())
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

    /// Why the validator halted, if it did.
    pub fn halted(&self) -> Option<HaltReason> {
        *self.halted.borrow()
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
            self.max_transaction_size,
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

    /// Waits until everything executed is decided (finalized or skipped): no minted checkpoint
    /// is pending. This is transient while submissions are in flight, so it is meaningful after
    /// an executed-count cut ([`wait_for_transactions`](ValidatorHandle::wait_for_transactions)
    /// first). Never resolves if a height cannot be decided, as under the baseline protocol
    /// with forked validators. Returns early if the driver has stopped.
    pub async fn wait_for_decided(&mut self) {
        loop {
            if *self.decided.borrow_and_update() {
                return;
            }
            if self.decided.changed().await.is_err() {
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

/// Stamps client transactions into envelopes and splits them, in order, into batches closing
/// at [`CLIENT_BATCH_BYTES`]; fails if an envelope exceeds `ceiling` bytes.
fn prepare_client_batches(
    timestamp_ms: u64,
    transactions: Vec<Transaction>,
    ceiling: u64,
) -> eyre::Result<Vec<Vec<ConsensusTransaction>>> {
    let envelopes = transactions
        .into_iter()
        .map(|transaction| {
            let bytes = Envelope::new(timestamp_ms, Payload::Execute(transaction)).to_bytes();
            eyre::ensure!(
                bytes.len() as u64 <= ceiling,
                "a {}-byte transaction exceeds the {ceiling}-byte ceiling of the proposal budget",
                bytes.len()
            );
            Ok(ConsensusTransaction::new(bytes.into()))
        })
        .collect::<eyre::Result<_>>()?;
    Ok(split_batch(envelopes, CLIENT_BATCH_BYTES))
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU64, path::Path, sync::Arc, time::Duration};

    use checkpoint::{
        certifier::{CheckpointCertifier, CheckpointTimings},
        checkpoint::{Checkpoint, Decision, Outcome},
        finality::FinalityProtocol,
    };
    use dag::{
        authority::Authority,
        block::{
            Block, BlockReference, data::Data, transaction::Transaction as ConsensusTransaction,
        },
        config::ImportExport,
        consensus::CommittedSubDag,
        context::TokioCtx,
        crypto::{AsBytes, CryptoEngine},
        output::DagEvent,
    };
    use execution::{
        crypto::Digest,
        fake::{FakeExecutor, FakeTransaction},
        object::ObjectId,
        scheduler::SequentialScheduler,
        transaction::Transaction,
    };
    use prometheus::Registry;
    use replica::config::{PrivateReplicaConfig, PublicReplicaConfig, ReplicaParameters};
    use tokio::sync::{mpsc, watch};

    use crate::{
        envelope::{Envelope, Payload},
        fork::ForkInjection,
        limits::{self, CLIENT_BATCH_BYTES, framed_size},
        metrics::{EVIDENCE_BUDGET, FAST, FINALIZE, SKIP, SLOW, ValidatorMetrics},
        outbox::ProtocolOutbox,
        parameters::ValidatorParameters,
        validator::{
            Driver, ExecutionState, HaltReason, Submitter, ValidatorBuilder, prepare_client_batches,
        },
    };

    impl ExecutionState<FakeExecutor> {
        /// [`execute_subdag`](ExecutionState::execute_subdag) with a local histogram of its own.
        fn execute(
            &mut self,
            metrics: &ValidatorMetrics,
            now: Duration,
            subdag: CommittedSubDag,
        ) -> (usize, Option<Checkpoint>) {
            let client_latency = metrics.client_commit_latency_s().local();
            self.execute_subdag(metrics, &client_latency, now, subdag)
        }
    }

    fn state(protocol: FinalityProtocol) -> ExecutionState<FakeExecutor> {
        ExecutionState {
            scheduler: SequentialScheduler::new(FakeExecutor),
            certifier: CheckpointCertifier::new_for_test(protocol, vec![1; 4], 3, 0),
            authority: Authority::new(0),
            fork: None,
            minted: 0,
            evidence_budget: ValidatorParameters::default_evidence_budget_bytes(),
        }
    }

    impl Submitter for mpsc::Sender<Vec<ConsensusTransaction>> {
        async fn submit(&self, payloads: Vec<ConsensusTransaction>) -> eyre::Result<()> {
            self.send(payloads)
                .await
                .map_err(|_| eyre::eyre!("submissions closed"))
        }
    }

    /// A driver over an execution state, on tokio, fed through `events` and submitting into
    /// `submitted`.
    struct TestDriver {
        events: mpsc::Sender<DagEvent>,
        submitted: mpsc::Receiver<Vec<ConsensusTransaction>>,
        halted: watch::Receiver<Option<HaltReason>>,
        metrics: Arc<ValidatorMetrics>,
        task: tokio::task::JoinHandle<(SequentialScheduler<FakeExecutor>, CheckpointCertifier)>,
    }

    impl TestDriver {
        /// The event channel's capacity: small, so that a driver that stops receiving blocks
        /// its feeder at once.
        const EVENTS: usize = 4;

        /// Spawns a driver pacing own payloads at `protocol_bytes_in_flight`.
        fn spawn(state: ExecutionState<FakeExecutor>, protocol_bytes_in_flight: u64) -> Self {
            let (events, receiver) = mpsc::channel(Self::EVENTS);
            let (submitter, submitted) = mpsc::channel(1024);
            let (halted_sender, halted) = watch::channel(None);
            let metrics = metrics();
            let driver = Driver {
                outbox: ProtocolOutbox::new(state.authority, protocol_bytes_in_flight),
                state,
                receiver,
                submitter,
                metrics: metrics.clone(),
                phase_one_timeout: ValidatorParameters::default_phase_one_timeout(),
                executed: watch::channel(0).0,
                decided: watch::channel(false).0,
                halted: halted_sender,
            };
            Self {
                events,
                submitted,
                halted,
                metrics,
                task: tokio::spawn(driver.run::<TokioCtx>()),
            }
        }

        /// Feeds `event`, failing if the driver does not take it within a second.
        async fn feed(&self, event: DagEvent) {
            let sent = tokio::time::timeout(Duration::from_secs(1), self.events.send(event));
            let sent = sent.await.expect("the driver must keep receiving events");
            sent.expect("the driver must be running");
        }

        /// Feeds a Byzantine author's early votes, round after round, with no commit, and
        /// returns why the driver halted.
        async fn halt_on_early_junk(&mut self) -> HaltReason {
            for round in 2..200 {
                self.feed(early_junk(round)).await;
            }
            let halted = self.halted.wait_for(Option::is_some);
            let halted = tokio::time::timeout(Duration::from_secs(1), halted).await;
            halted
                .expect("the driver must halt")
                .unwrap()
                .expect("halted")
        }
    }

    /// The vote of a validator that minted `anchor`.
    fn vote_for(anchor: BlockReference) -> Checkpoint {
        let mut twin =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 0);
        let (vote, _) = twin.push(anchor, Digest::default(), CheckpointTimings::default());
        vote
    }

    /// A Byzantine author's block at `round`, voting for both leaders of the round before as
    /// if they were committed: eligible as long as no commit passes that round.
    fn early_junk(round: u64) -> DagEvent {
        let votes = (0..2)
            .map(|leader| {
                let vote = vote_for(BlockReference::new_test(leader, round - 1));
                Envelope::new(0, Payload::Attest(vote)).to_bytes()
            })
            .collect();
        DagEvent::Block(block(3, round, votes))
    }

    const DEFAULT_IN_FLIGHT: u64 = 1 << 20;

    /// The smallest evidence budget a validator accepts.
    const SMALLEST_BUDGET: u64 = *ValidatorParameters::EVIDENCE_BUDGET_BYTES.start();

    /// Whether `decision` finalized `checkpoint`.
    fn finalizes(decision: &Decision, checkpoint: &Checkpoint) -> bool {
        decision.anchor() == checkpoint.anchor()
            && decision.outcome() == Outcome::Finalize(checkpoint.commitment())
    }

    fn metrics() -> Arc<ValidatorMetrics> {
        ValidatorMetrics::new(&Registry::new())
    }

    /// A block of `author` at `round` carrying the given raw payloads.
    fn block(author: usize, round: u64, payloads: Vec<Vec<u8>>) -> Data<Block> {
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
    }

    /// A sub-dag at `round` with one block per `(author, payloads)` entry, anchored at the
    /// first block.
    fn subdag_at(round: u64, blocks: Vec<(usize, Vec<Vec<u8>>)>) -> CommittedSubDag {
        let blocks: Vec<_> = blocks
            .into_iter()
            .map(|(author, payloads)| block(author, round, payloads))
            .collect();
        CommittedSubDag::new(*blocks[0].reference(), blocks)
    }

    /// The payload creating object `id`.
    fn creation(id: u64) -> Vec<u8> {
        let create = FakeTransaction::success(vec![], vec![ObjectId::new(id)], vec![]);
        Envelope::new(0, Payload::Execute(create.into())).to_bytes()
    }

    /// One block per author in `0..3` at `round`, each attesting `checkpoint`.
    fn quorum_of_votes(round: u64, checkpoint: &Checkpoint) -> Vec<Data<Block>> {
        (0..3)
            .map(|author| {
                let vote = Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes();
                block(author, round, vec![vote])
            })
            .collect()
    }

    /// A single-block sub-dag carrying the given raw payloads.
    fn subdag(payloads: Vec<Vec<u8>>) -> CommittedSubDag {
        subdag_at(1, vec![(0, payloads)])
    }

    #[test]
    fn undecodable_payloads_are_skipped() {
        let mut state = state(FinalityProtocol::Baseline);
        let transaction = FakeTransaction::success(vec![], vec![ObjectId::new(1)], vec![]);
        let valid = Envelope::new(0, Payload::Execute(transaction.into())).to_bytes();

        let (executed, minted) = state.execute(
            &metrics(),
            Duration::ZERO,
            subdag(vec![vec![0xFF; 16], valid]),
        );

        assert_eq!(executed, 1);
        assert!(minted.is_some());
        assert_eq!(state.certifier.pending().count(), 1);
    }

    #[test]
    fn client_metrics_count_client_transactions_only() {
        let mut state = state(FinalityProtocol::Baseline);
        let metrics = metrics();
        let execute = |id, stamp_ms| {
            let create = FakeTransaction::success(vec![], vec![ObjectId::new(id)], vec![]);
            Envelope::new(stamp_ms, Payload::Execute(create.into())).to_bytes()
        };
        let vote = Envelope::new(500, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        // The last one is stamped by a submitter whose clock runs ahead of ours.
        let payloads = vec![
            execute(1, 1_000),
            vote,
            vec![0xFF; 16],
            execute(2, 2_000),
            execute(3, 4_000),
        ];

        let (executed, _) = state.execute(&metrics, Duration::from_secs(3), subdag(payloads));

        // Votes and undecodable payloads are neither counted nor timed, and a stamp from the
        // future times zero.
        assert_eq!(executed, 3);
        assert_eq!(metrics.executed_transactions().get(), 3);
        let latency = metrics.client_commit_latency_s();
        assert_eq!(latency.get_sample_count(), 3);
        assert_eq!(latency.get_sample_sum(), 2.0 + 1.0 + 0.0);
    }

    #[test]
    fn subdags_with_only_undecodable_payloads_mint_no_checkpoint() {
        let mut state = state(FinalityProtocol::Baseline);

        let (executed, minted) =
            state.execute(&metrics(), Duration::ZERO, subdag(vec![vec![0xFF; 16]]));

        assert_eq!(executed, 0);
        assert!(minted.is_none());
        assert_eq!(state.certifier.pending().count(), 0);
    }

    #[test]
    fn forked_validators_mint_diverged_checkpoints_at_forked_heights_only() {
        let mut state = state(FinalityProtocol::Baseline);
        state.fork = Some(ForkInjection {
            groups: vec![vec![Authority::new(0)]],
            period: NonZeroU64::new(2).unwrap(),
        });
        let metrics = metrics();
        let mut diverged = Vec::new();
        for round in 1..=3 {
            // Sub-dags executing nothing mint nothing, so they do not count as heights.
            let unminted = subdag_at(round, vec![(1, vec![vec![0xFF; 16]])]);
            state.execute(&metrics, Duration::ZERO, unminted);
            let create = FakeTransaction::success(vec![], vec![ObjectId::new(round)], vec![]);
            let execute = Envelope::new(0, Payload::Execute(create.into())).to_bytes();
            let blocks = vec![(0, vec![execute])];
            let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag_at(round, blocks));
            let minted = minted.expect("executing sub-dag must mint a checkpoint");
            diverged.push(minted.commitment() != state.scheduler.store().commitment());
        }
        assert_eq!(diverged, [false, true, false]);
    }

    #[test]
    fn fork_recovery_protocols_reject_consensus_quorums_other_than_2f_plus_1() {
        // Hybrid Mysticeti with no fault budget waits for all 4 validators, not 2f+1 = 3.
        let file = tempfile::NamedTempFile::new().unwrap();
        let consensus = "consensus:\n  protocol: hybrid-mysticeti\n  f: 0\n  c: 0\n";
        std::fs::write(file.path(), consensus).unwrap();
        let replica_parameters = ReplicaParameters::load(file.path()).unwrap();
        let public_config =
            PublicReplicaConfig::new_for_tests(4).with_parameters(replica_parameters);
        let build = |finality| {
            let private_config =
                PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), 4).remove(0);
            ValidatorBuilder::new(
                FakeExecutor,
                Authority::new(0),
                public_config.clone(),
                private_config,
            )
            .with_parameters(ValidatorParameters {
                finality,
                ..Default::default()
            })
            .build()
        };
        assert!(build(FinalityProtocol::A).is_err());
        assert!(build(FinalityProtocol::B).is_err());
        assert!(build(FinalityProtocol::C).is_err());
        assert!(build(FinalityProtocol::Baseline).is_ok());
        assert!(build(FinalityProtocol::SuiBaseline).is_ok());
    }

    #[test]
    fn fork_groups_must_be_disjoint_non_empty_sets_of_committee_members() {
        let build = |groups: &[&[usize]]| {
            let fork = ForkInjection {
                groups: groups
                    .iter()
                    .map(|group| group.iter().copied().map(Authority::from).collect())
                    .collect(),
                period: NonZeroU64::new(5).unwrap(),
            };
            let private_config =
                PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), 4).remove(0);
            ValidatorBuilder::new(
                FakeExecutor,
                Authority::new(0),
                PublicReplicaConfig::new_for_tests(4),
                private_config,
            )
            .with_parameters(ValidatorParameters {
                fork: Some(fork),
                ..Default::default()
            })
            .build()
        };
        let fails_with =
            |groups, message| build(groups).is_err_and(|error| error.to_string().contains(message));
        assert!(build(&[&[1], &[2, 3]]).is_ok());
        assert!(fails_with(&[&[1], &[]], "must not be empty"));
        assert!(fails_with(
            &[&[1, 2], &[2]],
            "authority 2 appears in the fork groups twice"
        ));
        assert!(fails_with(
            &[&[1], &[4]],
            "member 4 is not in the committee"
        ));
    }

    #[tokio::test]
    async fn byzantine_early_votes_without_commits_halt_on_the_evidence_budget() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        state.evidence_budget = SMALLEST_BUDGET;
        let mut driver = TestDriver::spawn(state, DEFAULT_IN_FLIGHT);

        // No commit is processed, so the cursor never passes the junk: the budget bounds it.
        let HaltReason::EvidenceBudget { bytes } = driver.halt_on_early_junk().await;
        assert!(bytes > SMALLEST_BUDGET);
        assert_eq!(driver.metrics.retained_bytes().get(), bytes as i64);
        assert_eq!(driver.metrics.halted(EVIDENCE_BUDGET).get(), 1);
    }

    #[tokio::test]
    async fn a_halted_validator_drains_events_without_deciding_or_submitting() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        state.evidence_budget = SMALLEST_BUDGET;
        let mut driver = TestDriver::spawn(state, DEFAULT_IN_FLIGHT);
        driver.halt_on_early_junk().await;

        // Commits that would execute, mint and vote, and a quorum of votes for each, many
        // times the event channel's capacity.
        for round in 200..200 + 4 * TestDriver::EVENTS as u64 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            driver.feed(DagEvent::Commit(commit)).await;
            let vote = Checkpoint::new_for_test(round);
            for block in quorum_of_votes(round + 1, &vote) {
                driver.feed(DagEvent::Block(block)).await;
            }
        }
        let TestDriver {
            events,
            mut submitted,
            metrics,
            task,
            ..
        } = driver;
        drop(events);
        let (_, certifier) = task.await.unwrap();
        assert_eq!(metrics.executed_transactions().get(), 0);
        assert_eq!(certifier.pending().count(), 0);
        assert_eq!(certifier.highest_decided(), None);
        assert!(submitted.recv().await.is_none());
    }

    #[tokio::test]
    async fn deferred_payloads_go_out_once_an_own_proposal_makes_room() {
        // Room for one vote in flight (votes are of fixed size).
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        let vote_bytes = framed_size(&ConsensusTransaction::new(vote.into()));
        let mut driver = TestDriver::spawn(state(FinalityProtocol::Baseline), vote_bytes);
        let recv = async |driver: &mut TestDriver| {
            let batch = tokio::time::timeout(Duration::from_secs(1), driver.submitted.recv());
            batch
                .await
                .expect("a submission")
                .expect("the driver must be running")
        };

        // Two mints: the first vote goes out, the second waits.
        let first = subdag_at(1, vec![(0, vec![creation(1)])]);
        driver.feed(DagEvent::Commit(first)).await;
        let [first_vote] = recv(&mut driver).await.try_into().unwrap();
        let second = subdag_at(2, vec![(0, vec![creation(2)])]);
        driver.feed(DagEvent::Commit(second)).await;

        // An own proposal carrying the first vote releases the second.
        let proposal = block(0, 3, vec![first_vote.as_bytes().to_vec()]);
        driver.feed(DagEvent::Block(proposal)).await;
        let TestDriver {
            events,
            mut submitted,
            metrics,
            task,
            ..
        } = driver;
        drop(events);
        let (_, certifier) = task.await.unwrap();
        let [second_vote] = submitted.recv().await.unwrap().try_into().unwrap();
        assert!(submitted.recv().await.is_none());
        // The votes for both minted checkpoints, in mint order.
        let votes = [first_vote, second_vote]
            .map(|vote| Envelope::attestation_from_bytes(vote.as_bytes()).expect("a vote"));
        let pending: Vec<_> = certifier.pending().cloned().collect();
        assert_eq!(votes.to_vec(), pending);
        assert_eq!(metrics.protocol_submissions_deferred().get(), 1);
        assert_eq!(metrics.protocol_payloads_submitted().get(), 2);
        let proposal_bytes = metrics.max_proposal_protocol_bytes().get() as u64;
        assert_eq!(proposal_bytes, vote_bytes);
    }

    #[test]
    fn evidence_budgets_outside_the_supported_range_are_rejected() {
        let build = |evidence_budget_bytes| {
            let private_config =
                PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), 4).remove(0);
            ValidatorBuilder::new(
                FakeExecutor,
                Authority::new(0),
                PublicReplicaConfig::new_for_tests(4),
                private_config,
            )
            .with_parameters(ValidatorParameters {
                evidence_budget_bytes,
                ..Default::default()
            })
            .build()
        };
        let rejected = |bytes| {
            build(bytes).is_err_and(|error| error.to_string().contains("evidence_budget_bytes"))
        };
        assert!(rejected(1));
        assert!(rejected(SMALLEST_BUDGET - 1));
        assert!(build(SMALLEST_BUDGET).is_ok());
        assert!(build(64 << 30).is_ok());
        assert!(rejected((64 << 30) + 1));
    }

    /// A builder of validator 0 in a committee of four, with `parameters`.
    fn builder(parameters: ValidatorParameters) -> ValidatorBuilder<FakeExecutor> {
        let private_config =
            PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), 4).remove(0);
        ValidatorBuilder::new(
            FakeExecutor,
            Authority::new(0),
            PublicReplicaConfig::new_for_tests(4),
            private_config,
        )
        .with_parameters(parameters)
    }

    #[test]
    fn protocol_bytes_in_flight_outside_the_supported_range_are_rejected() {
        let build = |protocol_bytes_in_flight| {
            builder(ValidatorParameters {
                protocol_bytes_in_flight,
                ..Default::default()
            })
            .build()
        };
        let rejected = |bytes| {
            build(bytes).is_err_and(|error| error.to_string().contains("protocol_bytes_in_flight"))
        };
        let smallest = limits::max_protocol_payload(4);
        let largest = ValidatorParameters::MAX_PROTOCOL_BYTES_IN_FLIGHT;
        assert!(rejected(smallest - 1));
        assert!(build(smallest).is_ok());
        assert!(build(largest).is_ok());
        assert!(rejected(largest + 1));
    }

    /// A client transaction whose stamped envelope takes exactly `size` bytes.
    fn transaction_of_size(id: u64, size: usize) -> Transaction {
        let create = |args| {
            FakeTransaction::success_with_args(vec![], vec![ObjectId::new(id)], vec![], args).into()
        };
        let overhead = Envelope::new(0, Payload::Execute(create(vec![])))
            .to_bytes()
            .len();
        create(vec![0; size - overhead])
    }

    #[test]
    fn client_submissions_above_the_ceiling_are_rejected() {
        let ceiling = limits::max_transaction_size(1 << 20);
        let fits = transaction_of_size(1, ceiling as usize);
        let [batch] = prepare_client_batches(7, vec![fits], ceiling)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(batch[0].as_bytes().len() as u64, ceiling);

        let oversized = transaction_of_size(2, ceiling as usize + 1);
        let small = transaction_of_size(3, 128);
        assert!(prepare_client_batches(7, vec![small, oversized], ceiling).is_err());
    }

    #[test]
    fn large_client_submissions_are_split_under_the_batch_cap() {
        let transactions: Vec<_> = (0..40_000).map(|id| transaction_of_size(id, 512)).collect();
        let batches = prepare_client_batches(7, transactions, 539).unwrap();
        assert!(batches.len() > 1);
        for (index, batch) in batches.iter().enumerate() {
            // Each batch closes at the first payload reaching the cap.
            let (last, rest) = batch.split_last().unwrap();
            let rest: u64 = rest.iter().map(framed_size).sum();
            assert!(rest < CLIENT_BATCH_BYTES);
            if index + 1 < batches.len() {
                assert!(rest + framed_size(last) >= CLIENT_BATCH_BYTES);
            }
        }
        // In order, stamped.
        let ids: Vec<_> = batches
            .iter()
            .flatten()
            .map(|payload| {
                let envelope = Envelope::from_bytes(payload.as_bytes()).unwrap();
                assert_eq!(envelope.timestamp_ms(), 7);
                let Payload::Execute(transaction) = envelope.into_payload() else {
                    panic!("expected an execution payload");
                };
                transaction.inputs()[0].0
            })
            .collect();
        let expected: Vec<_> = (0..40_000).map(ObjectId::new).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn commits_executing_nothing_drop_the_arrivals_they_pass() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        state.count_arrivals(&metrics, Duration::ZERO, &block(1, 3, vec![vote]));
        assert_eq!(state.check_budget(&metrics), None);
        assert!(metrics.retained_bytes().get() > 0);

        // A commit of a later round with nothing to execute: the voted anchor never mints.
        let unminted = subdag_at(2, vec![(1, vec![vec![0xFF; 16]])]);
        state.execute(&metrics, Duration::ZERO, unminted);
        assert_eq!(state.certifier.retained_bytes(), 0);
        assert_eq!(state.check_budget(&metrics), None);
        assert_eq!(metrics.retained_bytes().get(), 0);
    }

    #[test]
    fn early_arrivals_are_held_for_as_many_anchors_per_round_as_consensus_has_leaders() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let consensus = "consensus:\n  protocol: mysticeti\n  leader_count: 3\n";
        std::fs::write(file.path(), consensus).unwrap();
        let replica_parameters = ReplicaParameters::load(file.path()).unwrap();
        let public_config =
            PublicReplicaConfig::new_for_tests(4).with_parameters(replica_parameters);
        let private_config =
            PrivateReplicaConfig::new_for_benchmarks(Path::new("unused"), 4).remove(0);
        let validator = ValidatorBuilder::new(
            FakeExecutor,
            Authority::new(0),
            public_config,
            private_config,
        )
        .with_parameters(ValidatorParameters {
            finality: FinalityProtocol::SuiBaseline,
            ..Default::default()
        })
        .build()
        .unwrap();

        // One author votes for each of the three leaders of round 1: all are held.
        let mut certifier = validator.state.certifier;
        let mut retained = Vec::new();
        for leader in 0..3 {
            let vote = vote_for(BlockReference::new_test(leader, 1));
            certifier.record_arrival(BlockReference::new_test(1, 3), vote);
            retained.push(certifier.retained_bytes());
        }
        let one = retained[0];
        assert_eq!(retained, [one, 2 * one, 3 * one]);
    }

    #[test]
    fn a_quorum_of_attestations_certifies_and_mints_nothing() {
        let mut state = state(FinalityProtocol::Baseline);
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
        let (_, minted) = state.execute(&metrics, Duration::from_secs(1), subdag(executes));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // A quorum of votes delivered in a later sub-dag, one block per author.
        let votes = (0..3)
            .map(|author| {
                let vote = Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes();
                (author, vec![vote])
            })
            .collect();
        let delivering = subdag_at(2, votes);
        let carrying: Vec<_> = delivering
            .blocks
            .iter()
            .map(|block| *block.reference())
            .collect();
        let (executed, minted) = state.execute(&metrics, Duration::from_secs(4), delivering);

        assert_eq!(executed, 0);
        assert!(minted.is_none());
        let certified = state
            .certifier
            .highest_decided()
            .expect("quorum must certify");
        assert!(finalizes(certified, &checkpoint));
        // The proof records the block carrying each counted vote.
        assert_eq!(certified.proof(), carrying);
        assert!(state.certifier.pending().next().is_none());
        // Certification closed the latency metrics, by the commit sequence: minted at 1s and
        // certified at 4s, with a mean submission stamp of 2s.
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(certification.get_sample_count(), 1);
        assert_eq!(certification.get_sample_sum(), 3.0);
        let end_to_end = metrics.end_to_end_latency_s();
        assert_eq!(end_to_end.get_sample_count(), 1);
        assert_eq!(end_to_end.get_sample_sum(), 2.0);
    }

    #[test]
    fn mixed_subdags_execute_mint_and_certify_together() {
        let mut state = state(FinalityProtocol::Baseline);
        let metrics = metrics();
        let create = FakeTransaction::success(vec![], vec![ObjectId::new(1)], vec![]);
        let execute = Envelope::new(0, Payload::Execute(create.into())).to_bytes();
        let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![execute]));
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
            state.execute(&metrics, Duration::from_secs(2), subdag_at(2, blocks));

        assert_eq!(executed, 1);
        let second = minted.expect("the update must mint a second checkpoint");
        let certified = state
            .certifier
            .highest_decided()
            .expect("quorum must certify");
        assert!(finalizes(certified, &checkpoint));
        // The prior checkpoint certified and was reclaimed; only the new mint is pending.
        assert_eq!(state.certifier.pending().count(), 1);
        assert_eq!(metrics.checkpoint_pending_heights().get(), 1);

        // Certifying the second checkpoint closes its metrics from the update's stamp alone:
        // minted at 2s from a 0.5s submission, certified at 6s.
        let votes = (0..3)
            .map(|author| {
                let vote = Envelope::new(0, Payload::Attest(second.clone())).to_bytes();
                (author, vec![vote])
            })
            .collect();
        state.execute(&metrics, Duration::from_secs(6), subdag_at(3, votes));
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(certification.get_sample_count(), 2);
        assert_eq!(certification.get_sample_sum(), 2.0 + 4.0);
        let end_to_end = metrics.end_to_end_latency_s();
        assert_eq!(end_to_end.get_sample_count(), 2);
        assert_eq!(end_to_end.get_sample_sum(), 2.0 + 5.5);
        // Each became contiguous when decided: finality times the same span.
        let finality = metrics.checkpoint_finality_latency_s(FINALIZE);
        assert_eq!(finality.get_sample_count(), 2);
        assert_eq!(finality.get_sample_sum(), 2.0 + 4.0);
        assert_eq!(metrics.checkpoint_pending_heights().get(), 0);
    }

    #[test]
    fn the_sui_baseline_finalizes_on_arrival_ahead_of_the_commit() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // Votes share blocks with other payloads: the scan reads past them.
        let mut votes = quorum_of_votes(2, &checkpoint);
        let vote = Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes();
        votes[2] = block(2, 2, vec![vec![0xFF; 16], vote]);
        let decided: Vec<_> = votes
            .iter()
            .map(|block| state.count_arrivals(&metrics, Duration::from_secs(1), block))
            .collect();
        assert_eq!(decided, [false, false, true]);
        let certified = state
            .certifier
            .highest_decided()
            .expect("quorum must certify");
        assert!(finalizes(certified, &checkpoint));

        // The same votes committing later decide nothing again.
        let anchor = *votes[0].reference();
        let delivering = CommittedSubDag::new(anchor, votes);
        state.execute(&metrics, Duration::from_secs(5), delivering);
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, FAST);
        assert_eq!(certification.get_sample_count(), 1);
        assert_eq!(certification.get_sample_sum(), 1.0);
        let committed = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(committed.get_sample_count(), 0);
        // It became contiguous on arrival as well, not at the commit.
        let finality = metrics.checkpoint_finality_latency_s(FINALIZE);
        assert_eq!(finality.get_sample_count(), 1);
        assert_eq!(finality.get_sample_sum(), 1.0);
        assert_eq!(metrics.end_to_end_latency_s().get_sample_sum(), 1.0);
    }

    #[test]
    fn the_sui_baseline_also_decides_on_committed_votes_alone() {
        // Replay and blocks recovered on restart are never streamed as arrivals.
        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        let votes = quorum_of_votes(2, &checkpoint);
        let delivering = CommittedSubDag::new(*votes[0].reference(), votes);
        state.execute(&metrics, Duration::ZERO, delivering);
        let certified = state
            .certifier
            .highest_decided()
            .expect("quorum must certify");
        assert!(finalizes(certified, &checkpoint));
        let committed = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(committed.get_sample_count(), 1);
    }

    #[test]
    fn commit_counted_protocols_ignore_arrivals() {
        for protocol in [FinalityProtocol::Baseline, FinalityProtocol::A] {
            let mut state = state(protocol);
            let metrics = metrics();
            let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));
            let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

            for block in quorum_of_votes(2, &checkpoint) {
                assert!(!state.count_arrivals(&metrics, Duration::ZERO, &block));
            }
            assert_eq!(state.certifier.highest_decided(), None);
        }
    }

    #[test]
    fn votes_arriving_before_the_mint_decide_it_on_minting() {
        // A twin validator ahead of this one mints the checkpoint it will vote for.
        let mut ahead = state(FinalityProtocol::SuiBaseline);
        let (_, minted) = ahead.execute(&metrics(), Duration::ZERO, subdag(vec![creation(1)]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        for block in quorum_of_votes(2, &checkpoint) {
            assert!(!state.count_arrivals(&metrics, Duration::ZERO, &block));
        }
        let (_, minted) =
            state.execute(&metrics, Duration::from_secs(3), subdag(vec![creation(1)]));
        assert_eq!(minted, Some(checkpoint.clone()));

        // Decided at the mint by arrivals, so certification took no time.
        let certified = state
            .certifier
            .highest_decided()
            .expect("quorum must certify");
        assert!(finalizes(certified, &checkpoint));
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, FAST);
        assert_eq!(certification.get_sample_count(), 1);
        assert_eq!(certification.get_sample_sum(), 0.0);
        assert_eq!(metrics.end_to_end_latency_s().get_sample_count(), 1);
    }

    #[test]
    fn protocol_b_decides_when_a_concluded_certificate_commits() {
        let mut state = state(FinalityProtocol::B);
        let metrics = metrics();
        let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // f+1 arrivals conclude a certificate to submit, but decide nothing.
        let votes = quorum_of_votes(2, &checkpoint);
        for block in &votes[..2] {
            assert!(!state.count_arrivals(&metrics, Duration::from_secs(1), block));
        }
        let certificates = state.certifier.take_certificates();
        assert_eq!(certificates.len(), 1);
        assert_eq!(state.certifier.highest_decided(), None);

        // The certificate commits along with the votes it cites, ahead of them in the sub-dag.
        let certify = Envelope::new(0, Payload::Certify(certificates[0].clone())).to_bytes();
        let blocks = [vec![block(3, 2, vec![certify])], votes].concat();
        let delivering = CommittedSubDag::new(*blocks[0].reference(), blocks);
        state.execute(&metrics, Duration::from_secs(3), delivering);
        let certified = state
            .certifier
            .highest_decided()
            .expect("certificate must decide");
        assert!(finalizes(certified, &checkpoint));
        assert_eq!(certified.proof(), certificates[0].votes());
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!(certification.get_sample_sum(), 3.0);
    }

    #[test]
    fn protocol_c_finalizes_on_arriving_phase_one_certificates() {
        let mut state = state(FinalityProtocol::C);
        let metrics = metrics();
        let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));
        let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");

        // 2f+1 matching arrivals conclude a phase-one certificate, but decide nothing.
        for block in quorum_of_votes(2, &checkpoint) {
            assert!(!state.count_arrivals(&metrics, Duration::from_secs(1), &block));
        }
        let [phase_one] = state.certifier.take_certificates().try_into().unwrap();

        // The same certificate arriving from 2f+1 validators decides; the scan reads past
        // other payloads.
        let certify = Envelope::new(0, Payload::Certify(phase_one)).to_bytes();
        let decided: Vec<_> = (0..3)
            .map(|author| {
                let block = block(author, 3, vec![vec![0xFF; 16], certify.clone()]);
                state.count_arrivals(&metrics, Duration::from_secs(2), &block)
            })
            .collect();
        assert_eq!(decided, [false, false, true]);
        let certified = state
            .certifier
            .highest_decided()
            .expect("phase-one certificates must decide");
        assert!(finalizes(certified, &checkpoint));
        let certification = metrics.checkpoint_certification_latency_s(FINALIZE, FAST);
        assert_eq!(certification.get_sample_sum(), 2.0);
    }

    #[test]
    fn protocol_c_skips_once_2f_plus_1_skip_certificates_commit() {
        // Validators 1 and 2 each fork alone: three commitments for the same checkpoint.
        let minted_by = |authority: usize| {
            let mut twin = state(FinalityProtocol::C);
            twin.authority = Authority::from(authority);
            twin.fork = Some(ForkInjection {
                groups: vec![vec![Authority::new(1)], vec![Authority::new(2)]],
                period: NonZeroU64::MIN,
            });
            let (_, minted) = twin.execute(&metrics(), Duration::ZERO, subdag(vec![creation(1)]));
            minted.expect("executing sub-dag must mint a checkpoint")
        };
        let checkpoints = [0, 1, 2].map(minted_by);
        let mut state = state(FinalityProtocol::C);
        let metrics = metrics();
        state.execute(&metrics, Duration::ZERO, subdag(vec![creation(1)]));

        // Three voted without 2f+1 matching: the timeout concludes a skip certificate.
        let votes: Vec<_> = (0..3)
            .map(|author| {
                let vote = Payload::Attest(checkpoints[author].clone());
                block(author, 2, vec![Envelope::new(0, vote).to_bytes()])
            })
            .collect();
        for block in &votes {
            state.count_arrivals(&metrics, Duration::from_secs(1), block);
        }
        assert!(state.certifier.take_certificates().is_empty());
        state.certifier.expire(checkpoints[0].anchor());
        let [skip] = state.certifier.take_certificates().try_into().unwrap();
        assert_eq!(skip.outcome(), Outcome::Skip);

        // The votes and 2f+1 validators' skip certificates commit together.
        let certify = Envelope::new(0, Payload::Certify(skip)).to_bytes();
        let certifying = (0..3).map(|author| block(author, 3, vec![certify.clone()]));
        let blocks: Vec<_> = votes.into_iter().chain(certifying).collect();
        let delivering = CommittedSubDag::new(*blocks[0].reference(), blocks);
        state.execute(&metrics, Duration::from_secs(4), delivering);
        let decided = state
            .certifier
            .highest_decided()
            .expect("skip certificates must decide");
        assert_eq!(decided.outcome(), Outcome::Skip);
        let certification = metrics.checkpoint_certification_latency_s(SKIP, SLOW);
        assert_eq!(certification.get_sample_sum(), 4.0);
        assert_eq!(metrics.end_to_end_latency_s().get_sample_count(), 0);
    }
}
