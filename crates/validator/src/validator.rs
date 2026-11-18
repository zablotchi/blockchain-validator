// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator node: a mysticeti replica wired to an execution engine.

use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use checkpoint::{
    certifier::{
        CheckpointCertifier, CheckpointTimings, Divergence, Item, Path, Released, anchor_bytes,
    },
    checkpoint::{Checkpoint, Outcome},
};
use dag::{
    authority::Authority,
    block::{Block, BlockReference, transaction::Transaction as ConsensusTransaction},
    consensus::CommittedSubDag,
    context::Ctx,
    crypto::AsBytes,
    metrics::Metrics,
    output::{DagConsumer, DagEvent},
    storage::Storage,
    sync::network::Network,
};
use execution::{
    crypto::Digest, effects::ExecutionOutput, engine::ExecutionEngine,
    scheduler::SequentialScheduler, transaction::Transaction,
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
    metrics::{
        EVIDENCE_BUDGET, FAST, NO_MATCHING_CANDIDATE, SLOW, UNSTABLE_HEIGHTS, ValidatorMetrics,
    },
    outbox::{Kind, Outgoing, ProtocolOutbox},
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
            max_unstable_heights,
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
        eyre::ensure!(
            ValidatorParameters::MAX_UNSTABLE_HEIGHTS.contains(&max_unstable_heights),
            "max_unstable_heights must be between 8 and 16384, not {max_unstable_heights}"
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
        let mut scheduler = SequentialScheduler::new(self.engine);
        scheduler.store_mut().enable_journal(1);
        Ok(Validator {
            state: ExecutionState {
                scheduler,
                certifier,
                authority: self.authority,
                fork,
                minted: 0,
                timeouts: VecDeque::new(),
                kept: VecDeque::new(),
                kept_bytes: 0,
                max_unstable_heights: max_unstable_heights as usize,
                halt: None,
                evidence_budget: evidence_budget_bytes,
                staged: Staged::default(),
                re_minted: Vec::new(),
                divergences: 0,
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
    /// C's phase-one timeouts in deadline order, one per pending checkpoint: the driver's clock
    /// at mint (its time since start), the anchor and the generation it was minted at.
    timeouts: VecDeque<(Duration, BlockReference, u32)>,
    /// The executed heights not yet released, one per pending checkpoint and in the same order,
    /// with the store's journal of each: what a recovery undoes and executes again.
    kept: VecDeque<KeptHeight>,
    /// The bytes the kept transactions hold.
    kept_bytes: u64,
    /// The most heights `kept` may hold: executing one more halts the validator.
    max_unstable_heights: usize,
    /// Why the validator must halt, once it must.
    halt: Option<HaltReason>,
    /// The bytes the validator may retain before it halts.
    evidence_budget: u64,
    /// Own votes and certificates produced while handling the current event.
    staged: Staged,
    /// Under C, the instances re-minted while handling the current event, by anchor and
    /// generation: their timers restart.
    re_minted: Vec<(BlockReference, u32)>,
    /// The released heights this validator's state diverged at so far.
    divergences: u64,
}

/// Own votes and certificates in the order they were produced, keeping only the newest
/// generation per height and kind.
#[derive(Default)]
struct Staged {
    list: Vec<Outgoing>,
    /// The position in `list` of each height and kind.
    index: HashMap<(BlockReference, Kind), usize>,
    /// The bytes `list` takes in proposals.
    bytes: u64,
}

impl Staged {
    /// Stages `outgoing` in place of an older generation of its height and kind, if staged;
    /// discards it if a newer one is.
    fn stage(&mut self, outgoing: Outgoing) {
        match self.index.entry((outgoing.anchor, outgoing.kind)) {
            Entry::Occupied(entry) => {
                let staged = &mut self.list[*entry.get()];
                if outgoing.generation > staged.generation {
                    self.bytes = self.bytes - staged.bytes() + outgoing.bytes();
                    *staged = outgoing;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(self.list.len());
                self.bytes += outgoing.bytes();
                self.list.push(outgoing);
            }
        }
    }

    /// Empties the staging area, returning what it held in order.
    fn take(&mut self) -> Vec<Outgoing> {
        self.index.clear();
        self.bytes = 0;
        std::mem::take(&mut self.list)
    }
}

/// An executed height not yet released.
struct KeptHeight {
    anchor: BlockReference,
    height: u64,
    transactions: Vec<Transaction>,
}

impl KeptHeight {
    fn bytes(&self) -> u64 {
        let bytes: usize = self
            .transactions
            .iter()
            .map(Transaction::memory_bytes)
            .sum();
        bytes as u64
    }
}

/// Why a validator halted: it keeps running consensus, so the replica never backs up and the
/// run completes, but it executes, decides and submits nothing more.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HaltReason {
    /// The validator retained more than the evidence budget.
    EvidenceBudget { bytes: u64 },
    /// As many executed heights as the window allows are not released yet.
    UnstableHeights { heights: usize },
    /// The checkpoint anchored at `anchor` finalized a commitment that no state this validator
    /// can compute matches: more validators were Byzantine than the protocols tolerate.
    NoMatchingCandidate { anchor: BlockReference },
}

impl HaltReason {
    /// The `reason` label of the halt gauge.
    fn label(self) -> &'static str {
        match self {
            Self::EvidenceBudget { .. } => EVIDENCE_BUDGET,
            Self::UnstableHeights { .. } => UNSTABLE_HEIGHTS,
            Self::NoMatchingCandidate { .. } => NO_MATCHING_CANDIDATE,
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

        eyre::ensure!(
            self.state.fork.is_none() || storage.iter_commits().next().is_none(),
            "fork injection needs an empty WAL: restarts are out of scope"
        );
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
            let state = &mut self.state;
            replayed += state.replay_subdag(&replay_metrics, &replay_latency, subdag)? as u64;
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
        // Phase-one timeouts are kept by the driver's clock since this instant.
        let epoch = C::now();
        // Re-attest checkpoints undecided at replay: votes in flight at shutdown died
        // with the transaction queue, and a validator otherwise attests only once, so an
        // undecided checkpoint could stall forever. The certifier's per-author dedupe
        // makes resubmission idempotent — votes that did commit are simply ignored.
        let pending: Vec<_> = state.certifier.pending().cloned().collect();
        // Replayed checkpoints time from now; replay never re-mints (it fails at a divergence),
        // so they are of the first generation.
        if times_out {
            for checkpoint in &pending {
                state.arm_timeout(C::elapsed(&epoch), checkpoint.anchor(), 0);
            }
        }
        if !pending.is_empty() {
            let timestamp_ms = C::timestamp_utc().as_millis() as u64;
            let attestations = pending
                .into_iter()
                .map(|checkpoint| Outgoing::vote(timestamp_ms, 0, checkpoint))
                .collect();
            Self::submit(&mut outbox, &client, &driver_metrics, attestations).await;
        }
        // Replay released into its own metrics; the live ones start from the replayed window.
        state.settle(&driver_metrics, C::timestamp_utc());

        let mut count = *executed_sender.borrow();
        // Armed for the earliest timeout; it may outlive it, waking once for nothing.
        let mut timer = None;
        loop {
            if timer.is_none()
                && let Some(&(minted, ..)) = state.timeouts.front()
            {
                let elapsed = C::elapsed(&epoch).saturating_sub(minted);
                let remaining = phase_one_timeout.saturating_sub(elapsed);
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
            while let Some(&(minted, anchor, generation)) = state.timeouts.front()
                && C::elapsed(&epoch).saturating_sub(minted) >= phase_one_timeout
            {
                state.certifier.expire(anchor, generation);
                state.timeouts.pop_front();
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
                state.arm_timeout(C::elapsed(&epoch), checkpoint.anchor(), 0);
            }
            // Every iteration, timer-only ones included: an expiry concludes certificates.
            let outgoing = state.drain_outputs(&driver_metrics, now);
            if times_out {
                let elapsed = C::elapsed(&epoch);
                for (anchor, generation) in std::mem::take(&mut state.re_minted) {
                    state.arm_timeout(elapsed, anchor, generation);
                }
            }
            if let Some(reason) = state.halt_reason(&driver_metrics, outbox.queued_bytes()) {
                tracing::error!(?reason, "validator halted: discarding events from now on");
                driver_metrics.set_halted(reason.label());
                let _ = halted_sender.send(Some(reason));
                // Receive without executing, deciding or submitting, so that the replica never
                // backs up behind a halted validator.
                while receiver.recv().await.is_some() {}
                break;
            }
            // Votes and certificates ride this validator's own signed blocks, behind any
            // payloads an own proposal has made room for.
            Self::submit(&mut outbox, &client, &driver_metrics, outgoing).await;
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
        payloads: Vec<Outgoing>,
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
}

impl<E: ExecutionEngine> ExecutionState<E> {
    /// Executes every transaction of a committed sub-dag in canonical order, dispatches its
    /// checkpoint votes and certificates to the certifier, and returns how many transactions
    /// were executed together with the checkpoint this sub-dag minted, if any, whose vote is
    /// staged. Undecodable payloads are skipped; the choice is deterministic. Sub-dags that
    /// execute nothing are not checkpointed: their commitment is unchanged, and their count
    /// varies across validators at any executed-transaction cut. `now` stamps the mint and the
    /// vote and closes the latency metrics of checkpoints released by the mint or this
    /// sub-dag's votes and certificates, and of every client transaction in `client_latency`, a
    /// local copy of `metrics`' histogram (so per-transaction observations stay off the shared
    /// one), flushed once per sub-dag.
    fn execute_subdag(
        &mut self,
        metrics: &ValidatorMetrics,
        client_latency: &LocalHistogram,
        now: Duration,
        mut subdag: CommittedSubDag,
    ) -> (usize, Option<Checkpoint>) {
        let anchor = subdag.anchor;
        subdag.sort();
        // Votes and certificates by carrying block, in commit and payload order.
        let mut carried = Vec::new();
        // Submission stamps reduce to their sum here, while the payloads are in hand.
        let mut stamp_sum_ms = 0u64;
        let mut transactions: Vec<Transaction> = Vec::new();
        for block in &subdag.blocks {
            let mut items = Vec::new();
            for payload in block.transactions() {
                let Ok(envelope) = Envelope::from_bytes(payload.as_bytes())
                    .inspect_err(|error| tracing::warn!(?error, "skipping undecodable payload"))
                else {
                    continue;
                };
                let stamp_ms = envelope.timestamp_ms();
                match envelope.into_payload() {
                    Payload::Execute(transaction) => {
                        stamp_sum_ms += stamp_ms;
                        let submitted = Duration::from_millis(stamp_ms);
                        client_latency.observe(now.saturating_sub(submitted).as_secs_f64());
                        transactions.push(transaction);
                    }
                    Payload::Attest(vote) => items.push(Item::Vote(vote)),
                    Payload::Certify(certificate) => items.push(Item::Certificate(certificate)),
                }
            }
            if !items.is_empty() {
                carried.push((*block.reference(), items));
            }
        }
        let executed = transactions.len();
        // The commitment of the latest minted checkpoint (genesis's before the first).
        let parent = self.scheduler.store().commitment();
        if executed > 0 {
            if self.kept.len() >= self.max_unstable_heights {
                // Nothing of this sub-dag is executed or observed.
                client_latency.clear();
                let heights = self.kept.len();
                self.halt
                    .get_or_insert(HaltReason::UnstableHeights { heights });
                return (0, None);
            }
            self.scheduler.store_mut().begin_height(self.minted + 1);
            self.scheduler.execute(&transactions);
            self.apply_fork_write(self.minted + 1);
        }
        metrics.inc_executed_transactions(executed as u64);
        client_latency.flush();
        let minted = (executed > 0).then(|| {
            self.minted += 1;
            let timings = CheckpointTimings {
                minted_at: now,
                mean_timestamp_ms: stamp_sum_ms / executed as u64,
            };
            let commitment = self.scheduler.store().commitment();
            // Arrivals held for the mint may conclude it; it is released with the rest below.
            let (checkpoint, _) = self.certifier.push(anchor, commitment, parent, timings);
            let vote = Outgoing::vote(now.as_millis() as u64, 0, checkpoint.clone());
            self.staged.stage(vote);
            let kept = KeptHeight {
                anchor,
                height: self.minted,
                transactions,
            };
            self.kept_bytes += kept.bytes();
            self.kept.push_back(kept);
            checkpoint
        });
        if minted.is_none() {
            self.certifier.observe_unminted_commit(anchor);
        }
        // A vote can never reference its own delivering sub-dag's checkpoint (it is created
        // only after that sub-dag commits), so recording after minting loses nothing.
        self.certifier.record_committed_subdag(carried);
        self.settle(metrics, now);
        (executed, minted)
    }

    /// Applies this validator's fork write after executing height `height`, if it forks there.
    fn apply_fork_write(&mut self, height: u64) {
        let Some(fork) = &self.fork else {
            return;
        };
        if let Some(object) = fork.write(self.authority, height, self.scheduler.store()) {
            let store = self.scheduler.store_mut();
            store.apply(ExecutionOutput::success(vec![object]));
        }
    }

    /// Records the checkpoint votes, and certificates if the protocol counts them, that `block`
    /// carries as it enters the local DAG, if the protocol counts arrivals, and returns whether
    /// a checkpoint was released; `now` closes the released checkpoints' metrics.
    fn count_arrivals(&mut self, metrics: &ValidatorMetrics, now: Duration, block: &Block) -> bool {
        let protocol = self.certifier.protocol();
        if !protocol.counts_arrivals() {
            return false;
        }
        let certificates = protocol.counts_arriving_certificates();
        let items: Vec<_> = block
            .transactions()
            .iter()
            .filter_map(|payload| {
                let bytes = payload.as_bytes();
                if let Some(vote) = Envelope::attestation_from_bytes(bytes) {
                    Some(Item::Vote(vote))
                } else if certificates {
                    Envelope::certificate_from_bytes(bytes).map(Item::Certificate)
                } else {
                    None
                }
            })
            .collect();
        if items.is_empty() {
            return false;
        }
        self.certifier
            .record_block_arrival(*block.reference(), items);
        self.settle(metrics, now)
    }

    /// Releases what the certifier allows and closes each released checkpoint's metrics once, at
    /// `now`: certification latency and the decision accounting on the path that concluded it,
    /// finality, and end-to-end if it finalized. Drops the released heights' kept transactions
    /// and journals. A released height that diverged is recovered from: the store is rewound to
    /// its canonical state, then the later kept heights are executed and re-minted again, lowest
    /// first, releasing after each, so that a height whose canonical instance already concluded
    /// is released (and rewound in turn if it diverged) before anything above it is executed
    /// again. Stages the certificates concluded so far and the re-votes, keeps the timeouts of
    /// pending instances only, and updates the pending gauge. Returns whether a checkpoint was
    /// released.
    fn settle(&mut self, metrics: &ValidatorMetrics, now: Duration) -> bool {
        if self.halt.is_some() {
            return false;
        }
        self.stage_certificates(now);
        let mut released_any = false;
        let mut re_minted_any = false;
        // The lowest kept height that a rewind undid and that is not executed again yet.
        let mut stale = None;
        loop {
            self.certifier.release();
            let mut released = 0;
            for Released {
                outcome,
                timings,
                path,
                waited,
            } in self.certifier.take_released()
            {
                let path = match path {
                    Path::Fast => FAST,
                    Path::Slow => SLOW,
                };
                metrics.observe_decision(now, outcome, path, timings);
                metrics.observe_contiguous(now, outcome, timings);
                if waited {
                    metrics.inc_release_waits();
                }
                released += 1;
            }
            released_any |= released > 0;
            let divergence = self.certifier.take_divergence();
            // A diverged height is released last, and its rewind needs what is kept of it.
            let stable = released - usize::from(divergence.is_some());
            let mut highest = None;
            for kept in self.kept.drain(..stable) {
                self.kept_bytes -= kept.bytes();
                highest = Some(kept.height);
            }
            if let Some(height) = highest {
                self.scheduler.store_mut().prune_through(height);
            }
            if let Some(divergence) = divergence {
                if !self.rewind(divergence) {
                    break;
                }
                stale = self.kept.front().map(|kept| kept.height);
                continue;
            }
            let Some(height) = stale else {
                break;
            };
            self.re_execute(height, now);
            re_minted_any = true;
            if self.halt.is_some() {
                break;
            }
            let last = self.kept.back().map(|kept| kept.height);
            stale = Some(height + 1).filter(|next| last >= Some(*next));
        }
        if released_any || re_minted_any {
            let certifier = &self.certifier;
            self.timeouts.retain(|&(_, anchor, generation)| {
                certifier.generation(anchor) == Some(generation)
            });
        }
        metrics.set_pending_heights(self.certifier.pending().len());
        debug_assert!(
            (self.kept.iter().map(|kept| kept.anchor))
                .eq(self.certifier.pending().map(Checkpoint::anchor)),
            "kept heights align with pending checkpoints"
        );
        released_any
    }

    /// Recovers from `divergence`, at the front kept height, just released: undoes that height
    /// and every later one, then gives the store the height's canonical state, by folding in
    /// the skip marker or by executing the height again and adopting the finalized state.
    /// Returns false if no state matches the finalized commitment, which halts this validator.
    fn rewind(&mut self, Divergence { anchor, outcome }: Divergence) -> bool {
        let kept = self.kept.pop_front().expect("the diverged height is kept");
        debug_assert_eq!(kept.anchor, anchor);
        self.kept_bytes -= kept.bytes();
        self.divergences += 1;
        let store = self.scheduler.store_mut();
        store.undo_from(kept.height);
        store.begin_height(kept.height);
        match outcome {
            Outcome::Skip => store.apply_skip(&anchor_bytes(anchor)),
            Outcome::Finalize(finalized) => {
                self.scheduler.execute(&kept.transactions);
                if !self.adopt(kept.height, finalized) {
                    self.halt
                        .get_or_insert(HaltReason::NoMatchingCandidate { anchor });
                    return false;
                }
            }
        }
        self.scheduler.store_mut().prune_through(kept.height);
        true
    }

    /// Applies the fork write, if any, that takes the store, just after executing height
    /// `height`, to `finalized`: none, or one fork group's (the state transfer from the
    /// winners, emulated by recomputation). Returns false if none does.
    fn adopt(&mut self, height: u64, finalized: Digest) -> bool {
        let store = self.scheduler.store();
        let candidates = match &self.fork {
            Some(fork) => fork.candidates(height, store),
            None => vec![None],
        };
        let matching = candidates.into_iter().find(|write| match write {
            None => store.commitment() == finalized,
            Some(object) => store.preview(object) == finalized,
        });
        let Some(write) = matching else {
            return false;
        };
        if let Some(object) = write {
            let store = self.scheduler.store_mut();
            store.apply(ExecutionOutput::success(vec![object]));
        }
        true
    }

    /// Executes the kept height `height` again, after a rewind undid it, with this validator's
    /// fork write if it forks there, and re-mints its checkpoint on the recovered parent:
    /// stages the re-vote and any certificate the rebuilt instance concludes, and under C
    /// restarts its timer. Re-execution observes nothing. Halts if the validator then retains
    /// more than the evidence budget.
    fn re_execute(&mut self, height: u64, now: Duration) {
        let index = (height - self.kept[0].height) as usize;
        let parent = self.scheduler.store().commitment();
        self.scheduler.store_mut().begin_height(height);
        self.scheduler.execute(&self.kept[index].transactions);
        self.apply_fork_write(height);
        let anchor = self.kept[index].anchor;
        let commitment = self.scheduler.store().commitment();
        let re_vote = self.certifier.re_mint(anchor, commitment, parent);
        let generation = self.certifier.generation(anchor).expect("re-minted");
        let timestamp_ms = now.as_millis() as u64;
        self.staged
            .stage(Outgoing::vote(timestamp_ms, generation, re_vote));
        self.stage_certificates(now);
        if self.certifier.protocol().times_out() {
            self.re_minted.push((anchor, generation));
        }
        let bytes = self.retained_bytes();
        if bytes > self.evidence_budget {
            self.halt
                .get_or_insert(HaltReason::EvidenceBudget { bytes });
        }
    }

    /// Stages the certificates the certifier concluded, stamped `now`, each with the generation
    /// of its instance. Taken before anything is released or re-minted after they concluded.
    fn stage_certificates(&mut self, now: Duration) {
        for certificate in self.certifier.take_certificates() {
            let generation = self
                .certifier
                .generation(certificate.anchor())
                .expect("taken before its height is released");
            let timestamp_ms = now.as_millis() as u64;
            let outgoing = Outgoing::certificate(timestamp_ms, generation, certificate);
            self.staged.stage(outgoing);
        }
    }

    /// Settles, then empties the staging area for submission, in the order its payloads were
    /// produced, without those of instances re-minted since: they are on a parent this
    /// validator recovered away from. Payloads of released heights are current.
    fn drain_outputs(&mut self, metrics: &ValidatorMetrics, now: Duration) -> Vec<Outgoing> {
        self.settle(metrics, now);
        let mut outgoing = self.staged.take();
        let certifier = &self.certifier;
        outgoing.retain(|staged| {
            let current = certifier.generation(staged.anchor);
            current.is_none_or(|generation| staged.generation >= generation)
        });
        outgoing
    }

    /// Replays a committed sub-dag from the WAL, exactly as the live stream delivered it:
    /// decisions drain into the discarded `metrics`, and staged votes and certificates are
    /// dropped, since replay submits nothing. Fails if a checkpoint diverged or the validator
    /// halted: restarts are out of scope.
    fn replay_subdag(
        &mut self,
        metrics: &ValidatorMetrics,
        client_latency: &LocalHistogram,
        subdag: CommittedSubDag,
    ) -> eyre::Result<usize> {
        let (executed, _) = self.execute_subdag(metrics, client_latency, Duration::ZERO, subdag);
        self.drain_outputs(metrics, Duration::ZERO);
        eyre::ensure!(
            self.divergences == 0,
            "a checkpoint released during replay diverged: restarts are out of scope"
        );
        if let Some(reason) = self.halt_reason(metrics, 0) {
            eyre::bail!("the validator halted during replay: {reason:?}");
        }
        Ok(executed)
    }

    /// Arms C's phase-one timeout of generation `generation` of the checkpoint minted at
    /// `anchor`, at `minted` on the driver's clock, unless it was released or re-minted since.
    fn arm_timeout(&mut self, minted: Duration, anchor: BlockReference, generation: u32) {
        if self.certifier.generation(anchor) == Some(generation) {
            self.timeouts.push_back((minted, anchor, generation));
        }
    }

    /// The bytes held for recovery: the certifier's state, the kept transactions, the store's
    /// journal and the staged payloads.
    fn retained_bytes(&self) -> u64 {
        let journal = self.scheduler.store().journal_bytes() as u64;
        self.certifier.retained_bytes() + self.kept_bytes + journal + self.staged.bytes
    }

    /// The reason to halt, if one arose or the validator retains, with the `queued` bytes of
    /// own payloads waiting to be submitted, more than the evidence budget. Updates the
    /// retained-bytes gauge.
    fn halt_reason(&self, metrics: &ValidatorMetrics, queued: u64) -> Option<HaltReason> {
        let bytes = self.retained_bytes() + queued;
        metrics.set_retained_bytes(bytes);
        self.halt
            .or((bytes > self.evidence_budget).then_some(HaltReason::EvidenceBudget { bytes }))
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
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet, VecDeque},
        num::NonZeroU64,
        path::Path,
        rc::Rc,
        sync::Arc,
        time::Duration,
    };

    use checkpoint::{
        certifier::{
            CheckpointCertifier, CheckpointTimings, MAX_RECORDS_PER_BLOCK_AND_HEIGHT, anchor_bytes,
        },
        checkpoint::{Certificate, Checkpoint, Decision, Outcome},
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
        effects::ExecutionOutput,
        engine::ExecutionEngine,
        fake::{FakeExecutor, FakeTransaction},
        object::ObjectId,
        scheduler::SequentialScheduler,
        store::StateView,
        transaction::Transaction,
    };
    use prometheus::Registry;
    use replica::config::{PrivateReplicaConfig, PublicReplicaConfig, ReplicaParameters};
    use tokio::sync::{mpsc, watch};

    use crate::{
        envelope::{Envelope, Payload},
        fork::ForkInjection,
        limits::{self, CLIENT_BATCH_BYTES, framed_size},
        metrics::{
            EVIDENCE_BUDGET, FAST, FINALIZE, NO_MATCHING_CANDIDATE, SKIP, SLOW, UNSTABLE_HEIGHTS,
            ValidatorMetrics,
        },
        outbox::{Kind, Outgoing, ProtocolOutbox},
        parameters::ValidatorParameters,
        validator::{
            Driver, ExecutionState, HaltReason, Staged, Submitter, ValidatorBuilder,
            prepare_client_batches,
        },
    };

    impl<E: ExecutionEngine> ExecutionState<E> {
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

        /// Empties the staging area, returning the certificates it held.
        fn take_staged_certificates(&mut self) -> Vec<Certificate> {
            let staged = self.staged.take().into_iter();
            staged
                .filter_map(|outgoing| {
                    Envelope::certificate_from_bytes(outgoing.payload.as_bytes())
                })
                .collect()
        }
    }

    fn state(protocol: FinalityProtocol) -> ExecutionState<FakeExecutor> {
        state_with(FakeExecutor, protocol)
    }

    /// The state of validator 0 of four equal ones, executing with `engine`.
    fn state_with<E: ExecutionEngine>(engine: E, protocol: FinalityProtocol) -> ExecutionState<E> {
        let mut scheduler = SequentialScheduler::new(engine);
        scheduler.store_mut().enable_journal(1);
        ExecutionState {
            scheduler,
            certifier: CheckpointCertifier::new_for_test(protocol, vec![1; 4], 3, 0),
            authority: Authority::new(0),
            fork: None,
            minted: 0,
            timeouts: VecDeque::new(),
            kept: VecDeque::new(),
            kept_bytes: 0,
            max_unstable_heights: ValidatorParameters::default_max_unstable_heights() as usize,
            halt: None,
            evidence_budget: ValidatorParameters::default_evidence_budget_bytes(),
            staged: Staged::default(),
            re_minted: Vec::new(),
            divergences: 0,
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
            let timeout = ValidatorParameters::default_phase_one_timeout();
            Self::spawn_timing_out(state, protocol_bytes_in_flight, timeout)
        }

        /// Spawns a driver pacing own payloads at `protocol_bytes_in_flight`, whose phase-one
        /// timeout is `phase_one_timeout`.
        fn spawn_timing_out(
            state: ExecutionState<FakeExecutor>,
            protocol_bytes_in_flight: u64,
            phase_one_timeout: Duration,
        ) -> Self {
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
                phase_one_timeout,
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

        /// The next batch the driver submits, failing if none comes within ten seconds.
        async fn recv(&mut self) -> Vec<ConsensusTransaction> {
            let batch = tokio::time::timeout(Duration::from_secs(10), self.submitted.recv());
            batch
                .await
                .expect("a submission")
                .expect("the driver must be running")
        }

        /// Feeds a Byzantine author's early votes, round after round, with no commit, and
        /// returns why the driver halted.
        async fn halt_on_early_junk(&mut self) -> HaltReason {
            for round in 2..200 {
                self.feed(early_junk(round)).await;
            }
            self.halted().await
        }

        /// Why the driver halted, failing if it does not within a second.
        async fn halted(&mut self) -> HaltReason {
            let halted = self.halted.wait_for(Option::is_some);
            let halted = tokio::time::timeout(Duration::from_secs(1), halted).await;
            halted
                .expect("the driver must halt")
                .unwrap()
                .expect("halted")
        }

        /// Closes the event stream and returns what the driver submitted and its final state.
        async fn finish(
            self,
        ) -> (
            mpsc::Receiver<Vec<ConsensusTransaction>>,
            SequentialScheduler<FakeExecutor>,
            CheckpointCertifier,
        ) {
            let Self {
                events,
                submitted,
                task,
                ..
            } = self;
            drop(events);
            let (scheduler, certifier) = task.await.unwrap();
            (submitted, scheduler, certifier)
        }
    }

    /// The vote of a validator that minted `anchor`.
    fn vote_for(anchor: BlockReference) -> Checkpoint {
        let mut twin =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 0);
        let (vote, _) = twin.push(
            anchor,
            Digest::default(),
            Digest::default(),
            CheckpointTimings::default(),
        );
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
    fn forked_validators_diverge_from_the_first_forked_height_on() {
        let metrics = metrics();
        let commitments = |fork| {
            let mut state = state(FinalityProtocol::Baseline);
            state.fork = fork;
            let mut commitments = Vec::new();
            for round in 1..=3 {
                // Sub-dags executing nothing mint nothing, so they do not count as heights.
                let unminted = subdag_at(round, vec![(1, vec![vec![0xFF; 16]])]);
                state.execute(&metrics, Duration::ZERO, unminted);
                let blocks = vec![(0, vec![creation(round)])];
                let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag_at(round, blocks));
                let minted = minted.expect("executing sub-dag must mint a checkpoint");
                // Votes attest the state itself.
                assert_eq!(minted.commitment(), state.scheduler.store().commitment());
                commitments.push(minted.commitment());
            }
            commitments
        };
        let honest = commitments(None);
        let forked = commitments(Some(ForkInjection {
            groups: vec![vec![Authority::new(0)]],
            period: NonZeroU64::new(2).unwrap(),
            episodes: None,
        }));
        let diverged: Vec<_> = honest.iter().zip(&forked).map(|(a, b)| a != b).collect();
        assert_eq!(diverged, [false, true, true]);
    }

    #[test]
    fn votes_name_the_previous_heights_commitment_as_parent() {
        let mut state = state(FinalityProtocol::Baseline);
        let metrics = metrics();
        let minted: Vec<_> = (1..=3)
            .map(|round| {
                let blocks = vec![(0, vec![creation(round)])];
                let (_, minted) = state.execute(&metrics, Duration::ZERO, subdag_at(round, blocks));
                minted.expect("executing sub-dag must mint a checkpoint")
            })
            .collect();
        // The first names genesis, every later one its predecessor's commitment.
        assert_eq!(minted[0].parent(), Digest::default());
        for pair in minted.windows(2) {
            assert_eq!(pair[1].parent(), pair[0].commitment());
        }
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
                episodes: None,
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
        let HaltReason::EvidenceBudget { bytes } = driver.halt_on_early_junk().await else {
            panic!("the evidence budget must halt the driver");
        };
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

    /// A quorum of committed votes for `checkpoint`, in a sub-dag at `round`.
    fn committed_votes(round: u64, checkpoint: &Checkpoint) -> CommittedSubDag {
        let vote = Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes();
        let blocks = (0..3).map(|author| (author, vec![vote.clone()])).collect();
        subdag_at(round, blocks)
    }

    /// The transaction [`creation`] wraps.
    fn creation_transaction(id: u64) -> Transaction {
        FakeTransaction::success(vec![], vec![ObjectId::new(id)], vec![]).into()
    }

    #[test]
    fn kept_heights_and_journals_are_pruned_as_they_are_released() {
        let mut state = state(FinalityProtocol::Baseline);
        state.max_unstable_heights = 3;
        let metrics = metrics();
        let mint = |state: &mut ExecutionState<FakeExecutor>, round| {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            let (_, minted) = state.execute(&metrics, Duration::ZERO, commit);
            minted.expect("executing sub-dag must mint a checkpoint")
        };
        let mut checkpoints: Vec<_> = (1..=3).map(|round| mint(&mut state, round)).collect();
        let kept = |state: &ExecutionState<FakeExecutor>| {
            assert_eq!(state.halt, None);
            let heights: Vec<_> = state.kept.iter().map(|kept| kept.height).collect();
            let journal = state.scheduler.store().journal_bytes() as u64;
            (heights, state.kept_bytes, journal)
        };
        // Each height creates one object.
        let (heights, transactions, journal) = kept(&state);
        assert_eq!(heights, [1, 2, 3]);
        let transaction = creation_transaction(1).memory_bytes() as u64;
        assert_eq!(transactions, 3 * transaction);
        let height = journal / 3;

        // At the window cap, releasing a height makes room for the next.
        let votes = committed_votes(4, &checkpoints[0]);
        state.execute(&metrics, Duration::ZERO, votes);
        assert_eq!(kept(&state), (vec![2, 3], 2 * transaction, 2 * height));
        checkpoints.push(mint(&mut state, 5));
        assert_eq!(kept(&state), (vec![2, 3, 4], 3 * transaction, 3 * height));
        for (round, checkpoint) in (6..).zip(&checkpoints[1..]) {
            state.execute(&metrics, Duration::ZERO, committed_votes(round, checkpoint));
        }
        assert_eq!(kept(&state), (vec![], 0, 0));
        assert_eq!(state.certifier.pending().count(), 0);
    }

    #[tokio::test]
    async fn reaching_the_window_cap_halts_with_its_error() {
        let parameters = ValidatorParameters {
            max_unstable_heights: 8,
            ..Default::default()
        };
        let state = builder(parameters).build().unwrap().state;
        let mut driver = TestDriver::spawn(state, DEFAULT_IN_FLIGHT);
        // No height is decided: the ninth would exceed the window.
        for round in 1..=9 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            driver.feed(DagEvent::Commit(commit)).await;
        }

        let reason = driver.halted().await;
        assert_eq!(reason, HaltReason::UnstableHeights { heights: 8 });
        assert_eq!(driver.metrics.halted(UNSTABLE_HEIGHTS).get(), 1);
        let metrics = driver.metrics.clone();
        let (_, scheduler, certifier) = driver.finish().await;
        // The ninth sub-dag was neither executed nor observed.
        assert_eq!(certifier.pending().count(), 8);
        assert_eq!(metrics.executed_transactions().get(), 8);
        assert_eq!(metrics.client_commit_latency_s().get_sample_count(), 8);
        assert!(scheduler.store().latest(&ObjectId::new(9)).is_none());
    }

    #[test]
    fn kept_state_counts_only_execute_transactions() {
        let mut state = state(FinalityProtocol::Baseline);
        let metrics = metrics();
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(7))).to_bytes();
        let anchor = Checkpoint::new_for_test(7).anchor();
        let votes = (0..3)
            .map(|author| BlockReference::new_test(author, 8))
            .collect();
        let certificate = Certificate::new(anchor, Digest::default(), Outcome::Skip, votes);
        let certificate = Envelope::new(0, Payload::Certify(certificate)).to_bytes();
        let payloads = vec![
            creation(1),
            vote,
            certificate,
            vec![0xFF; 16 << 10],
            creation(2),
        ];

        state.execute(&metrics, Duration::ZERO, subdag(payloads));
        // As the driver does before measuring: the vote leaves for the outbox.
        state.drain_outputs(&metrics, Duration::ZERO);

        assert_eq!(state.halt_reason(&metrics, 0), None);
        let transactions: usize = [1, 2]
            .map(|id| creation_transaction(id).memory_bytes())
            .iter()
            .sum();
        let journal = state.scheduler.store().journal_bytes();
        assert!(journal > 0);
        let retained = metrics.retained_bytes().get() as usize;
        assert_eq!(retained, transactions + journal);
    }

    #[tokio::test]
    async fn queued_own_payloads_count_against_the_evidence_budget() {
        // Room for one vote in flight (votes are of fixed size).
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        let vote_bytes = framed_size(&ConsensusTransaction::new(vote.into()));
        let driver = TestDriver::spawn(state(FinalityProtocol::Baseline), vote_bytes);
        for round in 1..=5 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            driver.feed(DagEvent::Commit(commit)).await;
        }
        // Any later event measures the four votes waiting behind the first.
        driver.feed(DagEvent::Block(block(1, 6, vec![]))).await;

        let metrics = driver.metrics.clone();
        let (_, scheduler, _) = driver.finish().await;
        let transactions: usize = (1..=5)
            .map(|id| creation_transaction(id).memory_bytes())
            .sum();
        let journal = scheduler.store().journal_bytes();
        let expected = transactions + journal + 4 * vote_bytes as usize;
        assert_eq!(metrics.retained_bytes().get() as usize, expected);
    }

    #[test]
    fn max_unstable_heights_outside_the_supported_range_are_rejected() {
        let build = |max_unstable_heights| {
            builder(ValidatorParameters {
                max_unstable_heights,
                ..Default::default()
            })
            .build()
        };
        let rejected = |heights| {
            build(heights).is_err_and(|error| error.to_string().contains("max_unstable_heights"))
        };
        assert!(rejected(7));
        assert!(build(8).is_ok());
        assert!(build(16_384).is_ok());
        assert!(rejected(16_385));
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
    fn released_decisions_close_every_metric_once() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        let mint = |state: &mut ExecutionState<FakeExecutor>, round, now| {
            let subdag = subdag_at(round, vec![(0, vec![creation(round)])]);
            let (_, minted) = state.execute(&metrics, now, subdag);
            minted.expect("executing sub-dag must mint a checkpoint")
        };
        let first = mint(&mut state, 1, Duration::ZERO);
        let second = mint(&mut state, 2, Duration::from_millis(500));
        // The second height concludes on arrival at 1 s, while the first is open.
        for block in quorum_of_votes(3, &second) {
            assert!(!state.count_arrivals(&metrics, Duration::from_secs(1), &block));
        }
        // The first concludes at a commit at 2 s, and releases both.
        let vote = Envelope::new(0, Payload::Attest(first)).to_bytes();
        let votes = subdag_at(
            4,
            (0..3).map(|author| (author, vec![vote.clone()])).collect(),
        );
        state.execute(&metrics, Duration::from_secs(2), votes);

        let fast = metrics.checkpoint_certification_latency_s(FINALIZE, FAST);
        let slow = metrics.checkpoint_certification_latency_s(FINALIZE, SLOW);
        assert_eq!((fast.get_sample_count(), fast.get_sample_sum()), (1, 1.5));
        assert_eq!((slow.get_sample_count(), slow.get_sample_sum()), (1, 2.0));
        let finality = metrics.checkpoint_finality_latency_s(FINALIZE);
        assert_eq!(
            (finality.get_sample_count(), finality.get_sample_sum()),
            (2, 3.5)
        );
        assert_eq!(metrics.end_to_end_latency_s().get_sample_count(), 2);
        assert_eq!(metrics.decision_accounting(FINALIZE, FAST), (1, 1.5));
        assert_eq!(metrics.decision_accounting(FINALIZE, SLOW), (1, 2.0));
        assert_eq!(metrics.release_waits().get(), 1);
    }

    #[test]
    fn timers_never_outlive_their_pending_height() {
        let mut state = state(FinalityProtocol::C);
        let metrics = metrics();
        let within_pending = |state: &ExecutionState<FakeExecutor>| {
            assert!(state.timeouts.len() <= state.certifier.pending().len());
        };
        // Twenty heights minted and finalized one after another, before any timeout expires.
        for height in 1..=20 {
            let round = 10 * height;
            let commit = subdag_at(round, vec![(0, vec![creation(height)])]);
            let (_, minted) = state.execute(&metrics, Duration::ZERO, commit);
            let checkpoint = minted.expect("executing sub-dag must mint a checkpoint");
            state.arm_timeout(Duration::ZERO, checkpoint.anchor(), 0);
            within_pending(&state);
            for block in quorum_of_votes(round + 1, &checkpoint) {
                state.count_arrivals(&metrics, Duration::ZERO, &block);
                within_pending(&state);
            }
            let [phase_one] = state.take_staged_certificates().try_into().unwrap();
            let certify = Envelope::new(0, Payload::Certify(phase_one)).to_bytes();
            for author in 0..3 {
                let block = block(author, round + 2, vec![certify.clone()]);
                state.count_arrivals(&metrics, Duration::ZERO, &block);
                within_pending(&state);
            }
        }
        assert_eq!(state.certifier.pending().count(), 0);
        assert!(state.timeouts.is_empty());
    }

    #[test]
    fn commits_executing_nothing_drop_the_arrivals_they_pass() {
        let mut state = state(FinalityProtocol::SuiBaseline);
        let metrics = metrics();
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        state.count_arrivals(&metrics, Duration::ZERO, &block(1, 3, vec![vote]));
        assert_eq!(state.halt_reason(&metrics, 0), None);
        assert!(metrics.retained_bytes().get() > 0);

        // A commit of a later round with nothing to execute: the voted anchor never mints.
        let unminted = subdag_at(2, vec![(1, vec![vec![0xFF; 16]])]);
        state.execute(&metrics, Duration::ZERO, unminted);
        assert_eq!(state.certifier.retained_bytes(), 0);
        assert_eq!(state.halt_reason(&metrics, 0), None);
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
        // Released already, its vote is still submitted.
        let outgoing = state.drain_outputs(&metrics, Duration::from_secs(3));
        assert_eq!(votes_in(&outgoing), [checkpoint]);
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
        let certificates = state.take_staged_certificates();
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
        let [phase_one] = state.take_staged_certificates().try_into().unwrap();

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
                episodes: None,
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
        assert!(state.take_staged_certificates().is_empty());
        state.certifier.expire(checkpoints[0].anchor(), 0);
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

    /// The payload of `checkpoint`'s vote, as its author submits it.
    fn vote_payload(checkpoint: &Checkpoint) -> Vec<u8> {
        Envelope::new(0, Payload::Attest(checkpoint.clone())).to_bytes()
    }

    /// Mints one height per round in `rounds` at `now`, each creating the object of its round,
    /// draining the outputs after each as the driver does; returns the minted checkpoints.
    fn mint_rounds<E: ExecutionEngine>(
        state: &mut ExecutionState<E>,
        metrics: &ValidatorMetrics,
        rounds: impl IntoIterator<Item = u64>,
        now: Duration,
    ) -> Vec<Checkpoint> {
        rounds
            .into_iter()
            .map(|round| {
                let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
                let (_, minted) = state.execute(metrics, now, commit);
                state.drain_outputs(metrics, now);
                minted.expect("executing sub-dag must mint a checkpoint")
            })
            .collect()
    }

    /// A sub-dag at `round` with one block per author in `authors`, each voting `checkpoint`.
    fn votes_from(round: u64, authors: &[usize], checkpoint: &Checkpoint) -> CommittedSubDag {
        let blocks = authors
            .iter()
            .map(|&author| (author, vec![vote_payload(checkpoint)]))
            .collect();
        subdag_at(round, blocks)
    }

    /// The votes of authorities 1 to 3 for the height anchored at `anchor` on `parent`, each
    /// attesting a commitment of its own.
    fn non_matching_votes(anchor: BlockReference, parent: Digest) -> Vec<(usize, Vec<u8>)> {
        (1..4)
            .map(|author| {
                let commitment = Digest::new_for_test(30 + author as u8);
                let vote = Checkpoint::new(anchor, commitment, parent);
                (author, vote_payload(&vote))
            })
            .collect()
    }

    /// A sub-dag at `round` committing [`non_matching_votes`]: under A, a skip.
    fn skipping(round: u64, anchor: BlockReference, parent: Digest) -> CommittedSubDag {
        let blocks = non_matching_votes(anchor, parent)
            .into_iter()
            .map(|(author, vote)| (author, vec![vote]))
            .collect();
        subdag_at(round, blocks)
    }

    /// A sub-dag committing, for the height anchored at `anchor` on genesis, the votes of
    /// [`non_matching_votes`] at `round`, then a skip certificate citing them from each voter:
    /// under C, a skip.
    fn skip_certificates(round: u64, anchor: BlockReference) -> CommittedSubDag {
        let votes: Vec<_> = non_matching_votes(anchor, Digest::default())
            .into_iter()
            .map(|(author, vote)| block(author, round, vec![vote]))
            .collect();
        let cited = votes.iter().map(|block| *block.reference()).collect();
        let skip = Certificate::new(anchor, Digest::default(), Outcome::Skip, cited);
        let certify = Envelope::new(0, Payload::Certify(skip)).to_bytes();
        let certificates = (1..4).map(|author| block(author, round + 1, vec![certify.clone()]));
        let blocks: Vec<_> = votes.into_iter().chain(certificates).collect();
        CommittedSubDag::new(*blocks[0].reference(), blocks)
    }

    /// The votes among `outgoing`.
    fn votes_in(outgoing: &[Outgoing]) -> Vec<Checkpoint> {
        outgoing
            .iter()
            .filter_map(|outgoing| Envelope::attestation_from_bytes(outgoing.payload.as_bytes()))
            .collect()
    }

    /// Fork groups of the given authorities, forking at the first height only.
    fn forking_once(groups: &[&[usize]]) -> ForkInjection {
        ForkInjection {
            groups: groups
                .iter()
                .map(|group| group.iter().copied().map(Authority::from).collect())
                .collect(),
            period: NonZeroU64::MIN,
            episodes: Some(NonZeroU64::MIN),
        }
    }

    #[test]
    fn a_skip_undoes_the_height_folds_the_marker_and_re_executes_the_rest() {
        let mut state = state(FinalityProtocol::A);
        let metrics = metrics();
        let minted = mint_rounds(&mut state, &metrics, 1..4, Duration::ZERO);
        let skipped = minted[0].anchor();
        let skip = skipping(4, skipped, Digest::default());
        state.execute(&metrics, Duration::ZERO, skip);

        // The canonical chain: the first height's skip marker, then the other two heights.
        let mut canonical = SequentialScheduler::new(FakeExecutor);
        canonical.store_mut().apply_skip(&anchor_bytes(skipped));
        let mut commitments = vec![canonical.store().commitment()];
        for id in [2, 3] {
            canonical.execute(&[creation_transaction(id)]);
            commitments.push(canonical.store().commitment());
        }
        assert_eq!(state.scheduler.store(), canonical.store());
        // The later heights are re-minted on it, and their re-votes staged.
        let re_minted: Vec<_> = (minted[1..].iter().zip(commitments.windows(2)))
            .map(|(checkpoint, pair)| Checkpoint::new(checkpoint.anchor(), pair[1], pair[0]))
            .collect();
        assert!(state.certifier.pending().eq(&re_minted));
        let kept: Vec<_> = state.kept.iter().map(|kept| kept.height).collect();
        assert_eq!(kept, [2, 3]);
        let outgoing = state.drain_outputs(&metrics, Duration::ZERO);
        assert_eq!(votes_in(&outgoing), re_minted);
        assert!(outgoing.iter().all(|outgoing| outgoing.generation == 1));
    }

    #[test]
    fn a_losing_finalize_adopts_the_winners_state() {
        let metrics = metrics();
        // Two heights minted by `authority`, forking at the first with `groups`.
        let minted = |authority: usize, groups: &[&[usize]]| {
            let mut state = state(FinalityProtocol::A);
            state.authority = Authority::from(authority);
            state.fork = Some(forking_once(groups));
            let checkpoints = mint_rounds(&mut state, &metrics, 1..3, Duration::ZERO);
            (state, checkpoints)
        };
        // The loser recovers onto the state f+1 winners finalized for the first height.
        let adopts = |loser, winner, groups: &[&[usize]], voters: [usize; 2]| {
            let (mut state, _) = minted(loser, groups);
            let (winning, won) = minted(winner, groups);
            state.execute(&metrics, Duration::ZERO, votes_from(3, &voters, &won[0]));

            assert_eq!(state.halt, None);
            assert_eq!(
                state.scheduler.store(),
                winning.scheduler.store(),
                "{groups:?}"
            );
            assert!(
                state
                    .certifier
                    .pending()
                    .eq(winning.certifier.pending().skip(1))
            );
        };
        // A liar adopts the honest state, and an honest validator a winning group's.
        adopts(3, 0, &[&[3]], [0, 1]);
        adopts(0, 1, &[&[1, 2]], [1, 2]);
    }

    #[tokio::test]
    async fn no_matching_candidate_halts() {
        let mut driver = TestDriver::spawn(state(FinalityProtocol::A), DEFAULT_IN_FLIGHT);
        let commit = subdag_at(1, vec![(0, vec![creation(1)])]);
        driver.feed(DagEvent::Commit(commit)).await;
        // f+1 others finalize a state this validator cannot compute.
        let anchor = BlockReference::new_test(0, 1);
        let theirs = Checkpoint::new(anchor, Digest::new_for_test(9), Digest::default());
        driver
            .feed(DagEvent::Commit(votes_from(2, &[1, 2], &theirs)))
            .await;

        assert_eq!(
            driver.halted().await,
            HaltReason::NoMatchingCandidate { anchor }
        );
        assert_eq!(driver.metrics.halted(NO_MATCHING_CANDIDATE).get(), 1);
    }

    #[test]
    fn recovery_counts_nothing_twice() {
        let mut state = state(FinalityProtocol::A);
        let metrics = metrics();
        // Two heights minted at 0 and 1 s, from transactions stamped at 0.
        let [first] = mint_rounds(&mut state, &metrics, [1], Duration::ZERO)
            .try_into()
            .unwrap();
        mint_rounds(&mut state, &metrics, [2], Duration::from_secs(1));
        // The first skips at 2 s: the second is executed and minted again, then finalizes at 4 s.
        let skip = skipping(3, first.anchor(), Digest::default());
        state.execute(&metrics, Duration::from_secs(2), skip);
        let pending: Vec<_> = state.certifier.pending().cloned().collect();
        let [re_minted] = pending.try_into().expect("the second height is pending");
        let votes = votes_from(4, &[1, 2], &re_minted);
        state.execute(&metrics, Duration::from_secs(4), votes);

        // Each transaction executed once as far as clients can tell.
        assert_eq!(metrics.executed_transactions().get(), 2);
        assert_eq!(metrics.client_commit_latency_s().get_sample_count(), 2);
        // Each height decided once, timed from its first mint.
        assert_eq!(metrics.decision_accounting(SKIP, SLOW), (1, 2.0));
        assert_eq!(metrics.decision_accounting(FINALIZE, SLOW), (1, 3.0));
        let finality = |outcome| {
            let histogram = metrics.checkpoint_finality_latency_s(outcome);
            (histogram.get_sample_count(), histogram.get_sample_sum())
        };
        assert_eq!((finality(SKIP), finality(FINALIZE)), ((1, 2.0), (1, 3.0)));
        let end_to_end = metrics.end_to_end_latency_s();
        assert_eq!(
            (end_to_end.get_sample_count(), end_to_end.get_sample_sum()),
            (1, 4.0)
        );
    }

    #[test]
    fn staging_keeps_the_newest_generation_per_anchor() {
        let [first, second] = [1, 2].map(Checkpoint::new_for_test);
        let mut staged = Staged::default();
        staged.stage(Outgoing::vote(0, 0, first.clone()));
        staged.stage(Outgoing::vote(0, 0, second.clone()));
        for generation in [2, 1] {
            staged.stage(Outgoing::vote(0, generation, first.clone()));
        }
        let bytes = staged.bytes;

        let outgoing = staged.take();
        let kept: Vec<_> = outgoing.iter().map(|o| (o.anchor, o.generation)).collect();
        assert_eq!(kept, [(first.anchor(), 2), (second.anchor(), 0)]);
        assert_eq!(bytes, outgoing.iter().map(Outgoing::bytes).sum::<u64>());
        assert_eq!(
            (staged.list.len(), staged.index.len(), staged.bytes),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn stale_queued_payloads_give_way_to_re_votes() {
        // Room for one vote in flight (votes are of fixed size).
        let vote = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(1))).to_bytes();
        let vote_bytes = framed_size(&ConsensusTransaction::new(vote.into()));
        let mut driver = TestDriver::spawn(state(FinalityProtocol::A), vote_bytes);
        // Two mints: the first vote goes out, the second waits.
        for round in 1..=2 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            driver.feed(DagEvent::Commit(commit)).await;
        }
        let [first_vote] = driver.recv().await.try_into().unwrap();

        // The first height skips: the second is re-minted, and its re-vote replaces the queued
        // vote. An own proposal carrying the first vote then makes room.
        let first = BlockReference::new_test(0, 1);
        let skip = skipping(3, first, Digest::default());
        driver.feed(DagEvent::Commit(skip)).await;
        let proposal = block(0, 4, vec![first_vote.as_bytes().to_vec()]);
        driver.feed(DagEvent::Block(proposal)).await;
        let (mut submitted, _, certifier) = driver.finish().await;
        let [re_vote] = submitted.recv().await.unwrap().try_into().unwrap();
        assert!(submitted.recv().await.is_none());
        let re_vote = Envelope::attestation_from_bytes(re_vote.as_bytes()).expect("a vote");
        assert_eq!(certifier.pending().next(), Some(&re_vote));
    }

    /// A [`FakeExecutor`] counting the executions of each transaction, by its first input.
    struct CountingExecutor(Rc<RefCell<BTreeMap<ObjectId, usize>>>);

    impl ExecutionEngine for CountingExecutor {
        fn execute<V: StateView>(&self, view: &V, transaction: &Transaction) -> ExecutionOutput {
            let mut counts = self.0.borrow_mut();
            *counts.entry(transaction.inputs()[0].0).or_default() += 1;
            FakeExecutor.execute(view, transaction)
        }
    }

    /// Validator 0 forks alone at every height under A and mints heights 1 to 40; the
    /// canonical votes for heights 2 to 10 commit, then one commit mints height 41 and
    /// finalizes height 1, so that ten divergences cascade in one event. Returns the state and
    /// how many times each round's transaction executed.
    fn cascade() -> (ExecutionState<CountingExecutor>, BTreeMap<ObjectId, usize>) {
        let metrics = metrics();
        let counts = Rc::default();
        let mut state = state_with(CountingExecutor(Rc::clone(&counts)), FinalityProtocol::A);
        state.max_unstable_heights = 64;
        state.fork = Some(ForkInjection {
            groups: vec![vec![Authority::new(0)]],
            period: NonZeroU64::MIN,
            episodes: None,
        });
        mint_rounds(&mut state, &metrics, 1..=40, Duration::ZERO);
        let mut honest = self::state(FinalityProtocol::A);
        let canonical = mint_rounds(&mut honest, &metrics, 1..=10, Duration::ZERO);
        let votes: Vec<_> = canonical[1..].iter().map(vote_payload).collect();
        let blocks = (1..3).map(|author| (author, votes.clone())).collect();
        state.execute(&metrics, Duration::ZERO, subdag_at(41, blocks));
        state.drain_outputs(&metrics, Duration::ZERO);

        let mut blocks = vec![(0, vec![creation(42)])];
        blocks.extend((1..3).map(|author| (author, vec![vote_payload(&canonical[0])])));
        state.execute(&metrics, Duration::ZERO, subdag_at(42, blocks));
        assert_eq!(state.halt, None);
        assert_eq!(state.divergences, 10);
        let decided = state
            .certifier
            .highest_decided()
            .expect("decided checkpoint");
        assert_eq!(decided.anchor(), canonical[9].anchor());
        let counts = counts.borrow().clone();
        (state, counts)
    }

    #[test]
    fn cascading_recoveries_stage_one_payload_per_height() {
        let (state, _) = cascade();
        // Everything above height 1 was re-minted once: one re-vote per height.
        let anchors: BTreeSet<_> = state.staged.list.iter().map(|o| o.anchor).collect();
        assert_eq!(state.staged.list.len(), 40);
        assert_eq!(anchors.len(), 40);
        assert!(
            (state.staged.list.iter())
                .all(|outgoing| outgoing.kind == Kind::Vote && outgoing.generation == 1)
        );
    }

    #[test]
    fn cascading_recoveries_re_execute_each_height_at_most_twice() {
        let (_, counts) = cascade();
        // Height 1 executes again to adopt the canonical state, heights 2 to 10 to catch up
        // and then to adopt it, and the rest once to catch up.
        let executions = |round| counts[&ObjectId::new(round)];
        assert_eq!(executions(1), 2);
        assert!((2..=10).all(|round| executions(round) == 3));
        assert!((11..=40).chain([42]).all(|round| executions(round) == 2));
    }

    #[tokio::test(start_paused = true)]
    async fn an_expiry_with_no_later_event_submits_the_skip_certificate() {
        let timeout = Duration::from_millis(500);
        let state = state(FinalityProtocol::C);
        let mut driver = TestDriver::spawn_timing_out(state, DEFAULT_IN_FLIGHT, timeout);
        let commit = subdag_at(1, vec![(0, vec![creation(1)])]);
        driver.feed(DagEvent::Commit(commit)).await;
        driver.recv().await;
        // 2f+1 others vote on arrival, none matching: only the timeout concludes.
        let anchor = BlockReference::new_test(0, 1);
        for (author, vote) in non_matching_votes(anchor, Digest::default()) {
            driver
                .feed(DagEvent::Block(block(author, 2, vec![vote])))
                .await;
        }

        // No event follows: the timer alone wakes the driver.
        let [certificate] = driver.recv().await.try_into().unwrap();
        let certificate = Envelope::certificate_from_bytes(certificate.as_bytes());
        let certificate = certificate.expect("a certificate");
        assert_eq!(certificate.anchor(), anchor);
        assert_eq!(certificate.outcome(), Outcome::Skip);
    }

    #[tokio::test]
    async fn a_commit_that_mints_and_recovers_submits_only_the_re_vote() {
        let mut driver = TestDriver::spawn(state(FinalityProtocol::A), DEFAULT_IN_FLIGHT);
        let commit = subdag_at(1, vec![(0, vec![creation(1)])]);
        driver.feed(DagEvent::Commit(commit)).await;
        driver.recv().await;
        // One commit both mints the second height and skips the first.
        let first = BlockReference::new_test(0, 1);
        let mut blocks = vec![(0, vec![creation(2)])];
        let votes = non_matching_votes(first, Digest::default()).into_iter();
        blocks.extend(votes.map(|(author, vote)| (author, vec![vote])));
        driver.feed(DagEvent::Commit(subdag_at(2, blocks))).await;

        let (mut submitted, _, certifier) = driver.finish().await;
        let [re_vote] = submitted.recv().await.unwrap().try_into().unwrap();
        assert!(submitted.recv().await.is_none());
        let re_vote = Envelope::attestation_from_bytes(re_vote.as_bytes()).expect("a vote");
        let skipped = Digest::default().skip(&anchor_bytes(first));
        assert_eq!(re_vote.parent(), skipped);
        assert_eq!(certifier.pending().next(), Some(&re_vote));
    }

    #[tokio::test(start_paused = true)]
    async fn c_timer_restarts_at_re_mint() {
        let timeout = Duration::from_millis(500);
        let state = state(FinalityProtocol::C);
        let mut driver = TestDriver::spawn_timing_out(state, DEFAULT_IN_FLIGHT, timeout);
        let start = tokio::time::Instant::now();
        for round in 1..=2 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            driver.feed(DagEvent::Commit(commit)).await;
            driver.recv().await;
        }
        let [first, second] = [1, 2].map(|round| BlockReference::new_test(0, round));
        // Others vote for the second height on arrival, on the state a skip of the first
        // leaves, none matching: only a timeout concludes it once this validator gets there.
        let skipped = Digest::default().skip(&anchor_bytes(first));
        for (author, vote) in non_matching_votes(second, skipped) {
            driver
                .feed(DagEvent::Block(block(author, 3, vec![vote])))
                .await;
        }

        // Halfway through the timeout, 2f+1 skip certificates commit for the first height,
        // with the votes they cite: the second height is re-minted.
        tokio::time::sleep(timeout / 2).await;
        let delivering = skip_certificates(4, first);
        driver.feed(DagEvent::Commit(delivering)).await;
        let [re_vote] = driver.recv().await.try_into().unwrap();
        let re_vote = Envelope::attestation_from_bytes(re_vote.as_bytes()).expect("a vote");
        assert_eq!((re_vote.anchor(), re_vote.parent()), (second, skipped));

        // Its skip certificate waits a full timeout from the re-mint.
        let [certificate] = driver.recv().await.try_into().unwrap();
        let certificate = Envelope::certificate_from_bytes(certificate.as_bytes());
        let certificate = certificate.expect("a certificate");
        assert_eq!(
            (certificate.anchor(), certificate.outcome()),
            (second, Outcome::Skip)
        );
        assert!(start.elapsed() >= timeout / 2 + timeout);
    }

    #[test]
    fn a_divergence_during_replay_fails_the_start() {
        let mut state = state(FinalityProtocol::A);
        let metrics = metrics();
        let latency = metrics.client_commit_latency_s().local();
        let commit = subdag_at(1, vec![(0, vec![creation(1)])]);
        state.replay_subdag(&metrics, &latency, commit).unwrap();

        let skip = skipping(2, BlockReference::new_test(0, 1), Digest::default());
        let error = state.replay_subdag(&metrics, &latency, skip).unwrap_err();
        assert!(error.to_string().contains("diverged"), "{error}");

        // So does a halt: here, a window of one height.
        let mut state = self::state(FinalityProtocol::A);
        state.max_unstable_heights = 1;
        for round in 1..=2 {
            let commit = subdag_at(round, vec![(0, vec![creation(round)])]);
            let replayed = state.replay_subdag(&metrics, &latency, commit);
            let halted = replayed.is_err_and(|error| error.to_string().contains("halted"));
            assert_eq!(halted, round == 2);
        }
    }

    #[test]
    fn certificates_of_a_re_minted_instance_are_not_submitted() {
        let mut state = state(FinalityProtocol::C);
        let metrics = metrics();
        let minted = mint_rounds(&mut state, &metrics, 1..3, Duration::ZERO);
        let [first, second] = [0, 1].map(|height| minted[height].anchor());
        // The second height times out with 2f+1 non-matching votes: a skip certificate.
        for (author, vote) in non_matching_votes(second, minted[0].commitment()) {
            state.count_arrivals(&metrics, Duration::ZERO, &block(author, 3, vec![vote]));
        }
        state.drain_outputs(&metrics, Duration::ZERO);
        state.certifier.expire(second, 0);

        // Before it is submitted, the first height skips: the second is re-minted, and the
        // certificate of its old instance is dropped.
        state.execute(&metrics, Duration::ZERO, skip_certificates(4, first));
        assert_eq!(state.divergences, 1);
        let outgoing = state.drain_outputs(&metrics, Duration::ZERO);
        let drained: Vec<_> = outgoing
            .iter()
            .map(|outgoing| (outgoing.anchor, outgoing.kind, outgoing.generation))
            .collect();
        assert_eq!(drained, [(second, Kind::Vote, 1)]);
    }

    #[test]
    fn byzantine_votes_for_a_stalled_height_halt_on_the_budget() {
        let mut state = state(FinalityProtocol::Baseline);
        state.evidence_budget = SMALLEST_BUDGET;
        let metrics = metrics();
        let [stalled] = mint_rounds(&mut state, &metrics, [1], Duration::ZERO)
            .try_into()
            .unwrap();
        // A Byzantine author votes for it on fresh parents in every block, K of them in the
        // first and twice as many in the others, with no application traffic.
        let mut retained = vec![state.retained_bytes()];
        let reason = (2..1000).find_map(|round| {
            let parents = if round == 2 { 1 } else { 2 } * MAX_RECORDS_PER_BLOCK_AND_HEIGHT;
            let votes = (0..parents as u64)
                .map(|n| {
                    let parent = Digest::default().salted(1000 * round + n);
                    let vote = Checkpoint::new(stalled.anchor(), Digest::default(), parent);
                    vote_payload(&vote)
                })
                .collect();
            state.execute(&metrics, Duration::ZERO, subdag_at(round, vec![(3, votes)]));
            state.drain_outputs(&metrics, Duration::ZERO);
            let reason = state.halt_reason(&metrics, 0);
            retained.push(state.retained_bytes());
            reason
        });

        assert!(matches!(reason, Some(HaltReason::EvidenceBudget { .. })));
        // Every block adds as much as the first: K records.
        let growth: BTreeSet<_> = retained.windows(2).map(|pair| pair[1] - pair[0]).collect();
        assert_eq!(growth.len(), 1);
    }

    #[test]
    fn replayed_subdags_leave_nothing_staged() {
        let mut state = state(FinalityProtocol::Baseline);
        state.evidence_budget = SMALLEST_BUDGET;
        let metrics = metrics();
        let latency = metrics.client_commit_latency_s().local();
        let mut previous: Option<Checkpoint> = None;
        for round in 1..=20 {
            // Each sub-dag mints a height and decides the one before.
            let mut blocks = vec![(0, vec![creation(round)])];
            if let Some(previous) = &previous {
                blocks.extend((1..4).map(|author| (author, vec![vote_payload(previous)])));
            }
            let replayed = state.replay_subdag(&metrics, &latency, subdag_at(round, blocks));
            assert_eq!(replayed.unwrap(), 1);
            assert!(state.staged.list.is_empty());
            previous = state.certifier.pending().last().cloned();
        }
    }
}
