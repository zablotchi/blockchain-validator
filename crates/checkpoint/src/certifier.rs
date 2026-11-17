// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Finality: tallying checkpoint votes into decided checkpoints, released in height order.
//!
//! Each pending height has one live instance, on this validator's own parent: the tally and
//! the evidence that certificates are checked against. Votes and certificates on any other
//! parent are kept as compact records, in recording order, and replayed if a re-mint makes
//! their parent the height's own. A conclusion of the live instance is a candidate; it is
//! released, and decided, once every earlier height is released and its parent is the
//! canonical commitment of the height before.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use dag::{
    authority::{Authority, AuthoritySet},
    block::BlockReference,
    committee::{Committee, Stake},
};
use execution::crypto::Digest;

use crate::{
    checkpoint::{Certificate, Checkpoint, Decision, Outcome},
    finality::{FinalityProtocol, Thresholds},
};

/// The votes, and separately the certificates, one block may have recorded for one height: the
/// last ones in payload order. An honest block carries at most two votes and three certificates
/// for a height, and its newest, the only one that can matter, is always kept. A constant, not a
/// setting: it decides which records exist, and so which certificates are valid.
pub const MAX_RECORDS_PER_BLOCK_AND_HEIGHT: usize = 4;

/// The first message of each authority for one checkpoint, keyed by what it attests (a vote's
/// commitment, or a certificate's outcome), in count order.
struct Tally<K = Digest> {
    voters: AuthoritySet,
    /// The stake of `voters`.
    voted: Stake,
    /// The stake attesting each key, in order of first appearance.
    support: Vec<(K, Stake)>,
    /// Each counted message's key and carrying block.
    votes: Vec<(K, BlockReference)>,
}

impl<K> Default for Tally<K> {
    fn default() -> Self {
        Self {
            voters: AuthoritySet::default(),
            voted: 0,
            support: Vec::new(),
            votes: Vec::new(),
        }
    }
}

impl<K: Copy + PartialEq> Tally<K> {
    /// `voters` bounds the vote buffer: one counted vote per authority, so it allocates once
    /// and never regrows.
    fn new(voters: usize) -> Self {
        Self {
            votes: Vec::with_capacity(voters),
            ..Default::default()
        }
    }

    /// Counts the message `block` carries and returns its key's support, or `None` if the
    /// block's author was already counted.
    fn add(&mut self, stake: Stake, key: K, block: BlockReference) -> Option<Stake> {
        if !self.voters.insert(block.authority) {
            return None;
        }
        self.voted += stake;
        self.votes.push((key, block));
        match self
            .support
            .iter_mut()
            .find(|(attested, _)| *attested == key)
        {
            Some((_, support)) => {
                *support += stake;
                Some(*support)
            }
            None => {
                self.support.push((key, stake));
                Some(stake)
            }
        }
    }

    /// The key `author`'s counted message attests, if any.
    fn attested(&self, author: Authority) -> Option<K> {
        self.votes
            .iter()
            .find(|(_, block)| block.authority == author)
            .map(|(attested, _)| *attested)
    }

    /// The best supported key, with its support.
    fn leading(&self) -> Option<(K, Stake)> {
        self.support.iter().copied().max_by_key(|&(_, stake)| stake)
    }

    /// The blocks carrying the counted messages attesting `key`, or all of them, in count order.
    fn blocks(&self, key: Option<K>) -> Vec<BlockReference> {
        self.votes
            .iter()
            .filter(|(attested, _)| key.is_none_or(|key| *attested == key))
            .map(|(_, block)| *block)
            .collect()
    }
}

impl Tally {
    /// The blocks carrying the votes backing `outcome`, in count order.
    fn proof(&self, outcome: Outcome) -> Vec<BlockReference> {
        self.blocks(match outcome {
            Outcome::Finalize(finalized) => Some(finalized),
            Outcome::Skip => None,
        })
    }
}

/// A vote or certificate a block carries, in payload order.
pub enum Item {
    Vote(Checkpoint),
    Certificate(Certificate),
}

impl Item {
    /// What one block records at most one of: a kind, a height and a parent.
    fn key(&self) -> (bool, BlockReference, Digest) {
        match self {
            Self::Vote(vote) => (false, vote.anchor(), vote.parent()),
            Self::Certificate(certificate) => (true, certificate.anchor(), certificate.parent()),
        }
    }
}

/// The items of one block that are recorded, in payload order: per height, the last vote per
/// parent and, of those, the last [`MAX_RECORDS_PER_BLOCK_AND_HEIGHT`]; likewise for
/// certificates. A function of the block alone, so every validator records the same.
fn select(items: Vec<Item>) -> Vec<Item> {
    if items.len() <= 1 {
        return items;
    }
    let mut seen = BTreeSet::new();
    let mut kept_per_height = BTreeMap::new();
    let mut selected: Vec<_> = items
        .into_iter()
        .rev()
        .filter(|item| {
            let (kind, anchor, parent) = item.key();
            if !seen.insert((kind, anchor, parent)) {
                return false;
            }
            let kept = kept_per_height.entry((kind, anchor)).or_insert(0);
            *kept += 1;
            *kept <= MAX_RECORDS_PER_BLOCK_AND_HEIGHT
        })
        .collect();
    selected.reverse();
    selected
}

/// A vote or certificate counted on arrival, with its carrying block, held until the mint of
/// the checkpoint it is for.
enum Arrival {
    Vote(Checkpoint, BlockReference),
    Certificate(Certificate, BlockReference),
}

impl Arrival {
    fn block(&self) -> BlockReference {
        match self {
            Self::Vote(_, block) | Self::Certificate(_, block) => *block,
        }
    }

    /// The bytes holding it retains: the arrival, and a certificate's cited votes.
    fn bytes(&self) -> u64 {
        let cited = match self {
            Self::Vote(..) => 0,
            Self::Certificate(certificate, _) => certificate.votes().len(),
        };
        (size_of::<Self>() + cited * size_of::<BlockReference>()) as u64
    }
}

/// A vote or certificate on another parent than its pending checkpoint's, kept in case a
/// re-mint makes that parent the checkpoint's own.
enum Record {
    Vote {
        block: BlockReference,
        commitment: Digest,
        parent: Digest,
        committed: bool,
    },
    Certificate {
        block: BlockReference,
        parent: Digest,
        outcome: Outcome,
        votes: Box<[BlockReference]>,
        committed: bool,
    },
}

impl Record {
    fn parent(&self) -> Digest {
        match self {
            Self::Vote { parent, .. } | Self::Certificate { parent, .. } => *parent,
        }
    }

    /// The bytes it retains: the record, and a certificate's cited votes.
    fn bytes(&self) -> u64 {
        let cited = match self {
            Self::Vote { .. } => 0,
            Self::Certificate { votes, .. } => votes.len(),
        };
        (size_of::<Self>() + cited * size_of::<BlockReference>()) as u64
    }
}

/// The latest processed commit, minted or not: its anchor round, and the anchors processed at
/// that round. Commits arrive in round order, so no anchor at or below it is processed again.
#[derive(Default)]
struct Cursor {
    round: u64,
    anchors: Vec<BlockReference>,
}

impl Cursor {
    fn passed(&self, anchor: BlockReference) -> bool {
        anchor.round < self.round || (anchor.round == self.round && self.anchors.contains(&anchor))
    }
}

/// Timing constants carried from mint to decision, for the caller's latency metrics.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct CheckpointTimings {
    /// The caller's clock at mint.
    pub minted_at: Duration,
    /// Mean submission stamp of the checkpointed transactions, in milliseconds since epoch.
    pub mean_timestamp_ms: u64,
}

/// Which evidence concluded a height.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Path {
    /// Blocks as they arrived, including arrivals held for the mint.
    Fast,
    /// The commit sequence.
    Slow,
}

/// A height released in order, and so decided: its outcome, its mint timings and the path
/// that concluded it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Released {
    pub outcome: Outcome,
    pub timings: CheckpointTimings,
    pub path: Path,
    /// Whether it was concluded before an earlier release, which could not release it: it
    /// waited for a predecessor.
    pub waited: bool,
}

/// A released height whose canonical outcome differs from this validator's commitment: this
/// validator's state diverged there, and so at every later height.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Divergence {
    pub anchor: BlockReference,
    pub outcome: Outcome,
}

/// The live instance's conclusion, released once every earlier height is and its parent is
/// canonical.
struct Candidate {
    outcome: Outcome,
    proof: Vec<BlockReference>,
    path: Path,
    /// The releases made before it was concluded.
    releases: u64,
}

/// A minted checkpoint: this validator's own value, its live instance and the records on
/// other parents, until released.
struct PendingCheckpoint {
    local: Checkpoint,
    timings: CheckpointTimings,
    /// Re-mints so far: C's timeouts of other generations are ignored.
    generation: u32,
    /// `None` once concluded: the live instance concludes, and certifies, at most once.
    tally: Option<Tally>,
    /// Whether C's phase-one timeout expired.
    expired: bool,
    /// Under certifying protocols; `None` once a candidate is concluded.
    certification: Option<Box<Certification>>,
    candidate: Option<Candidate>,
    /// Votes and certificates on other parents, in recording order: the order a replay
    /// follows, so that each certificate is checked only against the votes recorded before it.
    foreign: Vec<Record>,
    /// The bytes `foreign` retains.
    foreign_bytes: u64,
}

/// What the live instance's certificates are checked and counted against.
#[derive(Default)]
struct Certification {
    /// The committed votes by carrying block: the only votes a committed certificate may cite.
    committed: BTreeMap<BlockReference, Digest>,
    /// The committed valid skip certificates.
    skips: Tally<()>,
    /// Under C, the votes counted on arrival by carrying block: the only votes an arriving
    /// certificate may cite.
    arrived: BTreeMap<BlockReference, Digest>,
    /// Under C, the valid phase-one certificates counted on arrival.
    phase_one: Tally,
}

impl PendingCheckpoint {
    fn round(&self) -> u64 {
        self.local.round()
    }

    /// Keeps `record`, on another parent than this checkpoint's.
    fn keep(&mut self, record: Record) {
        self.foreign_bytes += record.bytes();
        self.foreign.push(record);
    }

    /// The bytes held for recovery: the live instance's evidence and the records.
    fn retained_bytes(&self) -> u64 {
        let votes = self.certification.as_deref().map_or(0, |certification| {
            certification.committed.len() + certification.arrived.len()
        });
        self.foreign_bytes + (votes * size_of::<(BlockReference, Digest)>()) as u64
    }
}

/// The bytes a skip of the height anchored at `anchor` folds into the canonical commitment:
/// its author, round and digest.
fn anchor_bytes(anchor: BlockReference) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&(anchor.authority.index() as u64).to_be_bytes());
    bytes[8..16].copy_from_slice(&anchor.round.to_be_bytes());
    bytes[16..].copy_from_slice(anchor.digest.as_ref());
    bytes
}

pub struct CheckpointCertifier {
    committee: Arc<Committee>,
    protocol: FinalityProtocol,
    thresholds: Thresholds,
    /// The minted but unreleased window, in commit order.
    pending: VecDeque<PendingCheckpoint>,
    /// The highest released checkpoint; `None` until the first release.
    watermark: Option<Decision>,
    /// The canonical commitment at the watermark: genesis's until the first release.
    canon: Digest,
    /// Under the emulated fork injection: `canon` stays at genesis and nothing diverges.
    emulated_forks: bool,
    /// The released height whose state diverged, until taken: nothing is released meanwhile.
    divergence: Option<Divergence>,
    /// Leaders per consensus round: an honest author votes for at most this many anchors of
    /// one round.
    leaders: NonZeroUsize,
    cursor: Cursor,
    /// Arrivals for anchors not processed yet, in arrival order.
    early: BTreeMap<BlockReference, Vec<Arrival>>,
    /// The distinct anchors of each round that each author's held arrivals are for, in
    /// arrival order: at most `leaders`.
    early_quota: BTreeMap<(u64, Authority), Vec<BlockReference>>,
    /// The bytes `early` retains.
    early_bytes: u64,
    /// Concluded certificates not yet taken for submission.
    certificates: Vec<Certificate>,
    /// Released heights not yet taken, in height order.
    released: Vec<Released>,
    /// Calls to [`release`](CheckpointCertifier::release) so far.
    releases: u64,
    /// Every decision by anchor, with its proof, recorded at release, so that tests can compare
    /// them across validators.
    #[cfg(any(test, feature = "decision-log"))]
    decision_log: BTreeMap<BlockReference, (Outcome, Vec<BlockReference>)>,
}

impl CheckpointCertifier {
    /// A certifier deciding with `protocol`; `quorum` and `leaders` are the consensus
    /// protocol's quorum threshold and leaders per round.
    pub fn new(
        committee: Arc<Committee>,
        protocol: FinalityProtocol,
        quorum: Stake,
        leaders: NonZeroUsize,
    ) -> Self {
        Self {
            thresholds: Thresholds::new(committee.total_stake(), quorum),
            committee,
            protocol,
            pending: VecDeque::new(),
            watermark: None,
            canon: Digest::default(),
            emulated_forks: false,
            divergence: None,
            leaders,
            cursor: Cursor::default(),
            early: BTreeMap::new(),
            early_quota: BTreeMap::new(),
            early_bytes: 0,
            certificates: Vec::new(),
            released: Vec::new(),
            releases: 0,
            #[cfg(any(test, feature = "decision-log"))]
            decision_log: BTreeMap::new(),
        }
    }

    /// Under the emulated fork injection, votes name the genesis digest as their parent and a
    /// skip changes no state: the canonical commitment stays at genesis and nothing diverges.
    pub fn with_emulated_forks(mut self) -> Self {
        self.emulated_forks = true;
        self
    }

    pub fn protocol(&self) -> FinalityProtocol {
        self.protocol
    }

    /// Mints this validator's checkpoint for the sub-dag anchored at `anchor`, on `parent` (the
    /// commitment it minted at the previous height), and returns it, ready to submit as this
    /// validator's vote, with the outcome if arrivals held for it conclude it. Only votes and
    /// certificates on `parent` count towards it. The timings ride along and are surrendered at
    /// release. Only arrivals can outrun minting: a vote or certificate commits after the
    /// sub-dag it is for, which we process first. Releases nothing.
    pub fn push(
        &mut self,
        anchor: BlockReference,
        commitment: Digest,
        parent: Digest,
        timings: CheckpointTimings,
    ) -> (Checkpoint, Option<Outcome>) {
        let held = self.advance_cursor(anchor);
        let local = Checkpoint::new(anchor, commitment, parent);
        self.pending.push_back(PendingCheckpoint {
            local: local.clone(),
            timings,
            generation: 0,
            tally: Some(Tally::new(self.committee.len())),
            expired: false,
            certification: self.protocol.certifies().then(Box::default),
            candidate: None,
            foreign: Vec::new(),
            foreign_bytes: 0,
        });
        let mut concluded = None;
        for arrival in held {
            let outcome = match arrival {
                Arrival::Vote(vote, block) => self.record_vote(block, vote, false),
                Arrival::Certificate(certificate, block) => {
                    self.record_certificate_item(block, certificate, false)
                }
            };
            concluded = concluded.or(outcome);
        }
        (local, concluded.map(|(outcome, _)| outcome))
    }

    /// Moves past the commit anchored at `anchor`, which minted nothing (it executed nothing):
    /// arrivals for it, or for anything it passes, are never held or counted.
    pub fn observe_unminted_commit(&mut self, anchor: BlockReference) {
        self.advance_cursor(anchor);
    }

    /// Re-mints the pending checkpoint at `anchor` with `commitment` on `parent`, the canonical
    /// commitment of the height before, once this validator recovered onto it, and returns the
    /// re-vote. Its generation increments, its instance and everything on the old parent are
    /// dropped (a parent recovered away from can never become canonical), and the instance is
    /// rebuilt from the votes and certificates recorded on `parent`, in recording order, as live
    /// processing would have built it. Releases nothing.
    pub fn re_mint(
        &mut self,
        anchor: BlockReference,
        commitment: Digest,
        parent: Digest,
    ) -> Checkpoint {
        let index = self
            .position(anchor)
            .expect("only a pending checkpoint is re-minted");
        let voters = self.committee.len();
        let certifies = self.protocol.certifies();
        let entry = &mut self.pending[index];
        debug_assert_ne!(entry.local.parent(), parent, "a re-mint changes the parent");
        entry.local = Checkpoint::new(anchor, commitment, parent);
        entry.generation += 1;
        entry.tally = Some(Tally::new(voters));
        entry.expired = false;
        entry.certification = certifies.then(Box::default);
        entry.candidate = None;
        let (replayed, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut entry.foreign)
            .into_iter()
            .partition(|record| record.parent() == parent);
        entry.foreign_bytes = kept.iter().map(Record::bytes).sum();
        entry.foreign = kept;
        for record in replayed {
            match record {
                Record::Vote {
                    block,
                    commitment,
                    committed,
                    ..
                } => self.live_vote(index, block, commitment, committed),
                Record::Certificate {
                    block,
                    outcome,
                    votes,
                    committed,
                    ..
                } => self.live_certificate(index, block, outcome, &votes, committed),
            };
        }
        self.pending[index].local.clone()
    }

    /// The bytes this certifier retains for recovery, against the caller's evidence budget:
    /// the held early arrivals, and each pending checkpoint's evidence and records.
    pub fn retained_bytes(&self) -> u64 {
        self.early_bytes
            + self
                .pending
                .iter()
                .map(PendingCheckpoint::retained_bytes)
                .sum::<u64>()
    }

    /// This validator's checkpoints not yet released, in commit order.
    pub fn pending(&self) -> impl ExactSizeIterator<Item = &Checkpoint> {
        self.pending.iter().map(|entry| &entry.local)
    }

    /// The generation of the pending checkpoint at `anchor` (0 until re-minted), or `None`
    /// once released.
    pub fn generation(&self, anchor: BlockReference) -> Option<u32> {
        self.position(anchor)
            .map(|index| self.pending[index].generation)
    }

    /// Records the votes and certificates `block` carries as it enters the local DAG, given in
    /// payload order: votes if the protocol counts arrivals, phase-one certificates if it counts
    /// arriving certificates (valid ones from 2f+1 decide, C's fast path). Those for checkpoints
    /// not minted yet count from the mint. Releases nothing.
    pub fn record_block_arrival(&mut self, block: BlockReference, items: Vec<Item>) {
        for item in select(items) {
            match item {
                Item::Vote(vote) => self.record_vote(block, vote, false),
                Item::Certificate(certificate) => {
                    self.record_certificate_item(block, certificate, false)
                }
            };
        }
    }

    /// Records a committed sub-dag's votes and certificates, given per carrying block in commit
    /// order and in payload order within a block: every vote first, then every certificate,
    /// since certificates cite votes from their causal history. Votes ride their author's own
    /// signed blocks, so no authority can forge another's. Releases nothing.
    pub fn record_committed_subdag(
        &mut self,
        blocks: impl IntoIterator<Item = (BlockReference, Vec<Item>)>,
    ) {
        let mut certificates = Vec::new();
        for (block, items) in blocks {
            for item in select(items) {
                match item {
                    Item::Vote(vote) => {
                        self.record_vote(block, vote, true);
                    }
                    Item::Certificate(certificate) => certificates.push((block, certificate)),
                }
            }
        }
        for (block, certificate) in certificates {
            self.record_certificate_item(block, certificate, true);
        }
    }

    /// Records the committed vote `block` carries, then releases: one item of
    /// [`record_committed_subdag`](CheckpointCertifier::record_committed_subdag), for tests and
    /// benches. Returns the outcome and the mint timings exactly when the vote concludes its
    /// checkpoint.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn record(
        &mut self,
        block: BlockReference,
        checkpoint: Checkpoint,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let concluded = self.record_vote(block, checkpoint, true);
        self.release();
        concluded
    }

    /// Records the vote `block` carries as it arrives, then releases: one item of
    /// [`record_block_arrival`](CheckpointCertifier::record_block_arrival). Returns like
    /// [`record`](CheckpointCertifier::record).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn record_arrival(
        &mut self,
        block: BlockReference,
        checkpoint: Checkpoint,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let concluded = self.record_vote(block, checkpoint, false);
        self.release();
        concluded
    }

    /// Records the certificate `block` carries as it arrives, then releases: one item of
    /// [`record_block_arrival`](CheckpointCertifier::record_block_arrival). Returns like
    /// [`record`](CheckpointCertifier::record).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn record_arriving_certificate(
        &mut self,
        block: BlockReference,
        certificate: Certificate,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let concluded = self.record_certificate_item(block, certificate, false);
        self.release();
        concluded
    }

    /// Records the committed certificate `block` carries, then releases: one item of
    /// [`record_committed_subdag`](CheckpointCertifier::record_committed_subdag). Returns like
    /// [`record`](CheckpointCertifier::record).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn record_certificate(
        &mut self,
        block: BlockReference,
        certificate: &Certificate,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let concluded = self.record_certificate_item(block, certificate.clone(), true);
        self.release();
        concluded
    }

    /// Expires C's phase-one timeout for generation `generation` of the checkpoint minted at
    /// `anchor`: from now on its tally concludes in a skip certificate once 2f+1 voted without
    /// 2f+1 matching, at once if they already did. A timeout of another generation is ignored:
    /// a re-mint restarts the timer.
    pub fn expire(&mut self, anchor: BlockReference, generation: u32) {
        let Some(index) = self.position(anchor) else {
            return;
        };
        let entry = &mut self.pending[index];
        if entry.generation != generation {
            return;
        }
        entry.expired = true;
        let Some(tally) = &entry.tally else {
            return;
        };
        let Some((commitment, support)) = tally.leading() else {
            return;
        };
        let concluded =
            self.protocol
                .conclude(self.thresholds, commitment, support, tally.voted, true);
        if let Some(outcome) = concluded {
            // Only certifying protocols time out: the conclusion is a certificate, on no path.
            let candidate = self.conclude(index, outcome, Path::Fast);
            debug_assert!(candidate.is_none());
        }
    }

    /// Releases, in height order, every pending checkpoint whose live instance concluded, whose
    /// parent is canonical and all of whose predecessors are released: each is decided, and
    /// advances the canonical commitment to what it finalized, or folds its skip in. Stops at
    /// the first one whose canonical commitment differs from this validator's: that divergence
    /// must be taken before anything more is released.
    pub fn release(&mut self) {
        while self.divergence.is_none()
            && self.pending.front().is_some_and(|entry| {
                entry.candidate.is_some() && entry.local.parent() == self.canon
            })
        {
            let entry = self.pending.pop_front().expect("releasable entry");
            let candidate = entry.candidate.expect("releasable entry");
            let local = entry.local;
            let anchor = local.anchor();
            let outcome = candidate.outcome;
            if let Outcome::Finalize(finalized) = outcome
                && local.commitment() != finalized
            {
                tracing::error!(
                    ?anchor,
                    "local checkpoint diverges from the finalized checkpoint"
                );
            }
            if !self.emulated_forks {
                self.canon = match outcome {
                    Outcome::Finalize(finalized) => finalized,
                    Outcome::Skip => self.canon.skip(&anchor_bytes(anchor)),
                };
                if self.canon != local.commitment() {
                    self.divergence = Some(Divergence { anchor, outcome });
                }
            }
            #[cfg(any(test, feature = "decision-log"))]
            {
                let decided = (outcome, candidate.proof.clone());
                let previous = self.decision_log.insert(anchor, decided);
                debug_assert!(previous.is_none(), "{anchor:?} decided twice");
            }
            self.released.push(Released {
                outcome,
                timings: entry.timings,
                path: candidate.path,
                waited: candidate.releases < self.releases,
            });
            self.watermark = Some(Decision::new(anchor, outcome, candidate.proof));
        }
        self.releases += 1;
    }

    /// The checkpoints released since the last call, in height order: when a client can use
    /// them, since commitments chain.
    pub fn take_released(&mut self) -> impl Iterator<Item = Released> + '_ {
        self.released.drain(..)
    }

    /// The released checkpoint at which this validator's state diverged, if any since the last
    /// call. Release resumes once taken, at the first pending checkpoint on the canonical
    /// parent.
    pub fn take_divergence(&mut self) -> Option<Divergence> {
        self.divergence.take()
    }

    /// The certificates this validator's tallies concluded since the last call, to submit
    /// through consensus.
    pub fn take_certificates(&mut self) -> Vec<Certificate> {
        std::mem::take(&mut self.certificates)
    }

    /// The highest released checkpoint: it and every earlier one are decided.
    pub fn highest_decided(&self) -> Option<&Decision> {
        self.watermark.as_ref()
    }

    #[cfg(any(test, feature = "decision-log"))]
    pub fn decision_log(&self) -> &BTreeMap<BlockReference, (Outcome, Vec<BlockReference>)> {
        &self.decision_log
    }

    fn decided_round(&self) -> u64 {
        self.watermark
            .as_ref()
            .map_or(0, |decision| decision.round())
    }

    /// The window index of the checkpoint minted at `anchor`, if pending.
    fn position(&self, anchor: BlockReference) -> Option<usize> {
        // Window entries are in commit order, so anchor rounds are non-decreasing: binary
        // search to the round, then walk only the same-round (multi-leader) run.
        let start = self
            .pending
            .partition_point(|entry| entry.round() < anchor.round);
        self.pending
            .range(start..)
            .take_while(|entry| entry.round() == anchor.round)
            .position(|entry| entry.local.anchor() == anchor)
            .map(|offset| start + offset)
    }

    /// Moves the cursor to the processed commit anchored at `anchor`, dropping the arrivals and
    /// quotas of the rounds it passes, and returns the arrivals held for `anchor`.
    fn advance_cursor(&mut self, anchor: BlockReference) -> Vec<Arrival> {
        if anchor.round > self.cursor.round {
            self.cursor.round = anchor.round;
            self.cursor.anchors.clear();
            while let Some(entry) = self.early.first_entry()
                && entry.key().round < anchor.round
            {
                self.early_bytes -= entry.remove().iter().map(Arrival::bytes).sum::<u64>();
            }
            while let Some(entry) = self.early_quota.first_entry()
                && entry.key().0 < anchor.round
            {
                entry.remove();
            }
        }
        debug_assert_eq!(
            anchor.round, self.cursor.round,
            "commits arrive in round order"
        );
        self.cursor.anchors.push(anchor);
        let held = self.early.remove(&anchor).unwrap_or_default();
        self.early_bytes -= held.iter().map(Arrival::bytes).sum::<u64>();
        held
    }

    /// Holds an arrival for `anchor`, not processed yet, to count from its mint, if an honest
    /// author could have sent it: honest authors vote only for anchors they committed, so from
    /// blocks of later rounds, and for at most `leaders` anchors of one round, whichever of
    /// their blocks carries the votes. Other arrivals are dropped.
    fn hold(&mut self, anchor: BlockReference, arrival: Arrival) {
        let block = arrival.block();
        let eligible = !self.cursor.passed(anchor)
            && anchor.round < block.round
            && self.within_quota(anchor, block.authority);
        if eligible {
            self.early_bytes += arrival.bytes();
            self.early.entry(anchor).or_default().push(arrival);
        } else if anchor.round > self.decided_round() {
            let author = block.authority;
            tracing::warn!(%author, ?anchor, "checkpoint arrival for an unknown anchor");
        }
    }

    /// Whether `author` may have arrivals held for `anchor`: it already has, or has them held
    /// for fewer than `leaders` anchors of that round, in which case `anchor` takes a place.
    fn within_quota(&mut self, anchor: BlockReference, author: Authority) -> bool {
        let anchors = self.early_quota.entry((anchor.round, author)).or_default();
        if anchors.contains(&anchor) {
            return true;
        }
        if anchors.len() == self.leaders.get() {
            return false;
        }
        anchors.push(anchor);
        true
    }

    /// Records the vote `block` carries, committed or arriving (if the protocol counts
    /// arrivals): into its pending checkpoint's live instance if on its parent, as a record if
    /// on another; an arrival for a checkpoint not minted yet is held. Returns the outcome and
    /// the mint timings exactly when it concludes the checkpoint.
    fn record_vote(
        &mut self,
        block: BlockReference,
        vote: Checkpoint,
        committed: bool,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if !committed && !self.protocol.counts_arrivals() {
            return None;
        }
        let voted_anchor = vote.anchor();
        let Some(index) = self.position(voted_anchor) else {
            if !committed {
                self.hold(voted_anchor, Arrival::Vote(vote, block));
            } else if voted_anchor.round > self.decided_round() {
                let author = block.authority;
                tracing::warn!(%author, ?voted_anchor, "checkpoint vote for an unknown anchor");
            }
            return None;
        };
        let entry = &mut self.pending[index];
        if vote.parent() != entry.local.parent() {
            entry.keep(Record::Vote {
                block,
                commitment: vote.commitment(),
                parent: vote.parent(),
                committed,
            });
            return None;
        }
        self.live_vote(index, block, vote.commitment(), committed)
    }

    /// Records the certificate `block` carries, committed (under certifying protocols) or
    /// arriving (phase-one certificates, if the protocol counts arriving certificates; skip
    /// certificates only count once committed), like
    /// [`record_vote`](CheckpointCertifier::record_vote).
    fn record_certificate_item(
        &mut self,
        block: BlockReference,
        certificate: Certificate,
        committed: bool,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let counted = if committed {
            self.protocol.certifies()
        } else {
            self.protocol.counts_arriving_certificates() && certificate.outcome() != Outcome::Skip
        };
        if !counted {
            return None;
        }
        let Some(index) = self.position(certificate.anchor()) else {
            if !committed {
                let anchor = certificate.anchor();
                self.hold(anchor, Arrival::Certificate(certificate, block));
            }
            return None;
        };
        let entry = &mut self.pending[index];
        if certificate.parent() != entry.local.parent() {
            entry.keep(Record::Certificate {
                block,
                parent: certificate.parent(),
                outcome: certificate.outcome(),
                votes: certificate.votes().into(),
                committed,
            });
            return None;
        }
        self.live_certificate(
            index,
            block,
            certificate.outcome(),
            certificate.votes(),
            committed,
        )
    }

    /// Counts the vote `block` carries for the live instance of the pending checkpoint at
    /// `index`: a committed vote backs certificates under certifying protocols and is tallied
    /// otherwise; an arriving vote is tallied, and under C also backs arriving certificates,
    /// even once this validator's own tally concluded. Returns like
    /// [`count`](CheckpointCertifier::count).
    fn live_vote(
        &mut self,
        index: usize,
        block: BlockReference,
        commitment: Digest,
        committed: bool,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let backs_certificates = if committed {
            self.protocol.certifies()
        } else {
            self.protocol.counts_arriving_certificates()
        };
        if backs_certificates && let Some(certification) = &mut self.pending[index].certification {
            let votes = match committed {
                true => &mut certification.committed,
                false => &mut certification.arrived,
            };
            votes.entry(block).or_insert(commitment);
        }
        if committed && self.protocol.certifies() {
            return None;
        }
        let path = if committed { Path::Slow } else { Path::Fast };
        self.count(index, commitment, block, path)
    }

    /// Counts a vote into the live tally of the pending checkpoint at `index`, and returns the
    /// outcome and mint timings exactly when it concludes the checkpoint, on `path`.
    fn count(
        &mut self,
        index: usize,
        commitment: Digest,
        block: BlockReference,
        path: Path,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let entry = &mut self.pending[index];
        // Concluded: an observed conclusion or certificate can never change.
        let tally = entry.tally.as_mut()?;
        let author = block.authority;
        let voted_anchor = entry.local.anchor();
        let stake = self
            .committee
            .get_stake(author)
            .expect("Authority not found");
        let Some(support) = tally.add(stake, commitment, block) else {
            if tally.attested(author) != Some(commitment) {
                tracing::warn!(%author, ?voted_anchor, "conflicting checkpoint vote");
            }
            return None;
        };
        let outcome = self.protocol.conclude(
            self.thresholds,
            commitment,
            support,
            tally.voted,
            entry.expired,
        )?;
        self.conclude(index, outcome, path)
    }

    /// Concludes the live tally of the pending checkpoint at `index` in `outcome`: a
    /// certificate to submit under certifying protocols, the candidate otherwise, returned like
    /// [`count`](CheckpointCertifier::count).
    fn conclude(
        &mut self,
        index: usize,
        outcome: Outcome,
        path: Path,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let entry = &mut self.pending[index];
        let proof = entry.tally.take().expect("tally concluded").proof(outcome);
        if self.protocol.certifies() {
            let local = &entry.local;
            let certificate = Certificate::new(local.anchor(), local.parent(), outcome, proof);
            self.certificates.push(certificate);
            return None;
        }
        Some(self.set_candidate(index, outcome, proof, path))
    }

    /// Counts the certificate `block` carries for the live instance of the pending checkpoint
    /// at `index`, with `outcome` and citing `votes`. A committed one, if valid against the
    /// committed votes, decides at once if it finalizes, even after its author's skip
    /// certificate committed; the first valid committed skip certificate of each authority
    /// counts until they [settle](FinalityProtocol::settles_skip). An arriving phase-one
    /// certificate, if valid against the arrived votes, counts towards C's fast path. Returns
    /// like [`count`](CheckpointCertifier::count).
    fn live_certificate(
        &mut self,
        index: usize,
        block: BlockReference,
        outcome: Outcome,
        votes: &[BlockReference],
        committed: bool,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let anchor = self.pending[index].local.anchor();
        let certification = self.pending[index].certification.as_deref()?;
        let evidence = match committed {
            true => &certification.committed,
            false => &certification.arrived,
        };
        if !self.justified(evidence, anchor, outcome, votes) {
            return None;
        }
        let stake = self.committee.get_stake(block.authority)?;
        let certification = self.pending[index].certification.as_deref_mut()?;
        let (proof, path) = match (outcome, committed) {
            (Outcome::Finalize(_), true) => (votes.to_vec(), Path::Slow),
            (Outcome::Skip, true) => {
                let support = certification.skips.add(stake, (), block)?;
                if !self.protocol.settles_skip(self.thresholds, support) {
                    return None;
                }
                // A skip certificate deciding alone (B's) is proven by its votes; several
                // (C's), by their blocks.
                let mut proof = certification.skips.blocks(None);
                if proof.len() == 1 {
                    proof = votes.to_vec();
                }
                (proof, Path::Slow)
            }
            (Outcome::Finalize(commitment), false) => {
                let support = certification.phase_one.add(stake, commitment, block)?;
                if !self.protocol.finalizes_on_arrival(self.thresholds, support) {
                    return None;
                }
                (certification.phase_one.blocks(Some(commitment)), Path::Fast)
            }
            (Outcome::Skip, false) => return None,
        };
        Some(self.set_candidate(index, outcome, proof, path))
    }

    /// Whether a certificate for `anchor` claiming `outcome` and citing `cited` is valid against
    /// `votes`, the votes by carrying block it may cite: it cites only those, from distinct
    /// authorities, and they justify its outcome.
    fn justified(
        &self,
        votes: &BTreeMap<BlockReference, Digest>,
        anchor: BlockReference,
        outcome: Outcome,
        cited: &[BlockReference],
    ) -> bool {
        let mut tally = Tally::new(cited.len());
        for block in cited {
            let counted = votes.get(block).and_then(|commitment| {
                let stake = self.committee.get_stake(block.authority)?;
                tally.add(stake, *commitment, *block)
            });
            if counted.is_none() {
                tracing::warn!(?anchor, %block, "certificate cites an unknown or repeated vote");
                return false;
            }
        }
        let justified =
            self.protocol
                .justifies(self.thresholds, outcome, &tally.support, tally.voted);
        if !justified {
            tracing::warn!(
                ?anchor,
                ?outcome,
                "certificate does not justify its outcome"
            );
        }
        justified
    }

    /// Makes `outcome`, proven by `proof`, the candidate of the pending checkpoint at `index`,
    /// concluded on `path`: its live instance stops counting. Returns the outcome and the mint
    /// timings.
    fn set_candidate(
        &mut self,
        index: usize,
        outcome: Outcome,
        proof: Vec<BlockReference>,
        path: Path,
    ) -> (Outcome, CheckpointTimings) {
        let releases = self.releases;
        let entry = &mut self.pending[index];
        entry.tally = None;
        entry.certification = None;
        entry.candidate = Some(Candidate {
            outcome,
            proof,
            path,
            releases,
        });
        (outcome, entry.timings)
    }

    /// A certifier over a [`Committee::new_test`] committee with two leaders per round that
    /// already minted checkpoints `1..=minted` matching [`Checkpoint::new_for_test`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(
        protocol: FinalityProtocol,
        stake: Vec<Stake>,
        quorum: Stake,
        minted: u64,
    ) -> Self {
        let leaders = NonZeroUsize::new(2).unwrap();
        let mut certifier = Self::new(Committee::new_test(stake), protocol, quorum, leaders);
        for n in 1..=minted {
            let checkpoint = Checkpoint::new_for_test(n);
            certifier.push(
                checkpoint.anchor(),
                checkpoint.commitment(),
                checkpoint.parent(),
                CheckpointTimings::default(),
            );
        }
        certifier
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use dag::{block::BlockReference, committee::Committee};
    use execution::crypto::Digest;

    use crate::{
        certifier::{
            Arrival, CheckpointCertifier, CheckpointTimings, Divergence, Item,
            MAX_RECORDS_PER_BLOCK_AND_HEIGHT, Path, Record, anchor_bytes,
        },
        checkpoint::{Certificate, Checkpoint, Decision, Outcome},
        finality::FinalityProtocol,
    };

    /// Leaders per round, as in [`CheckpointCertifier::new_for_test`].
    const LEADERS: NonZeroUsize = NonZeroUsize::new(2).unwrap();

    /// Shorthand for [`Checkpoint::new_for_test`]: the vote for the `n`-th checkpoint.
    fn vote(n: u64) -> Checkpoint {
        Checkpoint::new_for_test(n)
    }

    /// A vote for the checkpoint at `anchor` attesting `commitment`, on the default parent like
    /// every [`vote`].
    fn vote_for(anchor: BlockReference, commitment: Digest) -> Checkpoint {
        Checkpoint::new(anchor, commitment, Digest::default())
    }

    /// The checkpoint `decision` finalized; panics on a skip.
    fn finalized(decision: &Decision) -> Checkpoint {
        match decision.outcome() {
            Outcome::Finalize(commitment) => vote_for(decision.anchor(), commitment),
            Outcome::Skip => panic!("expected a finalized checkpoint"),
        }
    }

    /// The block of `author` carrying votes at the `n`-th round after the checkpointed ones.
    fn block(author: u64, n: u64) -> BlockReference {
        BlockReference::new_test(author, 100 + n)
    }

    /// A vote for the first checkpoint attesting a commitment of its own.
    fn diverged(byte: u8) -> Checkpoint {
        vote_for(vote(1).anchor(), Digest::new_for_test(byte))
    }

    /// The block of `author` carrying a certificate, after the blocks carrying votes.
    fn carrier(author: u64) -> BlockReference {
        BlockReference::new_test(author, 200)
    }

    /// A certificate for the first checkpoint citing `votes`.
    fn certificate(outcome: Outcome, votes: Vec<BlockReference>) -> Certificate {
        Certificate::new(vote(1).anchor(), Digest::default(), outcome, votes)
    }

    /// A parent of its own, naming an instance other than the default parent's.
    fn parent(byte: u8) -> Digest {
        Digest::new_for_test(byte)
    }

    /// The vote for the first checkpoint on `parent`.
    fn vote_on(parent: Digest) -> Checkpoint {
        Checkpoint::new(vote(1).anchor(), vote(1).commitment(), parent)
    }

    /// A certifier over four equal validators that minted the first checkpoint on `parent`.
    fn minted_on(protocol: FinalityProtocol, parent: Digest) -> CheckpointCertifier {
        let mut certifier = CheckpointCertifier::new_for_test(protocol, vec![1; 4], 3, 0);
        let local = vote_on(parent);
        let timings = CheckpointTimings::default();
        certifier.push(local.anchor(), local.commitment(), parent, timings);
        certifier
    }

    #[test]
    fn certification_surrenders_the_mint_timings() {
        let timings = CheckpointTimings {
            minted_at: Duration::from_secs(1),
            mean_timestamp_ms: 650,
        };
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 0);
        certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            Digest::default(),
            timings,
        );

        assert_eq!(certifier.record(block(0, 0), vote(1)), None);
        assert_eq!(certifier.record(block(1, 0), vote(1)), None);
        assert_eq!(
            certifier.record(block(2, 1), vote(1)),
            Some((Outcome::Finalize(vote(1).commitment()), timings))
        );
        // The certificate never changes, and the timings surrender exactly once.
        assert_eq!(certifier.record(block(3, 2), vote(1)), None);
    }

    #[test]
    fn certification_prunes_the_pending_checkpoints() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 2);
        for authority in 0..3 {
            certifier.record(block(authority, 0), vote(1));
        }
        assert_eq!(certifier.pending().collect::<Vec<_>>(), [&vote(2)]);
    }

    #[test]
    fn quorum_certifies_at_threshold_with_the_carrying_blocks_as_proof() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        certifier.record(block(2, 1), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(1));
        assert_eq!(certified.proof(), [block(0, 0), block(1, 0), block(2, 1)]);

        // A late matching vote does not grow the proof.
        certifier.record(block(3, 2), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [block(0, 0), block(1, 0), block(2, 1)]);
    }

    #[test]
    fn duplicate_votes_add_no_stake() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 2, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(0, 1), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        certifier.record(block(1, 2), vote(1));
        assert!(certifier.highest_decided().is_some());
    }

    #[test]
    fn a_single_vote_crossing_quorum_certifies() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![5, 1, 1, 1], 5, 1);
        certifier.record(block(0, 0), vote(1));

        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [block(0, 0)]);
    }

    #[test]
    fn minority_conflict_does_not_block_certification() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(block(0, 9), diverged(1));
        certifier.record(block(1, 0), vote(1));
        certifier.record(block(2, 0), vote(1));
        certifier.record(block(3, 1), vote(1));

        // The majority value certifies, and the diverged vote's block stays out of the proof.
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(1));
        assert_eq!(certified.proof(), [block(1, 0), block(2, 0), block(3, 1)]);
    }

    #[test]
    fn conflicting_commitments_cannot_both_certify() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), vote(1));
        certifier.record(block(2, 0), diverged(1));
        certifier.record(block(3, 0), diverged(1));
        assert_eq!(certifier.highest_decided(), None);

        // A conflicting second vote is ignored: the first wins.
        certifier.record(block(0, 1), diverged(1));
        assert_eq!(certifier.highest_decided(), None);
    }

    #[test]
    fn a_quorum_diverging_from_the_local_checkpoint_still_certifies() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        for authority in 0..3 {
            certifier.record(block(authority, 0), diverged(1));
        }

        // The certificate carries the quorum's commitment, not ours, and the entry is
        // reclaimed: the quorum decides the truth even when we are the diverged one.
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), diverged(1));
        assert!(certifier.pending().next().is_none());
    }

    #[test]
    fn same_round_checkpoints_are_distinguished() {
        // Multi-leader protocols commit several anchors in the same round.
        let round = 7;
        let first = || vote_for(BlockReference::new_test(0, round), Digest::default());
        let second = || vote_for(BlockReference::new_test(1, round), Digest::default());
        let unminted = || vote_for(BlockReference::new_test(2, round), Digest::default());

        let mut certifier = CheckpointCertifier::new(
            Committee::new_test(vec![1; 4]),
            FinalityProtocol::Baseline,
            3,
            LEADERS,
        );
        certifier.push(
            first().anchor(),
            Digest::default(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        certifier.push(
            second().anchor(),
            Digest::default(),
            Digest::default(),
            CheckpointTimings::default(),
        );

        // A same-round anchor that was never minted certifies nothing.
        for authority in 0..4 {
            certifier.record(block(authority, 9), unminted());
        }
        assert_eq!(certifier.highest_decided(), None);

        // Both same-round checkpoints certify, even voted out of mint order.
        for authority in 0..3 {
            certifier.record(block(authority, 0), second());
        }
        assert_eq!(certifier.highest_decided(), None);
        for authority in 0..3 {
            certifier.record(block(authority, 1), first());
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), second());
        assert!(certifier.pending().next().is_none());
    }

    #[test]
    fn votes_for_unminted_checkpoints_are_rejected() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);

        // Even a full quorum for a never-witnessed checkpoint allocates and certifies nothing:
        // counted at commit, a vote never precedes the mint it attests.
        for authority in 0..4 {
            certifier.record(block(authority, 0), vote(5));
        }
        assert_eq!(certifier.highest_decided(), None);
        assert!(certifier.early.is_empty());
    }

    #[test]
    fn arrivals_before_the_mint_count_from_it() {
        let timings = CheckpointTimings {
            minted_at: Duration::from_secs(1),
            mean_timestamp_ms: 650,
        };
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), vote(1));
        assert_eq!(
            certifier.push(
                vote(1).anchor(),
                vote(1).commitment(),
                Digest::default(),
                timings
            ),
            (vote(1), None)
        );

        // The held votes count first, in arrival order.
        let outcome = Outcome::Finalize(vote(1).commitment());
        assert_eq!(
            certifier.record_arrival(block(2, 1), vote(1)),
            Some((outcome, timings))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.proof(), [block(0, 0), block(1, 0), block(2, 1)]);
    }

    #[test]
    fn arrivals_before_the_mint_can_decide_it() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        for authority in 0..3 {
            assert_eq!(certifier.record_arrival(block(authority, 0), vote(1)), None);
        }

        let (_, outcome) = certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert_eq!(outcome, Some(Outcome::Finalize(vote(1).commitment())));
        // Concluded at the mint, released by the next release.
        certifier.release();
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(1));
        assert!(certifier.pending().next().is_none());
    }

    #[test]
    fn arrivals_for_a_later_same_round_anchor_are_held() {
        // Multi-leader protocols mint several anchors per round: votes for the second can
        // arrive after the first was minted.
        let first = BlockReference::new_test(0, 7);
        let second = BlockReference::new_test(1, 7);
        let mut certifier = CheckpointCertifier::new(
            Committee::new_test(vec![1; 4]),
            FinalityProtocol::SuiBaseline,
            3,
            LEADERS,
        );
        certifier.push(
            first,
            Digest::default(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        let vote = vote_for(second, Digest::default());
        for authority in 0..3 {
            assert_eq!(
                certifier.record_arrival(block(authority, 0), vote.clone()),
                None
            );
        }

        let (_, outcome) = certifier.push(
            second,
            Digest::default(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert_eq!(outcome, Some(Outcome::Finalize(Digest::default())));
    }

    #[test]
    fn arrivals_for_anchors_never_minted_are_dropped_once_passed() {
        let unminted = vote_for(BlockReference::new_test(2, 1), Digest::default());
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), unminted);

        // Another anchor of the same round may still mint after this one.
        certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert_eq!(certifier.early.len(), 1);
        certifier.push(
            vote(2).anchor(),
            vote(2).commitment(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert!(certifier.early.is_empty());
    }

    #[test]
    fn fabricated_early_arrivals_at_or_above_the_carrying_round_are_refused() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        let at = |round| vote_for(BlockReference::new_test(1, round), Digest::default());
        let carrying = BlockReference::new_test(0, 5);

        // An anchor of the carrying block's round or later is not committed when the block is
        // created, so no honest author votes for it.
        certifier.record_arrival(carrying, at(5));
        certifier.record_arrival(carrying, at(1_000_000));
        assert!(certifier.early.is_empty());
        assert_eq!(certifier.retained_bytes(), 0);
        certifier.record_arrival(carrying, at(4));
        assert_eq!(certifier.early.len(), 1);
    }

    #[test]
    fn early_arrivals_beyond_l_anchors_per_author_and_round_are_refused() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        let anchor = |author| BlockReference::new_test(author, 1);
        let vote = |author| vote_for(anchor(author), Digest::default());

        // A Byzantine author votes, from several of its blocks, for every anchor of round 1:
        // only its first `LEADERS` anchors are held, each as often as it votes for them.
        for (round, author) in [(5, 0), (6, 1), (6, 2), (7, 3), (7, 1)] {
            certifier.record_arrival(BlockReference::new_test(3, round), vote(author));
        }
        let held = |author| certifier.early.get(&anchor(author)).map_or(0, Vec::len);
        assert_eq!([0, 1, 2, 3].map(held), [1, 2, 0, 0]);

        // Its junk uses up its own quota only: honest votes for another anchor of the round are
        // held, and decide it at its mint.
        for author in 0..3 {
            certifier.record_arrival(block(author, 0), vote(2));
        }
        let (_, outcome) = certifier.push(
            anchor(2),
            Digest::default(),
            Digest::default(),
            Default::default(),
        );
        assert_eq!(outcome, Some(Outcome::Finalize(Digest::default())));
    }

    #[test]
    fn commits_without_a_mint_advance_the_cursor_and_prune_lower_rounds() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(0, 0), vote(2));
        // Commits executing nothing, as when no application traffic flows.
        let unminted = |round| BlockReference::new_test(1, round);

        certifier.observe_unminted_commit(unminted(2));
        // Another anchor of round 2 may still be processed.
        let held: Vec<_> = certifier.early.keys().copied().collect();
        assert_eq!(held, [vote(2).anchor()]);
        certifier.observe_unminted_commit(unminted(3));
        assert!(certifier.early.is_empty());
        assert!(certifier.early_quota.is_empty());
        assert_eq!(certifier.retained_bytes(), 0);
    }

    #[test]
    fn arrivals_for_a_processed_unminted_anchor_are_refused() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        let unminted = BlockReference::new_test(1, 2);
        certifier.observe_unminted_commit(unminted);

        // Nothing mints it any more, nor an anchor of an earlier round.
        certifier.record_arrival(block(0, 0), vote_for(unminted, Digest::default()));
        certifier.record_arrival(block(0, 0), vote(1));
        assert!(certifier.early.is_empty());
        // Another anchor of its round still may, and a later one.
        let same_round = vote_for(BlockReference::new_test(2, 2), Digest::default());
        certifier.record_arrival(block(0, 0), same_round);
        certifier.record_arrival(block(0, 0), vote(3));
        assert_eq!(certifier.early.len(), 2);
    }

    #[test]
    fn retained_bytes_track_held_arrivals_exactly() {
        let vote_bytes = size_of::<Arrival>() as u64;
        let certificate_bytes = vote_bytes + 3 * size_of::<BlockReference>() as u64;
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), vote(2));
        let finalize = Outcome::Finalize(vote(2).commitment());
        let cited = vec![block(0, 0), block(1, 0), block(2, 0)];
        let phase_one = Certificate::new(vote(2).anchor(), Digest::default(), finalize, cited);
        certifier.record_arriving_certificate(carrier(0), phase_one);
        assert_eq!(
            certifier.retained_bytes(),
            2 * vote_bytes + certificate_bytes
        );

        // The mint takes its arrival as evidence, and the cursor drops the arrivals it passes.
        let evidence = size_of::<(BlockReference, Digest)>() as u64;
        certifier.push(
            vote(1).anchor(),
            Digest::default(),
            Digest::default(),
            Default::default(),
        );
        assert_eq!(
            certifier.retained_bytes(),
            vote_bytes + certificate_bytes + evidence
        );
        certifier.observe_unminted_commit(BlockReference::new_test(1, 3));
        assert_eq!(certifier.retained_bytes(), evidence);
    }

    #[test]
    fn watermark_is_contiguous() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 3);
        let mut timings = None;
        for authority in 0..3 {
            timings = certifier.record(block(authority, 0), vote(2));
        }
        // The quorum concluded it — timings surrendered — but it is not released, nor decided.
        assert!(timings.is_some());
        assert_eq!(certifier.highest_decided(), None);
        assert!(certifier.decision_log().is_empty());
        // Logged at release with the blocks of the votes that decided it, at round `round`.
        let finalize = |n: u64, round| {
            let proof = (0..3).map(|author| block(author, round)).collect();
            let outcome = Outcome::Finalize(vote(n).commitment());
            (vote(n).anchor(), (outcome, proof))
        };

        // Late votes for the certified-but-not-yet-contiguous checkpoint change nothing, even
        // a full quorum of them (as when votes are counted on arrival and again at commit).
        for authority in 0..4 {
            certifier.record(block(authority, 9), vote(2));
        }

        for authority in 0..3 {
            certifier.record(block(authority, 1), vote(1));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(2));
        assert_eq!(certified.proof(), [block(0, 0), block(1, 0), block(2, 0)]);
        assert_eq!(
            certifier.decision_log().clone(),
            [finalize(1, 1), finalize(2, 0)].into()
        );

        // The watermark keeps advancing from where it stands.
        for authority in 0..3 {
            certifier.record(block(authority, 2), vote(3));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(3));
    }

    #[test]
    fn checkpoints_become_contiguous_once_in_commit_order() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 0);
        let timings = |n| CheckpointTimings {
            minted_at: Duration::from_secs(n),
            mean_timestamp_ms: n,
        };
        for n in 1..=2 {
            certifier.push(
                vote(n).anchor(),
                vote(n).commitment(),
                Digest::default(),
                timings(n),
            );
        }

        // The second height concludes first: nothing is released yet.
        for author in 0..2 {
            certifier.record(block(author, 0), vote(2));
        }
        assert_eq!(certifier.highest_decided(), None);
        assert_eq!(certifier.take_released().count(), 0);

        // Skipping the first releases it, once, and reports the divergence: the second height
        // was minted on the state the skip discarded, so it waits for a re-mint.
        for author in 0..3 {
            certifier.record(block(author, 1), diverged(author as u8));
        }
        let released = certifier.take_released();
        let released: Vec<_> = released
            .map(|release| (release.outcome, release.timings))
            .collect();
        assert_eq!(released, [(Outcome::Skip, timings(1))]);
        assert_eq!(certifier.take_released().count(), 0);
        let divergence = certifier.take_divergence().expect("a skip diverges");
        assert_eq!(divergence.anchor, vote(1).anchor());
        assert_eq!(certifier.pending().collect::<Vec<_>>(), [&vote(2)]);
    }

    #[test]
    fn votes_below_the_watermark_are_ignored() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        for authority in 0..3 {
            certifier.record(block(authority, 0), vote(1));
        }

        // A full quorum re-voting a reclaimed checkpoint cannot alter the certificate.
        for authority in 0..4 {
            certifier.record(block(authority, 5), vote(1));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [block(0, 0), block(1, 0), block(2, 0)]);
    }

    #[test]
    fn votes_are_stake_weighted() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![5, 1, 1, 1], 5, 1);
        certifier.record(block(1, 0), vote(1));
        certifier.record(block(2, 0), vote(1));
        certifier.record(block(3, 0), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        // The heavy validator tips 3 stake over the threshold.
        certifier.record(block(0, 1), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof().len(), 4);
    }

    #[test]
    fn votes_on_another_parent_are_not_counted() {
        let (own, stale) = (vote_on(parent(1)), vote_on(parent(2)));
        let finalize = Outcome::Finalize(own.commitment());
        // Committed votes (the baseline) and arriving ones (the Sui-style baseline).
        for protocol in [FinalityProtocol::Baseline, FinalityProtocol::SuiBaseline] {
            let mut certifier = minted_on(protocol, parent(1));
            let mut count = |block, vote: &Checkpoint| {
                let counted = match protocol {
                    FinalityProtocol::Baseline => certifier.record(block, vote.clone()),
                    _ => certifier.record_arrival(block, vote.clone()),
                };
                counted.map(|(outcome, _)| outcome)
            };
            // Every author first votes for the same commitment in another instance: none of
            // these votes counts, nor takes its author's place in the tally.
            for author in 0..4 {
                assert_eq!(count(block(author, 0), &stale), None, "{protocol}");
            }
            assert_eq!(count(block(0, 1), &own), None);
            assert_eq!(count(block(1, 1), &own), None);
            assert_eq!(count(block(2, 1), &own), Some(finalize), "{protocol}");
        }
    }

    #[test]
    fn votes_held_before_the_mint_on_another_parent_are_not_counted() {
        let (own, stale) = (vote_on(parent(1)), vote_on(parent(2)));
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        for author in 0..4 {
            certifier.record_arrival(block(author, 0), stale.clone());
        }
        let timings = CheckpointTimings::default();
        let (_, outcome) = certifier.push(own.anchor(), own.commitment(), parent(1), timings);
        assert_eq!(outcome, None);
        // The held votes took no author's place in the tally.
        let mut arrive = |author| {
            let decided = certifier.record_arrival(block(author, 1), own.clone());
            decided.map(|(outcome, _)| outcome)
        };
        assert_eq!(arrive(0), None);
        assert_eq!(arrive(1), None);
        assert_eq!(arrive(2), Some(Outcome::Finalize(own.commitment())));
    }

    #[test]
    fn a_block_carrying_two_parents_for_one_height_records_both() {
        // Each block carries its author's vote on a stale parent, attesting another commitment,
        // then its re-vote on the pending checkpoint's parent.
        let own = vote_on(parent(1));
        let stale = Checkpoint::new(own.anchor(), Digest::new_for_test(9), parent(2));
        let blocks = vec![block(0, 0), block(1, 0), block(2, 0)];
        let finalize = Outcome::Finalize(own.commitment());
        let certificate = Certificate::new(own.anchor(), parent(1), finalize, blocks.clone());

        // Under B, a committed certificate cites the committed re-votes.
        let mut certifier = minted_on(FinalityProtocol::B, parent(1));
        for &block in &blocks {
            certifier.record(block, stale.clone());
            certifier.record(block, own.clone());
        }
        let decided = certifier.record_certificate(carrier(0), &certificate);
        assert_eq!(decided.map(|(outcome, _)| outcome), Some(finalize));

        // Under C, arriving phase-one certificates cite the arrived re-votes.
        let mut certifier = minted_on(FinalityProtocol::C, parent(1));
        for &block in &blocks {
            certifier.record_arrival(block, stale.clone());
            certifier.record_arrival(block, own.clone());
        }
        let mut arrive = |author| {
            let decided =
                certifier.record_arriving_certificate(carrier(author), certificate.clone());
            decided.map(|(outcome, _)| outcome)
        };
        assert_eq!(arrive(0), None);
        assert_eq!(arrive(1), None);
        assert_eq!(arrive(2), Some(finalize));
    }

    #[test]
    fn certificates_validate_against_votes_on_their_own_parent() {
        // Three authors vote for the pending commitment in another instance, then in the
        // pending checkpoint's.
        let (own, stale) = (vote_on(parent(1)), vote_on(parent(2)));
        let stale_blocks: Vec<_> = (0..3).map(|author| block(author, 0)).collect();
        let own_blocks: Vec<_> = (0..3).map(|author| block(author, 1)).collect();
        let finalize = Outcome::Finalize(own.commitment());
        let citing =
            |votes: &Vec<_>| Certificate::new(own.anchor(), parent(1), finalize, votes.clone());

        // Under B, committed certificates.
        let mut certifier = minted_on(FinalityProtocol::B, parent(1));
        for (&stale_block, &own_block) in stale_blocks.iter().zip(&own_blocks) {
            certifier.record(stale_block, stale.clone());
            certifier.record(own_block, own.clone());
        }
        let decided = certifier.record_certificate(carrier(0), &citing(&stale_blocks));
        assert_eq!(decided, None);
        let decided = certifier.record_certificate(carrier(1), &citing(&own_blocks));
        assert_eq!(decided.map(|(outcome, _)| outcome), Some(finalize));

        // Under C, arriving phase-one certificates.
        let mut certifier = minted_on(FinalityProtocol::C, parent(1));
        for (&stale_block, &own_block) in stale_blocks.iter().zip(&own_blocks) {
            certifier.record_arrival(stale_block, stale.clone());
            certifier.record_arrival(own_block, own.clone());
        }
        let mut arrive = |author, votes| {
            let decided = certifier.record_arriving_certificate(carrier(author), citing(votes));
            decided.map(|(outcome, _)| outcome)
        };
        for author in 0..3 {
            assert_eq!(arrive(author, &stale_blocks), None);
        }
        assert_eq!(arrive(0, &own_blocks), None);
        assert_eq!(arrive(1, &own_blocks), None);
        assert_eq!(arrive(2, &own_blocks), Some(finalize));
    }

    #[test]
    fn certificates_on_another_parent_never_decide() {
        // Valid in their own instance: a quorum's votes on the stale parent back them.
        let stale = vote_on(parent(2));
        let cited: Vec<_> = (0..3).map(|author| block(author, 0)).collect();
        let finalize = Outcome::Finalize(stale.commitment());
        let certificate = Certificate::new(stale.anchor(), parent(2), finalize, cited.clone());

        // Committed, under B.
        let mut certifier = minted_on(FinalityProtocol::B, parent(1));
        for &block in &cited {
            certifier.record(block, stale.clone());
        }
        assert_eq!(certifier.record_certificate(carrier(0), &certificate), None);

        // Arriving, under C.
        let mut certifier = minted_on(FinalityProtocol::C, parent(1));
        for &block in &cited {
            certifier.record_arrival(block, stale.clone());
        }
        for author in 0..3 {
            let decided =
                certifier.record_arriving_certificate(carrier(author), certificate.clone());
            assert_eq!(decided, None);
        }
    }

    #[test]
    fn concluded_certificates_name_the_pending_checkpoints_parent() {
        let own = vote_on(parent(1));
        let mut certifier = minted_on(FinalityProtocol::B, parent(1));
        certifier.record_arrival(block(0, 0), own.clone());
        certifier.record_arrival(block(1, 0), own);
        let [certificate] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(certificate.parent(), parent(1));
    }

    #[test]
    fn protocol_a_finalizes_at_f_plus_one_matching_votes_before_skipping() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 1);
        assert_eq!(certifier.record(block(0, 0), diverged(1)), None);
        assert_eq!(certifier.record(block(1, 1), vote(1)), None);

        // The third voter completes a quorum, but its vote is also the second matching one.
        let outcome = Outcome::Finalize(vote(1).commitment());
        assert_eq!(
            certifier.record(block(2, 2), vote(1)),
            Some((outcome, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(1));
        assert_eq!(decided.proof(), [block(1, 1), block(2, 2)]);
    }

    #[test]
    fn protocol_a_skips_once_a_quorum_voted_without_f_plus_one_matching() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        // Repeat votes, matching or not, add no voted stake: two voters are not a quorum.
        certifier.record(block(0, 1), vote(1));
        certifier.record(block(0, 1), diverged(3));
        assert_eq!(certifier.record(block(1, 1), diverged(1)), None);
        assert_eq!(
            certifier.record(block(2, 2), diverged(2)),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.anchor(), vote(1).anchor());
        assert_eq!(decided.outcome(), Outcome::Skip);
        assert_eq!(decided.proof(), [block(0, 0), block(1, 1), block(2, 2)]);

        // A late vote that would make f+1 matching cannot overturn the skip.
        certifier.record(block(3, 3), vote(1));
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.outcome(), Outcome::Skip);
    }

    #[test]
    fn protocol_b_certifies_on_arrival_and_decides_on_the_committed_certificate() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 1);
        certifier.record_arrival(block(0, 0), diverged(1));
        certifier.record_arrival(block(1, 0), vote(1));
        assert!(certifier.take_certificates().is_empty());

        // f+1 matching arrivals conclude a certificate, not a decision.
        assert_eq!(certifier.record_arrival(block(2, 0), vote(1)), None);
        let finalize = Outcome::Finalize(vote(1).commitment());
        let expected = certificate(finalize, vec![block(1, 0), block(2, 0)]);
        assert_eq!(
            certifier.take_certificates(),
            std::slice::from_ref(&expected)
        );
        // It concludes once: later arrivals add nothing.
        certifier.record_arrival(block(3, 0), vote(1));
        assert!(certifier.take_certificates().is_empty());

        // Committed votes alone decide nothing; they back the certificate once it commits.
        for author in 0..3 {
            assert_eq!(certifier.record(block(author, 0), vote(1)), None);
        }
        assert_eq!(certifier.highest_decided(), None);
        assert_eq!(
            certifier.record_certificate(carrier(0), &expected),
            Some((finalize, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(1));
        assert_eq!(decided.proof(), [block(1, 0), block(2, 0)]);
    }

    #[test]
    fn protocol_b_certificates_must_cite_committed_votes_of_distinct_authors() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 1);
        let finalize = Outcome::Finalize(vote(1).commitment());
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(0, 1), vote(1));
        certifier.record(block(1, 1), diverged(1));

        // One author twice is not f+1, nor is a vote that never committed, nor one that
        // attests another commitment.
        let invalid = [
            certificate(finalize, vec![block(0, 0), block(0, 1)]),
            certificate(finalize, vec![block(0, 0), block(2, 0)]),
            certificate(finalize, vec![block(0, 0), block(1, 1)]),
        ];
        for certificate in &invalid {
            assert_eq!(certifier.record_certificate(carrier(0), certificate), None);
        }

        // The uncommitted vote commits: the same certificate now decides.
        certifier.record(block(2, 0), vote(1));
        assert!(
            certifier
                .record_certificate(carrier(0), &invalid[1])
                .is_some()
        );
    }

    #[test]
    fn protocol_b_skip_certificates_need_a_quorum_without_f_plus_one_matching() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), vote(1));
        certifier.record(block(2, 0), diverged(2));
        certifier.record(block(3, 0), diverged(3));

        let invalid = [
            // Two matching votes are f+1.
            certificate(Outcome::Skip, vec![block(0, 0), block(1, 0), block(2, 0)]),
            // Two voters are not a quorum.
            certificate(Outcome::Skip, vec![block(2, 0), block(3, 0)]),
        ];
        for certificate in &invalid {
            assert_eq!(certifier.record_certificate(carrier(0), certificate), None);
        }
        let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), block(3, 0)]);
        assert_eq!(
            certifier.record_certificate(carrier(0), &skip),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
        // Deciding alone, it is proven by its votes.
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.proof(), skip.votes());
    }

    #[test]
    fn protocol_b_the_first_valid_certificate_committed_wins() {
        // The second height, so that it stays in the window once decided.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 2);
        let anchor = vote(2).anchor();
        let diverged = |byte| vote_for(anchor, Digest::new_for_test(byte));
        certifier.record(block(0, 0), vote(2));
        certifier.record(block(1, 0), vote(2));
        certifier.record(block(2, 0), diverged(2));
        certifier.record(block(3, 0), diverged(3));

        // Validators saw different arrival orders: both certificates are valid.
        let cited = vec![block(1, 0), block(2, 0), block(3, 0)];
        let skip = Certificate::new(anchor, Digest::default(), Outcome::Skip, cited);
        let finalize = Outcome::Finalize(vote(2).commitment());
        let finalize = Certificate::new(
            anchor,
            Digest::default(),
            finalize,
            vec![block(0, 0), block(1, 0)],
        );
        assert!(certifier.record_certificate(carrier(0), &skip).is_some());
        assert_eq!(certifier.record_certificate(carrier(1), &finalize), None);

        // A decided height concludes no certificate of our own either.
        for author in 0..4 {
            certifier.record_arrival(block(author, 0), vote(2));
        }
        assert!(certifier.take_certificates().is_empty());

        // Once contiguous, the first certificate's outcome stands.
        certifier.record(block(0, 1), vote(1));
        certifier.record(block(1, 1), vote(1));
        let finalize = Outcome::Finalize(vote(1).commitment());
        certifier.record_certificate(
            carrier(0),
            &certificate(finalize, vec![block(0, 1), block(1, 1)]),
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.anchor(), anchor);
        assert_eq!(decided.outcome(), Outcome::Skip);
    }

    #[test]
    fn protocol_b_certificates_are_stake_weighted() {
        // f+1 is 2 under these stakes: the heavy validator alone reaches it.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![2, 1, 1, 1], 4, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), diverged(1));

        let light = Outcome::Finalize(diverged(1).commitment());
        let light = certificate(light, vec![block(1, 0)]);
        assert_eq!(certifier.record_certificate(carrier(0), &light), None);
        let heavy = Outcome::Finalize(vote(1).commitment());
        let heavy = certificate(heavy, vec![block(0, 0)]);
        assert!(certifier.record_certificate(carrier(0), &heavy).is_some());
    }

    #[test]
    fn protocol_b_certifies_arrivals_held_before_the_mint() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), vote(1));

        let (_, outcome) = certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert_eq!(outcome, None);
        let finalize = Outcome::Finalize(vote(1).commitment());
        let expected = certificate(finalize, vec![block(0, 0), block(1, 0)]);
        assert_eq!(certifier.take_certificates(), [expected]);
    }

    /// A C certifier over four unit-stake validators that minted the first checkpoint, with
    /// the votes of `authors` for it arrived, then taken: whatever they concluded is discarded.
    fn protocol_c_with_arrivals(authors: &[u64]) -> CheckpointCertifier {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        for &author in authors {
            certifier.record_arrival(block(author, 0), vote(1));
        }
        certifier.take_certificates();
        certifier
    }

    #[test]
    fn protocol_c_concludes_a_phase_one_certificate_at_2f_plus_1_matching_arrivals() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), diverged(1));
        // f+1 matching is not enough, unlike B.
        certifier.record_arrival(block(2, 0), vote(1));
        assert!(certifier.take_certificates().is_empty());

        // No timeout needed: the third matching vote concludes it, never a decision.
        assert_eq!(certifier.record_arrival(block(3, 0), vote(1)), None);
        let finalize = Outcome::Finalize(vote(1).commitment());
        let expected = certificate(finalize, vec![block(0, 0), block(2, 0), block(3, 0)]);
        assert_eq!(certifier.take_certificates(), [expected]);
        assert_eq!(certifier.highest_decided(), None);
    }

    #[test]
    fn protocol_c_concludes_a_skip_certificate_once_expired_and_2f_plus_1_voted() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 4);
        let anchor = |n| vote(n).anchor();
        let diverged = |n, byte| vote_for(anchor(n), Digest::new_for_test(byte));

        // A quorum voted without 2f+1 matching: the fourth vote may still make them.
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), vote(1));
        certifier.record_arrival(block(2, 0), diverged(1, 1));
        assert!(certifier.take_certificates().is_empty());
        certifier.expire(anchor(1), 0);
        let skip = Certificate::new(
            anchor(1),
            Digest::default(),
            Outcome::Skip,
            vec![block(0, 0), block(1, 0), block(2, 0)],
        );
        assert_eq!(certifier.take_certificates(), [skip]);

        // Expired before a quorum voted: the vote completing it concludes.
        certifier.record_arrival(block(0, 1), vote(2));
        certifier.record_arrival(block(1, 1), diverged(2, 1));
        certifier.expire(anchor(2), 0);
        assert!(certifier.take_certificates().is_empty());
        certifier.record_arrival(block(2, 1), diverged(2, 2));
        let [skip] = certifier.take_certificates().try_into().unwrap();
        assert_eq!((skip.anchor(), skip.outcome()), (anchor(2), Outcome::Skip));

        // ...unless it makes 2f+1 matching.
        certifier.record_arrival(block(0, 2), vote(3));
        certifier.record_arrival(block(1, 2), vote(3));
        certifier.expire(anchor(3), 0);
        certifier.record_arrival(block(2, 2), vote(3));
        let [phase_one] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(phase_one.outcome(), Outcome::Finalize(vote(3).commitment()));

        // Expired before any vote arrived (a short timeout, or replay after a restart): the
        // votes arriving later conclude all the same.
        certifier.expire(anchor(4), 0);
        assert!(certifier.take_certificates().is_empty());
        certifier.record_arrival(block(0, 3), vote(4));
        certifier.record_arrival(block(1, 3), diverged(4, 1));
        certifier.record_arrival(block(2, 3), diverged(4, 2));
        let [skip] = certifier.take_certificates().try_into().unwrap();
        assert_eq!((skip.anchor(), skip.outcome()), (anchor(4), Outcome::Skip));
    }

    #[test]
    fn protocol_c_concludes_one_certificate_per_height() {
        // Concluded phase one: expiring sends no skip certificate as well.
        let mut certifier = protocol_c_with_arrivals(&[0, 1, 2]);
        certifier.expire(vote(1).anchor(), 0);
        assert!(certifier.take_certificates().is_empty());

        // Concluded skip: later matching votes send no phase-one certificate as well.
        let mut certifier = protocol_c_with_arrivals(&[0]);
        certifier.record_arrival(block(1, 0), diverged(1));
        certifier.record_arrival(block(2, 0), diverged(2));
        certifier.expire(vote(1).anchor(), 0);
        assert_eq!(certifier.take_certificates().len(), 1);
        certifier.record_arrival(block(3, 0), vote(1));
        certifier.record_arrival(block(1, 1), vote(1));
        assert!(certifier.take_certificates().is_empty());
    }

    #[test]
    fn protocol_c_finalizes_on_2f_plus_1_arriving_phase_one_certificates() {
        let mut certifier = protocol_c_with_arrivals(&[0, 1, 2]);
        let finalize = Outcome::Finalize(vote(1).commitment());
        let phase_one = certificate(finalize, vec![block(0, 0), block(1, 0), block(2, 0)]);

        let arrive = |certifier: &mut CheckpointCertifier, carrier| {
            certifier.record_arriving_certificate(carrier, phase_one.clone())
        };
        assert_eq!(arrive(&mut certifier, carrier(0)), None);
        assert_eq!(arrive(&mut certifier, carrier(1)), None);
        // An authority's second certificate counts no stake.
        assert_eq!(
            arrive(&mut certifier, BlockReference::new_test(1, 201)),
            None
        );
        assert_eq!(
            arrive(&mut certifier, carrier(3)),
            Some((finalize, CheckpointTimings::default()))
        );

        // Decided before commit, with the certificates as proof.
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(1));
        assert_eq!(decided.proof(), [carrier(0), carrier(1), carrier(3)]);
    }

    #[test]
    fn protocol_c_arriving_certificates_must_cite_arrived_votes_and_finalize() {
        let mut certifier = protocol_c_with_arrivals(&[0, 1]);
        certifier.record_arrival(block(2, 0), diverged(1));
        certifier.record_arrival(block(3, 0), diverged(2));
        let finalize = Outcome::Finalize(vote(1).commitment());
        let early = certificate(finalize, vec![block(0, 0), block(1, 0), block(2, 1)]);
        let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), block(3, 0)]);

        // A vote not arrived yet backs nothing, and skip certificates only count committed:
        // a quorum of them decides nothing before commit.
        for author in 0..3 {
            let arriving = [(&early, carrier(author)), (&skip, carrier(author))];
            for (certificate, carrier) in arriving {
                assert_eq!(
                    certifier.record_arriving_certificate(carrier, certificate.clone()),
                    None
                );
            }
        }
        assert_eq!(certifier.highest_decided(), None);

        // Once the cited vote arrives, the same certificates count.
        certifier.record_arrival(block(2, 1), vote(1));
        for author in 0..3 {
            certifier.record_arriving_certificate(carrier(author), early.clone());
        }
        assert!(certifier.highest_decided().is_some());
    }

    #[test]
    fn protocol_c_the_first_committed_phase_one_certificate_finalizes() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        for author in 0..3 {
            certifier.record(block(author, 0), vote(1));
        }
        certifier.record(block(3, 0), diverged(1));
        let finalize = Outcome::Finalize(vote(1).commitment());
        let phase_one = certificate(finalize, vec![block(0, 0), block(1, 0), block(2, 0)]);
        let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), block(3, 0)]);

        // Fewer than 2f+1 skip certificates commit first: the phase-one one still wins, even
        // from an author whose skip certificate counted (a Byzantine one certifies both).
        assert_eq!(certifier.record_certificate(carrier(0), &skip), None);
        assert_eq!(certifier.record_certificate(carrier(1), &skip), None);
        assert_eq!(
            certifier.record_certificate(BlockReference::new_test(1, 201), &phase_one),
            Some((finalize, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.proof(), phase_one.votes());
    }

    #[test]
    fn protocol_c_skips_on_2f_plus_1_committed_skip_certificates_first() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), diverged(1));
        certifier.record(block(2, 0), diverged(2));
        let skip = certificate(Outcome::Skip, vec![block(0, 0), block(1, 0), block(2, 0)]);

        // An authority's second certificate counts no stake.
        assert_eq!(certifier.record_certificate(carrier(0), &skip), None);
        let second = BlockReference::new_test(0, 201);
        assert_eq!(certifier.record_certificate(second, &skip), None);
        assert_eq!(certifier.record_certificate(carrier(1), &skip), None);
        assert_eq!(
            certifier.record_certificate(carrier(3), &skip),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.outcome(), Outcome::Skip);
        assert_eq!(decided.proof(), [carrier(0), carrier(1), carrier(3)]);
    }

    #[test]
    fn protocol_c_certificates_need_2f_plus_1() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), vote(1));
        certifier.record(block(2, 0), diverged(2));
        certifier.record(block(3, 0), diverged(3));

        let finalize = Outcome::Finalize(vote(1).commitment());
        let invalid = [
            // f+1 matching votes are B's phase-one certificate, not C's.
            certificate(finalize, vec![block(0, 0), block(1, 0)]),
            certificate(finalize, vec![block(0, 0), block(1, 0), block(2, 0)]),
            // Two voters are not a quorum.
            certificate(Outcome::Skip, vec![block(2, 0), block(3, 0)]),
        ];
        for (author, certificate) in (0..).zip(&invalid) {
            assert_eq!(
                certifier.record_certificate(carrier(author), certificate),
                None
            );
        }
        // f+1 matching among 2f+1 voters is still a skip certificate under C, not under B.
        let skip = certificate(Outcome::Skip, vec![block(0, 0), block(1, 0), block(2, 0)]);
        for author in 0..2 {
            certifier.record_certificate(carrier(author), &skip);
        }
        assert!(certifier.record_certificate(carrier(3), &skip).is_some());
    }

    #[test]
    fn protocol_c_votes_arriving_after_its_own_skip_certificate_back_the_fast_path() {
        // This validator timed out before validator 3's vote arrived, and sent a skip
        // certificate; the others' phase-one certificates cite that vote.
        let mut fast = protocol_c_with_arrivals(&[0, 1]);
        fast.record_arrival(block(2, 0), diverged(1));
        fast.expire(vote(1).anchor(), 0);
        let [skip] = fast.take_certificates().try_into().unwrap();
        assert_eq!(skip.outcome(), Outcome::Skip);
        fast.record_arrival(block(3, 0), vote(1));
        let finalize = Outcome::Finalize(vote(1).commitment());
        let phase_one = certificate(finalize, vec![block(0, 0), block(1, 0), block(3, 0)]);
        for author in [0, 1] {
            let arriving = fast.record_arriving_certificate(carrier(author), phase_one.clone());
            assert_eq!(arriving, None);
        }
        assert!(
            fast.record_arriving_certificate(carrier(3), phase_one.clone())
                .is_some()
        );

        // At commit, its skip certificate may commit first: the phase-one one still wins.
        let mut slow = CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        for author in [0, 1, 3] {
            slow.record(block(author, 0), vote(1));
        }
        slow.record(block(2, 0), diverged(1));
        assert_eq!(slow.record_certificate(carrier(2), &skip), None);
        assert!(slow.record_certificate(carrier(0), &phase_one).is_some());

        let outcome = |certifier: &CheckpointCertifier| {
            let decision = certifier.highest_decided().expect("decided checkpoint");
            (decision.anchor(), decision.outcome())
        };
        assert_eq!(outcome(&fast), (vote(1).anchor(), finalize));
        assert_eq!(outcome(&fast), outcome(&slow));
    }

    #[test]
    fn protocol_c_arrivals_held_before_the_mint_can_decide_it() {
        // A lagging validator receives the votes and the phase-one certificates first.
        let finalize = Outcome::Finalize(vote(1).commitment());
        let cited = vec![block(0, 0), block(1, 0), block(2, 0)];
        let phase_one = certificate(finalize, cited.clone());
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 0);
        for &block in &cited {
            certifier.record_arrival(block, vote(1));
        }
        for author in 0..3 {
            let arriving =
                certifier.record_arriving_certificate(carrier(author), phase_one.clone());
            assert_eq!(arriving, None);
        }

        // In arrival order, the votes back the certificates, which decide at the mint: its
        // own phase-one certificate concluded first, from the same votes.
        let (_, outcome) = certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        assert_eq!(outcome, Some(finalize));
        assert_eq!(certifier.take_certificates(), [phase_one]);
    }

    #[test]
    fn protocol_c_certificates_are_stake_weighted() {
        // 2f+1 is 4 under these stakes: the heavy validator counts twice.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![2, 1, 1, 1], 4, 1);
        for author in 0..4 {
            certifier.record_arrival(block(author, 0), vote(1));
        }
        let finalize = Outcome::Finalize(vote(1).commitment());
        // Three light votes are short of 2f+1: counting this certificate would decide one
        // step early below.
        let light = certificate(finalize, vec![block(1, 0), block(2, 0), block(3, 0)]);
        assert_eq!(
            certifier.record_arriving_certificate(carrier(1), light),
            None
        );

        // Three valid certificates are enough when the heavy validator sent one.
        let heavy = certificate(finalize, vec![block(0, 0), block(1, 0), block(2, 0)]);
        for author in [3, 0] {
            let arriving = certifier.record_arriving_certificate(carrier(author), heavy.clone());
            assert_eq!(arriving, None);
        }
        assert!(
            certifier
                .record_arriving_certificate(carrier(2), heavy)
                .is_some()
        );

        // Committed skip certificates weigh their carriers' stake too.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![2, 1, 1, 1], 4, 1);
        certifier.record(block(0, 0), vote(1));
        certifier.record(block(1, 0), diverged(1));
        certifier.record(block(2, 0), diverged(2));
        let skip = certificate(Outcome::Skip, vec![block(0, 0), block(1, 0), block(2, 0)]);
        for author in [0, 1] {
            assert_eq!(certifier.record_certificate(carrier(author), &skip), None);
        }
        assert_eq!(
            certifier.record_certificate(carrier(2), &skip),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
    }

    /// This validator's commitment at the `n`-th height, on its own state.
    fn local(n: u8) -> Digest {
        Digest::new_for_test(10 + n)
    }

    /// The commitment the rest of the committee computed at the `n`-th height.
    fn canonical(n: u8) -> Digest {
        Digest::new_for_test(20 + n)
    }

    /// A vote for the `n`-th checkpoint attesting `commitment` on `parent`.
    fn vote_at(n: u64, commitment: Digest, parent: Digest) -> Checkpoint {
        Checkpoint::new(vote(n).anchor(), commitment, parent)
    }

    /// A certifier over four equal validators that minted the first two checkpoints on its own
    /// state: `local(1)` on genesis, then `local(2)` on it.
    fn minted_two(protocol: FinalityProtocol) -> CheckpointCertifier {
        let mut certifier = CheckpointCertifier::new_for_test(protocol, vec![1; 4], 3, 0);
        let timings = CheckpointTimings::default();
        certifier.push(vote(1).anchor(), local(1), Digest::default(), timings);
        certifier.push(vote(2).anchor(), local(2), local(1), timings);
        certifier
    }

    /// Commits a quorum of A votes for the first height, none matching: it skips.
    fn skip_the_first(certifier: &mut CheckpointCertifier) {
        for author in 0..3 {
            let commitment = Digest::new_for_test(30 + author as u8);
            certifier.record(block(author, 1), vote_at(1, commitment, Digest::default()));
        }
    }

    /// The canonical commitment once the first height skipped.
    fn first_skipped() -> Digest {
        Digest::default().skip(&anchor_bytes(vote(1).anchor()))
    }

    /// The outcomes released since the last take.
    fn released(certifier: &mut CheckpointCertifier) -> Vec<Outcome> {
        certifier
            .take_released()
            .map(|release| release.outcome)
            .collect()
    }

    #[test]
    fn decisions_are_released_in_height_order() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 2);
        for author in 0..3 {
            certifier.record(block(author, 0), vote(2));
        }
        // Concluded, but not its predecessor.
        assert_eq!(certifier.take_released().count(), 0);
        assert_eq!(certifier.highest_decided(), None);

        for author in 0..3 {
            certifier.record(block(author, 1), vote(1));
        }
        let finalize = Outcome::Finalize(Digest::default());
        let released = certifier.take_released();
        let released: Vec<_> = released
            .map(|release| (release.outcome, release.waited))
            .collect();
        assert_eq!(released, [(finalize, false), (finalize, true)]);
        assert_eq!(finalized(certifier.highest_decided().unwrap()), vote(2));
    }

    #[test]
    fn a_skip_reports_a_divergence_and_holds_successors_until_re_mint() {
        let mut certifier = minted_two(FinalityProtocol::A);
        // The second height concludes on this validator's own state.
        for author in 0..2 {
            certifier.record(block(author, 0), vote_at(2, local(2), local(1)));
        }
        skip_the_first(&mut certifier);
        assert_eq!(released(&mut certifier), [Outcome::Skip]);
        let divergence = Divergence {
            anchor: vote(1).anchor(),
            outcome: Outcome::Skip,
        };
        assert_eq!(certifier.take_divergence(), Some(divergence));
        // Taken or not, the divergence holds the second height: its parent is stale.
        certifier.release();
        assert_eq!(certifier.take_released().count(), 0);
        assert_eq!(certifier.pending().count(), 1);
        // A re-mint drops the stale instance's conclusion: nothing concludes the new one yet.
        certifier.re_mint(vote(2).anchor(), canonical(2), first_skipped());
        certifier.release();
        assert_eq!(certifier.take_released().count(), 0);
    }

    #[test]
    fn re_mint_rebuilds_the_tally_and_releases_the_next_height() {
        let mut certifier = minted_two(FinalityProtocol::A);
        // Votes for the second height on two other states wait as records: first on a stale
        // one, then on the state the skip leaves.
        let stale = vote_at(2, Digest::new_for_test(40), Digest::new_for_test(41));
        let canonical_vote = vote_at(2, canonical(2), first_skipped());
        for author in [0, 3] {
            certifier.record(block(author, 0), stale.clone());
        }
        for author in 1..3 {
            certifier.record(block(author, 0), canonical_vote.clone());
        }
        skip_the_first(&mut certifier);
        assert!(certifier.take_divergence().is_some());
        assert_eq!(released(&mut certifier), [Outcome::Skip]);

        // Recovered onto that state, this validator re-mints the second height: its tally
        // rebuilds from the records on its new parent, and f+1 of them finalize it.
        let re_vote = certifier.re_mint(vote(2).anchor(), canonical(2), first_skipped());
        assert_eq!(re_vote, canonical_vote);
        assert_eq!(certifier.generation(vote(2).anchor()), Some(1));
        assert_eq!(certifier.take_released().count(), 0);
        certifier.release();
        assert_eq!(released(&mut certifier), [Outcome::Finalize(canonical(2))]);
        assert_eq!(certifier.take_divergence(), None);
    }

    #[test]
    fn winners_votes_decide_the_next_height_once_the_loser_re_mints() {
        let mut certifier = minted_two(FinalityProtocol::A);
        // The winners vote for both heights on their own state, and finalize the first.
        for author in 1..3 {
            certifier.record(block(author, 0), vote_at(2, canonical(2), canonical(1)));
        }
        for author in 1..3 {
            certifier.record(
                block(author, 1),
                vote_at(1, canonical(1), Digest::default()),
            );
        }
        let divergence = certifier.take_divergence().expect("the loser diverges");
        assert_eq!(divergence.outcome, Outcome::Finalize(canonical(1)));

        // Re-minted on the winners' state, the second height concludes from their votes at once.
        certifier.re_mint(vote(2).anchor(), canonical(2), canonical(1));
        certifier.release();
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.anchor(), vote(2).anchor());
        assert_eq!(decided.outcome(), Outcome::Finalize(canonical(2)));
    }

    #[test]
    fn stale_parent_votes_never_decide() {
        let mut certifier = minted_two(FinalityProtocol::A);
        // A vote for the second height on this validator's own, soon stale, state.
        let stale = vote_at(2, Digest::new_for_test(40), local(1));
        certifier.record(block(0, 0), stale.clone());
        for author in 1..3 {
            certifier.record(
                block(author, 1),
                vote_at(1, canonical(1), Digest::default()),
            );
        }
        assert_eq!(released(&mut certifier), [Outcome::Finalize(canonical(1))]);
        assert!(certifier.take_divergence().is_some());
        certifier.re_mint(vote(2).anchor(), canonical(2), canonical(1));

        // The same commitment on the canonical parent, and more votes on the stale one: no
        // stale vote counts towards it, whether recorded before the re-mint or after.
        certifier.record(
            block(3, 2),
            vote_at(2, Digest::new_for_test(40), canonical(1)),
        );
        certifier.record(block(1, 2), stale.clone());
        certifier.release();
        assert_eq!(certifier.take_released().count(), 0);
        assert_eq!(certifier.pending().count(), 1);

        // Under B, committed stale votes back no certificate of the re-minted instance, even
        // one attesting their commitment on the canonical parent.
        let mut certifier = minted_two(FinalityProtocol::B);
        for author in [0, 3] {
            certifier.record(block(author, 0), stale.clone());
        }
        let winners = vote_at(1, canonical(1), Digest::default());
        for author in 1..3 {
            certifier.record(block(author, 1), winners.clone());
        }
        let finalize = Outcome::Finalize(canonical(1));
        let cited = vec![block(1, 1), block(2, 1)];
        let first = Certificate::new(winners.anchor(), Digest::default(), finalize, cited);
        certifier.record_certificate(carrier(1), &first);
        assert_eq!(released(&mut certifier), [finalize]);
        assert!(certifier.take_divergence().is_some());
        certifier.re_mint(vote(2).anchor(), canonical(2), canonical(1));
        let outcome = Outcome::Finalize(stale.commitment());
        let cited = vec![block(0, 0), block(3, 0)];
        let backed = Certificate::new(stale.anchor(), canonical(1), outcome, cited);
        assert_eq!(certifier.record_certificate(carrier(0), &backed), None);
        assert_eq!(certifier.take_released().count(), 0);
    }

    #[test]
    fn certificates_of_a_non_canonical_instance_never_decide() {
        // Under B, f+1 votes on this validator's own state back a valid certificate for the
        // second height in that instance; then the first height finalizes another state.
        let mut certifier = minted_two(FinalityProtocol::B);
        let own = vote_at(2, local(2), local(1));
        for author in [0, 3] {
            certifier.record(block(author, 0), own.clone());
        }
        let cited = vec![block(0, 0), block(3, 0)];
        let certificate =
            Certificate::new(own.anchor(), local(1), Outcome::Finalize(local(2)), cited);
        assert!(
            certifier
                .record_certificate(carrier(0), &certificate)
                .is_some()
        );
        let winners = vote_at(1, canonical(1), Digest::default());
        for author in 1..3 {
            certifier.record(block(author, 1), winners.clone());
        }
        let cited = vec![block(1, 1), block(2, 1)];
        let finalize = Outcome::Finalize(canonical(1));
        let first = Certificate::new(winners.anchor(), Digest::default(), finalize, cited);
        certifier.record_certificate(carrier(1), &first);
        assert_eq!(released(&mut certifier), [finalize]);
        assert!(certifier.take_divergence().is_some());
        certifier.release();
        assert_eq!(certifier.take_released().count(), 0);

        // Under C, 2f+1 arriving phase-one certificates in this validator's instance conclude
        // the second height on the fast path; Byzantine voters let the first height then skip.
        let mut certifier = minted_two(FinalityProtocol::C);
        for author in 0..3 {
            certifier.record_arrival(block(author, 0), own.clone());
        }
        let cited = vec![block(0, 0), block(1, 0), block(2, 0)];
        let phase_one =
            Certificate::new(own.anchor(), local(1), Outcome::Finalize(local(2)), cited);
        for author in 0..3 {
            certifier.record_arriving_certificate(carrier(author), phase_one.clone());
        }
        let mut skips = Vec::new();
        for author in 0..3 {
            let commitment = Digest::new_for_test(30 + author as u8);
            certifier.record(block(author, 1), vote_at(1, commitment, Digest::default()));
            skips.push(block(author, 1));
        }
        let skip = Certificate::new(vote(1).anchor(), Digest::default(), Outcome::Skip, skips);
        for author in 0..3 {
            certifier.record_certificate(carrier(author), &skip);
        }
        assert_eq!(released(&mut certifier), [Outcome::Skip]);
        assert!(certifier.take_divergence().is_some());
        certifier.release();
        assert_eq!(certifier.take_released().count(), 0);
    }

    #[test]
    fn a_b_certificate_committed_before_its_parent_is_known_decides_once_canonical() {
        // Commit order: a vote, a certificate citing a vote not committed yet (invalid), the
        // remaining votes, then two valid certificates of which the first, a skip, wins.
        let early = certificate(
            Outcome::Finalize(vote(1).commitment()),
            vec![block(0, 0), block(1, 0)],
        );
        let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), block(3, 0)]);
        let finalize = certificate(
            Outcome::Finalize(vote(1).commitment()),
            vec![block(0, 0), block(1, 0)],
        );
        let feed = |certifier: &mut CheckpointCertifier| {
            certifier.record(block(0, 0), vote(1));
            certifier.record_certificate(carrier(0), &early);
            certifier.record(block(1, 0), vote(1));
            certifier.record(block(2, 0), diverged(2));
            certifier.record(block(3, 0), diverged(3));
            certifier.record_certificate(carrier(1), &skip);
            certifier.record_certificate(carrier(2), &finalize);
        };
        // One validator holds the canonical parent from the start; the other minted on a
        // parent it recovers away from, so it keeps everything as records until it re-mints.
        let mut live = CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 1);
        feed(&mut live);
        let mut recovered = minted_on(FinalityProtocol::B, parent(2));
        feed(&mut recovered);
        assert_eq!(recovered.highest_decided(), None);
        recovered.re_mint(vote(1).anchor(), vote(1).commitment(), Digest::default());
        recovered.release();

        let skipped = (Outcome::Skip, skip.votes().to_vec());
        assert_eq!(
            live.decision_log().clone(),
            [(vote(1).anchor(), skipped)].into()
        );
        assert_eq!(recovered.decision_log(), live.decision_log());
    }

    #[test]
    fn a_c_instance_rebuilt_at_re_mint_reaches_the_live_verdict() {
        let all = vec![block(0, 0), block(1, 0), block(2, 0)];
        let phase_one = certificate(Outcome::Finalize(vote(1).commitment()), all.clone());
        // Fast path: the first phase-one certificate arrives before a vote it cites and is
        // invalid, so the decision's proof is the next three.
        let fast = |certifier: &mut CheckpointCertifier| {
            certifier.record_arrival(block(0, 0), vote(1));
            certifier.record_arrival(block(1, 0), vote(1));
            certifier.record_arriving_certificate(carrier(0), phase_one.clone());
            certifier.record_arrival(block(2, 0), vote(1));
            for author in 1..4 {
                certifier.record_arriving_certificate(carrier(author), phase_one.clone());
            }
        };
        // Slow path: a phase-one certificate commits before two of its votes and is invalid;
        // 2f+1 skip certificates then settle the skip.
        let cited = vec![block(0, 0), block(1, 0), block(3, 0)];
        let early = certificate(Outcome::Finalize(vote(1).commitment()), cited);
        let skip = certificate(Outcome::Skip, all.clone());
        let slow = |certifier: &mut CheckpointCertifier| {
            certifier.record(block(0, 0), vote(1));
            certifier.record_certificate(carrier(0), &early);
            certifier.record(block(1, 0), vote(1));
            certifier.record(block(2, 0), diverged(2));
            certifier.record(block(3, 0), vote(1));
            for author in 0..3 {
                certifier.record_certificate(carrier(author), &skip);
            }
        };
        for (path, feed) in [(Path::Fast, &fast as &dyn Fn(&mut _)), (Path::Slow, &slow)] {
            let mut live = CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
            feed(&mut live);
            let mut recovered = minted_on(FinalityProtocol::C, parent(2));
            feed(&mut recovered);
            recovered.re_mint(vote(1).anchor(), vote(1).commitment(), Digest::default());
            recovered.release();
            let paths = |certifier: &mut CheckpointCertifier| {
                certifier
                    .take_released()
                    .map(|release| release.path)
                    .collect::<Vec<_>>()
            };
            assert_eq!(paths(&mut live), [path]);
            assert_eq!(paths(&mut recovered), [path]);
            assert_eq!(recovered.decision_log(), live.decision_log(), "{path:?}");
        }
    }

    #[test]
    fn an_author_flooding_distinct_parents_allocates_no_tally() {
        // Every block of a Byzantine author votes for the height on ten parents of its own.
        let flood = |round: u64| {
            (0..10)
                .map(|n| Item::Vote(vote_on(Digest::default().salted(round * 10 + n))))
                .collect::<Vec<_>>()
        };
        let mut certifier = minted_on(FinalityProtocol::A, parent(1));
        let record = size_of::<Record>() as u64;
        for round in 0..20u64 {
            let votes = flood(round);
            certifier.record_committed_subdag([(block(3, round), votes)]);
            let kept = MAX_RECORDS_PER_BLOCK_AND_HEIGHT as u64 * (round + 1);
            assert_eq!(certifier.pending[0].foreign.len() as u64, kept);
            assert_eq!(certifier.retained_bytes(), kept * record);
        }
        // The one tally still counts the author's vote on the live parent, and decides.
        certifier.record(block(3, 30), vote_on(parent(1)));
        let decided = certifier.record(block(0, 30), vote_on(parent(1)));
        assert_eq!(
            decided.map(|(outcome, _)| outcome),
            Some(Outcome::Finalize(Digest::default()))
        );

        // Arriving blocks are selected alike: held before the mint, recorded after it.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        for round in 0..3 {
            certifier.record_block_arrival(block(3, round), flood(round));
        }
        let held = certifier.early[&vote(1).anchor()].len();
        assert_eq!(held, 3 * MAX_RECORDS_PER_BLOCK_AND_HEIGHT);
        let timings = CheckpointTimings::default();
        certifier.push(vote(1).anchor(), vote(1).commitment(), parent(1), timings);
        for round in 3..6 {
            certifier.record_block_arrival(block(3, round), flood(round));
        }
        let records = certifier.pending[0].foreign.len();
        assert_eq!(records, 6 * MAX_RECORDS_PER_BLOCK_AND_HEIGHT);
    }

    #[test]
    fn records_on_other_parents_survive_a_re_mint() {
        // f+1 votes on genesis wait through a re-mint onto another parent, and decide once the
        // checkpoint is re-minted onto genesis.
        let mut certifier = minted_on(FinalityProtocol::A, parent(1));
        for author in 0..2 {
            certifier.record(block(author, 0), vote(1));
        }
        certifier.record(block(2, 0), vote_on(parent(2)));
        certifier.re_mint(vote(1).anchor(), vote(1).commitment(), parent(2));
        certifier.re_mint(vote(1).anchor(), vote(1).commitment(), Digest::default());
        certifier.release();
        assert_eq!(
            released(&mut certifier),
            [Outcome::Finalize(Digest::default())]
        );
    }

    #[test]
    fn an_honest_re_vote_sharing_a_block_with_its_stale_original_is_counted() {
        // Re-minted on genesis, whose votes each share a block with the voter's original on a
        // parent it recovered away from.
        let mut certifier = minted_on(FinalityProtocol::A, parent(2));
        certifier.re_mint(vote(1).anchor(), vote(1).commitment(), Digest::default());
        let original = Checkpoint::new(vote(1).anchor(), Digest::new_for_test(9), parent(2));
        let blocks = (0..2).map(|author| {
            let items = vec![Item::Vote(original.clone()), Item::Vote(vote(1))];
            (block(author, 0), items)
        });
        certifier.record_committed_subdag(blocks);
        certifier.release();
        assert_eq!(
            released(&mut certifier),
            [Outcome::Finalize(Digest::default())]
        );
    }

    #[test]
    fn records_keep_the_last_k_per_block_and_height() {
        // One block per author carries a vote on K other parents, then on the live one.
        let parents = |author: u64| {
            (0..MAX_RECORDS_PER_BLOCK_AND_HEIGHT as u64)
                .map(move |n| Digest::default().salted(10 * author + n))
        };
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 1);
        let blocks = (0..2).map(|author| {
            let mut items: Vec<_> = parents(author)
                .map(|parent| Item::Vote(vote_on(parent)))
                .collect();
            items.push(Item::Vote(vote(1)));
            (block(author, 0), items)
        });
        certifier.record_committed_subdag(blocks);
        let records = MAX_RECORDS_PER_BLOCK_AND_HEIGHT - 1;
        assert_eq!(certifier.pending[0].foreign.len(), 2 * records);
        certifier.release();
        assert_eq!(
            released(&mut certifier),
            [Outcome::Finalize(Digest::default())]
        );

        // Likewise for certificates, under B.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::B, vec![1; 4], 3, 1);
        let cited = vec![block(0, 0), block(1, 0)];
        certifier.record_committed_subdag(
            (0..2).map(|author| (block(author, 0), vec![Item::Vote(vote(1))])),
        );
        let certificates = parents(0)
            .chain([Digest::default()])
            .map(|parent| {
                let outcome = Outcome::Finalize(Digest::default());
                Item::Certificate(Certificate::new(
                    vote(1).anchor(),
                    parent,
                    outcome,
                    cited.clone(),
                ))
            })
            .collect();
        certifier.record_committed_subdag([(carrier(0), certificates)]);
        assert_eq!(certifier.pending[0].foreign.len(), records);
        certifier.release();
        assert_eq!(
            released(&mut certifier),
            [Outcome::Finalize(Digest::default())]
        );
    }

    #[test]
    fn equivocating_siblings_in_any_arrival_order_give_identical_slow_path_verdicts() {
        // Author 3 equivocates: two blocks of one round voting differently, each with a
        // certificate of its own.
        let first = block(3, 0);
        let sibling = BlockReference {
            digest: block(3, 50).digest,
            ..first
        };
        let votes = |author| match author {
            0 => vote(1),
            _ => diverged(author as u8),
        };
        for protocol in [FinalityProtocol::B, FinalityProtocol::C] {
            let quorum = if protocol == FinalityProtocol::C {
                3
            } else {
                2
            };
            let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), sibling]);
            let finalize = certificate(
                Outcome::Finalize(vote(1).commitment()),
                vec![block(0, 0), first],
            );
            let carried = |block| match block == first {
                true => vec![Item::Vote(vote(1)), Item::Certificate(finalize.clone())],
                false => vec![Item::Vote(diverged(9)), Item::Certificate(skip.clone())],
            };
            let decide = |siblings: [BlockReference; 2]| {
                let mut certifier = CheckpointCertifier::new_for_test(protocol, vec![1; 4], 3, 1);
                for author in 0..3 {
                    certifier
                        .record_block_arrival(block(author, 0), vec![Item::Vote(votes(author))]);
                }
                for sibling in siblings {
                    certifier.record_block_arrival(sibling, carried(sibling));
                }
                certifier.release();
                let mut committed: Vec<_> = (0..3)
                    .map(|author| (block(author, 0), vec![Item::Vote(votes(author))]))
                    .collect();
                committed.extend([first, sibling].map(|block| (block, carried(block))));
                // The other authors' skip certificates complete C's 2f+1.
                committed.extend(
                    (1..quorum)
                        .map(|author| (carrier(author), vec![Item::Certificate(skip.clone())])),
                );
                certifier.record_committed_subdag(committed);
                certifier.release();
                let released: Vec<_> = certifier.take_released().collect();
                (released, certifier.decision_log().clone())
            };
            let (in_order, log) = decide([first, sibling]);
            let (swapped, swapped_log) = decide([sibling, first]);
            assert_eq!(log, swapped_log, "{protocol}");
            assert_eq!(log.len(), 1, "{protocol}");
            // A fast-path decision, where one occurs, has the slow path's outcome.
            for release in in_order.iter().chain(&swapped) {
                assert_eq!(release.outcome, log[&vote(1).anchor()].0, "{protocol}");
            }
        }
    }

    #[test]
    fn c_concludes_one_certificate_per_instance_and_a_new_one_after_re_mint() {
        let mut certifier = minted_on(FinalityProtocol::C, parent(1));
        for author in 0..4 {
            certifier.record_arrival(block(author, 0), vote_on(parent(1)));
            certifier.record_arrival(block(author, 0), vote_on(parent(2)));
        }
        let [own] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(own.parent(), parent(1));
        certifier.expire(vote(1).anchor(), 0);
        assert!(certifier.take_certificates().is_empty());

        // The rebuilt instance concludes its own certificate, once.
        certifier.re_mint(vote(1).anchor(), vote(1).commitment(), parent(2));
        let [rebuilt] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(rebuilt.parent(), parent(2));
        certifier.record_arrival(block(0, 1), vote_on(parent(2)));
        certifier.expire(vote(1).anchor(), 1);
        assert!(certifier.take_certificates().is_empty());
    }

    #[test]
    fn repeated_re_mints_keep_certificate_state_constant() {
        let mut certifier = minted_on(FinalityProtocol::B, parent(1));
        let mut retained = Vec::new();
        for generation in 1..=10u8 {
            // f+1 votes on the next parent wait as records, then certify it once re-minted.
            let next = Digest::new_for_test(100 + generation);
            for author in 0..2 {
                certifier.record_arrival(block(author, generation as u64), vote_on(next));
            }
            certifier.re_mint(vote(1).anchor(), vote(1).commitment(), next);
            let certificates = certifier.take_certificates();
            assert_eq!(certificates.len(), 1);
            assert_eq!(certificates[0].parent(), next);
            assert_eq!(
                certifier.generation(vote(1).anchor()),
                Some(generation as u32)
            );
            retained.push(certifier.retained_bytes());
        }
        assert!(retained.iter().all(|&bytes| bytes == retained[0]));
    }

    #[test]
    fn c_timeouts_of_an_earlier_generation_do_not_expire_a_re_minted_instance() {
        let mut certifier = minted_on(FinalityProtocol::C, parent(1));
        // A quorum votes on parent(2), without 2f+1 matching.
        for author in 0..3 {
            let vote = Checkpoint::new(
                vote(1).anchor(),
                Digest::new_for_test(author as u8),
                parent(2),
            );
            certifier.record_arrival(block(author, 0), vote);
        }
        // The first generation's timeout fires before the re-mint and after it: neither
        // expires the rebuilt instance.
        certifier.expire(vote(1).anchor(), 0);
        certifier.re_mint(vote(1).anchor(), vote(1).commitment(), parent(2));
        certifier.expire(vote(1).anchor(), 0);
        assert!(certifier.take_certificates().is_empty());
        certifier.expire(vote(1).anchor(), 1);
        let [skip] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(skip.outcome(), Outcome::Skip);
    }

    #[test]
    fn c_phase_one_after_the_same_authors_skip_decides_within_an_instance() {
        let skip = certificate(Outcome::Skip, vec![block(0, 0), block(1, 0), block(2, 0)]);
        let all = vec![block(0, 0), block(1, 0), block(3, 0)];
        let phase_one = certificate(Outcome::Finalize(vote(1).commitment()), all);
        let feed = |certifier: &mut CheckpointCertifier| {
            for author in [0, 1, 3] {
                certifier.record(block(author, 0), vote(1));
            }
            certifier.record(block(2, 0), diverged(2));
            certifier.record_certificate(carrier(0), &skip);
            certifier.record_certificate(carrier(0), &phase_one);
        };
        let mut live = CheckpointCertifier::new_for_test(FinalityProtocol::C, vec![1; 4], 3, 1);
        feed(&mut live);
        let mut recovered = minted_on(FinalityProtocol::C, parent(2));
        feed(&mut recovered);
        recovered.re_mint(vote(1).anchor(), vote(1).commitment(), Digest::default());
        recovered.release();
        let finalize = Outcome::Finalize(vote(1).commitment());
        assert_eq!(released(&mut live), [finalize]);
        assert_eq!(released(&mut recovered), [finalize]);
    }

    #[test]
    fn emulated_fork_mode_never_diverges() {
        // Under the emulated injection, commitments are this validator's own but every parent
        // is genesis.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 0)
                .with_emulated_forks();
        let timings = CheckpointTimings::default();
        certifier.push(vote(1).anchor(), local(1), Digest::default(), timings);
        certifier.push(vote(2).anchor(), local(2), Digest::default(), timings);
        skip_the_first(&mut certifier);
        for author in 0..2 {
            certifier.record(block(author, 2), vote_at(2, local(2), Digest::default()));
        }
        assert_eq!(
            released(&mut certifier),
            [Outcome::Skip, Outcome::Finalize(local(2))]
        );
        assert_eq!(certifier.take_divergence(), None);
    }
}
