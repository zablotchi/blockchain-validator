// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Finality: tallying checkpoint votes into decided checkpoints.

use std::{
    collections::{BTreeMap, VecDeque},
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

/// A vote or certificate counted on arrival, with its carrying block, held until the mint of
/// the checkpoint it is for.
enum Arrival {
    Vote(Digest, BlockReference),
    Certificate(Certificate, BlockReference),
}

/// Timing constants carried from mint to decision, for the caller's latency metrics.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct CheckpointTimings {
    /// The caller's clock at mint.
    pub minted_at: Duration,
    /// Mean submission stamp of the checkpointed transactions, in milliseconds since epoch.
    pub mean_timestamp_ms: u64,
}

/// A minted checkpoint with its vote tally: this validator's own value, and the decision once
/// the protocol reaches one (held until the watermark passes it).
struct PendingCheckpoint {
    local: Checkpoint,
    timings: CheckpointTimings,
    /// `None` once concluded.
    tally: Option<Tally>,
    /// Whether C's phase-one timeout expired.
    expired: bool,
    /// Under certifying protocols; `None` once decided.
    certification: Option<Box<Certification>>,
    decision: Option<Decision>,
}

/// What a pending checkpoint's certificates are checked and counted against.
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
}

pub struct CheckpointCertifier {
    committee: Arc<Committee>,
    protocol: FinalityProtocol,
    thresholds: Thresholds,
    /// The minted-but-not-contiguously-decided window, in commit order.
    pending: VecDeque<PendingCheckpoint>,
    /// The highest contiguously decided checkpoint; `None` until the first decision.
    watermark: Option<Decision>,
    /// Arrivals for anchors not minted yet, in arrival order.
    early: BTreeMap<BlockReference, Vec<Arrival>>,
    /// Concluded certificates not yet taken for submission.
    certificates: Vec<Certificate>,
    /// Decided checkpoints the watermark passed since the last take, in commit order, with
    /// their mint timings.
    contiguous: Vec<(Outcome, CheckpointTimings)>,
    /// Every decision by anchor, recorded when made, so that tests can compare decisions
    /// behind a gap the watermark never passes.
    #[cfg(any(test, feature = "decision-log"))]
    decision_log: BTreeMap<BlockReference, Outcome>,
}

impl CheckpointCertifier {
    /// A certifier deciding with `protocol`; `quorum` is the consensus protocol's quorum
    /// threshold.
    pub fn new(committee: Arc<Committee>, protocol: FinalityProtocol, quorum: Stake) -> Self {
        Self {
            thresholds: Thresholds::new(committee.total_stake(), quorum),
            committee,
            protocol,
            pending: VecDeque::new(),
            watermark: None,
            early: BTreeMap::new(),
            certificates: Vec::new(),
            contiguous: Vec::new(),
            #[cfg(any(test, feature = "decision-log"))]
            decision_log: BTreeMap::new(),
        }
    }

    pub fn protocol(&self) -> FinalityProtocol {
        self.protocol
    }

    /// Mints this validator's checkpoint for the sub-dag anchored at `anchor` and returns it,
    /// ready to submit as this validator's vote, with the outcome if arrivals counted before
    /// the mint decide it. The timings ride along and are surrendered when a later vote or
    /// certificate decides it. Only arrivals can outrun minting: a vote or certificate
    /// commits after the sub-dag it is for, which we process first.
    pub fn push(
        &mut self,
        anchor: BlockReference,
        commitment: Digest,
        timings: CheckpointTimings,
    ) -> (Checkpoint, Option<Outcome>) {
        // Anchors are minted in commit order, so rounds never decrease: early arrivals for
        // lower rounds are for anchors this validator never mints.
        while let Some(entry) = self.early.first_entry()
            && entry.key().round < anchor.round
        {
            entry.remove();
        }
        let local = Checkpoint::new(anchor, commitment);
        self.pending.push_back(PendingCheckpoint {
            local: local.clone(),
            timings,
            tally: Some(Tally::new(self.committee.len())),
            expired: false,
            certification: self.protocol.certifies().then(Box::default),
            decision: None,
        });
        let index = self.pending.len() - 1;
        let decided = self
            .early
            .remove(&anchor)
            .into_iter()
            .flatten()
            .find_map(|arrival| match arrival {
                Arrival::Vote(commitment, block) => self.arrive(index, commitment, block),
                Arrival::Certificate(certificate, block) => {
                    self.count_certificate(index, &certificate, block)
                }
            });
        if decided.is_some() {
            self.advance_watermark();
        }
        (local, decided.map(|(outcome, _)| outcome))
    }

    /// This validator's checkpoints not yet contiguously decided, in commit order.
    pub fn pending(&self) -> impl ExactSizeIterator<Item = &Checkpoint> {
        self.pending.iter().map(|entry| &entry.local)
    }

    /// Records the committed vote for `checkpoint` carried by `block`, attributed to the
    /// block's author: votes ride their author's own signed blocks, so no authority can forge
    /// another's. The first vote per authority and checkpoint counts; under certifying
    /// protocols, committed votes back certificates instead. Returns the outcome and the mint
    /// timings exactly when this vote decides the checkpoint.
    pub fn record(
        &mut self,
        block: BlockReference,
        checkpoint: Checkpoint,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let voted_anchor = checkpoint.anchor();
        let commitment = checkpoint.commitment();
        let Some(index) = self.position(voted_anchor) else {
            if voted_anchor.round > self.decided_round() {
                let author = block.authority;
                tracing::warn!(%author, ?voted_anchor, "checkpoint vote for an unknown anchor");
            }
            return None;
        };
        if self.protocol.certifies() {
            if let Some(certification) = &mut self.pending[index].certification {
                certification.committed.entry(block).or_insert(commitment);
            }
            return None;
        }
        let decided = self.count(index, commitment, block)?;
        self.advance_watermark();
        Some(decided)
    }

    /// Counts the vote for `checkpoint` carried by `block` as the block enters the local DAG,
    /// if the protocol counts arrivals; votes for checkpoints not minted yet count from the
    /// mint. Returns like [`record`](CheckpointCertifier::record).
    pub fn record_arrival(
        &mut self,
        block: BlockReference,
        checkpoint: Checkpoint,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if !self.protocol.counts_arrivals() {
            return None;
        }
        let commitment = checkpoint.commitment();
        let Some(index) = self.position(checkpoint.anchor()) else {
            self.hold(checkpoint.anchor(), Arrival::Vote(commitment, block));
            return None;
        };
        let decided = self.arrive(index, commitment, block)?;
        self.advance_watermark();
        Some(decided)
    }

    /// Counts the certificate carried by `block` as the block enters the local DAG, if the
    /// protocol counts arriving certificates: valid phase-one certificates from 2f+1 decide
    /// (C's fast path), and skip certificates only count once committed. Certificates for
    /// checkpoints not minted yet count from the mint. Returns like
    /// [`record`](CheckpointCertifier::record).
    pub fn record_arriving_certificate(
        &mut self,
        block: BlockReference,
        certificate: Certificate,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if !self.protocol.counts_arriving_certificates() || certificate.outcome() == Outcome::Skip {
            return None;
        }
        let Some(index) = self.position(certificate.anchor()) else {
            self.hold(
                certificate.anchor(),
                Arrival::Certificate(certificate, block),
            );
            return None;
        };
        let decided = self.count_certificate(index, &certificate, block)?;
        self.advance_watermark();
        Some(decided)
    }

    /// Records the committed certificate carried by `block`, under certifying protocols: a
    /// valid phase-one certificate decides at once, even if its author's skip certificate
    /// committed first, and the first valid skip certificate of each authority counts until
    /// they [settle](FinalityProtocol::settles_skip). Returns like
    /// [`record`](CheckpointCertifier::record).
    pub fn record_certificate(
        &mut self,
        block: BlockReference,
        certificate: &Certificate,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if !self.protocol.certifies() {
            return None;
        }
        let index = self.position(certificate.anchor())?;
        let certification = self.pending[index].certification.as_deref()?;
        if !self.justified(&certification.committed, certificate) {
            return None;
        }
        let stake = self.committee.get_stake(block.authority)?;
        let outcome = certificate.outcome();
        let proof = match outcome {
            Outcome::Finalize(_) => certificate.votes().to_vec(),
            Outcome::Skip => {
                let certification = self.pending[index].certification.as_deref_mut()?;
                let support = certification.skips.add(stake, (), block)?;
                if !self.protocol.settles_skip(self.thresholds, support) {
                    return None;
                }
                // A skip certificate deciding alone (B's) is proven by its votes; several
                // (C's), by their blocks.
                let mut proof = certification.skips.blocks(None);
                if proof.len() == 1 {
                    proof = certificate.votes().to_vec();
                }
                proof
            }
        };
        let decided = self.decide(index, outcome, proof);
        self.advance_watermark();
        Some(decided)
    }

    /// Expires C's phase-one timeout for the checkpoint minted at `anchor`: from now on its
    /// tally concludes in a skip certificate once 2f+1 voted without 2f+1 matching, at once
    /// if they already did.
    pub fn expire(&mut self, anchor: BlockReference) {
        let Some(index) = self.position(anchor) else {
            return;
        };
        let entry = &mut self.pending[index];
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
            // Only certifying protocols time out: the conclusion is a certificate.
            let decided = self.conclude(index, outcome);
            debug_assert!(decided.is_none());
        }
    }

    /// The certificates this validator's tallies concluded since the last call, to submit
    /// through consensus.
    pub fn take_certificates(&mut self) -> Vec<Certificate> {
        std::mem::take(&mut self.certificates)
    }

    /// The outcomes and mint timings of the checkpoints that became contiguously decided since
    /// the last call, in commit order: when a client can use them, since commitments chain.
    pub fn take_contiguous(&mut self) -> impl Iterator<Item = (Outcome, CheckpointTimings)> + '_ {
        self.contiguous.drain(..)
    }

    /// The highest checkpoint such that it and all earlier checkpoints are decided.
    pub fn highest_decided(&self) -> Option<&Decision> {
        self.watermark.as_ref()
    }

    #[cfg(any(test, feature = "decision-log"))]
    pub fn decision_log(&self) -> &BTreeMap<BlockReference, Outcome> {
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

    /// Holds an arrival for `anchor`, not minted yet, to count from its mint. Anchors below
    /// the latest minted round never mint: their arrivals are dropped.
    fn hold(&mut self, anchor: BlockReference, arrival: Arrival) {
        let minted_round = self
            .pending
            .back()
            .map_or(self.decided_round(), |entry| entry.round());
        if anchor.round >= minted_round {
            self.early.entry(anchor).or_default().push(arrival);
        } else if anchor.round > self.decided_round() {
            let author = match &arrival {
                Arrival::Vote(_, block) | Arrival::Certificate(_, block) => block.authority,
            };
            tracing::warn!(%author, ?anchor, "checkpoint arrival for an unknown anchor");
        }
    }

    /// Counts the vote `block` carries for the pending checkpoint at `index` as it arrives,
    /// and returns like [`count`](CheckpointCertifier::count). Under C, the vote may also back
    /// arriving certificates, even once this validator's own tally concluded.
    fn arrive(
        &mut self,
        index: usize,
        commitment: Digest,
        block: BlockReference,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if self.protocol.counts_arriving_certificates()
            && let Some(certification) = &mut self.pending[index].certification
        {
            certification.arrived.entry(block).or_insert(commitment);
        }
        self.count(index, commitment, block)
    }

    /// Counts a vote for the pending checkpoint at `index` into its tally, and returns the
    /// outcome and mint timings exactly when it decides the checkpoint.
    fn count(
        &mut self,
        index: usize,
        commitment: Digest,
        block: BlockReference,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let entry = &mut self.pending[index];
        // Concluded: an observed decision or certificate can never change.
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
        self.conclude(index, outcome)
    }

    /// Concludes the tally of the pending checkpoint at `index` in `outcome`: a certificate to
    /// submit under certifying protocols, the decision otherwise, returned like
    /// [`count`](CheckpointCertifier::count).
    fn conclude(&mut self, index: usize, outcome: Outcome) -> Option<(Outcome, CheckpointTimings)> {
        let entry = &mut self.pending[index];
        let proof = entry.tally.take().expect("tally concluded").proof(outcome);
        if self.protocol.certifies() {
            let certificate = Certificate::new(entry.local.anchor(), outcome, proof);
            self.certificates.push(certificate);
            return None;
        }
        Some(self.decide(index, outcome, proof))
    }

    /// Counts the arriving phase-one certificate `block` carries for the pending checkpoint at
    /// `index`, if valid against the votes arrived so far, and returns like
    /// [`count`](CheckpointCertifier::count).
    fn count_certificate(
        &mut self,
        index: usize,
        certificate: &Certificate,
        block: BlockReference,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let Outcome::Finalize(commitment) = certificate.outcome() else {
            return None;
        };
        let certification = self.pending[index].certification.as_deref()?;
        if !self.justified(&certification.arrived, certificate) {
            return None;
        }
        let stake = self.committee.get_stake(block.authority)?;
        let certification = self.pending[index].certification.as_deref_mut()?;
        let support = certification.phase_one.add(stake, commitment, block)?;
        if !self.protocol.finalizes_on_arrival(self.thresholds, support) {
            return None;
        }
        let proof = certification.phase_one.blocks(Some(commitment));
        Some(self.decide(index, Outcome::Finalize(commitment), proof))
    }

    /// Whether `certificate` is valid against `votes`, the votes by carrying block it may cite:
    /// it cites only those, from distinct authorities, and they justify its outcome.
    fn justified(
        &self,
        votes: &BTreeMap<BlockReference, Digest>,
        certificate: &Certificate,
    ) -> bool {
        let anchor = certificate.anchor();
        let mut cited = Tally::new(certificate.votes().len());
        for block in certificate.votes() {
            let counted = votes.get(block).and_then(|commitment| {
                let stake = self.committee.get_stake(block.authority)?;
                cited.add(stake, *commitment, *block)
            });
            if counted.is_none() {
                tracing::warn!(?anchor, %block, "certificate cites an unknown or repeated vote");
                return false;
            }
        }
        let outcome = certificate.outcome();
        let justified =
            self.protocol
                .justifies(self.thresholds, outcome, &cited.support, cited.voted);
        if !justified {
            tracing::warn!(
                ?anchor,
                ?outcome,
                "certificate does not justify its outcome"
            );
        }
        justified
    }

    /// Decides the pending checkpoint at `index`, returning the outcome and its mint timings.
    fn decide(
        &mut self,
        index: usize,
        outcome: Outcome,
        proof: Vec<BlockReference>,
    ) -> (Outcome, CheckpointTimings) {
        let entry = &mut self.pending[index];
        let anchor = entry.local.anchor();
        // A disagreement with our own pending checkpoint means our execution diverged.
        if let Outcome::Finalize(finalized) = outcome
            && entry.local.commitment() != finalized
        {
            tracing::error!(
                ?anchor,
                "local checkpoint diverges from the finalized checkpoint"
            );
        }
        entry.tally = None;
        entry.certification = None;
        entry.decision = Some(Decision::new(anchor, outcome, proof));
        #[cfg(any(test, feature = "decision-log"))]
        {
            let previous = self.decision_log.insert(anchor, outcome);
            debug_assert!(previous.is_none(), "{anchor:?} decided twice");
        }
        (outcome, entry.timings)
    }

    /// Advances the watermark over the contiguously decided prefix, reclaiming it.
    fn advance_watermark(&mut self) {
        while self
            .pending
            .front()
            .is_some_and(|entry| entry.decision.is_some())
        {
            let entry = self.pending.pop_front().expect("decided entry");
            let decision = entry.decision.expect("decided entry");
            self.contiguous.push((decision.outcome(), entry.timings));
            self.watermark = Some(decision);
        }
    }

    /// A certifier over a [`Committee::new_test`] committee that already minted checkpoints
    /// `1..=minted` matching [`Checkpoint::new_for_test`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(
        protocol: FinalityProtocol,
        stake: Vec<Stake>,
        quorum: Stake,
        minted: u64,
    ) -> Self {
        let mut certifier = Self::new(Committee::new_test(stake), protocol, quorum);
        for n in 1..=minted {
            let checkpoint = Checkpoint::new_for_test(n);
            certifier.push(
                checkpoint.anchor(),
                checkpoint.commitment(),
                CheckpointTimings::default(),
            );
        }
        certifier
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dag::{block::BlockReference, committee::Committee};
    use execution::crypto::Digest;

    use crate::{
        certifier::{CheckpointCertifier, CheckpointTimings},
        checkpoint::{Certificate, Checkpoint, Decision, Outcome},
        finality::FinalityProtocol,
    };

    /// Shorthand for [`Checkpoint::new_for_test`]: the vote for the `n`-th checkpoint.
    fn vote(n: u64) -> Checkpoint {
        Checkpoint::new_for_test(n)
    }

    /// The checkpoint `decision` finalized; panics on a skip.
    fn finalized(decision: &Decision) -> Checkpoint {
        match decision.outcome() {
            Outcome::Finalize(commitment) => Checkpoint::new(decision.anchor(), commitment),
            Outcome::Skip => panic!("expected a finalized checkpoint"),
        }
    }

    /// The block of `author` carrying votes at the `n`-th round after the checkpointed ones.
    fn block(author: u64, n: u64) -> BlockReference {
        BlockReference::new_test(author, 100 + n)
    }

    /// A vote for the first checkpoint attesting a commitment of its own.
    fn diverged(byte: u8) -> Checkpoint {
        Checkpoint::new(vote(1).anchor(), Digest::new_for_test(byte))
    }

    /// The block of `author` carrying a certificate, after the blocks carrying votes.
    fn carrier(author: u64) -> BlockReference {
        BlockReference::new_test(author, 200)
    }

    /// A certificate for the first checkpoint citing `votes`.
    fn certificate(outcome: Outcome, votes: Vec<BlockReference>) -> Certificate {
        Certificate::new(vote(1).anchor(), outcome, votes)
    }

    #[test]
    fn certification_surrenders_the_mint_timings() {
        let timings = CheckpointTimings {
            minted_at: Duration::from_secs(1),
            mean_timestamp_ms: 650,
        };
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 0);
        certifier.push(vote(1).anchor(), vote(1).commitment(), timings);

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
        let first = || Checkpoint::new(BlockReference::new_test(0, round), Digest::default());
        let second = || Checkpoint::new(BlockReference::new_test(1, round), Digest::default());
        let unminted = || Checkpoint::new(BlockReference::new_test(2, round), Digest::default());

        let mut certifier = CheckpointCertifier::new(
            Committee::new_test(vec![1; 4]),
            FinalityProtocol::Baseline,
            3,
        );
        certifier.push(
            first().anchor(),
            Digest::default(),
            CheckpointTimings::default(),
        );
        certifier.push(
            second().anchor(),
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
            certifier.push(vote(1).anchor(), vote(1).commitment(), timings),
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
            CheckpointTimings::default(),
        );
        assert_eq!(outcome, Some(Outcome::Finalize(vote(1).commitment())));
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
        );
        certifier.push(first, Digest::default(), CheckpointTimings::default());
        let vote = Checkpoint::new(second, Digest::default());
        for authority in 0..3 {
            assert_eq!(
                certifier.record_arrival(block(authority, 0), vote.clone()),
                None
            );
        }

        let (_, outcome) = certifier.push(second, Digest::default(), CheckpointTimings::default());
        assert_eq!(outcome, Some(Outcome::Finalize(Digest::default())));
    }

    #[test]
    fn arrivals_for_anchors_never_minted_are_dropped_once_passed() {
        let unminted = Checkpoint::new(BlockReference::new_test(2, 1), Digest::default());
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::SuiBaseline, vec![1; 4], 3, 0);
        certifier.record_arrival(block(0, 0), unminted);

        // Another anchor of the same round may still mint after this one.
        certifier.push(
            vote(1).anchor(),
            vote(1).commitment(),
            CheckpointTimings::default(),
        );
        assert_eq!(certifier.early.len(), 1);
        certifier.push(
            vote(2).anchor(),
            vote(2).commitment(),
            CheckpointTimings::default(),
        );
        assert!(certifier.early.is_empty());
    }

    #[test]
    fn watermark_is_contiguous() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 3);
        let mut timings = None;
        for authority in 0..3 {
            timings = certifier.record(block(authority, 0), vote(2));
        }
        // The certificate formed — timings surrendered — although not yet contiguous.
        assert!(timings.is_some());
        assert_eq!(certifier.highest_decided(), None);
        let finalize = |n| (vote(n).anchor(), Outcome::Finalize(vote(n).commitment()));
        assert_eq!(certifier.decision_log().clone(), [finalize(2)].into());

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
            [finalize(1), finalize(2)].into()
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
            certifier.push(vote(n).anchor(), vote(n).commitment(), timings(n));
        }

        // The second height finalizes first: nothing is contiguous yet.
        for author in 0..2 {
            certifier.record(block(author, 0), vote(2));
        }
        assert_eq!(certifier.highest_decided(), None);
        assert_eq!(certifier.take_contiguous().count(), 0);

        // Skipping the first makes both contiguous, in commit order, once: the watermark
        // advances over skips.
        for author in 0..3 {
            certifier.record(block(author, 1), diverged(author as u8));
        }
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(2));
        assert!(certifier.pending().next().is_none());
        let finalize = Outcome::Finalize(vote(2).commitment());
        assert_eq!(
            certifier.take_contiguous().collect::<Vec<_>>(),
            [(Outcome::Skip, timings(1)), (finalize, timings(2))]
        );
        assert_eq!(certifier.take_contiguous().count(), 0);
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
        let diverged = |byte| Checkpoint::new(anchor, Digest::new_for_test(byte));
        certifier.record(block(0, 0), vote(2));
        certifier.record(block(1, 0), vote(2));
        certifier.record(block(2, 0), diverged(2));
        certifier.record(block(3, 0), diverged(3));

        // Validators saw different arrival orders: both certificates are valid.
        let cited = vec![block(1, 0), block(2, 0), block(3, 0)];
        let skip = Certificate::new(anchor, Outcome::Skip, cited);
        let finalize = Outcome::Finalize(vote(2).commitment());
        let finalize = Certificate::new(anchor, finalize, vec![block(0, 0), block(1, 0)]);
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
        let diverged = |n, byte| Checkpoint::new(anchor(n), Digest::new_for_test(byte));

        // A quorum voted without 2f+1 matching: the fourth vote may still make them.
        certifier.record_arrival(block(0, 0), vote(1));
        certifier.record_arrival(block(1, 0), vote(1));
        certifier.record_arrival(block(2, 0), diverged(1, 1));
        assert!(certifier.take_certificates().is_empty());
        certifier.expire(anchor(1));
        let skip = Certificate::new(
            anchor(1),
            Outcome::Skip,
            vec![block(0, 0), block(1, 0), block(2, 0)],
        );
        assert_eq!(certifier.take_certificates(), [skip]);

        // Expired before a quorum voted: the vote completing it concludes.
        certifier.record_arrival(block(0, 1), vote(2));
        certifier.record_arrival(block(1, 1), diverged(2, 1));
        certifier.expire(anchor(2));
        assert!(certifier.take_certificates().is_empty());
        certifier.record_arrival(block(2, 1), diverged(2, 2));
        let [skip] = certifier.take_certificates().try_into().unwrap();
        assert_eq!((skip.anchor(), skip.outcome()), (anchor(2), Outcome::Skip));

        // ...unless it makes 2f+1 matching.
        certifier.record_arrival(block(0, 2), vote(3));
        certifier.record_arrival(block(1, 2), vote(3));
        certifier.expire(anchor(3));
        certifier.record_arrival(block(2, 2), vote(3));
        let [phase_one] = certifier.take_certificates().try_into().unwrap();
        assert_eq!(phase_one.outcome(), Outcome::Finalize(vote(3).commitment()));

        // Expired before any vote arrived (a short timeout, or replay after a restart): the
        // votes arriving later conclude all the same.
        certifier.expire(anchor(4));
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
        certifier.expire(vote(1).anchor());
        assert!(certifier.take_certificates().is_empty());

        // Concluded skip: later matching votes send no phase-one certificate as well.
        let mut certifier = protocol_c_with_arrivals(&[0]);
        certifier.record_arrival(block(1, 0), diverged(1));
        certifier.record_arrival(block(2, 0), diverged(2));
        certifier.expire(vote(1).anchor());
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
        fast.expire(vote(1).anchor());
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
}
