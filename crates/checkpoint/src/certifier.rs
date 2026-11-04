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

/// The first vote of each authority for one checkpoint, in count order.
#[derive(Default)]
struct Tally {
    voters: AuthoritySet,
    /// The stake of `voters`.
    voted: Stake,
    /// The stake attesting each commitment, in order of first appearance.
    support: Vec<(Digest, Stake)>,
    /// Each counted vote's commitment and carrying block.
    votes: Vec<(Digest, BlockReference)>,
}

impl Tally {
    /// `voters` bounds the vote buffer: one counted vote per authority, so it allocates once
    /// and never regrows.
    fn new(voters: usize) -> Self {
        Self {
            votes: Vec::with_capacity(voters),
            ..Default::default()
        }
    }

    /// Counts the vote `block` carries and returns its commitment's support, or `None` if the
    /// block's author already voted.
    fn add(&mut self, stake: Stake, commitment: Digest, block: BlockReference) -> Option<Stake> {
        if !self.voters.insert(block.authority) {
            return None;
        }
        self.voted += stake;
        self.votes.push((commitment, block));
        match self
            .support
            .iter_mut()
            .find(|(attested, _)| *attested == commitment)
        {
            Some((_, support)) => {
                *support += stake;
                Some(*support)
            }
            None => {
                self.support.push((commitment, stake));
                Some(stake)
            }
        }
    }

    /// The commitment `author`'s counted vote attests, if any.
    fn attested(&self, author: Authority) -> Option<Digest> {
        self.votes
            .iter()
            .find(|(_, block)| block.authority == author)
            .map(|(attested, _)| *attested)
    }

    /// The blocks carrying the votes backing `outcome`, in count order.
    fn proof(&self, outcome: Outcome) -> Vec<BlockReference> {
        self.votes
            .iter()
            .filter(|(attested, _)| match outcome {
                Outcome::Finalize(finalized) => *attested == finalized,
                Outcome::Skip => true,
            })
            .map(|(_, block)| *block)
            .collect()
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

/// A minted checkpoint with its vote tally: this validator's own value, and the decision once
/// the protocol reaches one (held until the watermark passes it).
struct PendingCheckpoint {
    local: Checkpoint,
    timings: CheckpointTimings,
    /// `None` once concluded.
    tally: Option<Tally>,
    /// Under certifying protocols, the committed votes by carrying block: the only votes a
    /// committed certificate may cite.
    committed: BTreeMap<BlockReference, Digest>,
    decision: Option<Decision>,
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
    /// Votes counted on arrival for anchors not minted yet, each with its carrying block, in
    /// arrival order.
    early: BTreeMap<BlockReference, Vec<(Digest, BlockReference)>>,
    /// Concluded certificates not yet taken for submission.
    certificates: Vec<Certificate>,
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
        }
    }

    pub fn protocol(&self) -> FinalityProtocol {
        self.protocol
    }

    /// Mints this validator's checkpoint for the sub-dag anchored at `anchor` and returns it,
    /// ready to submit as this validator's vote, with the outcome if votes counted before the
    /// mint decide it. The timings ride along and are surrendered when a later vote or
    /// certificate decides it. Only votes counted on arrival can outrun minting: a vote
    /// commits after the sub-dag it attests, which we process first.
    pub fn push(
        &mut self,
        anchor: BlockReference,
        commitment: Digest,
        timings: CheckpointTimings,
    ) -> (Checkpoint, Option<Outcome>) {
        // Anchors are minted in commit order, so rounds never decrease: early votes for lower
        // rounds attest anchors this validator never mints.
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
            committed: BTreeMap::new(),
            decision: None,
        });
        let index = self.pending.len() - 1;
        let decided = self
            .early
            .remove(&anchor)
            .into_iter()
            .flatten()
            .find_map(|(commitment, block)| self.count(index, commitment, block));
        if decided.is_some() {
            self.advance_watermark();
        }
        (local, decided.map(|(outcome, _)| outcome))
    }

    /// This validator's checkpoints not yet contiguously decided, in commit order.
    pub fn pending(&self) -> impl Iterator<Item = &Checkpoint> {
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
            let entry = &mut self.pending[index];
            if entry.decision.is_none() {
                entry.committed.entry(block).or_insert(commitment);
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
        let voted_anchor = checkpoint.anchor();
        let commitment = checkpoint.commitment();
        let Some(index) = self.position(voted_anchor) else {
            let minted_round = self
                .pending
                .back()
                .map_or(self.decided_round(), |entry| entry.round());
            if voted_anchor.round >= minted_round {
                self.early
                    .entry(voted_anchor)
                    .or_default()
                    .push((commitment, block));
            } else if voted_anchor.round > self.decided_round() {
                let author = block.authority;
                tracing::warn!(%author, ?voted_anchor, "checkpoint vote for an unknown anchor");
            }
            return None;
        };
        let decided = self.count(index, commitment, block)?;
        self.advance_watermark();
        Some(decided)
    }

    /// Records a committed certificate: under certifying protocols, the first that the
    /// committed votes justify decides its checkpoint. Returns like
    /// [`record`](CheckpointCertifier::record).
    pub fn record_certificate(
        &mut self,
        certificate: &Certificate,
    ) -> Option<(Outcome, CheckpointTimings)> {
        if !self.protocol.certifies() {
            return None;
        }
        let anchor = certificate.anchor();
        let index = self.position(anchor)?;
        let entry = &self.pending[index];
        if entry.decision.is_some() {
            return None;
        }
        let mut cited = Tally::new(certificate.votes().len());
        for block in certificate.votes() {
            let counted = entry.committed.get(block).and_then(|commitment| {
                let stake = self.committee.get_stake(block.authority)?;
                cited.add(stake, *commitment, *block)
            });
            if counted.is_none() {
                tracing::warn!(
                    ?anchor,
                    %block,
                    "certificate cites an uncommitted or repeated vote"
                );
                return None;
            }
        }
        let outcome = certificate.outcome();
        if !self
            .protocol
            .justifies(self.thresholds, outcome, &cited.support, cited.voted)
        {
            tracing::warn!(
                ?anchor,
                ?outcome,
                "certificate does not justify its outcome"
            );
            return None;
        }
        let decided = self.decide(index, outcome, certificate.votes().to_vec());
        self.advance_watermark();
        Some(decided)
    }

    /// The certificates this validator's tallies concluded since the last call, to submit
    /// through consensus.
    pub fn take_certificates(&mut self) -> Vec<Certificate> {
        std::mem::take(&mut self.certificates)
    }

    /// The highest checkpoint such that it and all earlier checkpoints are decided.
    pub fn highest_decided(&self) -> Option<&Decision> {
        self.watermark.as_ref()
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

    /// Counts a vote for the pending checkpoint at `index` into its tally, and returns the
    /// outcome and mint timings exactly when it decides the checkpoint. Under certifying
    /// protocols, the tally's conclusion becomes a certificate to submit instead.
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
        let outcome = self
            .protocol
            .conclude(self.thresholds, commitment, support, tally.voted)?;
        let proof = entry.tally.take().expect("tally concluded").proof(outcome);
        if self.protocol.certifies() {
            let certificate = Certificate::new(voted_anchor, outcome, proof);
            self.certificates.push(certificate);
            return None;
        }
        Some(self.decide(index, outcome, proof))
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
        entry.committed = BTreeMap::new();
        entry.decision = Some(Decision::new(anchor, outcome, proof));
        (outcome, entry.timings)
    }

    /// Advances the watermark over the contiguously decided prefix, reclaiming it.
    fn advance_watermark(&mut self) {
        while self
            .pending
            .front()
            .is_some_and(|entry| entry.decision.is_some())
        {
            self.watermark = self.pending.pop_front().and_then(|entry| entry.decision);
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

        // The watermark keeps advancing from where it stands.
        for authority in 0..3 {
            certifier.record(block(authority, 2), vote(3));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(3));
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
    fn the_watermark_advances_over_skips() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 2);
        for authority in 0..2 {
            certifier.record(block(authority, 0), vote(2));
        }
        assert_eq!(certifier.highest_decided(), None);

        // Skipping the first checkpoint makes the finalized second one contiguous.
        for authority in 0..3 {
            certifier.record(block(authority, 1), diverged(authority as u8));
        }
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(2));
        assert!(certifier.pending().next().is_none());
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
            certifier.record_certificate(&expected),
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
            assert_eq!(certifier.record_certificate(certificate), None);
        }

        // The uncommitted vote commits: the same certificate now decides.
        certifier.record(block(2, 0), vote(1));
        assert!(certifier.record_certificate(&invalid[1]).is_some());
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
            assert_eq!(certifier.record_certificate(certificate), None);
        }
        let skip = certificate(Outcome::Skip, vec![block(1, 0), block(2, 0), block(3, 0)]);
        assert_eq!(
            certifier.record_certificate(&skip),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
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
        assert!(certifier.record_certificate(&skip).is_some());
        assert_eq!(certifier.record_certificate(&finalize), None);

        // A decided height concludes no certificate of our own either.
        for author in 0..4 {
            certifier.record_arrival(block(author, 0), vote(2));
        }
        assert!(certifier.take_certificates().is_empty());

        // Once contiguous, the first certificate's outcome stands.
        certifier.record(block(0, 1), vote(1));
        certifier.record(block(1, 1), vote(1));
        let finalize = Outcome::Finalize(vote(1).commitment());
        certifier.record_certificate(&certificate(finalize, vec![block(0, 1), block(1, 1)]));
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
        assert_eq!(certifier.record_certificate(&light), None);
        let heavy = Outcome::Finalize(vote(1).commitment());
        let heavy = certificate(heavy, vec![block(0, 0)]);
        assert!(certifier.record_certificate(&heavy).is_some());
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
}
