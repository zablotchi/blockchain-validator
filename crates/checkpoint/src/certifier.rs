// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Finality: tallying checkpoint votes into decided checkpoints.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use dag::{
    authority::{Authority, AuthoritySet},
    block::BlockReference,
    committee::{Committee, Stake},
};
use execution::crypto::Digest;

use crate::{
    checkpoint::{Checkpoint, Decision, Outcome},
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
    /// Each counted vote's author, commitment, and delivering sub-dag.
    votes: Vec<(Authority, Digest, BlockReference)>,
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

    /// Counts `author`'s vote and returns its commitment's support, or `None` if `author`
    /// already voted.
    fn add(
        &mut self,
        author: Authority,
        stake: Stake,
        commitment: Digest,
        subdag: BlockReference,
    ) -> Option<Stake> {
        if !self.voters.insert(author) {
            return None;
        }
        self.voted += stake;
        self.votes.push((author, commitment, subdag));
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
            .find(|(voter, ..)| *voter == author)
            .map(|(_, attested, _)| *attested)
    }

    /// The delivering sub-dags of the votes backing `outcome`, in count order.
    fn proof(&self, outcome: Outcome) -> Vec<BlockReference> {
        self.votes
            .iter()
            .filter(|(_, attested, _)| match outcome {
                Outcome::Finalize(finalized) => *attested == finalized,
                Outcome::Skip => true,
            })
            .map(|(.., subdag)| *subdag)
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
    tally: Tally,
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
        }
    }

    /// Mints this validator's checkpoint for the sub-dag anchored at `anchor` and returns it,
    /// ready to submit as this validator's vote. The timings ride along and are surrendered
    /// by [`record`](CheckpointCertifier::record) when the decision forms. Deciding can never
    /// outrun minting: a vote only commits after the sub-dag it attests, which we process
    /// first.
    pub fn push(
        &mut self,
        anchor: BlockReference,
        commitment: Digest,
        timings: CheckpointTimings,
    ) -> &Checkpoint {
        self.pending.push_back(PendingCheckpoint {
            local: Checkpoint::new(anchor, commitment),
            timings,
            tally: Tally::new(self.committee.len()),
            decision: None,
        });
        &self.pending.back().expect("just pushed").local
    }

    /// This validator's checkpoints not yet contiguously decided, in commit order.
    pub fn pending(&self) -> impl Iterator<Item = &Checkpoint> {
        self.pending.iter().map(|entry| &entry.local)
    }

    /// Counts `author`'s vote for `checkpoint`, delivered in the committed sub-dag anchored at
    /// `subdag`. The first vote per authority and checkpoint wins. Returns the outcome and the
    /// mint timings exactly when this vote decides the checkpoint.
    pub fn record(
        &mut self,
        subdag: BlockReference,
        author: Authority,
        checkpoint: Checkpoint,
    ) -> Option<(Outcome, CheckpointTimings)> {
        let voted_anchor = checkpoint.anchor();
        // A vote cannot be witnessed before its anchor's sub-dag committed by construction.
        // Window entries are in commit order, so anchor rounds are non-decreasing: binary
        // search to the vote's round, then walk only the same-round (multi-leader) run.
        let start = self
            .pending
            .partition_point(|entry| entry.round() < voted_anchor.round);
        let entry = self
            .pending
            .range_mut(start..)
            .take_while(|entry| entry.round() == voted_anchor.round)
            .find(|entry| entry.local.anchor() == voted_anchor);
        let Some(entry) = entry else {
            let decided_round = self
                .watermark
                .as_ref()
                .map_or(0, |decision| decision.round());
            if voted_anchor.round > decided_round {
                tracing::warn!(%author, ?voted_anchor, "checkpoint vote for an unknown anchor");
            }
            return None;
        };
        // Already decided, awaiting contiguity: an observed decision can never change.
        if entry.decision.is_some() {
            return None;
        }

        let commitment = checkpoint.commitment();
        let stake = self
            .committee
            .get_stake(author)
            .expect("Authority not found");
        let Some(support) = entry.tally.add(author, stake, commitment, subdag) else {
            if entry.tally.attested(author) != Some(commitment) {
                tracing::warn!(%author, ?voted_anchor, "conflicting checkpoint vote");
            }
            return None;
        };
        let outcome =
            self.protocol
                .decide(self.thresholds, commitment, support, entry.tally.voted)?;
        // A disagreement with our own pending checkpoint means our execution diverged.
        if let Outcome::Finalize(finalized) = outcome
            && entry.local.commitment() != finalized
        {
            tracing::error!(
                ?voted_anchor,
                "local checkpoint diverges from the finalized checkpoint"
            );
        }
        let proof = std::mem::take(&mut entry.tally).proof(outcome);
        entry.decision = Some(Decision::new(voted_anchor, outcome, proof));
        let timings = entry.timings;

        // Advance the watermark over the contiguously decided prefix, reclaiming it.
        while self
            .pending
            .front()
            .is_some_and(|entry| entry.decision.is_some())
        {
            self.watermark = self.pending.pop_front().and_then(|entry| entry.decision);
        }
        Some((outcome, timings))
    }

    /// The highest checkpoint such that it and all earlier checkpoints are decided.
    pub fn highest_decided(&self) -> Option<&Decision> {
        self.watermark.as_ref()
    }

    /// A certifier over a [`Committee::new_test`] committee that already minted checkpoints
    /// `1..=minted` matching [`Checkpoint::new_for_test`]: votes are only admissible for
    /// locally witnessed checkpoints.
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

    use dag::{authority::Authority, block::BlockReference, committee::Committee};
    use execution::crypto::Digest;

    use crate::{
        certifier::{CheckpointCertifier, CheckpointTimings},
        checkpoint::{Checkpoint, Decision, Outcome},
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

    /// The anchor of the `n`-th sub-dag delivering votes, after the checkpointed ones.
    fn subdag(n: u64) -> BlockReference {
        BlockReference::new_test(0, 100 + n)
    }

    #[test]
    fn push_returns_the_minted_checkpoint() {
        // A non-empty window distinguishes the newly minted entry from the front.
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        let minted = certifier.push(
            vote(2).anchor(),
            vote(2).commitment(),
            CheckpointTimings::default(),
        );
        assert_eq!(minted, &vote(2));
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

        assert_eq!(
            certifier.record(subdag(0), Authority::new(0), vote(1)),
            None
        );
        assert_eq!(
            certifier.record(subdag(0), Authority::new(1), vote(1)),
            None
        );
        assert_eq!(
            certifier.record(subdag(1), Authority::new(2), vote(1)),
            Some((Outcome::Finalize(vote(1).commitment()), timings))
        );
        // The certificate never changes, and the timings surrender exactly once.
        assert_eq!(
            certifier.record(subdag(2), Authority::new(3), vote(1)),
            None
        );
    }

    #[test]
    fn certification_prunes_the_pending_checkpoints() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 2);
        for authority in 0..3 {
            certifier.record(subdag(0), Authority::new(authority), vote(1));
        }
        assert_eq!(certifier.pending().collect::<Vec<_>>(), [&vote(2)]);
    }

    #[test]
    fn quorum_certifies_at_threshold_with_the_delivering_subdags_as_proof() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(subdag(0), Authority::new(0), vote(1));
        certifier.record(subdag(0), Authority::new(1), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        certifier.record(subdag(1), Authority::new(2), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(1));
        assert_eq!(certified.proof(), [subdag(0), subdag(0), subdag(1)]);

        // A late matching vote does not grow the proof.
        certifier.record(subdag(2), Authority::new(3), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [subdag(0), subdag(0), subdag(1)]);
    }

    #[test]
    fn duplicate_votes_add_no_stake() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 2, 1);
        certifier.record(subdag(0), Authority::new(0), vote(1));
        certifier.record(subdag(1), Authority::new(0), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        certifier.record(subdag(2), Authority::new(1), vote(1));
        assert!(certifier.highest_decided().is_some());
    }

    #[test]
    fn a_single_vote_crossing_quorum_certifies() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![5, 1, 1, 1], 5, 1);
        certifier.record(subdag(0), Authority::new(0), vote(1));

        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [subdag(0)]);
    }

    #[test]
    fn minority_conflict_does_not_block_certification() {
        let diverged = || Checkpoint::new(vote(1).anchor(), Digest::new_for_test(1));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(subdag(9), Authority::new(0), diverged());
        certifier.record(subdag(0), Authority::new(1), vote(1));
        certifier.record(subdag(0), Authority::new(2), vote(1));
        certifier.record(subdag(1), Authority::new(3), vote(1));

        // The majority value certifies, and the diverged vote's sub-dag stays out of the proof.
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(1));
        assert_eq!(certified.proof(), [subdag(0), subdag(0), subdag(1)]);
    }

    #[test]
    fn conflicting_commitments_cannot_both_certify() {
        let diverged = || Checkpoint::new(vote(1).anchor(), Digest::new_for_test(1));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        certifier.record(subdag(0), Authority::new(0), vote(1));
        certifier.record(subdag(0), Authority::new(1), vote(1));
        certifier.record(subdag(0), Authority::new(2), diverged());
        certifier.record(subdag(0), Authority::new(3), diverged());
        assert_eq!(certifier.highest_decided(), None);

        // A conflicting second vote is ignored: the first wins.
        certifier.record(subdag(1), Authority::new(0), diverged());
        assert_eq!(certifier.highest_decided(), None);
    }

    #[test]
    fn a_quorum_diverging_from_the_local_checkpoint_still_certifies() {
        let diverged = || Checkpoint::new(vote(1).anchor(), Digest::new_for_test(1));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        for authority in 0..3 {
            certifier.record(subdag(0), Authority::new(authority), diverged());
        }

        // The certificate carries the quorum's commitment, not ours, and the entry is
        // reclaimed: the quorum decides the truth even when we are the diverged one.
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), diverged());
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
            certifier.record(subdag(9), Authority::new(authority), unminted());
        }
        assert_eq!(certifier.highest_decided(), None);

        // Both same-round checkpoints certify, even voted out of mint order.
        for authority in 0..3 {
            certifier.record(subdag(0), Authority::new(authority), second());
        }
        assert_eq!(certifier.highest_decided(), None);
        for authority in 0..3 {
            certifier.record(subdag(1), Authority::new(authority), first());
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), second());
        assert!(certifier.pending().next().is_none());
    }

    #[test]
    fn votes_for_unminted_checkpoints_are_rejected() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);

        // Even a full quorum for a never-witnessed checkpoint allocates and certifies nothing.
        for authority in 0..4 {
            certifier.record(subdag(0), Authority::new(authority), vote(5));
        }
        assert_eq!(certifier.highest_decided(), None);
    }

    #[test]
    fn watermark_is_contiguous() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 3);
        let mut timings = None;
        for authority in 0..3 {
            timings = certifier.record(subdag(0), Authority::new(authority), vote(2));
        }
        // The certificate formed — timings surrendered — although not yet contiguous.
        assert!(timings.is_some());
        assert_eq!(certifier.highest_decided(), None);

        // A late vote for the certified-but-not-yet-contiguous checkpoint changes nothing.
        certifier.record(subdag(9), Authority::new(3), vote(2));

        for authority in 0..3 {
            certifier.record(subdag(1), Authority::new(authority), vote(1));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(2));
        assert_eq!(certified.proof(), [subdag(0), subdag(0), subdag(0)]);

        // The watermark keeps advancing from where it stands.
        for authority in 0..3 {
            certifier.record(subdag(2), Authority::new(authority), vote(3));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(finalized(certified), vote(3));
    }

    #[test]
    fn votes_below_the_watermark_are_ignored() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![1; 4], 3, 1);
        for authority in 0..3 {
            certifier.record(subdag(0), Authority::new(authority), vote(1));
        }

        // A full quorum re-voting a reclaimed checkpoint cannot alter the certificate.
        for authority in 0..4 {
            certifier.record(subdag(5), Authority::new(authority), vote(1));
        }
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof(), [subdag(0), subdag(0), subdag(0)]);
    }

    #[test]
    fn votes_are_stake_weighted() {
        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::Baseline, vec![5, 1, 1, 1], 5, 1);
        certifier.record(subdag(0), Authority::new(1), vote(1));
        certifier.record(subdag(0), Authority::new(2), vote(1));
        certifier.record(subdag(0), Authority::new(3), vote(1));
        assert_eq!(certifier.highest_decided(), None);

        // The heavy validator tips 3 stake over the threshold.
        certifier.record(subdag(1), Authority::new(0), vote(1));
        let certified = certifier.highest_decided().expect("certified checkpoint");
        assert_eq!(certified.proof().len(), 4);
    }

    #[test]
    fn protocol_a_finalizes_at_f_plus_one_matching_votes_before_skipping() {
        let diverged = || Checkpoint::new(vote(1).anchor(), Digest::new_for_test(1));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 1);
        assert_eq!(
            certifier.record(subdag(0), Authority::new(0), diverged()),
            None
        );
        assert_eq!(
            certifier.record(subdag(1), Authority::new(1), vote(1)),
            None
        );

        // The third voter completes a quorum, but its vote is also the second matching one.
        let outcome = Outcome::Finalize(vote(1).commitment());
        assert_eq!(
            certifier.record(subdag(2), Authority::new(2), vote(1)),
            Some((outcome, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(1));
        assert_eq!(decided.proof(), [subdag(1), subdag(2)]);
    }

    #[test]
    fn protocol_a_skips_once_a_quorum_voted_without_f_plus_one_matching() {
        let diverged = |byte| Checkpoint::new(vote(1).anchor(), Digest::new_for_test(byte));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 1);
        certifier.record(subdag(0), Authority::new(0), vote(1));
        // Repeat votes, matching or not, add no voted stake: two voters are not a quorum.
        certifier.record(subdag(1), Authority::new(0), vote(1));
        certifier.record(subdag(1), Authority::new(0), diverged(3));
        assert_eq!(
            certifier.record(subdag(1), Authority::new(1), diverged(1)),
            None
        );
        assert_eq!(
            certifier.record(subdag(2), Authority::new(2), diverged(2)),
            Some((Outcome::Skip, CheckpointTimings::default()))
        );
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.anchor(), vote(1).anchor());
        assert_eq!(decided.outcome(), Outcome::Skip);
        assert_eq!(decided.proof(), [subdag(0), subdag(1), subdag(2)]);

        // A late vote that would make f+1 matching cannot overturn the skip.
        certifier.record(subdag(3), Authority::new(3), vote(1));
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(decided.outcome(), Outcome::Skip);
    }

    #[test]
    fn the_watermark_advances_over_skips() {
        let diverged = |byte| Checkpoint::new(vote(1).anchor(), Digest::new_for_test(byte));

        let mut certifier =
            CheckpointCertifier::new_for_test(FinalityProtocol::A, vec![1; 4], 3, 2);
        for authority in 0..2 {
            certifier.record(subdag(0), Authority::new(authority), vote(2));
        }
        assert_eq!(certifier.highest_decided(), None);

        // Skipping the first checkpoint makes the finalized second one contiguous.
        for authority in 0..3 {
            certifier.record(
                subdag(1),
                Authority::new(authority),
                diverged(authority as u8),
            );
        }
        let decided = certifier.highest_decided().expect("decided checkpoint");
        assert_eq!(finalized(decided), vote(2));
        assert!(certifier.pending().next().is_none());
    }
}
