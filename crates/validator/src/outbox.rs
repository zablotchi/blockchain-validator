// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pacing of this validator's own votes and certificates, so that every own proposal carries
//! at most a fixed budget of them.

use std::collections::VecDeque;

use checkpoint::checkpoint::{Certificate, Checkpoint};
use dag::{
    authority::Authority,
    block::{Block, BlockReference, transaction::Transaction as ConsensusTransaction},
    crypto::AsBytes,
};

use crate::{
    envelope::{Envelope, Payload},
    limits::framed_size,
};

/// Whether an own payload is a vote or a certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Kind {
    Vote,
    Certificate,
}

/// An own vote or certificate, ready to submit: the height it is for, its kind and the
/// generation of the instance it belongs to. Only the newest generation of a height and kind
/// is current: older ones are on a parent this validator recovered away from.
#[derive(Debug)]
pub(crate) struct Outgoing {
    pub(crate) anchor: BlockReference,
    pub(crate) kind: Kind,
    pub(crate) generation: u32,
    pub(crate) payload: ConsensusTransaction,
}

impl Outgoing {
    /// The vote `checkpoint`, stamped `timestamp_ms`.
    pub(crate) fn vote(timestamp_ms: u64, generation: u32, checkpoint: Checkpoint) -> Self {
        let anchor = checkpoint.anchor();
        Self::new(
            anchor,
            Kind::Vote,
            generation,
            timestamp_ms,
            Payload::Attest(checkpoint),
        )
    }

    /// The certificate `certificate`, stamped `timestamp_ms`.
    pub(crate) fn certificate(
        timestamp_ms: u64,
        generation: u32,
        certificate: Certificate,
    ) -> Self {
        let anchor = certificate.anchor();
        let payload = Payload::Certify(certificate);
        Self::new(anchor, Kind::Certificate, generation, timestamp_ms, payload)
    }

    fn new(
        anchor: BlockReference,
        kind: Kind,
        generation: u32,
        timestamp_ms: u64,
        payload: Payload,
    ) -> Self {
        let bytes = Envelope::new(timestamp_ms, payload).to_bytes();
        Self {
            anchor,
            kind,
            generation,
            payload: ConsensusTransaction::new(bytes.into()),
        }
    }

    /// Whether `other` is for the same height and of the same kind.
    pub(crate) fn replaces(&self, other: &Self) -> bool {
        self.anchor == other.anchor && self.kind == other.kind
    }

    /// The bytes it takes in a proposal.
    pub(crate) fn bytes(&self) -> u64 {
        framed_size(&self.payload)
    }
}

/// Own protocol payloads in submission order. A payload leaves the queue only while the framed
/// bytes submitted and not yet seen in an own proposal stay within the budget, so no own
/// proposal carries more than the budget of them, except after a restart: the payloads the
/// replica recovers from its WAL are not counted (restarts are out of scope).
pub(crate) struct ProtocolOutbox {
    authority: Authority,
    queue: VecDeque<Outgoing>,
    /// Framed bytes of `queue`.
    queued: u64,
    /// Framed bytes submitted and not yet seen in an own proposal.
    outstanding: u64,
    budget: u64,
}

impl ProtocolOutbox {
    pub(crate) fn new(authority: Authority, budget: u64) -> Self {
        Self {
            authority,
            queue: VecDeque::new(),
            queued: 0,
            outstanding: 0,
            budget,
        }
    }

    /// Queues one event's payloads behind those already queued. Of the queued payloads for one
    /// height and kind, only the newest generation stays, whichever order they come in.
    pub(crate) fn enqueue(&mut self, payloads: Vec<Outgoing>) {
        for outgoing in payloads {
            let newer = |queued: &Outgoing| {
                queued.replaces(&outgoing) && queued.generation > outgoing.generation
            };
            if self.queue.iter().any(newer) {
                continue;
            }
            let queued = &mut self.queued;
            self.queue.retain(|stale| {
                let keep = !stale.replaces(&outgoing) || stale.generation >= outgoing.generation;
                if !keep {
                    *queued -= stale.bytes();
                }
                keep
            });
            self.queued += outgoing.bytes();
            self.queue.push_back(outgoing);
        }
    }

    /// The payloads to submit now, counted as outstanding: from the front of the queue, as many
    /// as the budget admits. One always passes when nothing is outstanding, so a payload larger
    /// than the budget cannot block the queue.
    pub(crate) fn next_batch(&mut self) -> Vec<ConsensusTransaction> {
        let mut batch = Vec::new();
        while let Some(front) = self.queue.front() {
            let bytes = front.bytes();
            if self.outstanding > 0 && self.outstanding + bytes > self.budget {
                break;
            }
            self.outstanding += bytes;
            self.queued -= bytes;
            batch.extend(self.queue.pop_front().map(|outgoing| outgoing.payload));
        }
        batch
    }

    /// Whether payloads wait for the budget.
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The framed bytes of the payloads waiting for the budget.
    pub(crate) fn queued_bytes(&self) -> u64 {
        self.queued
    }

    /// Releases the protocol payloads of `block` if this validator authored it, and returns
    /// their framed size. Votes and certificates are told apart by their tag alone: own blocks
    /// carry no other protocol payloads, since client submissions are always wrapped as
    /// executions. Saturates, since payloads recovered from the WAL were never counted.
    pub(crate) fn observe_block(&mut self, block: &Block) -> Option<u64> {
        if block.author() != self.authority {
            return None;
        }
        let protocol: u64 = block
            .transactions()
            .iter()
            .filter(|payload| Envelope::is_protocol(payload.as_bytes()))
            .map(framed_size)
            .sum();
        self.outstanding = self.outstanding.saturating_sub(protocol);
        Some(protocol)
    }

    #[cfg(test)]
    fn outstanding(&self) -> u64 {
        self.outstanding
    }
}

#[cfg(test)]
mod tests {
    use checkpoint::checkpoint::{Certificate, Checkpoint, Outcome};
    use dag::{
        authority::Authority,
        block::{Block, BlockReference, transaction::Transaction as ConsensusTransaction},
        crypto::CryptoEngine,
    };
    use execution::{crypto::Digest, fake::FakeTransaction, object::ObjectId};

    use crate::{
        envelope::{Envelope, Payload},
        outbox::{Outgoing, ProtocolOutbox},
    };

    /// The vote for the `n`-th checkpoint, as queued.
    fn vote(n: u64) -> Outgoing {
        Outgoing::vote(0, 0, Checkpoint::new_for_test(n))
    }

    /// The vote for the `n`-th checkpoint, as submitted.
    fn submitted(n: u64) -> ConsensusTransaction {
        vote(n).payload
    }

    /// A skip certificate for the first checkpoint, as queued.
    fn certificate() -> Outgoing {
        let votes = (0..3)
            .map(|author| BlockReference::new_test(author, 2))
            .collect();
        let anchor = Checkpoint::new_for_test(1).anchor();
        let certificate = Certificate::new(anchor, Digest::default(), Outcome::Skip, votes);
        Outgoing::certificate(0, 0, certificate)
    }

    fn execution(id: u64) -> ConsensusTransaction {
        let create = FakeTransaction::success(vec![], vec![ObjectId::new(id)], vec![]);
        let bytes = Envelope::new(0, Payload::Execute(create.into())).to_bytes();
        ConsensusTransaction::new(bytes.into())
    }

    /// A block of `author` carrying `payloads`.
    fn block(author: usize, payloads: Vec<ConsensusTransaction>) -> Block {
        let author = Authority::from(author);
        Block::new(author, 1, vec![], payloads, 0, &CryptoEngine::disabled())
    }

    /// A block of `author` carrying the votes for the given checkpoints.
    fn voting(author: usize, checkpoints: &[u64]) -> Block {
        block(author, checkpoints.iter().map(|&n| submitted(n)).collect())
    }

    /// The framed size of one vote.
    fn vote_bytes() -> u64 {
        vote(0).bytes()
    }

    #[test]
    fn outbox_outstanding_never_exceeds_the_budget() {
        let budget = 2 * vote_bytes() + vote_bytes() / 2;
        let mut outbox = ProtocolOutbox::new(Authority::new(0), budget);
        let mut all = Vec::new();
        let mut submit = |outbox: &mut ProtocolOutbox| {
            let batch = outbox.next_batch();
            assert!(outbox.outstanding() <= budget);
            all.extend(batch.clone());
            batch.len()
        };

        outbox.enqueue(vec![vote(1), vote(2), vote(3)]);
        assert_eq!(outbox.queued_bytes(), 3 * vote_bytes());
        assert_eq!(submit(&mut outbox), 2);
        assert_eq!(submit(&mut outbox), 0);
        assert!(!outbox.is_empty());
        assert_eq!(outbox.queued_bytes(), vote_bytes());
        // An own block carrying the first vote makes room for the third.
        outbox.observe_block(&voting(0, &[1]));
        assert_eq!(submit(&mut outbox), 1);
        assert!(outbox.is_empty());
        assert_eq!(outbox.queued_bytes(), 0);
        outbox.enqueue(vec![vote(4)]);
        assert_eq!(submit(&mut outbox), 0);
        outbox.observe_block(&voting(0, &[2, 3]));
        assert_eq!(submit(&mut outbox), 1);
        assert_eq!(all, [1, 2, 3, 4].map(submitted));

        // With nothing outstanding, one payload passes even past the budget.
        let mut outbox = ProtocolOutbox::new(Authority::new(0), vote_bytes() - 1);
        outbox.enqueue(vec![vote(5), vote(6)]);
        assert_eq!(outbox.next_batch(), [submitted(5)]);
        assert_eq!(outbox.next_batch(), []);
        outbox.observe_block(&voting(0, &[5]));
        assert_eq!(outbox.next_batch(), [submitted(6)]);
    }

    #[test]
    fn outbox_submits_each_event_batch_unchanged_within_budget() {
        let mut outbox = ProtocolOutbox::new(Authority::new(0), 1 << 20);
        let events: [&[u64]; 4] = [&[1, 2], &[], &[3], &[4]];
        for checkpoints in events {
            outbox.enqueue(checkpoints.iter().map(|&n| vote(n)).collect());
            let expected: Vec<_> = checkpoints.iter().map(|&n| submitted(n)).collect();
            assert_eq!(outbox.next_batch(), expected);
            assert!(outbox.is_empty());
        }
    }

    #[test]
    fn own_blocks_release_only_protocol_bytes() {
        let mut outbox = ProtocolOutbox::new(Authority::new(0), 1 << 20);
        outbox.enqueue(vec![vote(1), vote(2), certificate()]);
        outbox.next_batch();
        let certificate_bytes = certificate().bytes();
        assert_eq!(outbox.outstanding(), 2 * vote_bytes() + certificate_bytes);

        // Other authors' blocks release nothing, nor do executions and undecodable payloads.
        assert_eq!(outbox.observe_block(&voting(1, &[1])), None);
        let garbage = ConsensusTransaction::new(vec![0xFF; 16].into());
        let unrelated = vec![execution(1), garbage.clone()];
        assert_eq!(outbox.observe_block(&block(0, unrelated)), Some(0));
        assert_eq!(outbox.outstanding(), 2 * vote_bytes() + certificate_bytes);

        let mixed = vec![execution(2), submitted(1), certificate().payload, garbage];
        let released = vote_bytes() + certificate_bytes;
        assert_eq!(outbox.observe_block(&block(0, mixed)), Some(released));
        assert_eq!(outbox.outstanding(), vote_bytes());
        // Payloads never counted, as recovered ones, release down to zero only.
        assert_eq!(
            outbox.observe_block(&voting(0, &[2, 7])),
            Some(2 * vote_bytes())
        );
        assert_eq!(outbox.outstanding(), 0);
    }

    #[test]
    fn outbox_keeps_the_newest_generation_in_either_order() {
        let checkpoint = Checkpoint::new_for_test(1);
        let original = || Outgoing::vote(0, 0, checkpoint.clone());
        // On the parent a recovery moved to.
        let recovered = Checkpoint::new(
            checkpoint.anchor(),
            Digest::new_for_test(2),
            Digest::new_for_test(3),
        );
        let re_vote = || Outgoing::vote(0, 1, recovered.clone());
        for order in [[original(), re_vote()], [re_vote(), original()]] {
            // Nothing passes: a payload is outstanding and the budget admits no more.
            let mut outbox = ProtocolOutbox::new(Authority::new(0), vote_bytes());
            outbox.enqueue(vec![vote(9)]);
            outbox.next_batch();
            for outgoing in order {
                outbox.enqueue(vec![outgoing]);
            }
            // A certificate for the same height stays: another kind.
            outbox.enqueue(vec![certificate()]);
            let queued = vote_bytes() + certificate().bytes();
            assert_eq!(outbox.queued_bytes(), queued);

            outbox.observe_block(&voting(0, &[9]));
            assert_eq!(outbox.next_batch(), [re_vote().payload]);
            outbox.observe_block(&block(0, vec![re_vote().payload]));
            assert_eq!(outbox.next_batch(), [certificate().payload]);
            assert!(outbox.is_empty());
        }
    }
}
