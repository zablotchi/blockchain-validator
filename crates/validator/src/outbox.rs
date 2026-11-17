// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pacing of this validator's own votes and certificates, so that every own proposal carries
//! at most a fixed budget of them.

use std::collections::VecDeque;

use dag::{
    authority::Authority,
    block::{Block, transaction::Transaction as ConsensusTransaction},
    crypto::AsBytes,
};

use crate::{envelope::Envelope, limits::framed_size};

/// Own protocol payloads in submission order. A payload leaves the queue only while the framed
/// bytes submitted and not yet seen in an own proposal stay within the budget, so no own
/// proposal carries more than the budget of them, except after a restart: the payloads the
/// replica recovers from its WAL are not counted (restarts are out of scope).
pub(crate) struct ProtocolOutbox {
    authority: Authority,
    queue: VecDeque<ConsensusTransaction>,
    /// Framed bytes submitted and not yet seen in an own proposal.
    outstanding: u64,
    budget: u64,
}

impl ProtocolOutbox {
    pub(crate) fn new(authority: Authority, budget: u64) -> Self {
        Self {
            authority,
            queue: VecDeque::new(),
            outstanding: 0,
            budget,
        }
    }

    /// Queues one event's payloads behind those already queued.
    pub(crate) fn enqueue(&mut self, payloads: Vec<ConsensusTransaction>) {
        self.queue.extend(payloads);
    }

    /// The payloads to submit now, counted as outstanding: from the front of the queue, as many
    /// as the budget admits. One always passes when nothing is outstanding, so a payload larger
    /// than the budget cannot block the queue.
    pub(crate) fn next_batch(&mut self) -> Vec<ConsensusTransaction> {
        let mut batch = Vec::new();
        while let Some(front) = self.queue.front() {
            let bytes = framed_size(front);
            if self.outstanding > 0 && self.outstanding + bytes > self.budget {
                break;
            }
            self.outstanding += bytes;
            batch.extend(self.queue.pop_front());
        }
        batch
    }

    /// Whether payloads wait for the budget.
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
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
        limits::framed_size,
        outbox::ProtocolOutbox,
    };

    /// The vote for the `n`-th checkpoint, as submitted.
    fn vote(n: u64) -> ConsensusTransaction {
        let bytes = Envelope::new(0, Payload::Attest(Checkpoint::new_for_test(n))).to_bytes();
        ConsensusTransaction::new(bytes.into())
    }

    /// A skip certificate for the first checkpoint, as submitted.
    fn certificate() -> ConsensusTransaction {
        let votes = (0..3)
            .map(|author| BlockReference::new_test(author, 2))
            .collect();
        let anchor = Checkpoint::new_for_test(1).anchor();
        let certificate = Certificate::new(anchor, Digest::default(), Outcome::Skip, votes);
        let bytes = Envelope::new(0, Payload::Certify(certificate)).to_bytes();
        ConsensusTransaction::new(bytes.into())
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

    /// The framed size of one vote.
    fn vote_bytes() -> u64 {
        framed_size(&vote(0))
    }

    #[test]
    fn outbox_outstanding_never_exceeds_the_budget() {
        let budget = 2 * vote_bytes() + vote_bytes() / 2;
        let mut outbox = ProtocolOutbox::new(Authority::new(0), budget);
        let mut submitted = Vec::new();
        let mut submit = |outbox: &mut ProtocolOutbox| {
            let batch = outbox.next_batch();
            assert!(outbox.outstanding() <= budget);
            submitted.extend(batch.clone());
            batch.len()
        };

        outbox.enqueue(vec![vote(1), vote(2), vote(3)]);
        assert_eq!(submit(&mut outbox), 2);
        assert_eq!(submit(&mut outbox), 0);
        assert!(!outbox.is_empty());
        // An own block carrying the first vote makes room for the third.
        outbox.observe_block(&block(0, vec![vote(1)]));
        assert_eq!(submit(&mut outbox), 1);
        assert!(outbox.is_empty());
        outbox.enqueue(vec![vote(4)]);
        assert_eq!(submit(&mut outbox), 0);
        outbox.observe_block(&block(0, vec![vote(2), vote(3)]));
        assert_eq!(submit(&mut outbox), 1);
        assert_eq!(submitted, [1, 2, 3, 4].map(vote));

        // With nothing outstanding, one payload passes even past the budget.
        let mut outbox = ProtocolOutbox::new(Authority::new(0), vote_bytes() - 1);
        outbox.enqueue(vec![vote(5), vote(6)]);
        assert_eq!(outbox.next_batch(), [vote(5)]);
        assert_eq!(outbox.next_batch(), []);
        outbox.observe_block(&block(0, vec![vote(5)]));
        assert_eq!(outbox.next_batch(), [vote(6)]);
    }

    #[test]
    fn outbox_submits_each_event_batch_unchanged_within_budget() {
        let mut outbox = ProtocolOutbox::new(Authority::new(0), 1 << 20);
        let events = [vec![vote(1), vote(2)], vec![], vec![vote(3)], vec![vote(4)]];
        for payloads in events {
            outbox.enqueue(payloads.clone());
            assert_eq!(outbox.next_batch(), payloads);
            assert!(outbox.is_empty());
        }
    }

    #[test]
    fn own_blocks_release_only_protocol_bytes() {
        let mut outbox = ProtocolOutbox::new(Authority::new(0), 1 << 20);
        outbox.enqueue(vec![vote(1), vote(2), certificate()]);
        outbox.next_batch();
        let certificate_bytes = framed_size(&certificate());
        assert_eq!(outbox.outstanding(), 2 * vote_bytes() + certificate_bytes);

        // Other authors' blocks release nothing, nor do executions and undecodable payloads.
        assert_eq!(outbox.observe_block(&block(1, vec![vote(1)])), None);
        let garbage = ConsensusTransaction::new(vec![0xFF; 16].into());
        let unrelated = vec![execution(1), garbage.clone()];
        assert_eq!(outbox.observe_block(&block(0, unrelated)), Some(0));
        assert_eq!(outbox.outstanding(), 2 * vote_bytes() + certificate_bytes);

        let mixed = vec![execution(2), vote(1), certificate(), garbage];
        let released = vote_bytes() + certificate_bytes;
        assert_eq!(outbox.observe_block(&block(0, mixed)), Some(released));
        assert_eq!(outbox.outstanding(), vote_bytes());
        // Payloads never counted, as recovered ones, release down to zero only.
        let recovered = vec![vote(2), vote(7)];
        assert_eq!(
            outbox.observe_block(&block(0, recovered)),
            Some(2 * vote_bytes())
        );
        assert_eq!(outbox.outstanding(), 0);
    }
}
