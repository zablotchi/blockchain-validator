// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proposal-size bound: what this validator submits must keep every own proposal under
//! mysticeti's 16 MiB network message limit (one block per message).
//!
//! A proposal takes the replica's pending payloads in order, and the replica stops receiving
//! batches once [`SOFT_MAX_PROPOSED_PER_BLOCK`] payloads are pending (a count checked before
//! each batch), so a proposal holds at most that many minus one plus one whole batch. With `S`
//! the largest client transaction, client batches split at [`CLIENT_BATCH_BYTES`] (`G`) and own
//! protocol bytes in flight capped at `C_max`:
//!
//! ```text
//! proposal ≤ (SOFT_MAX_PROPOSED_PER_BLOCK + 1)·(S + PAYLOAD_FRAMING)
//!            + G + C_max + HEADER_ALLOWANCE
//!          ≤ PROPOSAL_BUDGET
//! ```
//!
//! The header term is mysticeti's and assumed, not enforced: [`HEADER_ALLOWANCE`] holds about
//! 1,100 uncovered block references, which honest authors never approach but a Byzantine author
//! can exceed by flooding sibling blocks or delivering withheld unchained ones.

use std::mem;

pub use dag::core::block_handler::SOFT_MAX_PROPOSED_PER_BLOCK;
use dag::{
    authority::Authority,
    block::{Block, transaction::Transaction as ConsensusTransaction},
    crypto::AsBytes,
};
use execution::crypto::Digest;

use checkpoint::checkpoint::{Certificate, Outcome};

use crate::envelope::{Envelope, Payload};

/// 75% of mysticeti's 16 MiB message limit.
pub const PROPOSAL_BUDGET: u64 = 12 << 20;
/// A proposal's header, includes and signature.
pub const HEADER_ALLOWANCE: u64 = 64 << 10;
/// Client batches (the load generator's and [`submit`]'s) close at the first payload taking
/// their framed size to this.
///
/// [`submit`]: crate::validator::ValidatorHandle::submit
pub const CLIENT_BATCH_BYTES: u64 = 512 << 10;
/// The length prefix of every payload in a serialized block.
pub const PAYLOAD_FRAMING: u64 = 8;

/// The bytes `payload` takes in a serialized block.
pub(crate) fn framed_size(payload: &ConsensusTransaction) -> u64 {
    payload.as_bytes().len() as u64 + PAYLOAD_FRAMING
}

/// The largest client transaction (serialized envelope) that keeps every proposal within
/// [`PROPOSAL_BUDGET`] when own protocol bytes in flight are capped at
/// `protocol_bytes_in_flight`: 539 bytes at the default 1 MiB.
pub fn max_transaction_size(protocol_bytes_in_flight: u64) -> u64 {
    let room = PROPOSAL_BUDGET
        .saturating_sub(CLIENT_BATCH_BYTES + protocol_bytes_in_flight + HEADER_ALLOWANCE);
    (room / (SOFT_MAX_PROPOSED_PER_BLOCK as u64 + 1)).saturating_sub(PAYLOAD_FRAMING)
}

/// Fails unless client transactions of `transaction_size` bytes keep every proposal within
/// [`PROPOSAL_BUDGET`].
pub fn check_proposal_budget(
    transaction_size: usize,
    protocol_bytes_in_flight: u64,
) -> eyre::Result<()> {
    let ceiling = max_transaction_size(protocol_bytes_in_flight);
    eyre::ensure!(
        transaction_size as u64 <= ceiling,
        "transaction_size must not exceed {ceiling} bytes with protocol_bytes_in_flight = \
            {protocol_bytes_in_flight}, or proposals could outgrow {PROPOSAL_BUDGET} bytes"
    );
    Ok(())
}

/// The framed size of the largest payload this validator submits in a committee of
/// `committee_size`: a certificate finalizing with one vote per member.
pub fn max_protocol_payload(committee_size: usize) -> u64 {
    let reference = *Block::genesis(Authority::new(0)).reference();
    let votes = vec![reference; committee_size];
    let certificate = Certificate::new(
        reference,
        Digest::default(),
        Outcome::Finalize(Digest::default()),
        votes,
    );
    let bytes = Envelope::new(0, Payload::Certify(certificate)).to_bytes();
    bytes.len() as u64 + PAYLOAD_FRAMING
}

/// Splits `transactions`, in order, into batches that close at the first payload taking their
/// framed size to `cap`.
pub(crate) fn split_batch(
    transactions: Vec<ConsensusTransaction>,
    cap: u64,
) -> Vec<Vec<ConsensusTransaction>> {
    let mut batches = Vec::new();
    let mut batch = Vec::new();
    let mut bytes = 0;
    for transaction in transactions {
        bytes += framed_size(&transaction);
        batch.push(transaction);
        if bytes >= cap {
            batches.push(mem::take(&mut batch));
            bytes = 0;
        }
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

#[cfg(test)]
mod tests {
    use dag::block::transaction::Transaction as ConsensusTransaction;

    use crate::limits::{
        CLIENT_BATCH_BYTES, HEADER_ALLOWANCE, PAYLOAD_FRAMING, PROPOSAL_BUDGET,
        SOFT_MAX_PROPOSED_PER_BLOCK, check_proposal_budget, framed_size, max_protocol_payload,
        max_transaction_size, split_batch,
    };

    const DEFAULT_IN_FLIGHT: u64 = 1 << 20;

    #[test]
    fn proposal_budget_allows_512_byte_transactions_and_rejects_540() {
        assert_eq!(max_transaction_size(DEFAULT_IN_FLIGHT), 539);
        assert!(check_proposal_budget(512, DEFAULT_IN_FLIGHT).is_ok());
        assert!(check_proposal_budget(539, DEFAULT_IN_FLIGHT).is_ok());
        assert!(check_proposal_budget(540, DEFAULT_IN_FLIGHT).is_err());
        // More protocol bytes in flight leave less room for client transactions.
        assert!(check_proposal_budget(512, 4 << 20).is_err());

        // The ceiling is exact against the module's bound over the accepted protocol budgets.
        let proposal = |size: u64, in_flight: u64| {
            (SOFT_MAX_PROPOSED_PER_BLOCK as u64 + 1) * (size + PAYLOAD_FRAMING)
                + CLIENT_BATCH_BYTES
                + in_flight
                + HEADER_ALLOWANCE
        };
        for in_flight in (max_protocol_payload(4)..=4 << 20).step_by(101) {
            let ceiling = max_transaction_size(in_flight);
            assert!(
                proposal(ceiling, in_flight) <= PROPOSAL_BUDGET,
                "{in_flight}"
            );
            assert!(
                proposal(ceiling + 1, in_flight) > PROPOSAL_BUDGET,
                "{in_flight}"
            );
        }
    }

    fn payloads(count: usize, size: usize) -> Vec<ConsensusTransaction> {
        (0..count)
            .map(|i| ConsensusTransaction::new(vec![i as u8; size].into()))
            .collect()
    }

    #[test]
    fn generator_batches_stay_under_the_batch_cap() {
        let transactions = payloads(10_000, 512);
        let batches = split_batch(transactions.clone(), CLIENT_BATCH_BYTES);
        assert!(batches.len() > 1);
        let framed = |batch: &[ConsensusTransaction]| batch.iter().map(framed_size).sum::<u64>();
        for batch in &batches[..batches.len() - 1] {
            // Each batch closes at the first payload reaching the cap.
            let (last, rest) = batch.split_last().unwrap();
            assert!(framed(rest) < CLIENT_BATCH_BYTES);
            assert!(framed(rest) + framed_size(last) >= CLIENT_BATCH_BYTES);
        }
        assert!(framed(batches.last().unwrap()) < CLIENT_BATCH_BYTES + 512 + PAYLOAD_FRAMING);
        assert_eq!(batches.concat(), transactions);

        // The simulations' generator batches: four 128-byte transactions per 512-byte block.
        let sizes: Vec<_> = split_batch(payloads(10, 128), 512)
            .iter()
            .map(Vec::len)
            .collect();
        assert_eq!(sizes, [4, 4, 2]);
    }
}
