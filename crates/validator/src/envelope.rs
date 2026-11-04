// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The consensus payload envelope and its byte codec.

use std::ops::Range;

use bincode::Options;
use checkpoint::checkpoint::{Certificate, Checkpoint};
use execution::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// Payloads larger than this fail to decode. Bounds the allocations a malformed length prefix
/// can request, since payload bytes come from untrusted clients via consensus.
pub const MAX_PAYLOAD_SIZE: u64 = 1024 * 1024;

/// Where fixint bincode puts the payload's variant index, after the timestamp, and its values
/// for [`Payload::Attest`] and [`Payload::Certify`].
const TAG: Range<usize> = 8..12;
const ATTEST_TAG: [u8; 4] = 1u32.to_le_bytes();
const CERTIFY_TAG: [u8; 4] = 2u32.to_le_bytes();

/// What every consensus payload carries: the submission timestamp, then the payload proper.
///
/// The layout is load-bearing: `timestamp_ms` must stay the first field of the outer struct so
/// that fixint bincode places it in the payload's first 8 little-endian bytes, where dag's
/// `Transaction::extract_timestamp` reads the submission time — mysticeti's commit-latency
/// metric works with no upstream changes. Nesting the other way (enum outside) would put the
/// variant tag there instead.
#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub struct Envelope {
    timestamp_ms: u64,
    payload: Payload,
}

/// The payload proper, dispatched where the sub-dag consumer decodes it.
#[derive(PartialEq, Serialize, Deserialize, Debug)]
pub enum Payload {
    /// A client transaction bound for the execution engine.
    Execute(Transaction),
    /// A checkpoint vote bound for the certifier, attributed to the block author.
    Attest(Checkpoint),
    /// A certificate concluded by its author's tally, bound for every certifier.
    Certify(Certificate),
}

impl Envelope {
    pub fn new(timestamp_ms: u64, payload: Payload) -> Self {
        Self {
            timestamp_ms,
            payload,
        }
    }

    pub fn into_payload(self) -> Payload {
        self.payload
    }

    /// The submission time stamped at [`new`](Envelope::new), in milliseconds since epoch.
    pub(crate) fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Encodes the envelope into the opaque bytes carried by consensus.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Decodes an envelope from consensus payload bytes.
    pub fn from_bytes(bytes: &[u8]) -> bincode::Result<Self> {
        // Same format as `bincode::serialize` (fixint, trailing bytes tolerated), plus the
        // size limit; the envelope's few bytes of overhead eat into the transaction budget.
        bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_PAYLOAD_SIZE)
            .deserialize_from(bytes)
    }

    /// Decodes the checkpoint vote in consensus payload bytes, if they carry one. Other
    /// payloads are told apart by their variant tag, without decoding them.
    pub(crate) fn attestation_from_bytes(bytes: &[u8]) -> Option<Checkpoint> {
        match Self::tagged_from_bytes(bytes, ATTEST_TAG)? {
            Payload::Attest(checkpoint) => Some(checkpoint),
            Payload::Execute(_) | Payload::Certify(_) => None,
        }
    }

    /// Decodes the certificate in consensus payload bytes, like
    /// [`attestation_from_bytes`](Envelope::attestation_from_bytes).
    pub(crate) fn certificate_from_bytes(bytes: &[u8]) -> Option<Certificate> {
        match Self::tagged_from_bytes(bytes, CERTIFY_TAG)? {
            Payload::Certify(certificate) => Some(certificate),
            Payload::Execute(_) | Payload::Attest(_) => None,
        }
    }

    /// Decodes the payload in consensus payload bytes if its variant tag is `tag`.
    fn tagged_from_bytes(bytes: &[u8], tag: [u8; 4]) -> Option<Payload> {
        if bytes.get(TAG) != Some(&tag[..]) {
            return None;
        }
        Some(Self::from_bytes(bytes).ok()?.into_payload())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use checkpoint::checkpoint::Checkpoint;
    use dag::block::transaction::Transaction as ConsensusTransaction;
    use execution::transaction::{FunctionId, Transaction};

    use crate::envelope::{Envelope, Payload};

    fn envelope(timestamp_ms: u64, args: Vec<u8>) -> Envelope {
        let transaction = Transaction::new(FunctionId::new(7), vec![], args);
        Envelope::new(timestamp_ms, Payload::Execute(transaction))
    }

    #[test]
    fn envelopes_roundtrip_through_bytes() {
        let envelope = envelope(1234, vec![1, 2, 3]);
        let decoded = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn attestations_roundtrip_through_bytes() {
        let envelope = Envelope::new(1234, Payload::Attest(Checkpoint::new_for_test(1)));
        let decoded = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn attestations_are_told_apart_from_transactions() {
        let checkpoint = Checkpoint::new_for_test(1);
        let attestation = Envelope::new(1234, Payload::Attest(checkpoint.clone())).to_bytes();
        assert_eq!(
            Envelope::attestation_from_bytes(&attestation),
            Some(checkpoint)
        );
        let transaction = envelope(1234, vec![1, 2, 3]).to_bytes();
        assert_eq!(Envelope::attestation_from_bytes(&transaction), None);
        assert_eq!(Envelope::attestation_from_bytes(&attestation[..12]), None);
    }

    #[test]
    fn timestamp_lands_where_upstream_reads_it() {
        let timestamp_ms = 123_456_789;
        let bytes = envelope(timestamp_ms, vec![1, 2, 3]).to_bytes();
        let transaction = ConsensusTransaction::new(bytes.into());
        assert_eq!(
            transaction.extract_timestamp(),
            Some(Duration::from_millis(timestamp_ms))
        );
    }

    #[test]
    fn garbage_bytes_fail_to_decode() {
        assert!(Envelope::from_bytes(&[0xFF; 16]).is_err());
    }

    #[test]
    fn oversized_envelopes_fail_to_decode() {
        let args = vec![0; 2 * super::MAX_PAYLOAD_SIZE as usize];
        assert!(Envelope::from_bytes(&envelope(1234, args).to_bytes()).is_err());
    }
}
