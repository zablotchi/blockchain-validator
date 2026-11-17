// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives for state commitments.

use digest::Digest as _;
use serde::{Deserialize, Serialize};

/// The concrete hasher used for state commitments (Blake2b truncated to 256 bits).
pub(crate) type Hasher = blake2::Blake2b<digest::consts::U32>;

/// A 32-byte Blake2b-256 hash. The default value is the zero digest, which also serves as the
/// genesis state commitment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, Debug)]
pub struct Digest([u8; 32]);

impl Digest {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The hash of this digest and `salt`: deterministic, and distinct per salt. Fabricates
    /// diverging commitments without touching the state they commit to.
    pub fn salted(&self, salt: u64) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(self.0);
        hasher.update(salt.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// The commitment after skipping the height anchored at `anchor`: `H(self ‖ "skip" ‖
    /// anchor)`. Folding the marker makes a skip change the commitment even when the skipped
    /// height wrote nothing, so a vote computed before the skip never matches one after it.
    pub fn skip(&self, anchor: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(self.0);
        hasher.update(b"skip");
        hasher.update(anchor);
        Self(hasher.finalize().into())
    }

    /// An arbitrary digest distinct per `byte`, for tests that need unequal commitments.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(byte: u8) -> Self {
        Self([byte; 32])
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Digest;

    // Every validator folds the same marker into its commitment, so the exact bytes matter: pin
    // them so any change to the hash, the tag or the field order fails loudly.
    #[test]
    fn skip_digests_are_stable_across_releases() {
        let anchor: Vec<u8> = (1..=48).collect();
        let hex: String = Digest::default()
            .skip(&anchor)
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hex,
            "20cba0f6910974f2a6f9e50d2d28518aacbb47b8f9704c23b3c4f417701d549d"
        );
    }
}
