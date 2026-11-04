// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints: commitments to the execution state, sampled per committed sub-dag.

use dag::block::BlockReference;
use execution::crypto::Digest;
use serde::{Deserialize, Serialize};

/// A commitment to the execution state after executing a committed sub-dag's transactions.
///
/// Chaining is inherent: the commitment is the store's rolling hash, which already depends on
/// the full ordered write history. The anchor alone identifies the checkpoint — ordering is
/// local knowledge, so no sequence number travels. A checkpoint doubles as this validator's
/// vote when submitted through consensus.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Checkpoint {
    anchor: BlockReference,
    commitment: Digest,
}

impl Checkpoint {
    pub(crate) fn new(anchor: BlockReference, commitment: Digest) -> Self {
        Self { anchor, commitment }
    }

    pub fn anchor(&self) -> BlockReference {
        self.anchor
    }

    pub fn commitment(&self) -> Digest {
        self.commitment
    }

    pub fn round(&self) -> u64 {
        self.anchor.round
    }

    /// The checkpoint of the `n`-th executing sub-dag: anchored at round `n` (authority 0),
    /// with the default commitment.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(n: u64) -> Self {
        Self::new(BlockReference::new_test(0, n), Digest::default())
    }
}

/// What the committee decided at one checkpoint height.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub enum Outcome {
    /// The committee agrees on the execution state at this height.
    Finalize(Digest),
    /// No commitment can gather enough support; the height is passed over.
    Skip,
}

/// A claimed outcome for the checkpoint anchored at `anchor`, with the blocks carrying the
/// votes that justify it. It verifies against committed votes alone, so it needs no signature
/// of its own.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Certificate {
    anchor: BlockReference,
    outcome: Outcome,
    votes: Vec<BlockReference>,
}

impl Certificate {
    pub(crate) fn new(
        anchor: BlockReference,
        outcome: Outcome,
        votes: Vec<BlockReference>,
    ) -> Self {
        Self {
            anchor,
            outcome,
            votes,
        }
    }

    pub fn anchor(&self) -> BlockReference {
        self.anchor
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn votes(&self) -> &[BlockReference] {
        &self.votes
    }
}

/// A decided checkpoint height: its outcome and the block carrying each vote backing it.
#[derive(PartialEq, Debug)]
pub struct Decision {
    anchor: BlockReference,
    outcome: Outcome,
    proof: Vec<BlockReference>,
}

impl Decision {
    pub(crate) fn new(
        anchor: BlockReference,
        outcome: Outcome,
        proof: Vec<BlockReference>,
    ) -> Self {
        Self {
            anchor,
            outcome,
            proof,
        }
    }

    pub fn anchor(&self) -> BlockReference {
        self.anchor
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn proof(&self) -> &[BlockReference] {
        &self.proof
    }

    pub fn round(&self) -> u64 {
        self.anchor.round
    }
}
