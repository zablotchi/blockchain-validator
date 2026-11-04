// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The checkpoint finality protocols, selectable per run.

use std::fmt;

use dag::committee::Stake;
use execution::crypto::Digest;
use serde::{Deserialize, Serialize};

use crate::checkpoint::Outcome;

/// How a validator turns checkpoint votes into an outcome per height. Votes are counted in
/// commit order unless stated otherwise, first vote per authority.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum FinalityProtocol {
    /// Finalize at 2f+1 matching votes; never skip, so a fork stalls the height forever.
    #[default]
    Baseline,
    /// Sui's rule: the baseline's, with votes counted as their blocks enter the local DAG and
    /// again at commit, as Sui's consensus handler does (a backstop for blocks never streamed,
    /// such as those recovered on restart).
    SuiBaseline,
    /// Finalize at f+1 matching votes, the first commitment to reach them winning; skip once
    /// 2f+1 voted without one doing so.
    A,
}

impl FinalityProtocol {
    /// Decides a height once a counted vote lifts its `commitment`'s support to `support` and
    /// the height's voted stake to `voted`; `None` while undecided.
    pub(crate) fn decide(
        self,
        thresholds: Thresholds,
        commitment: Digest,
        support: Stake,
        voted: Stake,
    ) -> Option<Outcome> {
        match self {
            Self::Baseline | Self::SuiBaseline => {
                (support >= thresholds.quorum).then_some(Outcome::Finalize(commitment))
            }
            Self::A if support >= thresholds.validity => Some(Outcome::Finalize(commitment)),
            Self::A => (voted >= thresholds.quorum).then_some(Outcome::Skip),
        }
    }

    /// Whether votes count as their blocks arrive, before commit.
    pub fn counts_arrivals(self) -> bool {
        self == Self::SuiBaseline
    }

    /// Whether the protocol decides on f+1 votes.
    pub fn needs_validity(self) -> bool {
        self == Self::A
    }
}

/// The compact lowercase name, also used in result filenames.
impl fmt::Display for FinalityProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "baseline"),
            Self::SuiBaseline => write!(f, "sui-baseline"),
            Self::A => write!(f, "a"),
        }
    }
}

/// The stake thresholds the protocols decide on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Thresholds {
    /// 2f+1: the consensus protocol's quorum.
    pub quorum: Stake,
    /// f+1: any set this heavy holds an honest validator. Derived as `total - quorum + 1`,
    /// which is exact for 2f+1 quorums only.
    pub validity: Stake,
}

impl Thresholds {
    pub fn new(total: Stake, quorum: Stake) -> Self {
        Self {
            quorum,
            validity: total - quorum + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::finality::Thresholds;

    #[test]
    fn validity_is_f_plus_one_under_mysticeti_quorums() {
        // Mysticeti's quorum is 2n/3 + 1: 2f+1 at n = 3f+1.
        for (total, f) in [(4, 1), (7, 2), (10, 3), (100, 33)] {
            let thresholds = Thresholds::new(total, 2 * total / 3 + 1);
            assert_eq!(thresholds.validity, f + 1);
        }
    }
}
