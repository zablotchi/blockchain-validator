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
    /// A's rule over votes counted as their blocks arrive, concluding in a certificate each
    /// validator submits through consensus; the first valid certificate to commit decides.
    B,
    /// Two phases at 2f+1. Votes counted as their blocks arrive conclude in a phase-one
    /// certificate at 2f+1 matching, or a skip certificate at 2f+1 voted once the phase-one
    /// timeout expired. Phase-one certificates from 2f+1 decide as their blocks arrive (the
    /// fast path); otherwise the commit sequence decides: its first phase-one certificate, or
    /// 2f+1 skip certificates before any (the slow path).
    C,
}

impl FinalityProtocol {
    /// Concludes a height's tally with `commitment` at `support` (the one a counted vote just
    /// lifted, or on expiry the best supported) and the height's voted stake at `voted`;
    /// `None` while open. `expired` is whether C's phase-one timeout expired. The conclusion
    /// is the decision, or what the certificate claims if the protocol
    /// [certifies](FinalityProtocol::certifies).
    pub(crate) fn conclude(
        self,
        thresholds: Thresholds,
        commitment: Digest,
        support: Stake,
        voted: Stake,
        expired: bool,
    ) -> Option<Outcome> {
        match self {
            Self::Baseline | Self::SuiBaseline | Self::C if support >= thresholds.quorum => {
                Some(Outcome::Finalize(commitment))
            }
            Self::Baseline | Self::SuiBaseline => None,
            Self::A | Self::B if support >= thresholds.validity => {
                Some(Outcome::Finalize(commitment))
            }
            Self::A | Self::B => (voted >= thresholds.quorum).then_some(Outcome::Skip),
            Self::C => (expired && voted >= thresholds.quorum).then_some(Outcome::Skip),
        }
    }

    /// Whether a certificate's cited votes, totalling `voted` stake with `support` per
    /// commitment, justify the `outcome` it claims: they alone meet the thresholds of the
    /// conclusion.
    pub(crate) fn justifies(
        self,
        thresholds: Thresholds,
        outcome: Outcome,
        support: &[(Digest, Stake)],
        voted: Stake,
    ) -> bool {
        let threshold = match self {
            Self::Baseline | Self::SuiBaseline | Self::A => return false,
            Self::B => thresholds.validity,
            Self::C => thresholds.quorum,
        };
        match outcome {
            Outcome::Finalize(finalized) => support
                .iter()
                .any(|&(attested, stake)| attested == finalized && stake >= threshold),
            Outcome::Skip => {
                voted >= thresholds.quorum && support.iter().all(|&(_, stake)| stake < threshold)
            }
        }
    }

    /// Whether committed valid skip certificates from distinct authorities, totalling
    /// `support`, decide the skip. A committed valid phase-one certificate always decides.
    pub(crate) fn settles_skip(self, thresholds: Thresholds, support: Stake) -> bool {
        match self {
            Self::Baseline | Self::SuiBaseline | Self::A => false,
            Self::B => true,
            Self::C => support >= thresholds.quorum,
        }
    }

    /// Whether valid phase-one certificates arriving from distinct authorities, totalling
    /// `support`, finalize their commitment before commit: C's fast path.
    pub(crate) fn finalizes_on_arrival(self, thresholds: Thresholds, support: Stake) -> bool {
        self == Self::C && support >= thresholds.quorum
    }

    /// Whether votes count as their blocks arrive, before commit.
    pub fn counts_arrivals(self) -> bool {
        matches!(self, Self::SuiBaseline | Self::B | Self::C)
    }

    /// Whether certificates also count as their blocks arrive, before commit.
    pub fn counts_arriving_certificates(self) -> bool {
        self == Self::C
    }

    /// Whether tallies conclude in certificates, which decide once committed, rather than in
    /// decisions.
    pub(crate) fn certifies(self) -> bool {
        matches!(self, Self::B | Self::C)
    }

    /// Whether tallies await a timeout from the local mint (C's phase-one timeout) before
    /// concluding without a winner.
    pub fn times_out(self) -> bool {
        self == Self::C
    }

    /// Whether the thresholds hold only under the 2f+1 quorum of n = 3f+1: A and B derive f+1
    /// from it, and C relies on any two quorums sharing an honest validator.
    pub fn needs_bft_quorum(self) -> bool {
        matches!(self, Self::A | Self::B | Self::C)
    }
}

/// The compact lowercase name, also used in result filenames.
impl fmt::Display for FinalityProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "baseline"),
            Self::SuiBaseline => write!(f, "sui-baseline"),
            Self::A => write!(f, "a"),
            Self::B => write!(f, "b"),
            Self::C => write!(f, "c"),
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
