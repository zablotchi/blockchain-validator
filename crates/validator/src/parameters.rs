// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's knobs beyond the replica's.

use std::{ops::RangeInclusive, time::Duration};

use checkpoint::finality::FinalityProtocol;
use dag::config::ImportExport;
use serde::{Deserialize, Serialize};

use crate::fork::ForkInjection;

/// Shared by the whole committee, like the replica parameters.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ValidatorParameters {
    #[serde(default)]
    pub finality: FinalityProtocol,
    /// `None` runs fault-free.
    #[serde(default)]
    pub fork: Option<ForkInjection>,
    /// How long protocols that [time out](FinalityProtocol::times_out) wait after the local
    /// mint before concluding without a winner. Accepts humantime strings (`"1s"`, `"500ms"`).
    #[serde(default = "ValidatorParameters::default_phase_one_timeout")]
    #[serde(with = "humantime_serde")]
    pub phase_one_timeout: Duration,
    /// The bytes of state this validator may retain against Byzantine input (votes and
    /// certificates held for anchors not processed yet) before it halts. It only halts this
    /// node, so nodes may differ.
    #[serde(default = "ValidatorParameters::default_evidence_budget_bytes")]
    pub evidence_budget_bytes: u64,
    /// The framed bytes of own votes and certificates submitted to consensus and not yet seen
    /// in an own proposal: every own proposal carries at most this many. Excess payloads wait
    /// for own proposals. It only paces this node, so nodes may differ.
    #[serde(default = "ValidatorParameters::default_protocol_bytes_in_flight")]
    pub protocol_bytes_in_flight: u64,
    /// The executed heights not yet released this validator may keep, to undo them in a
    /// recovery, before it halts. It only halts this node, so nodes may differ.
    #[serde(default = "ValidatorParameters::default_max_unstable_heights")]
    pub max_unstable_heights: u32,
}

impl ValidatorParameters {
    pub const DEFAULT_FILENAME: &'static str = "validator-parameters.yaml";
    /// The accepted `evidence_budget_bytes`, from 4 KiB (for tests) to 64 GiB.
    pub const EVIDENCE_BUDGET_BYTES: RangeInclusive<u64> = 4 << 10..=64 << 30;
    /// The largest accepted `protocol_bytes_in_flight`; the smallest is the largest protocol
    /// payload ([`max_protocol_payload`](crate::limits::max_protocol_payload)).
    pub const MAX_PROTOCOL_BYTES_IN_FLIGHT: u64 = 4 << 20;
    /// The accepted `max_unstable_heights`.
    pub const MAX_UNSTABLE_HEIGHTS: RangeInclusive<u32> = 8..=16_384;

    /// Mysticeti's round timeout for partially synchronous protocols
    /// (`Protocol::default_round_timeout`).
    pub fn default_phase_one_timeout() -> Duration {
        Duration::from_secs(1)
    }

    /// 1 GiB: far above fork-free use, far below an instance's memory.
    pub fn default_evidence_budget_bytes() -> u64 {
        1 << 30
    }

    /// 1 MiB: a few thousand votes, far above what a round carries without forks.
    pub fn default_protocol_bytes_in_flight() -> u64 {
        1 << 20
    }

    /// About 80 s of heights at the 12.8 per second measured on AWS, where fork-free runs keep
    /// at most a handful.
    pub fn default_max_unstable_heights() -> u32 {
        1024
    }
}

impl Default for ValidatorParameters {
    fn default() -> Self {
        Self {
            finality: FinalityProtocol::default(),
            fork: None,
            phase_one_timeout: Self::default_phase_one_timeout(),
            evidence_budget_bytes: Self::default_evidence_budget_bytes(),
            protocol_bytes_in_flight: Self::default_protocol_bytes_in_flight(),
            max_unstable_heights: Self::default_max_unstable_heights(),
        }
    }
}

impl ImportExport for ValidatorParameters {}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU64, time::Duration};

    use checkpoint::finality::FinalityProtocol;
    use dag::{authority::Authority, config::ImportExport};

    use crate::{fork::ForkInjection, parameters::ValidatorParameters};

    #[test]
    fn hand_written_parameters_parse() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "finality: c\nfork:\n  groups: [[1], [2, 3]]\n  period: 10\nphase_one_timeout: 250ms\n",
        )
        .unwrap();
        let loaded = ValidatorParameters::load(file.path()).unwrap();
        let groups = vec![
            vec![Authority::new(1)],
            vec![Authority::new(2), Authority::new(3)],
        ];
        let expected = ValidatorParameters {
            finality: FinalityProtocol::C,
            fork: Some(ForkInjection {
                groups,
                period: NonZeroU64::new(10).unwrap(),
                episodes: None,
            }),
            phase_one_timeout: Duration::from_millis(250),
            evidence_budget_bytes: 1 << 30,
            protocol_bytes_in_flight: 1 << 20,
            max_unstable_heights: 1024,
        };
        assert_eq!(loaded, expected);
    }
}
