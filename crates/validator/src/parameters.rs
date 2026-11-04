// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's knobs beyond the replica's.

use std::time::Duration;

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
}

impl ValidatorParameters {
    pub const DEFAULT_FILENAME: &'static str = "validator-parameters.yaml";

    /// Mysticeti's round timeout for partially synchronous protocols
    /// (`Protocol::default_round_timeout`).
    pub fn default_phase_one_timeout() -> Duration {
        Duration::from_secs(1)
    }
}

impl Default for ValidatorParameters {
    fn default() -> Self {
        Self {
            finality: FinalityProtocol::default(),
            fork: None,
            phase_one_timeout: Self::default_phase_one_timeout(),
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
            }),
            phase_one_timeout: Duration::from_millis(250),
        };
        assert_eq!(loaded, expected);
    }
}
