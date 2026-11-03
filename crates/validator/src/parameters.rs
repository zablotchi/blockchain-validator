// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's knobs beyond the replica's.

use checkpoint::finality::FinalityProtocol;
use dag::config::ImportExport;
use serde::{Deserialize, Serialize};

use crate::fork::ForkInjection;

/// Shared by the whole committee, like the replica parameters.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ValidatorParameters {
    #[serde(default)]
    pub finality: FinalityProtocol,
    /// `None` runs fault-free.
    #[serde(default)]
    pub fork: Option<ForkInjection>,
}

impl ValidatorParameters {
    pub const DEFAULT_FILENAME: &'static str = "validator-parameters.yaml";
}

impl ImportExport for ValidatorParameters {}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use checkpoint::finality::FinalityProtocol;
    use dag::{authority::Authority, config::ImportExport};

    use crate::{fork::ForkInjection, parameters::ValidatorParameters};

    #[test]
    fn hand_written_parameters_parse() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "finality: a\nfork:\n  groups: [[1], [2, 3]]\n  period: 10\n",
        )
        .unwrap();
        let loaded = ValidatorParameters::load(file.path()).unwrap();
        let groups = vec![
            vec![Authority::new(1)],
            vec![Authority::new(2), Authority::new(3)],
        ];
        let expected = ValidatorParameters {
            finality: FinalityProtocol::A,
            fork: Some(ForkInjection {
                groups,
                period: NonZeroU64::new(10).unwrap(),
            }),
        };
        assert_eq!(loaded, expected);
    }
}
