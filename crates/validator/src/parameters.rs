// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator's knobs beyond the replica's.

use checkpoint::finality::FinalityProtocol;
use dag::config::ImportExport;
use serde::{Deserialize, Serialize};

/// Shared by the whole committee, like the replica parameters.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ValidatorParameters {
    #[serde(default)]
    pub finality: FinalityProtocol,
}

impl ValidatorParameters {
    pub const DEFAULT_FILENAME: &'static str = "validator-parameters.yaml";
}

impl ImportExport for ValidatorParameters {}

#[cfg(test)]
mod tests {
    use checkpoint::finality::FinalityProtocol;
    use dag::config::ImportExport;

    use crate::parameters::ValidatorParameters;

    #[test]
    fn hand_written_parameters_parse() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "finality: a\n").unwrap();
        let loaded = ValidatorParameters::load(file.path()).unwrap();
        let expected = ValidatorParameters {
            finality: FinalityProtocol::A,
        };
        assert_eq!(loaded, expected);
    }
}
