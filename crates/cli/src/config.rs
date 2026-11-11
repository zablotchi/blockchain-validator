// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Strict loading of the configuration files the CLI reads. Serde defaults missing fields and
//! ignores unknown ones, so a misspelled key would silently run with the default.

use std::{fs, path::Path};

use eyre::{Result, WrapErr, ensure};
use replica::config::{PrivateReplicaConfig, PublicReplicaConfig, ReplicaParameters};
use serde::{Serialize, de::DeserializeOwned};
use serde_yaml::Value;
use validator::{generator::LoadGeneratorConfig, parameters::ValidatorParameters};

use crate::remote::protocol::{ClientParameters, NodeParameters};

/// A configuration type through which every key of a valid file survives a serde round trip:
/// no input-only fields (`skip_serializing`, `skip_deserializing`, `alias`), flattened fields
/// that re-serialize to the same flat shape, and no externally tagged enum carrying fields
/// (tagged values are not walked). The orchestrator's `Settings` has input-only fields, so it
/// keeps its own loader.
pub trait RoundTrip: Serialize + DeserializeOwned {}

impl RoundTrip for ReplicaParameters {}
impl RoundTrip for PublicReplicaConfig {}
impl RoundTrip for PrivateReplicaConfig {}
impl RoundTrip for LoadGeneratorConfig {}
impl RoundTrip for ValidatorParameters {}
impl RoundTrip for NodeParameters {}
impl RoundTrip for ClientParameters {}

/// Loads `path` as a `T`, rejecting every key, at any depth, that `T` does not know: the keys
/// absent from `T`'s re-serialization.
pub fn load<T: RoundTrip>(path: impl AsRef<Path>) -> Result<T> {
    let path = path.as_ref();
    let load = || -> Result<T> {
        let input: Value = serde_yaml::from_str(&fs::read_to_string(path)?)?;
        let parsed: T = serde_yaml::from_value(input.clone())?;
        let mut unknown = Vec::new();
        unknown_keys(&input, &serde_yaml::to_value(&parsed)?, "", &mut unknown);
        ensure!(unknown.is_empty(), "unknown keys: {}", unknown.join(", "));
        Ok(parsed)
    };
    load().wrap_err_with(|| format!("Failed to load {}", path.display()))
}

/// Pushes to `unknown` the path of every mapping key of `input` absent from `output`.
fn unknown_keys(input: &Value, output: &Value, at: &str, unknown: &mut Vec<String>) {
    match (input, output) {
        (Value::Mapping(input), Value::Mapping(output)) => {
            for (key, value) in input {
                let key_name = match key {
                    Value::String(name) => name.clone(),
                    other => format!("{other:?}"),
                };
                let path = match at {
                    "" => key_name,
                    _ => format!("{at}.{key_name}"),
                };
                match output.get(key) {
                    Some(output) => unknown_keys(value, output, &path, unknown),
                    None => unknown.push(path),
                }
            }
        }
        (Value::Sequence(input), Value::Sequence(output)) => {
            for (index, (input, output)) in input.iter().zip(output).enumerate() {
                unknown_keys(input, output, &format!("{at}[{index}]"), unknown);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use replica::config::{PublicReplicaConfig, ReplicaParameters};
    use serde_yaml::Value;
    use validator::{generator::LoadGeneratorConfig, parameters::ValidatorParameters};

    use crate::{
        config::{RoundTrip, load},
        remote::protocol::{ClientParameters, NodeParameters},
    };

    const CONSENSUS: &str = "consensus:\n  protocol: mysticeti\n  leader_count: 1\n";
    const DAG: &str = "dag:\n  round_timeout: null\n  max_block_size: 1024\n  \
        enable_synchronizer: false\n  fsync: true\n";
    const VALIDATOR: &str = "finality: c\nfork:\n  groups: [[1], [2, 3]]\n  period: 5\n\
        phase_one_timeout: 250ms\n";
    const LOAD_GENERATOR: &str = "load: 10\ntransaction_size: 512\ninitial_delay: 10s\n";

    fn load_yaml<T: RoundTrip>(yaml: &str) -> eyre::Result<T> {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), yaml).unwrap();
        load(file.path())
    }

    /// Asserts that loading `yaml` as a `T` fails naming exactly `keys`, in input order.
    fn rejects<T: RoundTrip>(yaml: &str, keys: &str) {
        let error = format!("{:#}", load_yaml::<T>(yaml).err().expect("must fail"));
        assert!(error.ends_with(&format!("unknown keys: {keys}")), "{error}");
    }

    /// A test public config, with `key: true` inserted into the mapping at `path`.
    fn public_config_with(path: &[&str], key: &str) -> String {
        let mut config = serde_yaml::to_value(PublicReplicaConfig::new_for_tests(4)).unwrap();
        let mut mapping = &mut config;
        for step in path {
            mapping = match step.parse::<usize>() {
                Ok(index) => &mut mapping[index],
                Err(_) => &mut mapping[*step],
            };
        }
        let mapping = mapping.as_mapping_mut().unwrap();
        mapping.insert(Value::from(key), Value::from(true));
        serde_yaml::to_string(&config).unwrap()
    }

    #[test]
    fn files_setting_every_field_load() {
        let replica = format!("{CONSENSUS}{DAG}");
        let parameters: ReplicaParameters = load_yaml(&replica).unwrap();
        assert!(parameters.dag.fsync);
        load_yaml::<ValidatorParameters>(VALIDATOR).unwrap();
        load_yaml::<NodeParameters>(&format!("{replica}{VALIDATOR}")).unwrap();
        load_yaml::<LoadGeneratorConfig>(LOAD_GENERATOR).unwrap();
        load_yaml::<ClientParameters>(LOAD_GENERATOR).unwrap();
    }

    #[test]
    fn misspelled_keys_fail_at_every_depth() {
        // `test-genesis`'s replica parameters (`dag` is tested through `test-genesis` itself).
        rejects::<ReplicaParameters>(
            &format!("{CONSENSUS}consensus_typo: {{}}\n"),
            "consensus_typo",
        );
        let consensus = "consensus:\n  protocol: mysticeti\n  leader_count_typo: 2\n";
        rejects::<ReplicaParameters>(consensus, "consensus.leader_count_typo");

        // `run`'s public config and validator parameters.
        rejects::<PublicReplicaConfig>(
            &public_config_with(&[], "identifiers_typo"),
            "identifiers_typo",
        );
        let fsync_typo = public_config_with(&["parameters", "dag"], "fsync_typo");
        rejects::<PublicReplicaConfig>(&fsync_typo, "parameters.dag.fsync_typo");
        let consensus = public_config_with(&["parameters", "consensus"], "leader_count_typo");
        rejects::<PublicReplicaConfig>(&consensus, "parameters.consensus.leader_count_typo");
        let identifier = public_config_with(&["identifiers", "2"], "stake_typo");
        rejects::<PublicReplicaConfig>(&identifier, "identifiers[2].stake_typo");
        rejects::<ValidatorParameters>("finality_typo: c\n", "finality_typo");
        let fork = "fork:\n  groups: [[1]]\n  period: 5\n  period_typo: 3\n";
        rejects::<ValidatorParameters>(fork, "fork.period_typo");

        // The benchmark's node and client parameters.
        rejects::<NodeParameters>(&format!("{CONSENSUS}finality_typo: c\n"), "finality_typo");
        rejects::<NodeParameters>(
            &format!("{CONSENSUS}dag:\n  fsync_typo: true\n"),
            "dag.fsync_typo",
        );
        let consensus = "consensus:\n  protocol: mysticeti\n  leader_count_typo: 2\n";
        rejects::<NodeParameters>(consensus, "consensus.leader_count_typo");
        rejects::<NodeParameters>(&format!("{CONSENSUS}{fork}"), "fork.period_typo");
        rejects::<ClientParameters>("load_typo: 10\n", "load_typo");

        // Every unknown key is reported, not just the first.
        let typos = format!(
            "consensus_typo: {{}}\n{CONSENSUS}dag:\n  fsync_typo: true\nfinality_typo: c\n"
        );
        rejects::<NodeParameters>(&typos, "consensus_typo, dag.fsync_typo, finality_typo");
    }
}
