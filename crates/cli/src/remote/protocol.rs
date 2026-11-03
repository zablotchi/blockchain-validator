// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The orchestrator's view of the validator: how to configure, run, and scrape it.

use std::{
    fmt::{self, Debug},
    net::IpAddr,
    ops::Deref,
    path::PathBuf,
};

use dag::authority::Authority;
use orchestrator::{
    benchmark::BenchmarkParameters,
    collector::{MetricKind, MetricSpec},
    protocol::{BINARY_PATH, Protocol, ProtocolCommands, ProtocolMetrics, ProtocolParameters},
    provider::Instance,
    settings::Settings,
};
use replica::config::{PublicReplicaConfig, ReplicaParameters};
use serde::{Deserialize, Serialize};
use validator::{generator::LoadGeneratorConfig, parameters::ValidatorParameters};

const PUBLIC_REPLICA_CONFIG_FILENAME: &str = PublicReplicaConfig::DEFAULT_FILENAME;
const LOAD_GENERATOR_CONFIG_FILENAME: &str = LoadGeneratorConfig::DEFAULT_FILENAME;
const VALIDATOR_PARAMETERS_FILENAME: &str = ValidatorParameters::DEFAULT_FILENAME;

/// The parameters distributed to every validator: the replica's and the validator's, side by
/// side in one flat file. The `Debug` output keys the benchmark's measurement files, so it
/// must stay short and filesystem-safe.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NodeParameters {
    #[serde(flatten)]
    replica: ReplicaParameters,
    #[serde(flatten)]
    validator: ValidatorParameters,
}

impl Debug for NodeParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}-{}",
            self.replica.consensus, self.validator.finality
        )?;
        if let Some(fork) = &self.validator.fork {
            let groups: Vec<_> = fork
                .groups
                .iter()
                .map(|group| {
                    let members: Vec<_> = group.iter().map(|a| a.index().to_string()).collect();
                    members.join(".")
                })
                .collect();
            write!(f, "-fork-{}-every-{}", groups.join("_"), fork.period)?;
        }
        Ok(())
    }
}

impl ProtocolParameters for NodeParameters {}

/// The load generator config distributed to every validator; the benchmark's total load is
/// split across the committee before upload.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(transparent)]
pub struct ClientParameters(LoadGeneratorConfig);

impl Deref for ClientParameters {
    type Target = LoadGeneratorConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for ClientParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.transaction_size)
    }
}

impl ProtocolParameters for ClientParameters {}

pub struct ValidatorProtocol {
    working_dir: PathBuf,
}

impl ValidatorProtocol {
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }
}

impl Protocol for ValidatorProtocol {
    type NodeParameters = NodeParameters;
    type ClientParameters = ClientParameters;
}

impl ProtocolCommands for ValidatorProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec![]
    }

    fn db_directories(&self) -> Vec<PathBuf> {
        vec![self.working_dir.join("storage-*")]
    }

    async fn genesis_command<'a, I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters<Self::NodeParameters, Self::ClientParameters>,
    ) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        let ips = instances
            .map(|x| x.main_ip.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        let replica_parameters = &parameters.node_parameters.replica;
        let replica_parameters_string = serde_yaml::to_string(replica_parameters).unwrap();
        let replica_parameters_path = self.working_dir.join("replica-parameters.yaml");
        let upload_replica_parameters = format!(
            "echo -e '{replica_parameters_string}' > {}",
            replica_parameters_path.display()
        );

        let validator_parameters = &parameters.node_parameters.validator;
        let validator_parameters_string = serde_yaml::to_string(validator_parameters).unwrap();
        let validator_parameters_path = self.working_dir.join(VALIDATOR_PARAMETERS_FILENAME);
        let upload_validator_parameters = format!(
            "echo -e '{validator_parameters_string}' > {}",
            validator_parameters_path.display()
        );

        let mut load_generator_config = parameters.client_parameters.clone();
        load_generator_config.0.load = parameters.load / parameters.nodes;
        let load_generator_config_string = serde_yaml::to_string(&load_generator_config).unwrap();
        let load_generator_config_path = self.working_dir.join(LOAD_GENERATOR_CONFIG_FILENAME);
        let upload_load_generator_config = format!(
            "echo -e '{load_generator_config_string}' > {}",
            load_generator_config_path.display()
        );

        let genesis = [
            &format!("./{BINARY_PATH}/validator"),
            "test-genesis",
            &format!(
                "--ips {ips} --working-directory {} --replica-parameters-path {}",
                self.working_dir.display(),
                replica_parameters_path.display(),
            ),
        ]
        .join(" ");

        [
            "source $HOME/.cargo/env",
            &upload_replica_parameters,
            &upload_validator_parameters,
            &upload_load_generator_config,
            &genesis,
        ]
        .join(" && ")
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters<Self::NodeParameters, Self::ClientParameters>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // The per-node share of the total load; the generator rejects a zero load, so nodes
        // without one to bear run without the flag (and without a generator).
        // Todo: unit-test this builder once orchestrator's `Instance` has a test constructor
        // (asonnino/mysticeti#225).
        let load = parameters.load / parameters.nodes;
        instances
            .into_iter()
            .enumerate()
            .map(|(i, instance)| {
                let authority = Authority::from(i);
                let public_config_path = self.working_dir.join(PUBLIC_REPLICA_CONFIG_FILENAME);
                let private_config_path = self
                    .working_dir
                    .join(format!("private-replica-config-{authority}.yaml"));
                let load_generator_config_path =
                    self.working_dir.join(LOAD_GENERATOR_CONFIG_FILENAME);
                let validator_parameters_path =
                    self.working_dir.join(VALIDATOR_PARAMETERS_FILENAME);

                let mut run = vec![
                    format!("./{BINARY_PATH}/validator"),
                    "run".into(),
                    format!("--authority {}", authority.index()),
                    format!("--public-config-path {}", public_config_path.display()),
                    format!("--private-config-path {}", private_config_path.display()),
                    format!(
                        "--validator-parameters-path {}",
                        validator_parameters_path.display()
                    ),
                ];
                if load > 0 {
                    run.push(format!(
                        "--load-generator-config-path {}",
                        load_generator_config_path.display()
                    ));
                }
                let run = run.join(" ");

                let command = ["source $HOME/.cargo/env", &run].join(" && ");
                (instance, command)
            })
            .collect()
    }

    fn client_command<I>(
        &self,
        _instances: I,
        _parameters: &BenchmarkParameters<Self::NodeParameters, Self::ClientParameters>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // The load generator runs inside the validator process.
        vec![]
    }
}

impl ProtocolMetrics for ValidatorProtocol {
    fn metrics(&self) -> Vec<MetricSpec> {
        vec![
            MetricSpec {
                // Exposed as a counter but represents elapsed seconds — querying
                // `rate(benchmark_duration[1m])` always returns ~1.0, useless.
                // The cumulative value is what aggregation actually needs.
                name: dag::metrics::BENCHMARK_DURATION.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: dag::metrics::LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: format!("{}_count", dag::metrics::LATENCY_S),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: format!("{}_sum", dag::metrics::LATENCY_S),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: dag::metrics::LATENCY_SQUARED_S.into(),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: validator::metrics::END_TO_END_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: format!("{}_count", validator::metrics::END_TO_END_LATENCY_S),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: format!("{}_sum", validator::metrics::END_TO_END_LATENCY_S),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: validator::metrics::CHECKPOINT_CERTIFICATION_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: validator::metrics::SUBDAG_EXECUTION_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: validator::metrics::SUBMITTED_TRANSACTIONS.into(),
                kind: MetricKind::Counter,
            },
        ]
    }

    fn nodes_metrics_path<I>(
        &self,
        instances: I,
        _parameters: &BenchmarkParameters<Self::NodeParameters, Self::ClientParameters>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let (ips, instances): (_, Vec<_>) = instances
            .into_iter()
            .map(|x| (IpAddr::V4(x.main_ip), x))
            .unzip();

        // Recomputing the deterministic genesis assigns each instance the same metrics
        // address the on-instance configs hold.
        let public_config = PublicReplicaConfig::new_for_benchmarks(ips);
        let metrics_paths = public_config
            .all_metric_addresses()
            .map(|x| format!("{x}{}", replica::prometheus::METRICS_ROUTE));

        instances.into_iter().zip(metrics_paths).collect()
    }

    fn clients_metrics_path<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters<Self::NodeParameters, Self::ClientParameters>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        // The load generators live inside the nodes, which are scraped already.
        self.nodes_metrics_path(instances, parameters)
    }
}

#[cfg(test)]
mod tests {
    use crate::remote::protocol::NodeParameters;

    const CONSENSUS: &str = "consensus:\n  protocol: mysticeti\n  leader_count: 1\n";

    #[test]
    fn node_parameters_name_the_finality_protocol_and_forks() {
        let yaml = format!("{CONSENSUS}finality: a\nfork:\n  groups: [[1, 2], [3]]\n  period: 5\n");
        let parameters: NodeParameters = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            format!("{parameters:?}"),
            "mysticeti-l1-a-fork-1.2_3-every-5"
        );
    }

    #[test]
    fn node_parameters_without_validator_fields_run_the_baseline() {
        let parameters: NodeParameters = serde_yaml::from_str(CONSENSUS).unwrap();
        assert_eq!(format!("{parameters:?}"), "mysticeti-l1-baseline");
    }
}
