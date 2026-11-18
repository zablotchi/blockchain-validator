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
/// side in one flat file. The `Debug` output is the readable part of the benchmark's file
/// names, so it must stay short and filesystem-safe.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct NodeParameters {
    #[serde(flatten)]
    replica: ReplicaParameters,
    #[serde(flatten)]
    validator: ValidatorParameters,
}

impl Debug for NodeParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let finality = self.validator.finality;
        write!(f, "{:?}-{finality}", self.replica.consensus)?;
        if finality.times_out() {
            // Never rounded: whole microseconds unless the timeout is finer.
            let timeout = self.validator.phase_one_timeout;
            match timeout.as_nanos() % 1_000 {
                0 => write!(f, "-timeout-{}us", timeout.as_micros())?,
                _ => write!(f, "-timeout-{}ns", timeout.as_nanos())?,
            }
        }
        if let Some(fork) = &self.validator.fork {
            write!(f, "-fork-{}g-every-{}", fork.groups.len(), fork.period)?;
            if let Some(episodes) = fork.episodes {
                write!(f, "-x{episodes}")?;
            }
        }
        Ok(())
    }
}

impl NodeParameters {
    /// Fails unless `client`'s transactions keep every proposal within the proposal budget.
    pub(crate) fn check_proposal_budget(&self, client: &ClientParameters) -> eyre::Result<()> {
        let in_flight = self.validator.protocol_bytes_in_flight;
        validator::limits::check_proposal_budget(client.transaction_size, in_flight)
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
                name: validator::metrics::CHECKPOINT_FINALITY_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: validator::metrics::CHECKPOINT_PENDING_HEIGHTS.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::SUBDAG_EXECUTION_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            // Decision counts and latency sums since the process started, collected raw: a
            // counter spec would become a one-minute rate. Exact means pair `decisions` and
            // `latency_s` from the same tick, never across ticks: one name is one instant
            // query, whose series come from one scrape per node. Totals are scrape-bounded:
            // decisions after a node's last scrape, as when a fault kills it, are lost.
            MetricSpec {
                name: validator::metrics::CHECKPOINT_DECISION_ACCOUNTING.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::VALIDATOR_HALTED.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::VALIDATOR_RETAINED_BYTES.into(),
                kind: MetricKind::Gauge,
            },
            // Totals, collected raw like the accounting family.
            MetricSpec {
                name: validator::metrics::PROTOCOL_SUBMISSIONS_DEFERRED.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::PROTOCOL_PAYLOADS_SUBMITTED.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::MAX_PROPOSAL_BYTES.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::MAX_PROPOSAL_PROTOCOL_BYTES.into(),
                kind: MetricKind::Gauge,
            },
            // A total, collected raw like the accounting family.
            MetricSpec {
                name: validator::metrics::CHECKPOINT_RELEASE_WAITS.into(),
                kind: MetricKind::Gauge,
            },
            MetricSpec {
                name: validator::metrics::SUBMITTED_TRANSACTIONS.into(),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: validator::metrics::EXECUTED_TRANSACTIONS.into(),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: validator::metrics::CLIENT_COMMIT_LATENCY_S.into(),
                kind: MetricKind::Histogram,
            },
            MetricSpec {
                name: format!("{}_count", validator::metrics::CLIENT_COMMIT_LATENCY_S),
                kind: MetricKind::Counter,
            },
            MetricSpec {
                name: format!("{}_sum", validator::metrics::CLIENT_COMMIT_LATENCY_S),
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
    use std::path::PathBuf;

    use orchestrator::{collector::MetricKind, protocol::ProtocolMetrics};
    use validator::metrics::{
        CHECKPOINT_RELEASE_WAITS, MAX_PROPOSAL_BYTES, MAX_PROPOSAL_PROTOCOL_BYTES,
        PROTOCOL_PAYLOADS_SUBMITTED, PROTOCOL_SUBMISSIONS_DEFERRED, VALIDATOR_HALTED,
        VALIDATOR_RETAINED_BYTES,
    };

    use crate::remote::protocol::{NodeParameters, ValidatorProtocol};

    const CONSENSUS: &str = "consensus:\n  protocol: mysticeti\n  leader_count: 1\n";

    fn name(validator: &str) -> String {
        let yaml = format!("{CONSENSUS}{validator}");
        let parameters: NodeParameters = serde_yaml::from_str(&yaml).unwrap();
        format!("{parameters:?}")
    }

    /// The fork-recovery metrics are all collected, and raw: a counter spec would turn a total
    /// into a one-minute rate.
    #[test]
    fn fork_recovery_metrics_are_collected_raw() {
        let protocol = ValidatorProtocol {
            working_dir: PathBuf::new(),
        };
        let specs = protocol.metrics();
        for name in [
            VALIDATOR_HALTED,
            VALIDATOR_RETAINED_BYTES,
            PROTOCOL_SUBMISSIONS_DEFERRED,
            PROTOCOL_PAYLOADS_SUBMITTED,
            MAX_PROPOSAL_BYTES,
            MAX_PROPOSAL_PROTOCOL_BYTES,
            CHECKPOINT_RELEASE_WAITS,
        ] {
            let kind = specs
                .iter()
                .find(|spec| spec.name == name)
                .map(|spec| &spec.kind);
            assert!(matches!(kind, Some(MetricKind::Gauge)), "{name}");
        }
    }

    #[test]
    fn node_parameters_name_the_finality_protocol_and_forks() {
        assert_eq!(
            name("finality: a\nfork:\n  groups: [[1, 2], [3]]\n  period: 5\n"),
            "mysticeti-l1-a-fork-2g-every-5"
        );
        assert_eq!(
            name("finality: a\nfork:\n  groups: [[3]]\n  period: 200\n  episodes: 5\n"),
            "mysticeti-l1-a-fork-1g-every-200-x5"
        );
    }

    #[test]
    fn node_parameters_name_many_fork_groups_briefly() {
        let groups: Vec<_> = (1..=99).map(|i| format!("[{i}]")).collect();
        let fork = format!("fork:\n  groups: [{}]\n  period: 5\n", groups.join(", "));
        let name = name(&format!("finality: c\n{fork}"));
        assert_eq!(name, "mysticeti-l1-c-timeout-1000000us-fork-99g-every-5");
        assert!(name.len() < 120);
    }

    #[test]
    fn node_parameters_name_the_phase_one_timeout_of_protocols_timing_out() {
        assert_eq!(name("finality: c\n"), "mysticeti-l1-c-timeout-1000000us");
        assert_eq!(
            name("finality: c\nphase_one_timeout: 250ms\n"),
            "mysticeti-l1-c-timeout-250000us"
        );
        assert_eq!(
            name("finality: b\nphase_one_timeout: 250ms\n"),
            "mysticeti-l1-b"
        );
    }

    #[test]
    fn node_parameters_name_the_phase_one_timeout_unrounded() {
        assert_eq!(
            name("finality: c\nphase_one_timeout: 250ms 500us\n"),
            "mysticeti-l1-c-timeout-250500us"
        );
        assert_eq!(
            name("finality: c\nphase_one_timeout: 250ms 1ns\n"),
            "mysticeti-l1-c-timeout-250000001ns"
        );
    }

    #[test]
    fn transactions_must_fit_the_proposal_budget() {
        let node: NodeParameters = serde_yaml::from_str(CONSENSUS).unwrap();
        let client = |size| serde_yaml::from_str(&format!("transaction_size: {size}\n")).unwrap();
        assert!(node.check_proposal_budget(&client(539)).is_ok());
        assert!(node.check_proposal_budget(&client(540)).is_err());
        // More protocol bytes in flight lower the ceiling.
        let yaml = format!("{CONSENSUS}protocol_bytes_in_flight: 4194304\n");
        let node: NodeParameters = serde_yaml::from_str(&yaml).unwrap();
        assert!(node.check_proposal_budget(&client(512)).is_err());
    }

    #[test]
    fn node_parameters_without_validator_fields_run_the_baseline() {
        assert_eq!(name(""), "mysticeti-l1-baseline");
    }
}
