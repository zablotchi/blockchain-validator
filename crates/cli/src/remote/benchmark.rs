// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The remote benchmark driver: composes the orchestrator's phases per load and reports
//! progress through plain tracing lines.

use std::{
    fmt::Debug,
    fs::{self, File},
    path::{Path, PathBuf},
    time::SystemTime,
};

use eyre::{Context, Result};
use orchestrator::{
    benchmark::{BenchmarkParameters, Parameters},
    orchestrator::Orchestrator,
    protocol::{ProtocolCommands, ProtocolMetrics, ProtocolParameters},
    provider::Instance,
    report::{MonitoringReport, TickReport},
    session::BenchmarkSession,
    settings::Settings,
};

use crate::remote::protocol::{ClientParameters, NodeParameters, ValidatorProtocol};

pub(crate) struct RemoteBenchmarkDriver {
    settings: Settings,
    username: String,
}

impl RemoteBenchmarkDriver {
    pub(crate) fn new(settings: Settings, username: String) -> Self {
        Self { settings, username }
    }

    pub(crate) async fn benchmark(
        mut self,
        instances: Vec<Instance>,
        setup_commands: Vec<String>,
        committee: usize,
        loads: Vec<usize>,
        skip_testbed_update: bool,
        skip_testbed_configuration: bool,
    ) -> Result<()> {
        let protocol_commands = ValidatorProtocol::new(&self.settings);
        let node_parameters = match &self.settings.node_parameters_path {
            Some(path) => {
                NodeParameters::load(path).wrap_err("Failed to load node's parameters")?
            }
            None => NodeParameters::default(),
        };
        let client_parameters = match &self.settings.client_parameters_path {
            Some(path) => {
                ClientParameters::load(path).wrap_err("Failed to load client's parameters")?
            }
            None => ClientParameters::default(),
        };

        // Apply the commit side-effect before settings are snapshotted into per-benchmark
        // parameters by new_from_loads.
        if skip_testbed_update {
            self.settings.repository.set_unknown_commit();
            tracing::warn!("Skipping testbed update! Use with care");
        }
        if skip_testbed_configuration {
            tracing::warn!("Skipping testbed configuration! Use with care");
        }
        tracing::info!(
            committee,
            ?loads,
            commit = %self.settings.repository.commit,
            "Starting remote benchmark"
        );

        let parameters_set = BenchmarkParameters::new_from_loads(
            self.settings.clone(),
            node_parameters,
            client_parameters,
            committee,
            loads,
        );

        let orchestrator = Orchestrator::new(
            self.settings.clone(),
            instances,
            setup_commands,
            protocol_commands,
            &self.username,
        );

        // Validate instance capacity up front.
        if let Some(parameters) = parameters_set.first() {
            orchestrator
                .select_instances(parameters)
                .wrap_err("Not enough instances for this benchmark")?;
        }

        for (index, parameters) in parameters_set.into_iter().enumerate() {
            tracing::info!("Benchmark {}: {parameters}", index + 1);

            if index == 0 {
                tracing::info!("Cleaning up testbed");
                orchestrator
                    .cleanup(true)
                    .await
                    .wrap_err("Cleanup failed")?;
                if !skip_testbed_update {
                    tracing::info!("Installing dependencies on all machines");
                    orchestrator.install().await.wrap_err("Install failed")?;
                    tracing::info!("Updating all instances");
                    orchestrator.update().await.wrap_err("Update failed")?;
                }
            }

            tracing::info!("Cleaning up testbed");
            orchestrator
                .cleanup(true)
                .await
                .wrap_err("Cleanup failed")?;

            // When monitoring is disabled, start_monitoring always returns None; skip the
            // call entirely rather than performing a no-op SSH round-trip.
            let monitoring = if self.settings.monitoring {
                tracing::info!("Configuring monitoring instance");
                let report = orchestrator
                    .start_monitoring(&parameters)
                    .await
                    .wrap_err("Monitoring setup failed")?;
                if let Some(r) = &report {
                    tracing::info!("Grafana at {} (admin/admin)", r.grafana_address);
                }
                report
            } else {
                None
            };

            self.run_one(
                &orchestrator,
                &parameters,
                monitoring.as_ref(),
                skip_testbed_configuration,
            )
            .await?;

            tracing::info!("Cleaning up testbed");
            orchestrator
                .cleanup(false)
                .await
                .wrap_err("Cleanup failed")?;

            if self.settings.log_processing {
                tracing::info!("Downloading logs");
                let logs = orchestrator
                    .download_logs(&parameters)
                    .await
                    .wrap_err("Failed to download logs")?;
                tracing::info!(
                    node_errors = logs.node_errors,
                    node_panic = logs.node_panic,
                    "Logs downloaded"
                );
            }
        }
        Ok(())
    }

    async fn run_one<P: ProtocolCommands + ProtocolMetrics>(
        &self,
        orchestrator: &Orchestrator<P>,
        parameters: &Parameters<P>,
        monitoring: Option<&MonitoringReport>,
        skip_testbed_configuration: bool,
    ) -> Result<()> {
        if !skip_testbed_configuration {
            tracing::info!("Configuring instances");
            orchestrator
                .configure(parameters)
                .await
                .wrap_err("Configure failed")?;
        }

        tracing::info!("Deploying validators");
        orchestrator
            .run_nodes(parameters)
            .await
            .wrap_err("Deploying validators failed")?;

        // A no-op with the in-process load generator, kept for the load == 0 semantics.
        orchestrator
            .run_clients(parameters)
            .await
            .wrap_err("Starting load generators failed")?;

        self.run_benchmark_loop(orchestrator, parameters, monitoring)
            .await
    }

    /// Drives the metrics + faults tick loop for a single run: logs a heartbeat from the
    /// collector's scraped stats on each metrics tick, persists each scrape's YAML, and
    /// announces fault injections.
    async fn run_benchmark_loop<P: ProtocolCommands + ProtocolMetrics>(
        &self,
        orchestrator: &Orchestrator<P>,
        parameters: &Parameters<P>,
        monitoring: Option<&MonitoringReport>,
    ) -> Result<()> {
        let benchmark_duration = parameters.settings.benchmark_duration;
        // A zero duration means "run indefinitely" (until Ctrl-C).
        let indefinite = benchmark_duration.is_zero();
        if indefinite {
            tracing::info!("Benchmark running indefinitely, Ctrl-C to stop");
        } else {
            tracing::info!("Benchmark running for at least {benchmark_duration:?}");
        }

        let mut session = BenchmarkSession::new(orchestrator, parameters, monitoring)
            .await
            .wrap_err("Failed to start benchmark session")?;

        let results_dir = self
            .settings
            .results_dir
            .join(format!("results-{}", self.settings.repository.commit));
        fs::create_dir_all(&results_dir).wrap_err("Failed to create results directory")?;
        let mut measurements = MeasurementsFile::new(&results_dir, parameters, SystemTime::now());

        loop {
            let tick = tokio::select! {
                biased;
                // Stop gracefully on Ctrl-C so the caller still runs cleanup and tears down
                // the remote validators, rather than leaking them.
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Interrupted, stopping the benchmark");
                    return Ok(());
                }
                tick = session.tick(orchestrator, parameters) => tick,
            };
            match tick.wrap_err("Benchmark tick failed")? {
                TickReport::MetricsTick {
                    elapsed,
                    results,
                    stats,
                } => {
                    // Counters scrape as rates: the executed counter gives client transactions
                    // per second (mysticeti's `latency_s_count` would include votes and
                    // certificates). Latencies are reported in seconds.
                    let executed = validator::metrics::EXECUTED_TRANSACTIONS;
                    let client_commit_p50 =
                        format!("{}.p50", validator::metrics::CLIENT_COMMIT_LATENCY_S);
                    tracing::info!(
                        elapsed = elapsed.as_secs(),
                        tps = stats.get(executed).map(|v| v.round()),
                        commit_p50_s = stats.get(&client_commit_p50),
                        e2e_p50_s = stats.get("end_to_end_latency_s.p50"),
                        "Benchmark tick"
                    );
                    if let Some(yaml) = results {
                        measurements.write(&yaml)?;
                    }
                    if !indefinite && elapsed > benchmark_duration {
                        tracing::info!("Results in {}", measurements.path.display());
                        return Ok(());
                    }
                }
                TickReport::FaultUpdate { elapsed: _, action } => {
                    if !action.kill.is_empty() || !action.boot.is_empty() {
                        tracing::info!("Testbed update: {action}");
                    }
                }
            }
        }
    }
}

/// One run's results, `measurements-{parameters:?}-{start}.yaml` with the run's UTC start to
/// the second (`20231114T221320Z`). The parameters part is readable but not unique
/// (configurations can share it, repeats always do), so the start gives every run its own
/// file, and a run fails rather than overwrite one. Analysis groups runs by the parameters
/// stored in each file, never by its name.
struct MeasurementsFile {
    path: PathBuf,
    created: bool,
}

impl MeasurementsFile {
    fn new(results_dir: &Path, parameters: &impl Debug, start: SystemTime) -> Self {
        let start = humantime::format_rfc3339_seconds(start)
            .to_string()
            .replace(['-', ':'], "");
        let path = results_dir.join(format!("measurements-{parameters:?}-{start}.yaml"));
        Self {
            path,
            created: false,
        }
    }

    /// Each write replaces the previous scrape, so a torn write is repaired by the next one.
    fn write(&mut self, yaml: &str) -> Result<()> {
        if !self.created {
            File::create_new(&self.path)
                .wrap_err_with(|| format!("Failed to create {}", self.path.display()))?;
            self.created = true;
        }
        fs::write(&self.path, yaml).wrap_err("Failed to save benchmark results")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{Duration, SystemTime},
    };

    use crate::remote::{benchmark::MeasurementsFile, protocol::NodeParameters};

    #[test]
    fn every_run_gets_its_own_measurements_file() {
        let dir = tempfile::tempdir().unwrap();
        let parameters = NodeParameters::default();
        let second = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let start = second + Duration::from_millis(500);

        let mut run = MeasurementsFile::new(dir.path(), &parameters, start);
        let expected = format!("measurements-{parameters:?}-20231114T221320Z.yaml");
        assert_eq!(run.path, dir.path().join(expected));
        run.write("first scrape").unwrap();
        run.write("second scrape").unwrap();

        let later = start + Duration::from_secs(1);
        let mut repeat = MeasurementsFile::new(dir.path(), &parameters, later);
        repeat.write("repeat").unwrap();

        // Another run started within the same second.
        let mut clash = MeasurementsFile::new(dir.path(), &parameters, second);
        assert!(clash.write("clash").is_err());

        assert_eq!(fs::read_to_string(&run.path).unwrap(), "second scrape");
        assert_eq!(fs::read_to_string(&repeat.path).unwrap(), "repeat");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
