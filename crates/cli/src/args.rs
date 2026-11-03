// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{net::IpAddr, path::PathBuf};

use clap::Parser;
use dag::authority::Authority;
use tracing_subscriber::filter::LevelFilter;

/// Blockchain validator: a mysticeti consensus replica composed with execution and
/// self-certifying checkpoints.
#[derive(Parser)]
#[command(author, version, propagate_version = true)]
pub struct Args {
    /// Log level (trace, debug, info, warn, error). Overrides the per-command default.
    /// RUST_LOG env var takes precedence over this.
    #[arg(long, global = true)]
    pub log_level: Option<LevelFilter>,

    /// Write logs to this file instead of stderr.
    #[arg(long, global = true, value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Parser)]
pub enum Command {
    /// Generate test genesis files: one public replica config (identities, stakes, and
    /// parameters) plus a private config per validator (keys and storage paths). Keys are
    /// written in plaintext.
    TestGenesis(TestGenesisArgs),

    /// Run a single validator from config files.
    Run(RunArgs),

    /// Manage a remote (cloud) testbed of validators and run benchmarks on it.
    ///
    /// Requires a settings file describing the cloud provider, regions, and repository to
    /// deploy. See `crates/cli/assets/settings-aws-template.yml` for a starting point.
    RemoteTestbed(RemoteTestbedArgs),
}

#[derive(clap::Args)]
pub struct TestGenesisArgs {
    /// IP addresses of all validators.
    #[arg(long, value_name = "ADDR", value_delimiter = ' ', num_args(3..))]
    pub ips: Vec<IpAddr>,
    /// Working directory where files will be generated.
    #[arg(long, value_name = "DIR", default_value = "genesis")]
    pub working_directory: PathBuf,
    /// Path to custom replica parameters (YAML). Uses defaults if omitted.
    #[arg(long, value_name = "FILE")]
    pub replica_parameters_path: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Authority index of this node.
    #[arg(long, value_name = "INT")]
    pub authority: Authority,
    /// Path to the public replica config file (YAML: identities, stakes, and parameters).
    #[arg(long, value_name = "FILE")]
    pub public_config_path: String,
    /// Path to the private replica config file (YAML, includes keys).
    #[arg(long, value_name = "FILE")]
    pub private_config_path: String,
    /// Path to the load generator config file (YAML). Omit to run without the built-in load
    /// generator.
    #[arg(long, value_name = "FILE")]
    pub load_generator_config_path: Option<String>,
    /// Path to the validator parameters file (YAML: finality protocol, fork injection). Uses
    /// defaults if omitted.
    #[arg(long, value_name = "FILE")]
    pub validator_parameters_path: Option<String>,
}

#[derive(clap::Args)]
pub struct RemoteTestbedArgs {
    /// Path to the YAML settings file (cloud provider, regions, repository, etc.).
    #[arg(long, value_name = "FILE")]
    pub settings_path: PathBuf,

    #[command(subcommand)]
    pub command: RemoteTestbedCommand,
}

#[derive(clap::Subcommand)]
pub enum RemoteTestbedCommand {
    /// Print the current testbed instances and SSH commands to reach them.
    Status,

    /// Create a given number of instances per region (or in a single specified region).
    Create {
        /// Number of instances to create (per region, unless `--region` is set).
        #[arg(long)]
        instances: usize,
        /// Limit creation to this region. Omit to create instances in every configured region.
        #[arg(long)]
        region: Option<String>,
    },

    /// Boot the specified number of stopped instances per region.
    Start {
        /// Maximum number of instances to start per region.
        #[arg(long, default_value_t = 10)]
        instances: usize,
    },

    /// Stop all active instances (does not destroy them).
    Stop,

    /// Destroy the testbed and terminate every instance.
    Destroy,

    /// Deploy validators and run a benchmark sweep over the supplied loads.
    Benchmark {
        /// Committee size for the benchmark.
        #[arg(long, value_name = "INT", default_value_t = 4)]
        committee: usize,

        /// Comma-separated list of loads to sweep (tx/s). One run per load.
        /// A load of `0` runs the validators without load generators.
        #[arg(long, value_name = "INT", value_delimiter = ',', default_value = "200")]
        loads: Vec<usize>,

        /// Skip `apt`/repo update on the testbed before benchmarking. Dangerous: may run
        /// outdated validators. Useful only when iterating locally on the same commit.
        #[arg(long)]
        skip_testbed_update: bool,

        /// Skip generating fresh genesis + per-validator configs. Dangerous: validators may
        /// be misconfigured for the requested committee size.
        #[arg(long)]
        skip_testbed_configuration: bool,
    },
}
