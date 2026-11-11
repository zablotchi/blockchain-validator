// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use dag::{authority::Authority, config::ImportExport};
use eyre::{Context, Result};
use replica::config::{PrivateReplicaConfig, PublicReplicaConfig, ReplicaParameters};
use tracing_subscriber::filter::LevelFilter;

use crate::{args::TestGenesisArgs, config, tracing::ValidatorTracing};

pub fn test_genesis(
    args: TestGenesisArgs,
    log_level: Option<LevelFilter>,
    log_file: Option<PathBuf>,
) -> Result<()> {
    let _guard = match log_level {
        Some(level) => ValidatorTracing::new(level),
        None => ValidatorTracing::default(),
    }
    .with_log_file(log_file)
    .setup()?;
    write_genesis(args)
}

/// Writes the public config and one private config per validator to the working directory.
fn write_genesis(args: TestGenesisArgs) -> Result<()> {
    let TestGenesisArgs {
        ips,
        working_directory,
        replica_parameters_path,
    } = args;
    let committee_size = ips.len();
    tracing::info!("Generating test genesis for {committee_size} validators");

    fs::create_dir_all(&working_directory).wrap_err(format!(
        "Failed to create working directory '{}'",
        working_directory.display()
    ))?;

    let parameters = match replica_parameters_path {
        Some(path) => {
            tracing::info!("Loading replica parameters from {}", path.display());
            config::load::<ReplicaParameters>(&path)?
        }
        None => {
            tracing::info!("Using default replica parameters");
            ReplicaParameters::default()
        }
    };

    // The public replica config: parameters + per-validator identities (public key, stake,
    // network/metrics addresses). The committee is derived from this file at runtime.
    let public_config = PublicReplicaConfig::new_for_benchmarks(ips).with_parameters(parameters);
    let public_config_path = working_directory.join(PublicReplicaConfig::DEFAULT_FILENAME);
    public_config.print(&public_config_path)?;
    tracing::info!("Wrote {}", public_config_path.display());

    // One private config per validator (keys, storage path).
    let private_configs =
        PrivateReplicaConfig::new_for_benchmarks(&working_directory, committee_size);
    for (i, private_config) in private_configs.into_iter().enumerate() {
        let authority = Authority::from(i);
        fs::create_dir_all(&private_config.storage_path).wrap_err(format!(
            "Failed to create storage directory for validator {authority}"
        ))?;
        let path = working_directory.join(PrivateReplicaConfig::default_filename(authority));
        private_config.print(&path)?;
        tracing::info!("Wrote {}", path.display());
    }

    tracing::info!(
        "Test genesis for {committee_size} validators ready in '{}'",
        working_directory.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{IpAddr, Ipv4Addr},
    };

    use dag::authority::Authority;
    use replica::config::{PrivateReplicaConfig, PublicReplicaConfig};

    use crate::{args::TestGenesisArgs, commands::genesis::write_genesis, config};

    fn genesis(dir: &tempfile::TempDir, replica_parameters: &str) -> eyre::Result<()> {
        let path = dir.path().join("replica-parameters.yaml");
        fs::write(&path, replica_parameters).unwrap();
        write_genesis(TestGenesisArgs {
            ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST); 4],
            working_directory: dir.path().join("genesis"),
            replica_parameters_path: Some(path),
        })
    }

    #[test]
    fn generated_configs_load_strictly() {
        let dir = tempfile::tempdir().unwrap();
        let parameters =
            "consensus:\n  protocol: mysticeti\n  leader_count: 1\ndag:\n  fsync: true\n";
        genesis(&dir, parameters).unwrap();
        let genesis = dir.path().join("genesis");
        let public: PublicReplicaConfig =
            config::load(genesis.join(PublicReplicaConfig::DEFAULT_FILENAME)).unwrap();
        assert!(public.parameters.dag.fsync);
        for authority in (0..4usize).map(Authority::from) {
            let path = genesis.join(PrivateReplicaConfig::default_filename(authority));
            config::load::<PrivateReplicaConfig>(path).unwrap();
        }
    }

    #[test]
    fn misspelled_replica_parameters_fail_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let error = genesis(&dir, "dag:\n  fsync_typo: true\n").unwrap_err();
        assert!(format!("{error:#}").contains("unknown keys: dag.fsync_typo"));
    }
}
