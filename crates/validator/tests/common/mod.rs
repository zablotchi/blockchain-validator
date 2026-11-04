// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Test harness booting validator committees on the local tokio network.

// Each test binary compiles its own copy of this module and uses a subset of it.
#![allow(dead_code)]

use std::{fs, path::Path, time::Duration};

use checkpoint::{certifier::CheckpointCertifier, finality::FinalityProtocol};
use dag::{authority::Authority, context::TokioCtx};
use execution::{fake::FakeExecutor, scheduler::SequentialScheduler, transaction::Transaction};
use prometheus::Registry;
use replica::{
    builder::StorageKind,
    config::{PrivateReplicaConfig, PublicReplicaConfig},
};
use tokio::time;
use validator::{
    parameters::ValidatorParameters,
    validator::{ValidatorBuilder, ValidatorHandle},
};

const COMMITTEE_SIZE: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(30);

/// A committee of validators running on the local tokio network.
pub struct Testbed {
    validators: Vec<ValidatorHandle<TokioCtx, FakeExecutor>>,
    /// One registry per validator, shared between its replica and validator metrics.
    registries: Vec<Registry>,
}

impl Testbed {
    /// Boots a committee with ephemeral storage.
    pub async fn start(port_offset: u16) -> Self {
        Self::boot(None, port_offset, FinalityProtocol::default()).await
    }

    /// Boots a committee deciding with `finality`, persisting each replica's WAL under `dir`.
    pub async fn start_with_wal(dir: &Path, port_offset: u16, finality: FinalityProtocol) -> Self {
        Self::boot(Some(dir), port_offset, finality).await
    }

    async fn boot(dir: Option<&Path>, port_offset: u16, finality: FinalityProtocol) -> Self {
        let public_config =
            PublicReplicaConfig::new_for_tests(COMMITTEE_SIZE).with_port_offset(port_offset);
        let private_configs = PrivateReplicaConfig::new_for_benchmarks(
            dir.unwrap_or(Path::new("unused")),
            COMMITTEE_SIZE,
        );

        let mut validators = Vec::with_capacity(COMMITTEE_SIZE);
        let mut registries = Vec::with_capacity(COMMITTEE_SIZE);
        for (index, private_config) in private_configs.into_iter().enumerate() {
            let storage = match dir {
                Some(_) => {
                    fs::create_dir_all(&private_config.storage_path).expect("storage directory");
                    StorageKind::Wal(private_config.wal())
                }
                None => StorageKind::Ephemeral,
            };
            let registry = Registry::new();
            registries.push(registry.clone());
            let validator = ValidatorBuilder::new(
                FakeExecutor,
                Authority::from(index),
                public_config.clone(),
                private_config,
            )
            .with_storage(storage)
            .with_registry(registry)
            .with_parameters(ValidatorParameters {
                finality,
                fork: None,
            })
            .build()
            .expect("validator must build")
            .start::<TokioCtx>()
            .await
            .expect("validator must start");
            validators.push(validator);
        }
        Self {
            validators,
            registries,
        }
    }

    pub fn registries(&self) -> &[Registry] {
        &self.registries
    }

    pub fn validators(&self) -> &[ValidatorHandle<TokioCtx, FakeExecutor>] {
        &self.validators
    }

    /// Submits transactions through the `validator`-th committee member.
    pub async fn submit(&self, validator: usize, transactions: Vec<Transaction>) {
        self.validators[validator]
            .submit(transactions)
            .await
            .expect("submission must succeed");
    }

    /// Waits until every validator has executed at least `count` transactions.
    pub async fn wait_for_transactions(&mut self, count: u64) {
        for validator in &mut self.validators {
            time::timeout(TIMEOUT, validator.wait_for_transactions(count))
                .await
                .expect("timed out waiting for transactions to execute");
        }
    }

    /// Waits until everything executed is decided on every validator; call after an
    /// executed-count cut.
    pub async fn wait_for_decided(&mut self) {
        for validator in &mut self.validators {
            time::timeout(TIMEOUT, validator.wait_for_decided())
                .await
                .expect("timed out waiting for decisions");
        }
    }

    /// Stops every validator and returns the schedulers with their executed state and
    /// checkpoint certifiers.
    pub async fn shutdown(self) -> Vec<(SequentialScheduler<FakeExecutor>, CheckpointCertifier)> {
        let mut results = Vec::with_capacity(self.validators.len());
        for validator in self.validators {
            results.push(validator.shutdown().await);
        }
        results
    }
}
