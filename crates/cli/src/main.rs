// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The validator binary: genesis generation, a single node, and remote benchmarks.

use clap::Parser;
use eyre::Result;

use crate::args::{Args, Command};

mod args;
mod commands;
mod config;
mod remote;
mod tracing;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let log_level = args.log_level;
    let log_file = args.log_file;

    match args.command {
        Command::TestGenesis(sub) => commands::genesis::test_genesis(sub, log_level, log_file)?,
        Command::Run(sub) => commands::run::run(sub, log_level, log_file).await?,
        Command::RemoteTestbed(sub) => {
            commands::remote_testbed::remote_testbed(sub, log_level, log_file).await?
        }
    }

    Ok(())
}
