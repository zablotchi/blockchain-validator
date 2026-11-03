// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Validator node.
//!
//! Glue in the spirit of sui-node: builds the consensus replica and wires its committed
//! sub-dags into the execution scheduler. Checkpointing comes later.

pub mod envelope;
pub mod fork;
#[cfg(any(test, feature = "benchmark"))]
pub mod generator;
pub mod metrics;
pub mod parameters;
pub mod validator;
