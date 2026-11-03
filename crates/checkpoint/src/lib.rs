// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoint engine.
//!
//! Mints commitments to the execution state, one per committed sub-dag that executed
//! transactions, and decides each (finalize or skip) from the votes validators attest through
//! consensus, under the run's finality protocol.

pub mod certifier;
pub mod checkpoint;
pub mod finality;
