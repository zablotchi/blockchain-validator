// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-episode records of fork recovery: what each validator did at each forked height of the
//! schedule, exported through the metrics.

use std::time::Duration;

use checkpoint::checkpoint::Outcome;

use crate::metrics::{ADOPT, SKIP, ValidatorMetrics, WINNER};

/// How a validator came through a fork episode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// The forked height skipped: it recovered from the skip.
    Skip,
    /// The forked height finalized a state other than its own: it adopted it.
    Adopt,
    /// The forked height finalized its own state: it recovered from nothing.
    Winner,
}

impl Role {
    pub const ALL: [Self; 3] = [Self::Skip, Self::Adopt, Self::Winner];

    /// The role of a validator whose state at a forked height, released with `outcome`,
    /// diverged (`true`) or not.
    fn of(outcome: Outcome, diverged: bool) -> Self {
        match (outcome, diverged) {
            (Outcome::Skip, _) => Self::Skip,
            (Outcome::Finalize(_), true) => Self::Adopt,
            (Outcome::Finalize(_), false) => Self::Winner,
        }
    }

    /// The `role` label of the recovery metrics.
    pub fn label(self) -> &'static str {
        match self {
            Self::Skip => SKIP,
            Self::Adopt => ADOPT,
            Self::Winner => WINNER,
        }
    }

    /// The role as the number the per-episode gauges hold.
    pub fn code(self) -> f64 {
        match self {
            Self::Skip => 1.0,
            Self::Adopt => 2.0,
            Self::Winner => 3.0,
        }
    }
}

/// What one validator did in one fork episode.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct EpisodeRecord {
    /// The forked height.
    pub height: u64,
    pub role: Role,
    /// From the forked height's first mint to its release.
    pub detection: Duration,
    /// From the forked height's first mint until every height pending at its release was
    /// released; `None` until then.
    pub stall: Option<Duration>,
    /// The height executions the recovery performed, a height executed twice counting twice,
    /// and their transactions.
    pub re_executed_heights: u64,
    pub re_executed_transactions: u64,
    /// The forked height's transactions, if it skipped.
    pub skipped_transactions: u64,
    /// The recovery's re-votes submitted to consensus.
    pub re_votes: u64,
    /// The time spent undoing and executing again, by the driver's clock: zero under the
    /// simulator.
    pub recovery: Duration,
}

/// The work of one recovery step: a rewind or one height's re-execution.
#[derive(Default)]
pub(crate) struct Work {
    pub(crate) heights: u64,
    pub(crate) transactions: u64,
    pub(crate) skipped: u64,
    pub(crate) time: Duration,
}

/// An episode whose record may still change.
struct OpenEpisode {
    index: u64,
    minted_at: Duration,
    /// The highest height pending at the forked height's release: the stall ends at its release.
    stall_until: u64,
    record: EpisodeRecord,
}

/// The records of the episodes still open. A record stays open until its stall ended and none
/// of its re-votes waits to be submitted, and its gauges follow every change; once final it
/// joins the accounting, which covers every episode, exported or not.
pub(crate) struct EpisodeLog {
    open: Vec<OpenEpisode>,
    /// The driver's clock, which times recoveries.
    clock: Box<dyn Fn() -> Duration + Send + Sync>,
}

impl Default for EpisodeLog {
    fn default() -> Self {
        Self {
            open: Vec::new(),
            clock: Box::new(|| Duration::ZERO),
        }
    }
}

impl EpisodeLog {
    /// Times recoveries by `clock` from now on.
    pub(crate) fn set_clock(&mut self, clock: impl Fn() -> Duration + Send + Sync + 'static) {
        self.clock = Box::new(clock);
    }

    /// The time by the driver's clock.
    pub(crate) fn now(&self) -> Duration {
        (self.clock)()
    }

    /// Takes one release at `now`, of heights up to `highest`, the last of which `diverged` or
    /// not, while `minted` heights are minted: opens an episode for each forked height released,
    /// given by its episode index, height, first mint and outcome, and ends the stalls the
    /// release ends. Returns the episode a divergence is attributed to: the one it opened, else
    /// the latest one whose stall it falls in.
    pub(crate) fn release(
        &mut self,
        metrics: &ValidatorMetrics,
        now: Duration,
        forked: Vec<(u64, u64, Duration, Outcome)>,
        highest: u64,
        diverged: bool,
        minted: u64,
    ) -> Option<u64> {
        for (index, height, minted_at, outcome) in forked {
            let record = EpisodeRecord {
                height,
                role: Role::of(outcome, diverged && height == highest),
                detection: now.saturating_sub(minted_at),
                stall: None,
                re_executed_heights: 0,
                re_executed_transactions: 0,
                skipped_transactions: 0,
                re_votes: 0,
                recovery: Duration::ZERO,
            };
            metrics.export_episode(index, &record);
            self.open.push(OpenEpisode {
                index,
                minted_at,
                stall_until: minted,
                record,
            });
        }
        let attributed = if diverged {
            let stalled = (self.open.iter().rev())
                .find(|episode| episode.record.stall.is_none() && episode.stall_until >= highest);
            if stalled.is_none() {
                tracing::warn!(highest, "a recovery outside every fork episode");
            }
            stalled.map(|episode| episode.index)
        } else {
            None
        };
        for episode in &mut self.open {
            if episode.record.stall.is_none() && episode.stall_until <= highest {
                episode.record.stall = Some(now.saturating_sub(episode.minted_at));
                metrics.export_episode(episode.index, &episode.record);
            }
        }
        attributed
    }

    /// Adds `work` to the record of `episode`, if the recovery is attributed to one.
    pub(crate) fn recovered(
        &mut self,
        metrics: &ValidatorMetrics,
        episode: Option<u64>,
        work: Work,
    ) {
        self.update(metrics, episode, |record| {
            record.re_executed_heights += work.heights;
            record.re_executed_transactions += work.transactions;
            record.skipped_transactions += work.skipped;
            record.recovery += work.time;
        });
    }

    /// Counts a re-vote of `episode` submitted to consensus.
    pub(crate) fn submitted_re_vote(&mut self, metrics: &ValidatorMetrics, episode: u64) {
        self.update(metrics, Some(episode), |record| record.re_votes += 1);
    }

    /// Closes the records whose stall ended and none of whose re-votes is `queued`: adds them to
    /// the accounting and logs them.
    pub(crate) fn finish(&mut self, metrics: &ValidatorMetrics, queued: impl Fn(u64) -> bool) {
        if self.open.is_empty() {
            return;
        }
        self.open.retain(|episode| {
            let record = &episode.record;
            let Some(stall) = record.stall else {
                return true;
            };
            if queued(episode.index) {
                return true;
            }
            metrics.account_episode(record);
            tracing::info!(
                episode = episode.index,
                height = record.height,
                role = record.role.label(),
                detection_s = record.detection.as_secs_f64(),
                stall_s = stall.as_secs_f64(),
                re_executed_heights = record.re_executed_heights,
                re_executed_transactions = record.re_executed_transactions,
                skipped_transactions = record.skipped_transactions,
                re_votes = record.re_votes,
                recovery_s = record.recovery.as_secs_f64(),
                "fork_recovery_episode"
            );
            false
        });
    }

    fn update(
        &mut self,
        metrics: &ValidatorMetrics,
        episode: Option<u64>,
        change: impl FnOnce(&mut EpisodeRecord),
    ) {
        let Some(open) = (self.open.iter_mut()).find(|open| Some(open.index) == episode) else {
            return;
        };
        change(&mut open.record);
        metrics.export_episode(open.index, &open.record);
    }
}
