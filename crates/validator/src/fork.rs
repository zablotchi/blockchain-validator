// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork injection: validators executing diverged states, for fork-recovery experiments.

use std::num::NonZeroU64;

use dag::authority::Authority;
use execution::{
    object::{Object, ObjectId, Version},
    store::StateView,
};
use serde::{Deserialize, Serialize};

/// The object the fork writes go to: no transaction touches it, since every other id has
/// leading zero bytes.
const FORK_OBJECT: ObjectId = ObjectId::from_bytes([0xFF; 32]);

/// Diverges execution at the forked checkpoint heights: after executing such a height, the
/// members of each group write the fork object with their group's index, so groups disagree
/// with each other and with the validators outside them, from that height on.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ForkInjection {
    pub groups: Vec<Vec<Authority>>,
    pub period: NonZeroU64,
    /// Fork only the first this many multiples of `period`; `None` forks every multiple.
    #[serde(default)]
    pub episodes: Option<NonZeroU64>,
}

impl ForkInjection {
    /// Whether checkpoint height `height` (counted from 1) is forked.
    pub(crate) fn forked(&self, height: u64) -> bool {
        let period = self.period.get();
        height.is_multiple_of(period)
            && self
                .episodes
                .is_none_or(|episodes| height / period <= episodes.get())
    }

    /// The index in the schedule of the episode forking height `height`, from 1, if it is
    /// forked: every validator knows it, forked or not.
    pub(crate) fn episode(&self, height: u64) -> Option<u64> {
        self.forked(height).then(|| height / self.period.get())
    }

    /// The fork write `authority` applies after executing height `height` on `state`, if any.
    pub(crate) fn write(
        &self,
        authority: Authority,
        height: u64,
        state: &impl StateView,
    ) -> Option<Object> {
        if !self.forked(height) {
            return None;
        }
        let group = self
            .groups
            .iter()
            .position(|group| group.contains(&authority))?;
        Some(Self::group_write(group, state))
    }

    /// The writes a validator may have applied after executing height `height` on `state`:
    /// none, as honest validators do, then each group's at a forked height.
    pub(crate) fn candidates(&self, height: u64, state: &impl StateView) -> Vec<Option<Object>> {
        let groups = if self.forked(height) {
            self.groups.len()
        } else {
            0
        };
        let writes = (0..groups).map(|group| Some(Self::group_write(group, state)));
        std::iter::once(None).chain(writes).collect()
    }

    /// The fork object at its next version on `state`, holding `group`.
    fn group_write(group: usize, state: &impl StateView) -> Object {
        let latest = state.latest(&FORK_OBJECT);
        let version = latest.map_or(Version::ZERO, Object::version).next();
        Object::new(FORK_OBJECT, version, (group as u64).to_be_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use dag::authority::Authority;
    use execution::{effects::ExecutionOutput, store::InMemoryStore};

    use crate::fork::{FORK_OBJECT, ForkInjection};

    /// Groups {1, 2} and {3}, forking every third height.
    fn fork(episodes: Option<u64>) -> ForkInjection {
        ForkInjection {
            groups: vec![
                vec![Authority::new(1), Authority::new(2)],
                vec![Authority::new(3)],
            ],
            period: NonZeroU64::new(3).unwrap(),
            episodes: episodes.map(|episodes| NonZeroU64::new(episodes).unwrap()),
        }
    }

    #[test]
    fn forked_heights_follow_the_period_and_the_episode_count() {
        let forked = |fork: ForkInjection| -> Vec<_> {
            (1..=12).filter(|&height| fork.forked(height)).collect()
        };
        assert_eq!(forked(fork(None)), [3, 6, 9, 12]);
        assert_eq!(forked(fork(Some(2))), [3, 6]);
    }

    #[test]
    fn group_members_write_the_fork_object_and_others_do_not() {
        let fork = fork(None);
        let mut store = InMemoryStore::default();
        let write = |authority, height, store: &InMemoryStore| {
            fork.write(Authority::new(authority), height, store)
        };
        for height in [1, 2, 4] {
            assert!((0..4).all(|authority| write(authority, height, &store).is_none()));
        }
        assert!(write(0, 3, &store).is_none());
        let [first, second, third] =
            [1, 2, 3].map(|authority| write(authority, 3, &store).expect("a group member"));
        assert_eq!(first, second);
        assert_eq!((first.id(), third.id()), (FORK_OBJECT, FORK_OBJECT));
        assert_eq!(first.version(), third.version());
        assert_ne!(first.contents(), third.contents());

        // Each write goes to the fork object's next version.
        store.apply(ExecutionOutput::success(vec![first]));
        let next = write(3, 6, &store).expect("a group member");
        assert_eq!(next.version(), third.version().next());
    }

    #[test]
    fn candidates_cover_the_honest_state_and_every_group() {
        let fork = fork(None);
        let store = InMemoryStore::default();
        assert_eq!(fork.candidates(2, &store), [None]);
        let groups = [1, 3].map(|authority| fork.write(Authority::new(authority), 3, &store));
        let expected: Vec<_> = std::iter::once(None).chain(groups).collect();
        assert_eq!(fork.candidates(3, &store), expected);
    }
}
