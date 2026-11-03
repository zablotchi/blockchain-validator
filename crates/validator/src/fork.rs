// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fork injection: validators attesting diverged checkpoints, for fork-recovery experiments.

use std::num::NonZeroU64;

use dag::authority::Authority;
use execution::crypto::Digest;
use serde::{Deserialize, Serialize};

/// Emulates diverged execution at every `period`-th checkpoint height: the members of each
/// group attest a commitment of their own, so groups disagree with each other and with the
/// validators outside them. Only the attested commitment diverges, not the store, so the next
/// height agrees again.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ForkInjection {
    pub groups: Vec<Vec<Authority>>,
    pub period: NonZeroU64,
}

impl ForkInjection {
    /// The commitment `authority` attests at checkpoint `height` (counted from 1) when its
    /// store commits to `commitment`.
    pub(crate) fn commitment(
        &self,
        authority: Authority,
        height: u64,
        commitment: Digest,
    ) -> Digest {
        if !height.is_multiple_of(self.period.get()) {
            return commitment;
        }
        match self
            .groups
            .iter()
            .position(|group| group.contains(&authority))
        {
            Some(group) => commitment.salted(group as u64),
            None => commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use dag::authority::Authority;
    use execution::crypto::Digest;

    use crate::fork::ForkInjection;

    #[test]
    fn groups_diverge_from_each_other_and_the_rest_at_forked_heights_only() {
        let fork = ForkInjection {
            groups: vec![
                vec![Authority::new(1), Authority::new(2)],
                vec![Authority::new(3)],
            ],
            period: NonZeroU64::new(3).unwrap(),
        };
        let store = Digest::new_for_test(7);
        let attested =
            |authority, height| fork.commitment(Authority::new(authority), height, store);

        for height in [1, 2, 4] {
            assert!((0..4).all(|authority| attested(authority, height) == store));
        }
        for height in [3, 6] {
            assert_eq!(attested(0, height), store);
            assert_eq!(attested(1, height), attested(2, height));
            assert_ne!(attested(1, height), store);
            assert_ne!(attested(3, height), store);
            assert_ne!(attested(3, height), attested(1, height));
        }
    }
}
