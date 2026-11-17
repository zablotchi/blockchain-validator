// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The versioned in-memory object store.

use std::{
    collections::{BTreeMap, VecDeque},
    mem::size_of,
};

use digest::Digest as _;

use crate::{
    crypto::{Digest, Hasher},
    effects::ExecutionOutput,
    object::{Object, ObjectId, Version},
};

/// A read-only view of the store against which transactions execute.
pub trait StateView {
    /// The latest version of an object, or `None` if it was never written.
    fn latest(&self, id: &ObjectId) -> Option<&Object>;
}

/// An in-memory versioned object store.
///
/// Every write creates a new `(id, version)` entry; existing entries are never overwritten. The
/// store holds derived state only — durability is the job of the consensus WAL, which execution
/// replays on restart.
///
/// With the journal on, writes are grouped into consecutive heights, and the heights not yet
/// pruned can be undone, newest first.
#[derive(Default, Debug)]
pub struct InMemoryStore {
    /// Every object version ever written.
    objects: BTreeMap<(ObjectId, Version), Object>,
    /// The highest written version of each object.
    latest: BTreeMap<ObjectId, Version>,
    /// Rolling commitment to the full ordered write history; a persistent backend must persist
    /// it in the same atomic batch as its delta's writes.
    commitment: Digest,
    /// Undo data of the heights not yet pruned; `None` (the default) journals nothing.
    journal: Option<Journal>,
}

/// One write in the journal: the object, the version written, and the latest version it replaced.
type JournalEntry = (ObjectId, Version, Option<Version>);

#[derive(Debug)]
struct Journal {
    /// One journal per height, oldest first; the last one is the open height.
    heights: VecDeque<HeightJournal>,
    /// The height of `heights[0]`, or the next height to begin while `heights` is empty.
    first: u64,
    /// The bytes `heights` holds, as [`HeightJournal::bytes`] counts them.
    bytes: usize,
}

#[derive(Debug)]
struct HeightJournal {
    /// The commitment when the height began.
    start: Digest,
    /// The height's writes, in application order.
    writes: Vec<JournalEntry>,
}

impl HeightJournal {
    /// A fixed cost per height plus one entry per write.
    fn bytes(&self) -> usize {
        size_of::<Self>() + self.writes.len() * size_of::<JournalEntry>()
    }
}

impl InMemoryStore {
    /// The object frozen at exactly `(id, version)`, or `None` if absent.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn get(&self, id: &ObjectId, version: Version) -> Option<&Object> {
        self.objects.get(&(*id, version))
    }

    /// Consumes an execution output: each written object moves into the store at its version,
    /// which becomes the latest version of its id. Aborted outputs carry no writes, so applying
    /// them is a no-op. With the journal on, the writes join the open height.
    pub fn apply(&mut self, output: ExecutionOutput) {
        for object in output.into_writes() {
            let (id, version) = (object.id(), object.version());
            let previous = self.latest.insert(id, version);
            assert!(
                previous.is_none_or(|p| p < version),
                "object versions must move forward"
            );
            if let Some(journal) = &mut self.journal {
                journal.open().writes.push((id, version, previous));
                journal.bytes += size_of::<JournalEntry>();
            }
            self.commitment = fold(self.commitment, &object);
            self.objects.insert((id, version), object);
        }
    }

    /// Folds the skip marker of the height anchored at `anchor` into the commitment, which
    /// becomes `commitment.skip(anchor)`; nothing is written. With the journal on, the marker
    /// belongs to the open height and is undone with it.
    pub fn apply_skip(&mut self, anchor: &[u8]) {
        if let Some(journal) = &mut self.journal {
            journal.open();
        }
        self.commitment = self.commitment.skip(anchor);
    }

    /// The commitment to the state: `H(previous ‖ id ‖ version ‖ contents)` folded over every
    /// write in execution order, with the skip markers folded in where they were applied.
    pub fn commitment(&self) -> Digest {
        self.commitment
    }

    /// The commitment the store would have after applying `object` next.
    pub fn preview(&self, object: &Object) -> Digest {
        fold(self.commitment, object)
    }

    /// Turns the journal on: `next_height` is the first height that can begin.
    pub fn enable_journal(&mut self, next_height: u64) {
        assert!(self.journal.is_none(), "the journal is already on");
        self.journal = Some(Journal {
            heights: VecDeque::new(),
            first: next_height,
            bytes: 0,
        });
    }

    /// Opens `height`, which must follow the last height begun (or be the `next_height` the
    /// journal was enabled with, or the height just undone or pruned up to): the writes and skip
    /// markers applied from now on belong to it.
    pub fn begin_height(&mut self, height: u64) {
        let journal = self.journal.as_mut().expect("heights need the journal");
        let next = journal.first + journal.heights.len() as u64;
        assert_eq!(height, next, "heights begin in order");
        let opened = HeightJournal {
            start: self.commitment,
            writes: Vec::new(),
        };
        journal.bytes += opened.bytes();
        journal.heights.push_back(opened);
    }

    /// Undoes every height from `height` to the open one, newest height and newest write first:
    /// afterwards the objects, the latest versions and the commitment are exactly what they were
    /// when `height` began. `height` must have begun and must not be pruned.
    pub fn undo_from(&mut self, height: u64) {
        let journal = self.journal.as_mut().expect("undo needs the journal");
        assert!(height >= journal.first, "undo below a pruned height");
        let kept = (height - journal.first) as usize;
        assert!(kept < journal.heights.len(), "undo of a height never begun");
        for undone in journal.heights.drain(kept..).rev() {
            journal.bytes -= undone.bytes();
            for (id, version, previous) in undone.writes.into_iter().rev() {
                let removed = self.objects.remove(&(id, version));
                debug_assert!(removed.is_some(), "undone writes are in the store");
                let replaced = match previous {
                    Some(previous) => self.latest.insert(id, previous),
                    None => self.latest.remove(&id),
                };
                debug_assert_eq!(replaced, Some(version), "undo runs newest write first");
            }
            self.commitment = undone.start;
        }
    }

    /// Forgets the undo data of every height up to and including `height`, which must have
    /// begun: those heights are stable and are never undone.
    pub fn prune_through(&mut self, height: u64) {
        let journal = self.journal.as_mut().expect("pruning needs the journal");
        while journal.first <= height {
            let pruned = journal
                .heights
                .pop_front()
                .expect("prune of a height never begun");
            journal.bytes -= pruned.bytes();
            journal.first += 1;
        }
    }

    /// The bytes the journal holds: zero while it is off.
    pub fn journal_bytes(&self) -> usize {
        self.journal.as_ref().map_or(0, |journal| journal.bytes)
    }
}

impl Journal {
    /// The open height; changes applied with the journal on need one.
    fn open(&mut self) -> &mut HeightJournal {
        self.heights
            .back_mut()
            .expect("changes with the journal on need an open height")
    }
}

/// `H(commitment ‖ id ‖ version ‖ contents)`: the commitment after writing `object`. Only the
/// trailing element is variable, so no length framing is needed.
fn fold(commitment: Digest, object: &Object) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(commitment.as_bytes());
    hasher.update(object.id().as_bytes());
    hasher.update(object.version().as_u64().to_be_bytes());
    hasher.update(object.contents());
    Digest::new(hasher.finalize().into())
}

/// Stores compare by state: validators with different journals (another window, or the journal
/// off) hold the same state when their objects, latest versions and commitments agree.
impl PartialEq for InMemoryStore {
    fn eq(&self, other: &Self) -> bool {
        self.objects == other.objects
            && self.latest == other.latest
            && self.commitment == other.commitment
    }
}

impl StateView for InMemoryStore {
    fn latest(&self, id: &ObjectId) -> Option<&Object> {
        let version = self.latest.get(id)?;
        self.objects.get(&(*id, *version))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use crate::{
        crypto::Digest,
        effects::{AbortReason, ExecutionOutput},
        object::{Object, ObjectId, Version},
        store::{HeightJournal, InMemoryStore, JournalEntry, StateView},
    };

    /// The anchor bytes of a skipped height (author, round, digest).
    const ANCHOR: [u8; 48] = [7; 48];

    fn with_journal() -> InMemoryStore {
        let mut store = InMemoryStore::default();
        store.enable_journal(1);
        store
    }

    /// A successful output writing `contents` to each of `ids`, one past its latest version.
    fn write(store: &InMemoryStore, ids: &[u64], contents: u8) -> ExecutionOutput {
        let objects = ids
            .iter()
            .map(|&id| {
                let id = ObjectId::new(id);
                let latest = store.latest(&id).map_or(Version::ZERO, |o| o.version());
                Object::new(id, latest.next(), vec![contents])
            })
            .collect();
        ExecutionOutput::success(objects)
    }

    /// The writes of height `h` in a history that rewrites shared objects: objects 1 and 2,
    /// then object 1 again with one fresh object; four writes in all.
    fn apply_height(store: &mut InMemoryStore, h: u64) {
        store.apply(write(store, &[1, 2], h as u8));
        store.apply(write(store, &[1, 100 + h], h as u8));
    }

    /// Begins height `h` and applies its writes.
    fn run_height(store: &mut InMemoryStore, h: u64) {
        store.begin_height(h);
        apply_height(store, h);
    }

    #[test]
    fn apply_moves_writes_in_and_bumps_latest() {
        let mut store = InMemoryStore::default();
        let id = ObjectId::new(1);
        store.apply(ExecutionOutput::success(vec![Object::new(
            id,
            Version::new(1),
            vec![1],
        )]));
        store.apply(ExecutionOutput::success(vec![Object::new(
            id,
            Version::new(2),
            vec![2],
        )]));

        assert_eq!(store.latest(&id).unwrap().contents(), [2]);
        assert_eq!(store.get(&id, Version::new(1)).unwrap().contents(), [1]);
        assert!(store.get(&id, Version::new(3)).is_none());
        assert!(store.latest(&ObjectId::new(9)).is_none());
    }

    #[test]
    fn aborted_outputs_leave_the_store_untouched() {
        let mut store = InMemoryStore::default();
        store.apply(ExecutionOutput::aborted(AbortReason::ExplicitAbort));
        assert_eq!(store, InMemoryStore::default());
    }

    #[test]
    #[should_panic(expected = "versions must move forward")]
    fn rewriting_a_version_panics() {
        let mut store = InMemoryStore::default();
        let object = || Object::new(ObjectId::new(1), Version::new(1), vec![1]);
        store.apply(ExecutionOutput::success(vec![object()]));
        store.apply(ExecutionOutput::success(vec![object()]));
    }

    #[test]
    fn commitments_track_the_write_history() {
        let write = |version: u64| {
            ExecutionOutput::success(vec![Object::new(
                ObjectId::new(1),
                Version::new(version),
                vec![version as u8],
            )])
        };
        let (mut first, mut second) = (InMemoryStore::default(), InMemoryStore::default());
        assert_eq!(first.commitment(), Digest::default());

        first.apply(write(1));
        second.apply(write(1));
        assert_eq!(first.commitment(), second.commitment());

        first.apply(write(2));
        assert_ne!(first.commitment(), second.commitment());
        second.apply(write(2));
        assert_eq!(first.commitment(), second.commitment());
    }

    #[test]
    fn commitments_flip_on_any_differing_write() {
        let commit = |id: u64, version: u64, contents: Vec<u8>| {
            let mut store = InMemoryStore::default();
            let object = Object::new(ObjectId::new(id), Version::new(version), contents);
            store.apply(ExecutionOutput::success(vec![object]));
            store.commitment()
        };
        let reference = commit(1, 1, vec![7]);
        assert_ne!(reference, commit(2, 1, vec![7]));
        assert_ne!(reference, commit(1, 2, vec![7]));
        assert_ne!(reference, commit(1, 1, vec![8]));
    }

    #[test]
    fn commitments_are_order_sensitive() {
        let first = || Object::new(ObjectId::new(1), Version::new(1), vec![1]);
        let second = || Object::new(ObjectId::new(2), Version::new(1), vec![2]);

        let mut forward = InMemoryStore::default();
        forward.apply(ExecutionOutput::success(vec![first()]));
        forward.apply(ExecutionOutput::success(vec![second()]));
        let mut reverse = InMemoryStore::default();
        reverse.apply(ExecutionOutput::success(vec![second()]));
        reverse.apply(ExecutionOutput::success(vec![first()]));

        assert_ne!(forward.commitment(), reverse.commitment());
    }

    #[test]
    fn commitments_ignore_batch_boundaries() {
        let first = || Object::new(ObjectId::new(1), Version::new(1), vec![1]);
        let second = || Object::new(ObjectId::new(2), Version::new(1), vec![2]);

        let mut batched = InMemoryStore::default();
        batched.apply(ExecutionOutput::success(vec![first(), second()]));
        let mut split = InMemoryStore::default();
        split.apply(ExecutionOutput::success(vec![first()]));
        split.apply(ExecutionOutput::success(vec![second()]));

        assert_eq!(batched.commitment(), split.commitment());
    }

    // Commitments are persisted and compared across nodes, so the exact bytes matter: pin them so
    // any change to the hash, field order, or endianness fails loudly.
    #[test]
    fn commitments_are_stable_across_releases() {
        let mut store = InMemoryStore::default();
        store.apply(ExecutionOutput::success(vec![
            Object::new(ObjectId::new(1), Version::new(1), vec![1, 2, 3]),
            Object::new(ObjectId::new(2), Version::new(7), vec![]),
        ]));

        let hex: String = store
            .commitment()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hex,
            "bc3d1e39e90374f882e0c4ecc1b5f7f3ed4638ad3eeaa165fd86a768ec5224df"
        );
    }

    #[test]
    fn undo_from_restores_exactly_the_state_before_the_height() {
        let mut store = with_journal();
        for h in 1..=5 {
            run_height(&mut store, h);
        }
        let mut reference = with_journal();
        for h in 1..=2 {
            run_height(&mut reference, h);
        }

        store.undo_from(3);
        assert_eq!(store, reference);
        assert_eq!(store.journal_bytes(), reference.journal_bytes());

        // The undone heights execute again on top, as recovery re-executes them.
        let mut replayed = with_journal();
        for h in 1..=5 {
            run_height(&mut replayed, h);
        }
        for h in 3..=5 {
            run_height(&mut store, h);
        }
        assert_eq!(store, replayed);
    }

    #[test]
    fn undo_from_the_first_height_restores_genesis() {
        let mut store = with_journal();
        for h in 1..=3 {
            run_height(&mut store, h);
        }
        store.undo_from(1);
        assert_eq!(store, InMemoryStore::default());
        assert_eq!(store.commitment(), Digest::default());
        assert_eq!(store.journal_bytes(), 0);
    }

    #[test]
    fn undo_restores_the_state_the_journal_was_enabled_on() {
        let mut store = InMemoryStore::default();
        let mut reference = InMemoryStore::default();
        apply_height(&mut store, 0);
        apply_height(&mut reference, 0);

        store.enable_journal(4);
        for h in 4..=6 {
            run_height(&mut store, h);
        }
        store.undo_from(4);
        assert_eq!(store, reference);
        assert_eq!(store.journal_bytes(), 0);
    }

    #[test]
    fn the_skip_marker_reproduces_the_canonical_skip_digest() {
        let mut store = with_journal();
        run_height(&mut store, 1);
        let canonical = store.commitment().skip(&ANCHOR);

        store.begin_height(2);
        store.apply_skip(&ANCHOR);
        assert_eq!(store.commitment(), canonical);
    }

    #[test]
    fn the_skip_marker_changes_the_commitment_without_writes() {
        let mut store = with_journal();
        run_height(&mut store, 1);
        let mut not_skipped = with_journal();
        run_height(&mut not_skipped, 1);
        let before = store.commitment();

        // A height whose transactions all aborted leaves the commitment as it was...
        store.begin_height(2);
        store.apply(ExecutionOutput::aborted(AbortReason::ExplicitAbort));
        assert_eq!(store.commitment(), before);
        // ...and only the marker sets it apart, writing nothing.
        store.apply_skip(&ANCHOR);
        assert_ne!(store.commitment(), before);
        assert_eq!(store.objects, not_skipped.objects);
        assert_eq!(store.latest, not_skipped.latest);

        // The marker is undone with its height.
        store.undo_from(2);
        assert_eq!(store, not_skipped);
    }

    #[test]
    #[should_panic(expected = "undo below a pruned height")]
    fn undo_below_a_pruned_height_panics() {
        let mut store = with_journal();
        for h in 1..=3 {
            run_height(&mut store, h);
        }
        store.prune_through(2);
        store.undo_from(2);
    }

    #[test]
    #[should_panic(expected = "heights begin in order")]
    fn heights_begin_in_order() {
        let mut store = with_journal();
        run_height(&mut store, 1);
        store.begin_height(3);
    }

    #[test]
    #[should_panic(expected = "changes with the journal on need an open height")]
    fn writes_with_the_journal_on_need_an_open_height() {
        let mut store = with_journal();
        store.apply(write(&store, &[1], 1));
    }

    #[test]
    fn journal_bytes_follow_heights_undo_and_pruning() {
        let height = size_of::<HeightJournal>() + 4 * size_of::<JournalEntry>();
        let mut store = InMemoryStore::default();
        store.enable_journal(1);
        assert_eq!(store.journal_bytes(), 0);
        for h in 1..=4 {
            run_height(&mut store, h);
        }
        assert_eq!(store.journal_bytes(), 4 * height);

        store.prune_through(1);
        assert_eq!(store.journal_bytes(), 3 * height);
        store.undo_from(4);
        assert_eq!(store.journal_bytes(), 2 * height);
        store.prune_through(3);
        assert_eq!(store.journal_bytes(), 0);
        // Pruning everything leaves the next height to begin.
        run_height(&mut store, 4);
        assert_eq!(store.journal_bytes(), height);
    }

    #[test]
    fn preview_matches_apply() {
        let mut store = InMemoryStore::default();
        store.apply(write(&store, &[1], 1));
        for object in [
            Object::new(ObjectId::new(1), Version::new(2), vec![9]),
            Object::new(ObjectId::new(7), Version::new(1), vec![3, 4]),
        ] {
            let before = store.commitment();
            let preview = store.preview(&object);
            assert_eq!(store.commitment(), before);
            store.apply(ExecutionOutput::success(vec![object]));
            assert_eq!(store.commitment(), preview);
        }
    }

    #[test]
    fn stores_compare_by_state_not_by_journal() {
        let mut journal_on = with_journal();
        let mut plain = InMemoryStore::default();
        for h in 1..=3 {
            run_height(&mut journal_on, h);
            apply_height(&mut plain, h);
        }
        journal_on.prune_through(1);
        assert_eq!(journal_on, plain);

        // The commitment counts: a skip marker sets stores apart without any write.
        plain.apply_skip(&ANCHOR);
        assert_ne!(journal_on, plain);
        journal_on.apply_skip(&ANCHOR);
        assert_eq!(journal_on, plain);

        plain.apply(write(&plain, &[1], 9));
        assert_ne!(journal_on, plain);
    }
}
