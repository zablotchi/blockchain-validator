// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The sequential transaction scheduler.

use crate::{
    effects::{AbortReason, ExecutionStatus},
    engine::ExecutionEngine,
    store::InMemoryStore,
    transaction::Transaction,
};

/// Executes transactions strictly in commit order and owns the resulting state.
pub struct SequentialScheduler<E> {
    store: InMemoryStore,
    engine: E,
}

impl<E: ExecutionEngine> SequentialScheduler<E> {
    pub fn new(engine: E) -> Self {
        Self {
            store: InMemoryStore::default(),
            engine,
        }
    }

    /// Executes `transactions` in order, applying each transaction's output before executing the
    /// next, and returns their statuses in the same order. The transactions are only borrowed,
    /// so the caller can keep them to execute again.
    pub fn execute(&mut self, transactions: &[Transaction]) -> Vec<ExecutionStatus> {
        transactions
            .iter()
            .map(|transaction| {
                if !transaction.verify() {
                    return ExecutionStatus::Aborted(AbortReason::InvalidTransaction);
                }
                let output = self.engine.execute(&self.store, transaction);
                let status = output.status();
                self.store.apply(output);
                status
            })
            .collect()
    }

    pub fn store(&self) -> &InMemoryStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut InMemoryStore {
        &mut self.store
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        effects::{AbortReason, ExecutionStatus},
        fake::{FakeExecutor, FakeTransaction},
        object::{ObjectId, Version},
        scheduler::SequentialScheduler,
        store::StateView,
        transaction::Transaction,
    };

    fn batch() -> Vec<Transaction> {
        let id = ObjectId::new(1);
        vec![
            FakeTransaction::success(vec![], vec![id], vec![]).into(),
            FakeTransaction::abort().into(),
            FakeTransaction::success(vec![], vec![], vec![id]).into(),
        ]
    }

    #[test]
    fn transactions_execute_in_commit_order() {
        let mut scheduler = SequentialScheduler::new(FakeExecutor);
        let statuses = scheduler.execute(&batch());

        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[0], ExecutionStatus::Success);
        assert_eq!(
            statuses[1],
            ExecutionStatus::Aborted(AbortReason::ExplicitAbort)
        );
        // The abort did not halt the batch: the read-modify-write landed on top of the creation.
        assert_eq!(statuses[2], ExecutionStatus::Success);
        let latest = scheduler.store().latest(&ObjectId::new(1)).unwrap();
        assert_eq!(latest.version(), Version::new(2));
    }

    #[test]
    fn invalid_transactions_abort_without_executing() {
        let id = ObjectId::new(1);
        let transaction = FakeTransaction::success(vec![], vec![id, id], vec![]).into();
        let mut scheduler = SequentialScheduler::new(FakeExecutor);
        let statuses = scheduler.execute(&[transaction]);

        assert_eq!(
            statuses,
            [ExecutionStatus::Aborted(AbortReason::InvalidTransaction)]
        );
        assert!(scheduler.store().latest(&id).is_none());
    }
}
