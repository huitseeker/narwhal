// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use config::Stake;
use futures::{
    future::{self, BoxFuture},
    stream::{futures_unordered::FuturesUnordered, StreamExt as _},
    Future, FutureExt,
};
use std::{pin::Pin, task::Context, task::Poll};

/// Drives completion of a set of JoinHandles, specifically [`CancelOnDropHandler`], each weighted by a [`Stake`], until a threshold of them complete.
/// Stays pending until this threshold of futures (by stake) complete.
/// If the threshold stake is greater than the sum of the stakes of the futures passed as argument, then this operates like a [`futures::future::join_all`]
pub struct QuorumWaiter {
    futures: FuturesUnordered<BoxFuture<'static, Stake>>,
    stake_target: Stake,
}

impl QuorumWaiter {
    pub fn new<T, F: Future<Output = T> + Send + 'static, I: IntoIterator<Item = (F, Stake)>>(
        handlers: I,
        threshold_stake: Stake,
    ) -> Self {
        let futures: FuturesUnordered<_> = handlers
            .into_iter()
            // Note: this implicitly requires that the handlers are always successful when they return.
            .map(|(wait_for, stake)| wait_for.then(move |_val| future::ready(stake)).boxed())
            .collect();

        Self {
            futures,
            stake_target: threshold_stake,
        }
    }
}

impl Future for QuorumWaiter {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The stream can only return None if there are no futures. The stream mustn't be polled
        // after it has yielded None so we ensure that we do not attempt to poll in this case.
        if self.futures.is_empty() {
            return Poll::Ready(());
        }
        while let Poll::Ready(result) = self.futures.poll_next_unpin(cx) {
            // Unwrap because we checked that it isn't empty.
            let result = result.unwrap();
            self.stake_target = self.stake_target.saturating_sub(result);

            if self.futures.is_empty() || self.stake_target == 0 {
                return Poll::Ready(());
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::{self};

    #[test]
    fn ready_because_count() {
        let futs = vec![
            (future::pending().boxed(), 1),
            (future::ready(()).boxed(), 1),
            (future::ready(()).boxed(), 1),
        ];

        let quorum_wait = QuorumWaiter::new(futs, 2);

        assert!(quorum_wait.now_or_never().is_some());
    }

    #[test]
    fn ready_because_complete() {
        let futs = vec![
            (future::ready(()).boxed(), 1),
            (future::ready(()).boxed(), 1),
            (future::ready(()).boxed(), 1),
        ];

        let quorum_wait = QuorumWaiter::new(futs, 4);

        assert!(quorum_wait.now_or_never().is_some());
    }

    #[test]
    fn not_ready_because_pending() {
        let futs = vec![
            (future::pending().boxed(), 1),
            (future::pending().boxed(), 1),
            (future::ready(()).boxed(), 1),
        ];

        let quorum_wait = QuorumWaiter::new(futs, 2);

        assert!(quorum_wait.now_or_never().is_none());
    }
}
