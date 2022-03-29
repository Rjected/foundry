//! background service

use crate::eth::{backend, miner::MiningMode, pool::Pool};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// The type that drives the blockchain's state
///
/// This service is basically an endless future that continuously polls the miner which returns
/// transactions for the next block, then those transactions are handed off to the
/// [backend](backend::mem::Backend) to construct a new block, if all transactions were successfully
/// included in a new block they get purged from the `Pool`.
pub struct NodeService {
    /// the pool that holds all transactions
    pool: Arc<Pool>,
    /// holds the blockchain's state
    backend: Arc<backend::mem::Backend>,
    /// the miner responsible to select transactions from the `pool´
    miner: MiningMode,
}

impl Future for NodeService {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let pin = self.get_mut();

        while let Poll::Ready(transactions) = pin.miner.poll(&pin.pool, cx) {
            // miner returned a set of transaction to put into a new block
            let _ = pin.backend.mine_block(transactions);
        }

        Poll::Pending
    }
}
