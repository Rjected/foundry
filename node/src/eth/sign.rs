use crate::eth::error::BlockchainError;
use forge_node_core::eth::transaction::SignedTransaction;
use ethers::types::{transaction::eip2718::TypedTransaction, Address};

/// A transaction signer
pub trait Signer: Send + Sync {
    /// returns the available accounts for this signer
    fn accounts(&self) -> Vec<Address>;
    /// signs a transaction request using the given account in request
    fn sign(
        &self,
        request: TypedTransaction,
        address: &Address,
    ) -> Result<SignedTransaction, BlockchainError>;
}

// TODO implement a dev signer
