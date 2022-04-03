//! transaction related data

use crate::eth::utils::enveloped;
use ethers_core::{
    types::{
        transaction::{eip2930::{AccessList, AccessListItem}, eip2718::TypedTransaction as EthersTypedTransaction},
        Address, Signature, SignatureError, TxHash, H256, U256, NameOrAddress,
        Eip2930TransactionRequest, Eip1559TransactionRequest, TransactionRequest, Bytes
    },
    utils::{
        keccak256, rlp,
        rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream},
    },
};
use foundry_evm::{
    revm::{CreateScheme, TransactTo, TxEnv},
    utils::h256_to_u256_be,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// i like this type, can we add it to all the ethers types?
pub enum TransactionKind {
    Call(Address),
    Create,
}

impl Encodable for TransactionKind {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TransactionKind::Call(address) => {
                s.encoder().encode_value(&address[..]);
            }
            TransactionKind::Create => s.encoder().encode_value(&[]),
        }
    }
}

impl Decodable for TransactionKind {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            if rlp.is_data() {
                Ok(TransactionKind::Create)
            } else {
                Err(DecoderError::RlpExpectedToBeData)
            }
        } else {
            Ok(TransactionKind::Call(rlp.as_val()?))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTransaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub kind: TransactionKind,
    pub value: U256,
    pub input: Bytes,
    pub signature: Signature,
}

impl LegacyTransaction {
    pub fn nonce(&self) -> &U256 {
        &self.nonce
    }

    pub fn hash(&self) -> H256 {
        H256::from_slice(keccak256(&rlp::encode(self)).as_slice())
    }

    /// Recovers the Ethereum address which was used to sign the transaction.
    pub fn recover(&self) -> Result<Address, SignatureError> {
        // todo since the requests are removed and it wouldn't compile otherwise
        todo!()
    }

    pub fn chain_id(&self) -> Option<u64> {
        if self.signature.v > 36 {
            Some((self.signature.v - 35) / 2)
        } else {
            None
        }
    }
}

impl Encodable for LegacyTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.kind);
        s.append(&self.value);
        s.append(&self.input.as_ref());
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl Decodable for LegacyTransaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen)
        }

        let v = rlp.val_at(6)?;
        let r = rlp.val_at::<U256>(7)?;
        let s = rlp.val_at::<U256>(8)?;

        Ok(Self {
            nonce: rlp.val_at(0)?,
            gas_price: rlp.val_at(1)?,
            gas_limit: rlp.val_at(2)?,
            kind: rlp.val_at(3)?,
            value: rlp.val_at(4)?,
            input: rlp.val_at::<Vec<u8>>(5)?.into(),
            signature: Signature { v, r, s },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EIP2930Transaction {
    pub chain_id: u64,
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub kind: TransactionKind,
    pub value: U256,
    pub input: Bytes,
    pub access_list: AccessList,
    pub odd_y_parity: bool,
    pub r: H256,
    pub s: H256,
}

impl EIP2930Transaction {
    pub fn nonce(&self) -> &U256 {
        &self.nonce
    }

    pub fn hash(&self) -> H256 {
        let encoded = rlp::encode(self);
        let mut out = vec![0; 1 + encoded.len()];
        out[0] = 1;
        out[1..].copy_from_slice(&encoded);
        H256::from_slice(keccak256(&out).as_slice())
    }

    /// Recovers the Ethereum address which was used to sign the transaction.
    pub fn recover(&self) -> Result<Address, SignatureError> {
        // todo since the requests are removed and it wouldn't compile otherwise
        todo!()
    }
}

impl Encodable for EIP2930Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(11);
        s.append(&self.chain_id);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.kind);
        s.append(&self.value);
        s.append(&self.input.as_ref());
        s.append(&self.access_list);
        s.append(&self.odd_y_parity);
        s.append(&U256::from_big_endian(&self.r[..]));
        s.append(&U256::from_big_endian(&self.s[..]));
    }
}

impl Decodable for EIP2930Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 11 {
            return Err(DecoderError::RlpIncorrectListLen)
        }

        Ok(Self {
            chain_id: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            gas_price: rlp.val_at(2)?,
            gas_limit: rlp.val_at(3)?,
            kind: rlp.val_at(4)?,
            value: rlp.val_at(5)?,
            input: rlp.val_at::<Vec<u8>>(6)?.into(),
            access_list: rlp.val_at(7)?,
            odd_y_parity: rlp.val_at(8)?,
            r: {
                let mut rarr = [0_u8; 32];
                rlp.val_at::<U256>(9)?.to_big_endian(&mut rarr);
                H256::from(rarr)
            },
            s: {
                let mut sarr = [0_u8; 32];
                rlp.val_at::<U256>(10)?.to_big_endian(&mut sarr);
                H256::from(sarr)
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EIP1559Transaction {
    pub chain_id: u64,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub kind: TransactionKind,
    pub value: U256,
    pub input: Bytes,
    pub access_list: AccessList,
    pub odd_y_parity: bool,
    pub r: H256,
    pub s: H256,
}

impl EIP1559Transaction {
    pub fn nonce(&self) -> &U256 {
        &self.nonce
    }

    pub fn hash(&self) -> H256 {
        let encoded = rlp::encode(self);
        let mut out = vec![0; 1 + encoded.len()];
        out[0] = 2;
        out[1..].copy_from_slice(&encoded);
        H256::from_slice(keccak256(&out).as_slice())
    }

    /// Recovers the Ethereum address which was used to sign the transaction.
    pub fn recover(&self) -> Result<Address, SignatureError> {
        // todo since the requests are removed and it wouldn't compile otherwise
        todo!()
    }
}

impl Encodable for EIP1559Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(12);
        s.append(&self.chain_id);
        s.append(&self.nonce);
        s.append(&self.max_priority_fee_per_gas);
        s.append(&self.max_fee_per_gas);
        s.append(&self.gas_limit);
        s.append(&self.kind);
        s.append(&self.value);
        s.append(&self.input.as_ref());
        s.append(&self.access_list);
        s.append(&self.odd_y_parity);
        s.append(&U256::from_big_endian(&self.r[..]));
        s.append(&U256::from_big_endian(&self.s[..]));
    }
}

impl Decodable for EIP1559Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? != 12 {
            return Err(DecoderError::RlpIncorrectListLen)
        }

        Ok(Self {
            chain_id: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            max_priority_fee_per_gas: rlp.val_at(2)?,
            max_fee_per_gas: rlp.val_at(3)?,
            gas_limit: rlp.val_at(4)?,
            kind: rlp.val_at(5)?,
            value: rlp.val_at(6)?,
            input: rlp.val_at::<Vec<u8>>(7)?.into(),
            access_list: rlp.val_at(8)?,
            odd_y_parity: rlp.val_at(9)?,
            r: {
                let mut rarr = [0_u8; 32];
                rlp.val_at::<U256>(10)?.to_big_endian(&mut rarr);
                H256::from(rarr)
            },
            s: {
                let mut sarr = [0_u8; 32];
                rlp.val_at::<U256>(11)?.to_big_endian(&mut sarr);
                H256::from(sarr)
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedTransaction {
    /// Legacy transaction type
    Legacy(LegacyTransaction),
    /// EIP-2930 transaction
    EIP2930(EIP2930Transaction),
    /// EIP-1559 transaction
    EIP1559(EIP1559Transaction),
}

// == impl TypedTransaction ==

impl TypedTransaction {
    pub fn nonce(&self) -> &U256 {
        match self {
            TypedTransaction::Legacy(t) => t.nonce(),
            TypedTransaction::EIP2930(t) => t.nonce(),
            TypedTransaction::EIP1559(t) => t.nonce(),
        }
    }

    pub fn hash(&self) -> H256 {
        match self {
            TypedTransaction::Legacy(t) => t.hash(),
            TypedTransaction::EIP2930(t) => t.hash(),
            TypedTransaction::EIP1559(t) => t.hash(),
        }
    }

    /// Recovers the Ethereum address which was used to sign the transaction.
    pub fn recover(&self) -> Result<Address, SignatureError> {
        match self {
            TypedTransaction::Legacy(tx) => tx.recover(),
            TypedTransaction::EIP2930(tx) => tx.recover(),
            TypedTransaction::EIP1559(tx) => tx.recover(),
        }
    }
}

impl Encodable for TypedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TypedTransaction::Legacy(tx) => tx.rlp_append(s),
            TypedTransaction::EIP2930(tx) => enveloped(1, tx, s),
            TypedTransaction::EIP1559(tx) => enveloped(2, tx, s),
        }
    }
}

impl Decodable for TypedTransaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let data = rlp.data()?;
        let first = *data.get(0).ok_or(DecoderError::Custom("empty slice"))?;
        if rlp.is_list() {
            return Ok(TypedTransaction::Legacy(rlp.as_val()?))
        }
        let s = data.get(1..).ok_or(DecoderError::Custom("no tx body"))?;
        if first == 0x01 {
            return rlp::decode(s).map(TypedTransaction::EIP2930)
        }
        if first == 0x02 {
            return rlp::decode(s).map(TypedTransaction::EIP1559)
        }
        Err(DecoderError::Custom("invalid tx type"))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Signed is a signed transaction request - we might be able to introduce this kind of type into
/// ethers. This would replace the above `TypedTransaction`. rlp::Encodable and rlp::Decodable
/// still need to be implemented. In ethers-rs#1096 the decoding methods are NOT part of the
/// ethers-core::...::TypedTransaction Decodable and Encodable implementations, mainly because we
/// are basically decoding to an entirely different type, a signed transaction. It might make sense
/// to introduce a signed transaction type like the following into ethers-rs, using ethers-rs#1096
/// to implement Encodable and Decodable. Then, we could remove the `TypedTransaction`
pub struct SignedTransaction {
    pub tx: EthersTypedTransaction,
    pub signature: Signature,
}

impl SignedTransaction {
    pub fn nonce(&self) -> Option<&U256> {
        self.tx.nonce()
    }

    /// returns the tx hash for the signed tx
    pub fn hash(&self) -> H256 {
        H256::from_slice(&keccak256(self.tx.rlp_signed(&self.signature))[..])
    }

    /// Recovers the Ethereum address which was used to sign the transaction.
    pub fn recover(&self) -> Result<Address, SignatureError> {
        self.signature.recover(self.tx.sighash())
    }

    // just for convenience, remove if we start using kinds. also since ethers transactions use
    // NameOrAddress we have to handle the Name case!
    // This begs the question, will ethers send a .eth name over jsonrpc if it's passed?
    // Wouldn't clients reject this always?
    // If so, we should prevent serialization when it's a Name, or figure out whether or not it's
    // worth replacing NameOrAddress with Kind, combining the two types, or something else.
    // If other clients reject ens names, we should expect to not receive a Name here and should
    // error out.
    /// Gets the TransactionKind from the underlying transaction type
    pub fn kind(&self) -> TransactionKind {
        self.tx.to().map_or(TransactionKind::Create ,
        |to| {
            match to {
                NameOrAddress::Name(_) => panic!("names are not allowed"),
                NameOrAddress::Address(addr) => TransactionKind::Call(*addr),
            }
        })
    }

    // questions: nonce here returns an Option<U256>. Is this desirable?
    // related is whether or not we want a `chain_id` method to return the chain_id from the
    // signature, or from the inner tx struct.
    pub fn chain_id(&self) -> Option<u64> {
        if self.signature.v > 36 {
            Some((self.signature.v - 35) / 2)
        } else {
            None
        }
    }
}

// NOTE: ethers types vs these types. ethers types have Option everywhere, these types don't.
// ethers types are meant to be filled / built, so it makes sense to have options
// However, this means we need to handle these options, for example for converting to revm TxEnv.
// This is sort of annoying because we'd need to change to_revm_tx_env to be a result.
// As we've seen above in the SignedTransaction nonce method, this also means we need to use
// Options there, and anywhere we would use that method.
/// Queued transaction
#[derive(Clone, Debug, PartialEq)]
pub struct PendingTransaction {
    /// The actual transaction
    pub transaction: SignedTransaction,
    /// the recovered sender of this transaction
    sender: Address,
    /// hash of `transaction`, so it can easily be reused with encoding and hashing agan
    hash: TxHash,
}

// == impl PendingTransaction ==

impl PendingTransaction {
    /// Creates a new pending transaction and tries to verify transaction and recover sender.
    pub fn new(transaction: SignedTransaction) -> Result<Self, SignatureError> {
        let sender = transaction.recover()?;
        Ok(Self { hash: transaction.hash(), transaction, sender })
    }

    pub fn nonce(&self) -> Option<&U256> {
        self.transaction.nonce()
    }

    pub fn hash(&self) -> &TxHash {
        &self.hash
    }

    pub fn sender(&self) -> &Address {
        &self.sender
    }

    /// Converts the [PendingTransaction] into the [TxEnv] context that [`revm`](foundry_evm)
    /// expects.
    pub fn to_revm_tx_env(&self) -> TxEnv {
        fn to_access_list(list: Vec<AccessListItem>) -> Vec<(Address, Vec<U256>)> {
            list.into_iter()
                .map(|item| {
                    (item.address, item.storage_keys.into_iter().map(h256_to_u256_be).collect())
                })
                .collect()
        }

        let current_kind = self.transaction.kind();
        fn transact_to(kind: &TransactionKind) -> TransactTo {
            match kind {
                TransactionKind::Call(c) => TransactTo::Call(*c),
                TransactionKind::Create => TransactTo::Create(CreateScheme::Create),
            }
        }

        let caller = *self.sender();
        match &self.transaction.tx {
            // TODO: remove unwraps
            // to remove the unwraps we need to return a Result, but we might want to make sure
            // that these fields are filled before we would ever return an Err here
            EthersTypedTransaction::Legacy(tx) => {
                let TransactionRequest { nonce, gas_price, gas, value, data, chain_id, .. } = tx;
                TxEnv {
                    caller,
                    transact_to: transact_to(&current_kind),
                    data: data.clone().unwrap().0,
                    chain_id: chain_id.map(|id| id.as_u64()),
                    nonce: Some(nonce.unwrap().as_u64()),
                    value: value.unwrap(),
                    gas_price: gas_price.unwrap(),
                    gas_priority_fee: None,
                    gas_limit: gas.unwrap().as_u64(),
                    access_list: vec![],
                }
            }
            EthersTypedTransaction::Eip2930(tx) => {
                let TransactionRequest { nonce, gas_price, gas, value, data, chain_id, .. } = &tx.tx;
                TxEnv {
                    caller,
                    transact_to: transact_to(&current_kind),
                    data: data.clone().unwrap().0,
                    chain_id: chain_id.map(|id| id.as_u64()),
                    nonce: Some(nonce.unwrap().as_u64()),
                    value: value.unwrap(),
                    gas_price: gas_price.unwrap(),
                    gas_priority_fee: None,
                    gas_limit: gas.unwrap().as_u64(),
                    access_list: to_access_list(tx.access_list.0.clone()),
                }
            }
            EthersTypedTransaction::Eip1559(tx) => {
                let Eip1559TransactionRequest {
                    chain_id,
                    nonce,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas,
                    value,
                    data,
                    access_list,
                    ..
                } = tx;
                TxEnv {
                    caller,
                    transact_to: transact_to(&current_kind),
                    data: data.clone().unwrap().0,
                    chain_id: chain_id.map(|id| id.as_u64()),
                    nonce: Some(nonce.unwrap().as_u64()),
                    value: value.unwrap(),
                    gas_price: max_fee_per_gas.unwrap(),
                    gas_priority_fee: *max_priority_fee_per_gas,
                    gas_limit: gas.unwrap().as_u64(),
                    access_list: to_access_list(access_list.0.clone()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::utils::hex;

    #[test]
    fn can_recover_sender() {
        let bytes = hex::decode("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();

        let tx: TypedTransaction = rlp::decode(&bytes).expect("decoding TypedTransaction failed");
        let tx = match tx {
            TypedTransaction::Legacy(tx) => tx,
            _ => panic!("Invalid typed transaction"),
        };
        assert_eq!(tx.input, b"".into());
        assert_eq!(tx.gas_price, U256::from(0x01u64));
        assert_eq!(tx.gas_limit, U256::from(0x5208u64));
        assert_eq!(tx.nonce, U256::from(0x00u64));
        if let TransactionKind::Call(ref to) = tx.kind {
            assert_eq!(*to, "095e7baea6a6c7c4c2dfeb977efac326af552d87".parse().unwrap());
        } else {
            panic!();
        }
        assert_eq!(tx.value, U256::from(0x0au64));
        assert_eq!(
            tx.recover().unwrap(),
            "0f65fe9276bc9a24ae7083ae28e2660ef72df99e".parse().unwrap()
        );
    }
}
