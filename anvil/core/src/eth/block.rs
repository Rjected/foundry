use crate::eth::{
    receipt::TypedReceipt,
    transaction::{TransactionInfo, TypedTransaction},
    trie,
};
use ethers_core::{
    types::{Address, Bloom, Bytes, H256, U256, U64},
    utils::{
        keccak256, rlp,
        rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream},
    },
};
use fastrlp::{Encodable as FastEncodable, length_of_length, Decodable as FastDecodable};
use serde::{Deserialize, Serialize};

/// Container type that gathers all block data
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub block: Block,
    pub transactions: Vec<TransactionInfo>,
    pub receipts: Vec<TypedReceipt>,
}

/// ethereum block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<TypedTransaction>,
    pub ommers: Vec<Header>,
}

// == impl Block ==

impl Block {
    pub fn new(
        partial_header: PartialHeader,
        transactions: Vec<TypedTransaction>,
        ommers: Vec<Header>,
    ) -> Self {
        let ommers_hash = H256::from_slice(keccak256(&rlp::encode_list(&ommers)[..]).as_slice());
        let transactions_root =
            trie::ordered_trie_root(transactions.iter().map(|r| rlp::encode(r).freeze()));

        Self {
            header: Header::new(partial_header, ommers_hash, transactions_root),
            transactions,
            ommers,
        }
    }
}

impl Encodable for Block {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.header);
        s.append_list(&self.transactions);
        s.append_list(&self.ommers);
    }
}

impl Decodable for Block {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self { header: rlp.val_at(0)?, transactions: rlp.list_at(1)?, ommers: rlp.list_at(2)? })
    }
}

/// ethereum block header
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: U64,
    /// BaseFee was added by EIP-1559 and is ignored in legacy headers.
    pub base_fee_per_gas: Option<U256>,
}

// == impl Header ==

impl Header {
    pub fn new(partial_header: PartialHeader, ommers_hash: H256, transactions_root: H256) -> Self {
        Self {
            parent_hash: partial_header.parent_hash,
            ommers_hash,
            beneficiary: partial_header.beneficiary,
            state_root: partial_header.state_root,
            transactions_root,
            receipts_root: partial_header.receipts_root,
            logs_bloom: partial_header.logs_bloom,
            difficulty: partial_header.difficulty,
            number: partial_header.number,
            gas_limit: partial_header.gas_limit,
            gas_used: partial_header.gas_used,
            timestamp: partial_header.timestamp,
            extra_data: partial_header.extra_data,
            mix_hash: partial_header.mix_hash,
            nonce: partial_header.nonce,
            base_fee_per_gas: partial_header.base_fee,
        }
    }

    pub fn hash(&self) -> H256 {
        H256::from_slice(keccak256(&rlp::encode(self)).as_slice())
    }

    /// Returns the rlp length of the Header body, _not including_ trailing EIP155 fields or the
    /// rlp list header
    /// To get the length including the rlp list header, refer to the Encodable implementation.
    pub(crate) fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length();
        length += self.ommers_hash.length();
        length += self.beneficiary.length();
        length += self.state_root.length();
        length += self.transactions_root.length();
        length += self.receipts_root.length();
        length += self.logs_bloom.length();
        length += self.difficulty.length();
        length += self.number.length();
        length += self.gas_limit.length();
        length += self.gas_used.length();
        length += self.timestamp.length();
        length += self.extra_data.length();
        length += self.mix_hash.length();
        length += self.nonce.length();
        length += match self.base_fee_per_gas {
            Some(base_fee_per_gas) => base_fee_per_gas.length(),
            None => 0,
        };
        length
    }
}

impl rlp::Encodable for Header {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(15);
        s.append(&self.parent_hash);
        s.append(&self.ommers_hash);
        s.append(&self.beneficiary);
        s.append(&self.state_root);
        s.append(&self.transactions_root);
        s.append(&self.receipts_root);
        s.append(&self.logs_bloom);
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);
        s.append(&self.extra_data.as_ref());
        s.append(&self.mix_hash);
        s.append(&self.nonce);
        if let Some(ref base_fee) = self.base_fee_per_gas {
            s.append(base_fee);
        }
    }
}

impl rlp::Decodable for Header {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let result = Header {
            parent_hash: rlp.val_at(0)?,
            ommers_hash: rlp.val_at(1)?,
            beneficiary: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            logs_bloom: rlp.val_at(6)?,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at::<Vec<u8>>(12)?.into(),
            mix_hash: rlp.val_at(13)?,
            nonce: rlp.val_at(14)?,
            base_fee_per_gas: if let Ok(base_fee) = rlp.at(15) {
                Some(<U256 as Decodable>::decode(&base_fee)?)
            } else {
                None
            },
        };
        Ok(result)
    }
}

impl fastrlp::Encodable for Header {
    fn length(&self) -> usize {
        // add each of the fields' rlp encoded lengths
        let mut length = 0;
        length += self.header_payload_length();

        // header would encode length_of_length + 1 bytes
        length += if length > 55 { 1 + length_of_length(length) } else { 1 };

        length
    }

    fn encode(&self, out: &mut dyn fastrlp::BufMut) {
        let list_header = fastrlp::Header { list: true, payload_length: self.header_payload_length() };
        list_header.encode(out);
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        self.difficulty.encode(out);
        self.number.encode(out);
        self.gas_limit.encode(out);
        self.gas_used.encode(out);
        self.timestamp.encode(out);
        self.extra_data.encode(out);
        self.mix_hash.encode(out);
        self.nonce.encode(out);
        if let Some(base_fee_per_gas) = self.base_fee_per_gas {
            base_fee_per_gas.encode(out);
        }
    }
}

impl fastrlp::Decodable for Header {
    fn decode(buf: &mut &[u8]) -> Result<Self, fastrlp::DecodeError> {
        // slice out the rlp list header
        let _header = fastrlp::Header::decode(buf)?;

        Ok(Self {
            parent_hash: <H256 as FastDecodable>::decode(buf)?,
            ommers_hash: <H256 as FastDecodable>::decode(buf)?,
            beneficiary: <Address as FastDecodable>::decode(buf)?,
            state_root: <H256 as FastDecodable>::decode(buf)?,
            transactions_root: <H256 as FastDecodable>::decode(buf)?,
            receipts_root: <H256 as FastDecodable>::decode(buf)?,
            logs_bloom: <Bloom as FastDecodable>::decode(buf)?,
            difficulty: <U256 as FastDecodable>::decode(buf)?,
            number: <U256 as FastDecodable>::decode(buf)?,
            gas_limit: <U256 as FastDecodable>::decode(buf)?,
            gas_used: <U256 as FastDecodable>::decode(buf)?,
            timestamp: <u64 as FastDecodable>::decode(buf)?,
            extra_data: <Bytes as FastDecodable>::decode(buf)?,
            mix_hash: <H256 as FastDecodable>::decode(buf)?,
            nonce: <U64 as FastDecodable>::decode(buf)?,
            base_fee_per_gas: if let Ok(base_fee) = <U256 as FastDecodable>::decode(buf) {
                Some(base_fee)
            } else {
                None
            }
        })
    }
}

/// Partial header definition without ommers hash and transactions root
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PartialHeader {
    pub parent_hash: H256,
    pub beneficiary: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: U64,
    pub base_fee: Option<U256>,
}

impl From<Header> for PartialHeader {
    fn from(header: Header) -> PartialHeader {
        Self {
            parent_hash: header.parent_hash,
            beneficiary: header.beneficiary,
            state_root: header.state_root,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom,
            difficulty: header.difficulty,
            number: header.number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            extra_data: header.extra_data,
            mix_hash: header.mix_hash,
            nonce: header.nonce,
            base_fee: header.base_fee_per_gas,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rlp_roundtrip() {
        let mut header = Header {
            parent_hash: Default::default(),
            ommers_hash: Default::default(),
            beneficiary: Default::default(),
            state_root: Default::default(),
            transactions_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: Default::default(),
            difficulty: Default::default(),
            number: 124u64.into(),
            gas_limit: Default::default(),
            gas_used: 1337u64.into(),
            timestamp: 0,
            extra_data: Default::default(),
            mix_hash: Default::default(),
            nonce: 99u64.into(),
            base_fee_per_gas: None,
        };

        let encoded = rlp::encode(&header);
        let decoded: Header = rlp::decode(encoded.as_ref()).unwrap();
        assert_eq!(header, decoded);

        header.base_fee_per_gas = Some(12345u64.into());

        let encoded = rlp::encode(&header);
        let decoded: Header = rlp::decode(encoded.as_ref()).unwrap();
        assert_eq!(header, decoded);
    }
}
