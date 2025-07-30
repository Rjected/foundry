use crate::traces::identifier::SignaturesIdentifier;
use alloy_consensus::Transaction;
use alloy_network::{AnyHeader, AnyRpcTransaction, TransactionResponse};
use alloy_primitives::{Address, FixedBytes, U256, hex, utils::format_ether};
use alloy_rpc_types::{Block, BlockTransactions, Header};
use comfy_table::{Attribute, Cell, Color, Table};
use eyre::Result;
use foundry_common::fmt::UIfmt;
use std::{cmp::Ordering, collections::HashMap, str::FromStr};

/// Field to sort transactions by
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSortField {
    GasUsed,
    GasPrice,
    Value,
    Nonce,
    Index,
}

impl FromStr for TxSortField {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gas-used" => Ok(Self::GasUsed),
            "gas-price" => Ok(Self::GasPrice),
            "value" => Ok(Self::Value),
            "nonce" => Ok(Self::Nonce),
            "index" => Ok(Self::Index),
            _ => Err(eyre::eyre!(
                "Invalid sort field: {}. Valid options are: gas-used, gas-price, value, nonce, index",
                s
            )),
        }
    }
}

impl std::fmt::Display for TxSortField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GasUsed => write!(f, "gas-used"),
            Self::GasPrice => write!(f, "gas-price"),
            Self::Value => write!(f, "value"),
            Self::Nonce => write!(f, "nonce"),
            Self::Index => write!(f, "index"),
        }
    }
}

/// Filter operator for transaction filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Gt,
    Lt,
}

/// Filter expression for transactions
#[derive(Debug, Clone)]
pub struct TxFilter {
    pub field: TxFilterField,
    pub op: FilterOp,
    pub value: FilterValue,
}

/// Field that can be filtered
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFilterField {
    GasUsed,
    GasPrice,
    Value,
    Nonce,
    From,
    To,
}

/// Value for filtering
#[derive(Debug, Clone)]
pub enum FilterValue {
    Number(u128),
    Address(Address),
}

impl FromStr for TxFilter {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse expressions like "gas>100000" or "to=0x..."
        let (field_str, op, value_str) = if let Some(pos) = s.find('=') {
            (&s[..pos], FilterOp::Eq, &s[pos + 1..])
        } else if let Some(pos) = s.find('>') {
            (&s[..pos], FilterOp::Gt, &s[pos + 1..])
        } else if let Some(pos) = s.find('<') {
            (&s[..pos], FilterOp::Lt, &s[pos + 1..])
        } else {
            return Err(eyre::eyre!(
                "Invalid filter expression: {}. Expected format: field{{=|>|<}}value",
                s
            ));
        };

        let field = match field_str {
            "gas" | "gas-used" => TxFilterField::GasUsed,
            "gas-price" => TxFilterField::GasPrice,
            "value" => TxFilterField::Value,
            "nonce" => TxFilterField::Nonce,
            "from" => TxFilterField::From,
            "to" => TxFilterField::To,
            _ => return Err(eyre::eyre!("Invalid filter field: {}", field_str)),
        };

        let value = match field {
            TxFilterField::From | TxFilterField::To => {
                FilterValue::Address(Address::from_str(value_str)?)
            }
            _ => FilterValue::Number(value_str.parse()?),
        };

        Ok(TxFilter { field, op, value })
    }
}

pub struct TransactionAnalyzer;

impl TransactionAnalyzer {
    /// Format ETH value without trailing zeros
    fn format_ether_pretty(value: U256) -> String {
        let formatted = format_ether(value);
        // Remove trailing zeros after decimal point
        if formatted.contains('.') {
            let trimmed = formatted.trim_end_matches('0').trim_end_matches('.');
            if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
        } else {
            formatted
        }
    }
    /// Sort transactions based on the specified field
    pub fn sort_transactions(
        txs: &mut [AnyRpcTransaction],
        sort_by: TxSortField,
        reverse: bool,
        receipt_gas_used: &HashMap<alloy_primitives::TxHash, u128>,
    ) {
        let cmp_fn: Box<dyn Fn(&AnyRpcTransaction, &AnyRpcTransaction) -> Ordering> = match sort_by
        {
            TxSortField::GasUsed => Box::new(|a, b| {
                // Use actual gas used from receipts when available
                let a_gas = receipt_gas_used
                    .get(&a.tx_hash())
                    .copied()
                    .unwrap_or_else(|| a.gas_limit() as u128);
                let b_gas = receipt_gas_used
                    .get(&b.tx_hash())
                    .copied()
                    .unwrap_or_else(|| b.gas_limit() as u128);
                a_gas.cmp(&b_gas)
            }),
            TxSortField::GasPrice => Box::new(|a, b| {
                let a_price = a.effective_gas_price.unwrap_or(0);
                let b_price = b.effective_gas_price.unwrap_or(0);
                a_price.cmp(&b_price)
            }),
            TxSortField::Value => Box::new(|a, b| a.value().cmp(&b.value())),
            TxSortField::Nonce => Box::new(|a, b| a.nonce().cmp(&b.nonce())),
            TxSortField::Index => Box::new(|a, b| {
                a.transaction_index.unwrap_or(0).cmp(&b.transaction_index.unwrap_or(0))
            }),
        };

        if reverse {
            txs.sort_by(|a, b| cmp_fn(b, a));
        } else {
            txs.sort_by(|a, b| cmp_fn(a, b));
        }
    }

    /// Filter transactions based on the given filter
    pub fn filter_transactions(
        txs: Vec<AnyRpcTransaction>,
        filter: &TxFilter,
        receipt_gas_used: &HashMap<alloy_primitives::TxHash, u128>,
    ) -> Vec<AnyRpcTransaction> {
        txs.into_iter()
            .filter(|tx| match (&filter.field, &filter.value) {
                (TxFilterField::GasUsed, FilterValue::Number(value)) => {
                    let gas = receipt_gas_used
                        .get(&tx.tx_hash())
                        .copied()
                        .unwrap_or_else(|| tx.gas_limit() as u128);
                    match filter.op {
                        FilterOp::Gt => gas > *value,
                        FilterOp::Lt => gas < *value,
                        FilterOp::Eq => gas == *value,
                    }
                }
                (TxFilterField::GasPrice, FilterValue::Number(value)) => {
                    let price = tx.effective_gas_price.unwrap_or(0) as u128;
                    match filter.op {
                        FilterOp::Gt => price > *value,
                        FilterOp::Lt => price < *value,
                        FilterOp::Eq => price == *value,
                    }
                }
                (TxFilterField::Value, FilterValue::Number(value)) => {
                    let tx_value = U256::from(*value);
                    match filter.op {
                        FilterOp::Gt => tx.value() > tx_value,
                        FilterOp::Lt => tx.value() < tx_value,
                        FilterOp::Eq => tx.value() == tx_value,
                    }
                }
                (TxFilterField::Nonce, FilterValue::Number(value)) => {
                    let nonce = tx.nonce() as u128;
                    match filter.op {
                        FilterOp::Gt => nonce > *value,
                        FilterOp::Lt => nonce < *value,
                        FilterOp::Eq => nonce == *value,
                    }
                }
                (TxFilterField::From, FilterValue::Address(addr)) => {
                    matches!(filter.op, FilterOp::Eq) && tx.from() == *addr
                }
                (TxFilterField::To, FilterValue::Address(addr)) => {
                    matches!(filter.op, FilterOp::Eq) && tx.to().map_or(false, |to| to == *addr)
                }
                _ => false,
            })
            .collect()
    }

    /// Extract transactions from block data
    pub fn extract_transactions(
        block_txs: &BlockTransactions<AnyRpcTransaction>,
    ) -> Vec<AnyRpcTransaction> {
        match block_txs {
            BlockTransactions::Full(txs) => txs.clone(),
            _ => vec![],
        }
    }

    /// Format transactions as a pretty table
    pub async fn format_pretty_table(
        block: &Block<AnyRpcTransaction, Header<AnyHeader>>,
        mut transactions: Vec<AnyRpcTransaction>,
        receipt_gas_used: HashMap<alloy_primitives::TxHash, u128>,
        sort_by: Option<TxSortField>,
        filter: Option<TxFilter>,
        limit: Option<usize>,
        reverse: bool,
        no_truncate: bool,
        decode: bool,
    ) -> Result<String> {
        // Apply filter if specified
        if let Some(filter) = filter.as_ref() {
            transactions = Self::filter_transactions(transactions, filter, &receipt_gas_used);
        }

        // Apply sorting if specified
        if let Some(sort_field) = sort_by {
            Self::sort_transactions(&mut transactions, sort_field, reverse, &receipt_gas_used);
        }

        // Apply limit if specified
        if let Some(limit) = limit {
            transactions.truncate(limit);
        }

        // Create table
        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("Tx Hash").add_attribute(Attribute::Bold),
            Cell::new("From").add_attribute(Attribute::Bold),
            Cell::new("To").add_attribute(Attribute::Bold),
            Cell::new("Value (ETH)").add_attribute(Attribute::Bold),
            Cell::new("Gas Used").add_attribute(Attribute::Bold),
            Cell::new("Gas Price (Gwei)").add_attribute(Attribute::Bold),
            Cell::new("Fee (ETH)").add_attribute(Attribute::Bold),
            Cell::new("Method").add_attribute(Attribute::Bold),
        ]);

        // Batch decode all selectors if requested
        let mut decoded_selectors = HashMap::new();
        if decode {
            if let Ok(identifier) = SignaturesIdentifier::new(false) {
                // Collect unique selectors
                let mut unique_selectors = Vec::new();
                for tx in &transactions {
                    if tx.input().len() >= 4 {
                        if let Ok(selector) = FixedBytes::<4>::try_from(&tx.input()[..4]) {
                            if !decoded_selectors.contains_key(&selector) {
                                unique_selectors.push(selector);
                            }
                        }
                    }
                }

                // Decode all unique selectors in parallel
                for selector in unique_selectors {
                    if let Some(function) = identifier.identify_function(selector).await {
                        decoded_selectors.insert(selector, function.signature());
                    }
                }
            }
        }

        // Calculate statistics
        let mut total_gas_used = U256::ZERO;
        let mut total_value = U256::ZERO;
        let mut total_fees = U256::ZERO;

        for tx in &transactions {
            let tx_hash = if no_truncate {
                format!("{}", tx.tx_hash())
            } else {
                format!("{:?}", tx.tx_hash())
            };
            let from =
                if no_truncate { format!("{}", tx.from()) } else { format!("{:?}", tx.from()) };
            let to = tx.to().map_or(String::from("Contract Creation"), |addr| {
                if no_truncate { format!("{}", addr) } else { format!("{:?}", addr) }
            });

            // Format value in ETH
            let value_eth = Self::format_ether_pretty(tx.value());

            // Gas price in Gwei
            let gas_price_gwei = if let Some(gas_price) = <_ as TransactionResponse>::gas_price(tx)
            {
                // Convert from wei to gwei (1 gwei = 1e9 wei)
                let gwei = U256::from(gas_price) / U256::from(1_000_000_000u64);
                gwei.to_string()
            } else if let (Some(max_fee), Some(max_priority_fee)) = (
                <_ as TransactionResponse>::max_fee_per_gas(tx),
                <_ as Transaction>::max_priority_fee_per_gas(tx),
            ) {
                // For EIP-1559 transactions, estimate effective gas price
                let base_fee = block.header.base_fee_per_gas.unwrap_or_default();
                let effective_gas_price =
                    std::cmp::min(max_fee, base_fee as u128 + max_priority_fee);
                let gwei = U256::from(effective_gas_price) / U256::from(1_000_000_000u64);
                gwei.to_string()
            } else {
                "0".to_string()
            };

            // Get actual gas used from receipt, fallback to gas limit
            let gas_used = receipt_gas_used
                .get(&tx.tx_hash())
                .map(|g| g.to_string())
                .unwrap_or_else(|| tx.gas_limit().to_string());

            // Calculate fee using actual gas used from receipt
            let gas_for_fee = receipt_gas_used
                .get(&tx.tx_hash())
                .map(|g| U256::from(*g))
                .unwrap_or_else(|| U256::from(tx.gas_limit()));

            let fee = if let Some(gas_price) = <_ as TransactionResponse>::gas_price(tx) {
                gas_for_fee * U256::from(gas_price)
            } else if let (Some(max_fee), Some(max_priority_fee)) = (
                <_ as TransactionResponse>::max_fee_per_gas(tx),
                <_ as Transaction>::max_priority_fee_per_gas(tx),
            ) {
                let base_fee = block.header.base_fee_per_gas.unwrap_or_default();
                let effective_gas_price =
                    std::cmp::min(max_fee, base_fee as u128 + max_priority_fee);
                gas_for_fee * U256::from(effective_gas_price)
            } else {
                U256::ZERO
            };
            let fee_eth = Self::format_ether_pretty(fee);

            // Extract method selector (first 4 bytes of input)
            let method = if tx.input().len() >= 4 {
                let selector_bytes = &tx.input()[..4];
                let selector_hex = format!("0x{}", hex::encode(selector_bytes));

                if decode {
                    // Check if we have a decoded signature for this selector
                    if let Ok(selector) = FixedBytes::<4>::try_from(selector_bytes) {
                        decoded_selectors.get(&selector).cloned().unwrap_or(selector_hex)
                    } else {
                        selector_hex
                    }
                } else {
                    selector_hex
                }
            } else if tx.input().is_empty() {
                "Transfer".to_string()
            } else {
                "Unknown".to_string()
            };

            // Update statistics with actual gas used
            let actual_gas = receipt_gas_used
                .get(&tx.tx_hash())
                .map(|g| U256::from(*g))
                .unwrap_or_else(|| U256::from(tx.gas_limit()));
            total_gas_used += actual_gas;
            total_value += tx.value();
            total_fees += fee;

            table.add_row(vec![
                Cell::new(tx_hash),
                Cell::new(from),
                Cell::new(to),
                Cell::new(value_eth),
                Cell::new(gas_used),
                Cell::new(gas_price_gwei),
                Cell::new(fee_eth),
                Cell::new(method),
            ]);
        }

        // Add summary row
        table.add_row(vec![
            Cell::new("").add_attribute(Attribute::Bold),
            Cell::new("").add_attribute(Attribute::Bold),
            Cell::new("TOTAL:").add_attribute(Attribute::Bold).fg(Color::Green),
            Cell::new(Self::format_ether_pretty(total_value))
                .add_attribute(Attribute::Bold)
                .fg(Color::Green),
            Cell::new(total_gas_used.to_string()).add_attribute(Attribute::Bold).fg(Color::Green),
            Cell::new("").add_attribute(Attribute::Bold),
            Cell::new(Self::format_ether_pretty(total_fees))
                .add_attribute(Attribute::Bold)
                .fg(Color::Green),
            Cell::new(format!("{} txs", transactions.len()))
                .add_attribute(Attribute::Bold)
                .fg(Color::Green),
        ]);

        // Get the full block pretty output and extract just the header part
        let block_pretty = block.pretty();
        let header_end = block_pretty.find("transactions:").unwrap_or(block_pretty.len());
        let block_header = block_pretty[..header_end].trim();

        let mut result = String::new();
        result.push_str(&format!("{}\n", block_header));

        // Add our custom transactions header
        result.push_str(&format!("transactions:        {} total", transactions.len()));
        if let Some(sort_field) = sort_by {
            result.push_str(&format!(
                " (sorted by {}{})",
                sort_field,
                if reverse { " desc" } else { "" }
            ));
        }
        if filter.is_some() {
            result.push_str(&format!(" [filtered]"));
        }
        result.push_str(&format!("\n\n{}", table));

        Ok(result)
    }
}
