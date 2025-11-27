use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cashu::{BlindSignature, BlindedMessage, crypto::SecretKey};

/// Public keys for a set of amounts
pub type AmountKeys = BTreeMap<u64, String>;

#[derive(Debug, Serialize, Deserialize)]
pub struct MintQuote {
    pub quote: String,
    pub request: String,
    pub amount: u64,
    pub unit: String,
    pub state: QuoteState,
    pub pubkey: Option<String>,
}

impl MintQuote {
    /// Returns Schnorr signature according to NUT-20 using `secret_key`
    pub fn sign(&self, outputs: &[BlindedMessage], secret_key: SecretKey) -> String {
        let mut msg = String::from(&self.quote);

        let bs: Vec<String> = outputs.iter().map(|m| m.b_.0.clone()).collect();

        msg.push_str(&bs.join(""));

        let signature = secret_key.sign_mint_quote(&msg);
        hex::encode(signature)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MeltQuote {
    pub quote: String,
    pub request: String,
    pub amount: u64,
    pub unit: String,
    pub state: QuoteState,
    pub fee_reserve: u64,
    pub payment_preimage: Option<String>,
    #[serde(skip_serializing)]
    pub change: Option<Vec<BlindSignature>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QuoteState {
    Unpaid,
    Paid,
    Issued,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllKeysets {
    keysets: Vec<Keyset>,
}

impl AllKeysets {
    pub fn by_id(self, id: &str) -> Option<Keyset> {
        self.keysets.into_iter().find(|ks| ks.id == id)
    }
}

#[expect(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Keyset {
    pub id: String,
    pub unit: String,
    pub keys: AmountKeys,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllKeysetInfos {
    pub keysets: Vec<KeysetInfo>,
}

impl AllKeysetInfos {
    pub fn for_unit(self, unit: &str) -> Option<KeysetInfo> {
        self.keysets.into_iter().find(|s| s.unit == unit)
    }

    pub fn by_id(self, id: &str) -> Option<KeysetInfo> {
        self.keysets.into_iter().find(|ks| ks.id == id)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeysetInfo {
    pub id: String,
    pub unit: String,
    pub active: bool,
    #[serde(default)]
    pub input_fee_ppk: u64,
}
