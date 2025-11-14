use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MintQuote {
    pub quote: String,
    pub request: String,
    pub amount: u64,
    pub unit: String,
    pub state: QuoteState,
    pub pubkey: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QuoteState {
    Unpaid,
    Paid,
    Issued,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Keys {
    keysets: Vec<Keyset>,
}

impl Keys {
    pub fn by_id(self, id: &str) -> Option<Keyset> {
        self.keysets.into_iter().find(|ks| ks.id == id)
    }
}

#[expect(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Keyset {
    pub id: String,
    pub unit: String,
    pub keys: BTreeMap<u64, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Keysets {
    pub keysets: Vec<KeysetInfo>,
}

impl Keysets {
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
