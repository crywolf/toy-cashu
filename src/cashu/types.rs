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

#[derive(Debug, Deserialize)]
pub struct Keys {
    keysets: Vec<Keyset>,
}

impl Keys {
    pub fn by_id(self, id: String) -> Option<Keyset> {
        self.keysets.into_iter().find(|ks| ks.id == id)
    }
}

#[expect(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Keyset {
    pub id: String,
    pub unit: String,
    pub keys: BTreeMap<u64, String>,
}

#[derive(Debug, Deserialize)]
pub struct Keysets {
    pub keysets: Vec<KeysetInfo>,
}

#[expect(dead_code)]
#[derive(Debug, Deserialize)]
pub struct KeysetInfo {
    pub id: String,
    pub unit: String,
    pub active: bool,
    #[serde(default)]
    pub input_fee_ppk: u64,
}
