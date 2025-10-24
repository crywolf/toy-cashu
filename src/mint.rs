use std::collections::HashMap;

use anyhow::{Ok, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Mint {
    #[serde(rename = "mint")]
    url: Url,
    #[serde(skip, default = "reqwest::blocking::Client::new")]
    http: reqwest::blocking::Client,
}

impl Mint {
    pub fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url)?;
        let c = reqwest::blocking::Client::new();

        Ok(Self { url, http: c })
    }

    pub fn url(&self) -> String {
        self.url.to_string()
    }

    pub fn get_info(&self) -> Result<String> {
        let r = self.http.get(self.url.join("/v1/info")?).send()?;
        let info = r.text()?;
        Ok(info)
    }

    pub fn get_keys(&self) -> Result<Keys> {
        let r = self.http.get(self.url.join("/v1/keys")?).send()?;
        let keys: Keys = r.json()?;
        Ok(keys)
    }

    pub fn get_keysets(&self) -> Result<Keysets> {
        let r = self.http.get(self.url.join("/v1/keysets")?).send()?;
        let keysets: Keysets = r.json()?;
        Ok(keysets)
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Keys {
    keysets: Vec<Keyset>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Keyset {
    id: String,
    unit: String,
    keys: HashMap<u64, String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Keysets {
    keysets: Vec<KeysetInfo>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct KeysetInfo {
    id: String,
    unit: String,
    active: bool,
    #[serde(default)]
    input_fee_ppk: u64,
}
