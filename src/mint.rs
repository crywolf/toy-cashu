use std::collections::BTreeMap;

use anyhow::Result;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Mint {
    #[serde(rename = "mint")]
    url: Url,
    #[serde(skip)]
    info: Option<MintInfo>,
    #[serde(skip, default = "reqwest::blocking::Client::new")]
    http: reqwest::blocking::Client,
}

#[derive(Deserialize)]
pub struct MintInfo {
    pub name: String,
    pub pubkey: String,
}

impl Mint {
    pub fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url)?;
        let c = reqwest::blocking::Client::new();

        Ok(Self {
            url,
            info: None,
            http: c,
        })
    }

    pub fn url(&self) -> String {
        self.url.to_string()
    }

    pub fn get_info(&mut self) -> Result<&MintInfo> {
        if self.info.is_none() {
            let r = self.http.get(self.url.join("/v1/info")?).send()?;
            let info: MintInfo = r.json()?;
            self.info = Some(info);
        }

        Ok(self.info.as_ref().expect("info was downloaded"))
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
    keys: BTreeMap<u64, String>,
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
