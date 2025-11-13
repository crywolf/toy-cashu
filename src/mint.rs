use std::collections::HashMap;

use anyhow::{Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::cashu::{
    BlindSignatures, BlindedMessage, Proof,
    types::{Keys, Keysets, MintQuote},
};

/// Mint object represents remote mint. Used by [`super::Wallet`] to communicate with mint server specified by its `url`.
#[derive(Deserialize, Serialize)]
pub struct Mint {
    #[serde(rename = "mint")]
    url: Url,
    #[serde(skip)]
    info: Option<MintInfo>,
    #[serde(skip, default = "reqwest::blocking::Client::new")]
    http: reqwest::blocking::Client,
}

#[derive(Clone, Deserialize)]
pub struct MintInfo {
    pub name: String,
    #[serde(skip)]
    pub url: String,
    pub pubkey: String,
    pub version: String,
    pub nuts: HashMap<u16, Nut>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Nut {
    #[serde(default)]
    supported: serde_json::Value,
    #[serde(default)]
    disabled: bool,
}

impl Nut {
    /// Is NUT supported by mint and not disabled?
    pub fn is_active(&self) -> bool {
        !self.disabled && self.supported != serde_json::Value::Bool(false)
    }
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

    /// NUT-06: Mint information
    pub fn get_info(&mut self) -> Result<&MintInfo> {
        if self.info.is_none() {
            let r = self.http.get(self.url.join("/v1/info")?).send()?;
            let info: MintInfo = r.json()?;
            self.info = Some(info);
        }

        Ok(self.info.as_ref().expect("info was downloaded"))
    }

    /// NUT-01: Mint public key exchange
    pub fn get_keys(&self) -> Result<Keys> {
        let r = self.http.get(self.url.join("/v1/keys")?).send()?;
        let keys: Keys = r.json()?;
        Ok(keys)
    }

    /// NUT-02: Keysets and fees
    pub fn get_keysets(&self) -> Result<Keysets> {
        let r = self.http.get(self.url.join("/v1/keysets")?).send()?;
        let keysets: Keysets = r.json()?;
        Ok(keysets)
    }

    /// NUT-23: BOLT11
    pub fn create_mint_quote(&self, amount: u64) -> Result<MintQuote> {
        #[derive(Serialize)]
        struct QuoteRequest {
            amount: u64,
            unit: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            pubkey: Option<String>,
        }

        let payment_method = "bolt11";
        let req = QuoteRequest {
            amount,
            unit: "sat".to_owned(),
            pubkey: None,
        };

        let r = self
            .http
            .post(self.url.join(&format!("/v1/mint/quote/{payment_method}"))?)
            .json(&req)
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }

    pub fn get_mint_quote(&self, quote_id: &str) -> Result<MintQuote> {
        let payment_method = "bolt11";

        let r = self
            .http
            .get(
                self.url
                    .join(&format!("/v1/mint/quote/{payment_method}/{quote_id}"))?,
            )
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }

    // NUT-04: Mint tokens
    pub fn do_minting(
        &self,
        quote_id: String,
        outputs: Vec<BlindedMessage>,
    ) -> Result<BlindSignatures> {
        #[derive(Serialize)]
        struct MintRequest {
            quote: String,
            outputs: Vec<BlindedMessage>,
        }

        let payment_method = "bolt11";
        let req = MintRequest {
            quote: quote_id,
            outputs,
        };

        let r = self
            .http
            .post(self.url.join(&format!("/v1/mint/{payment_method}"))?)
            .json(&req)
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }

    // NUT-03: Swap tokens
    pub fn do_swap(&self, inputs: &[Proof], outputs: &[BlindedMessage]) -> Result<BlindSignatures> {
        #[derive(Serialize)]
        struct SwapRequest<'a> {
            inputs: &'a [Proof],
            outputs: &'a [BlindedMessage],
        }

        let req = SwapRequest { inputs, outputs };

        let r = self
            .http
            .post(self.url.join("/v1/swap")?)
            .json(&req)
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }
}
