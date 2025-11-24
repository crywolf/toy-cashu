use std::collections::HashMap;

use anyhow::{Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::cashu::{
    BlindSignatures, BlindedMessage, Proof,
    crypto::PublicKey,
    types::{Keys, Keysets, MeltQuote, MintQuote},
};

/// Mint object represents remote mint. Used by [`super::Wallet`] to communicate with mint server specified by its `url`.
#[derive(Deserialize, Serialize)]
pub struct Mint {
    #[serde(rename = "mint")]
    url: Url,
    #[serde(skip)]
    info: Option<MintInfo>,
    #[serde(skip)]
    keys: Option<Keys>,
    #[serde(skip)]
    keysets: Option<Keysets>,
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
            keys: None,
            keysets: None,
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
    pub fn get_keys(&mut self) -> Result<&Keys> {
        if self.keys.is_none() {
            let r = self.http.get(self.url.join("/v1/keys")?).send()?;
            let keys: Keys = r.json()?;
            self.keys = Some(keys);
        }

        Ok(self.keys.as_ref().expect("keys were downloaded"))
    }

    /// NUT-02: Keysets and fees
    pub fn get_keysets(&mut self) -> Result<&Keysets> {
        if self.keysets.is_none() {
            let r = self.http.get(self.url.join("/v1/keysets")?).send()?;
            let keysets: Keysets = r.json()?;
            self.keysets = Some(keysets);
        }
        Ok(self.keysets.as_ref().expect("keysets were downloaded"))
    }

    /// NUT-23: BOLT11
    pub fn create_mint_quote(&self, amount: u64, pubkey: PublicKey) -> Result<MintQuote> {
        #[derive(Serialize)]
        struct QuoteRequest {
            amount: u64,
            unit: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            pubkey: Option<String>, // NUT-20: Signature on Mint Quote
        }

        let payment_method = "bolt11";
        let req = QuoteRequest {
            amount,
            unit: "sat".to_owned(),
            pubkey: Some(pubkey.to_hex()),
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
        quote_id: &str,
        outputs: &[BlindedMessage],
        signature: &str,
    ) -> Result<BlindSignatures> {
        #[derive(Serialize)]
        struct MintRequest<'a> {
            quote: &'a str,
            outputs: &'a [BlindedMessage],
            signature: String, // NUT-20: Signature on Mint Quote
        }

        let payment_method = "bolt11";
        let req = MintRequest {
            quote: quote_id,
            outputs,
            signature: signature.to_owned(),
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

    /// NUT-23: BOLT11
    pub fn create_melt_quote(&self, invoice: &str) -> Result<MeltQuote> {
        #[derive(Serialize)]
        struct QuoteRequest<'a> {
            request: &'a str,
            unit: &'a str,
        }

        let payment_method = "bolt11";
        let req = QuoteRequest {
            request: invoice,
            unit: "sat",
        };

        let r = self
            .http
            .post(self.url.join(&format!("/v1/melt/quote/{payment_method}"))?)
            .json(&req)
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }

    // NUT-05: Melt tokens
    pub fn do_melting(
        &self,
        quote_id: &str,
        proofs: &[Proof],
        blank_outputs: &[BlindedMessage],
    ) -> Result<MeltQuote> {
        #[derive(Serialize)]
        struct MeltRequest<'a> {
            quote: &'a str,
            inputs: &'a [Proof],
            outputs: &'a [BlindedMessage],
        }

        let payment_method = "bolt11";
        let req = MeltRequest {
            quote: quote_id,
            inputs: proofs,
            outputs: blank_outputs,
        };

        let r = self
            .http
            .post(self.url.join(&format!("/v1/melt/{payment_method}"))?)
            .json(&req)
            .send()?;

        if r.status().is_success() {
            Ok(r.json()?)
        } else {
            bail!("Response: {} \n  {}", r.status(), r.text()?);
        }
    }
}
