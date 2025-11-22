use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::{
    cashu::types::MeltQuote,
    mint::{Mint, MintInfo},
};
use crate::{
    cashu::{
        BlindedMessage, BlindedSecret, Proof, TokenV4,
        crypto::{PublicKey, Secret, SecretKey},
        types::{Keys, Keysets, MintQuote, QuoteState},
    },
    file, helpers,
};

const WALLETS_DIR: &str = ".wallets";
const WALLET_FILE_EXT: &str = ".bin";

#[derive(Deserialize, Serialize)]
pub struct Wallet {
    pub name: String,
    #[serde(flatten)]
    mint: Mint,
    proofs: Vec<Proof>,
    #[serde(skip)]
    mint_quotes: Vec<MintQuote>,
    #[serde(skip)]
    encryption_key: [u8; 32],
}

impl Wallet {
    pub fn names_list() -> Result<Vec<String>> {
        let path = Path::new(WALLETS_DIR);

        let mut wallet_names = path
            .read_dir()
            .context("read_dir call failed")?
            .flatten()
            .filter_map(|entry| {
                let filename = entry.file_name().into_string().unwrap_or("???".to_string());

                if filename.ends_with(WALLET_FILE_EXT) {
                    let wallet_name = filename
                        .strip_suffix(WALLET_FILE_EXT)
                        .unwrap_or("???")
                        .to_string();
                    Some(wallet_name)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        wallet_names.sort();

        Ok(wallet_names)
    }

    pub fn create(name: &str, mint: &str, password: &str) -> Result<Self> {
        let file = PathBuf::from(WALLETS_DIR).join(Self::filename(name));

        if file.exists() {
            bail!("Wallet {} already exists!", name);
        }

        password::save(name, password)?;

        let encryption_key = password::derive_encryption_key(password, name)?;

        let w = Self {
            name: name.to_owned(),
            mint: Mint::new(mint)?,
            proofs: Default::default(),
            mint_quotes: Default::default(),
            encryption_key,
        };

        w.save()
            .with_context(|| format!("save newly created wallet '{}'", name))?;

        Ok(w)
    }

    pub fn open(name: &str, password: &str) -> Result<Self> {
        let file = PathBuf::from(WALLETS_DIR).join(Self::filename(name));

        if !file.exists() {
            bail!("Wallet {} does not exist!", name);
        }

        if !password::is_valid_for_wallet(password, name).context("validate password")? {
            bail!("Invalid password!");
        }

        let w = Self::load(name, password).with_context(|| format!("load wallet {}", name))?;
        // TODO check mint quotes
        Ok(w)
    }

    pub fn mint_url(&self) -> String {
        self.mint.url()
    }

    pub fn mint_info(&mut self) -> Result<MintInfo> {
        let mut info = self.mint.get_info().cloned()?;
        info.url = self.mint_url();
        Ok(info)
    }

    pub fn mint_keys(&mut self) -> Result<Keys> {
        self.mint.get_keys().cloned()
    }

    pub fn mint_keysets(&mut self, only_active: bool) -> Result<Keysets> {
        let mut ks = self.mint.get_keysets().cloned().context("get_keysets")?;
        if only_active {
            let ks_vec = ks
                .keysets
                .into_iter()
                .filter(|s| s.active)
                .collect::<Vec<_>>();
            ks.keysets = ks_vec;
        }
        Ok(ks)
    }

    pub fn balance(&self) -> u64 {
        self.proofs.iter().fold(0, |acc, x| acc + x.amount)
    }

    pub fn proofs(&self) -> std::slice::Iter<'_, Proof> {
        self.proofs.iter()
    }

    pub fn mint_tokens(&mut self, amount: u64) -> Result<Vec<u64>> {
        let quote = self.create_mint_quote(amount)?;

        let quote_id = quote.quote.clone();
        let unit = quote.unit.clone();

        // TODO store quote and request the mint later for its state
        self.mint_quotes.push(quote);

        // TODO loop
        let quote = self.check_mint_quote(&quote_id)?;
        let invoice_state = quote.state;

        if invoice_state == QuoteState::Issued {
            bail!("Tokens from the quote {} were already issued", quote_id);
        }

        if invoice_state == QuoteState::Paid {
            let amounts = Self::split_amount(amount);

            let active_keyset_info = self
                .mint_keysets(true)?
                .for_unit(&unit)
                .ok_or_else(|| anyhow!("No active keyset for '{}'", unit))?;
            let keyset_id = active_keyset_info.id;

            let active_keyset = self
                .mint_keys()?
                .by_id(&keyset_id)
                .ok_or_else(|| anyhow!("Mint did not provided active keys"))?;

            let active_keys = active_keyset.keys;

            let mut outputs = vec![];
            let mut minting_secrets: BTreeMap<u64, MintSecret> = BTreeMap::new();

            for amount in amounts {
                let secret = Secret::generate();

                let (b_, r) = BlindedSecret::from_bytes(secret.as_bytes())?;

                let blinded_message = BlindedMessage::new(amount, &keyset_id, b_.clone());
                outputs.push(blinded_message);

                minting_secrets.insert(amount, MintSecret { secret, r });
            }

            let blind_signatures = self.mint.do_minting(&quote_id, &outputs)?;

            self.save()?; // save balance

            let promises = blind_signatures.signatures;

            let mut minted_amounts = vec![];
            for promise in promises {
                let amount = &promise.amount;
                let amount_key = active_keys
                    .get(amount)
                    .ok_or_else(|| anyhow!("Mint error: key for amount does not exist"))?
                    .clone();

                let minting_secret = minting_secrets
                    .get(amount)
                    .ok_or_else(|| anyhow!("Missing secret for amount: {}", amount))?;

                let r = &minting_secret.r;
                let amount_pubkey = &PublicKey::from_hex(amount_key)?;
                let secret = &minting_secret.secret;
                let proof = promise
                    .construct_proof(r, amount_pubkey, secret)
                    .context("construct proof")?;
                self.proofs.push(proof);

                minted_amounts.push(*amount);
            }

            self.save()?;

            Ok(minted_amounts)
        } else {
            bail!("Invoice not paid");
        }
    }

    pub fn melt_tokens(&mut self, invoice: &str) -> Result<MeltQuote> {
        let available_amounts = self.proofs().map(|p| p.amount).collect::<Vec<_>>();
        let have_total = available_amounts.iter().sum::<u64>();

        let quote = self.create_melt_quote(invoice)?;

        let quote_id = quote.quote.clone();
        let fee_reserve = quote.fee_reserve;

        let total_amount = quote.amount + fee_reserve;
        if have_total < total_amount {
            bail!(
                "Insufficient funds, requested: {} including fee reserve; available: {}",
                total_amount,
                have_total
            );
        }

        let mut proofs = self.extract_proofs_for_melting(total_amount)?;

        let mut blank_outputs = vec![];
        let mut melting_secrets = vec![];

        let unit = "sat";
        let active_keyset_info = self
            .mint_keysets(true)?
            .for_unit(unit)
            .ok_or_else(|| anyhow!("No active keyset for '{}'", unit))
            .inspect_err(|_| self.proofs.append(&mut proofs))?;
        let keyset_id = active_keyset_info.id;

        let active_keyset = self
            .mint_keys()?
            .by_id(&keyset_id)
            .ok_or_else(|| anyhow!("Mint did not provided active keys"))
            .inspect_err(|_| self.proofs.append(&mut proofs))?;
        let active_keys = active_keyset.keys;

        let blank_outputs_num = Self::calculate_number_of_blank_outputs(fee_reserve);

        for _ in 0..blank_outputs_num {
            let secret = Secret::generate();
            let (b_, r) = BlindedSecret::from_bytes(secret.as_bytes())?;
            let blinded_message = BlindedMessage::new(1, &keyset_id, b_.clone());

            blank_outputs.push(blinded_message);

            melting_secrets.push(MintSecret { secret, r });
        }

        let melt_res = self
            .mint
            .do_melting(&quote_id, &proofs, &blank_outputs)
            .with_context(|| format!("do melting with quote: {}", quote_id));

        let res_quote = match melt_res {
            Ok(v) => Ok(v),
            Err(e) => {
                self.proofs.append(&mut proofs);
                self.save()?;
                Err(e)
            }
        }?;

        self.save()?; // save after successful payment

        // deal with returned change from overpaid fee
        if let Some(promises) = &res_quote.change {
            for (i, promise) in promises.iter().enumerate() {
                let amount = &promise.amount;
                let amount_key = active_keys
                    .get(amount)
                    .ok_or_else(|| anyhow!("Mint error: key for amount does not exist"))?
                    .clone();

                let minting_secret = melting_secrets.get(i).ok_or_else(|| {
                    anyhow!("Missing secret for change amount: {} (index {})", amount, i)
                })?;

                let r = &minting_secret.r;
                let amount_pubkey = &PublicKey::from_hex(amount_key)?;
                let secret = &minting_secret.secret;
                let proof = promise
                    .construct_proof(r, amount_pubkey, secret)
                    .context("construct proof")?;
                self.proofs.push(proof);
            }
            if !promises.is_empty() {
                self.save()?; // save stored change
            }
        }

        if res_quote.state != QuoteState::Paid {
            eprintln!("WARN: LN payment failed: {:?}", res_quote.state)
        }

        Ok(res_quote)
    }

    /// Used for melting.
    fn extract_proofs_for_melting(&mut self, amount_to_melt: u64) -> Result<Vec<Proof>> {
        let mut available_amounts = self.proofs.iter().map(|p| p.amount).collect::<Vec<_>>();
        available_amounts.sort();

        let have_total = available_amounts.iter().sum::<u64>();
        assert!(have_total >= amount_to_melt);

        let unit = "sat";

        // first try to find combinations in 'have_amounts', so we would not need to do swap for a change
        let (amounts_to_melt, missing_amount) =
            match helpers::find_subset_sum(&available_amounts, amount_to_melt) {
                Some(amounts) => (amounts, 0),
                None => {
                    let mut to_spend_acc = 0;
                    let mut amounts_to_melt = vec![];

                    for amount in available_amounts.iter() {
                        to_spend_acc += *amount;
                        if to_spend_acc < amount_to_melt {
                            amounts_to_melt.push(*amount);
                        } else {
                            to_spend_acc -= *amount;
                            break;
                        }
                    }

                    let missing_amount = amount_to_melt - to_spend_acc;

                    (amounts_to_melt, missing_amount)
                }
            };

        let mut proofs_to_melt = self.extract_proofs_with_amounts(&amounts_to_melt)?;

        // calculate fee and add additional proofs
        let mut sum_fee_ppk = 0;
        for proof in proofs_to_melt.iter() {
            let proof_keyset_id = &proof.keyset_id;

            let proof_keyset = self
                .mint_keysets(false)?
                .by_id(proof_keyset_id)
                .ok_or(anyhow!("Missing keyset {}", proof_keyset_id))?;

            sum_fee_ppk += proof_keyset.input_fee_ppk;

            let index = available_amounts
                .iter()
                .position(|a| a == &proof.amount)
                .expect("amount is present");
            available_amounts.remove(index);
        }

        let inputs_fee = sum_fee_ppk.div_ceil(1000);

        let additional_amount_to_spend = inputs_fee + missing_amount;

        if have_total < amount_to_melt + inputs_fee {
            self.proofs.append(&mut proofs_to_melt);
            self.save()?;
            bail!(
                "Insufficient funds, requested: {} including fees; available: {}",
                amount_to_melt + inputs_fee,
                have_total
            );
        }

        let (mut proofs_to_swap, mut output_amounts, mut additional_amounts_to_melt) = self
            .prepare_amounts_for_swap_before_spend(additional_amount_to_spend)
            .inspect_err(|_| self.proofs.append(&mut proofs_to_melt))?;

        if !proofs_to_swap.is_empty() && !output_amounts.is_empty() {
            println!("--> Need change");
            let amounts_count = additional_amounts_to_melt.len() as u64;

            let active_keyset_info = self
                .mint_keysets(true)?
                .for_unit(unit)
                .ok_or_else(|| anyhow!("No active keyset for '{}'", unit))
                .inspect_err(|_| self.proofs.append(&mut proofs_to_swap))?;
            let active_fee_ppk = active_keyset_info.input_fee_ppk;

            // estimate total fee including additional_amounts_to_melt inputs
            let fee_estimate = (sum_fee_ppk + amounts_count * active_fee_ppk).div_ceil(1000);

            if inputs_fee < fee_estimate {
                // not enough to cover input fee, try it again with amount adjusted
                let new_additional_amount_to_spend =
                    additional_amount_to_spend + (fee_estimate - inputs_fee);

                println!(
                    "--> Need to add more input fee: {} => {} sats",
                    inputs_fee, fee_estimate,
                );
                self.proofs.append(&mut proofs_to_swap);

                if have_total < amount_to_melt + fee_estimate {
                    self.save()?;
                    bail!(
                        "Insufficient funds, requested: {} including fees; available: {}",
                        amount_to_melt + fee_estimate,
                        have_total
                    );
                }

                let (new_proofs_to_swap, new_output_amounts, new_additional_amounts_to_melt) = self
                    .prepare_amounts_for_swap_before_spend(new_additional_amount_to_spend)
                    .inspect_err(|_| self.proofs.append(&mut proofs_to_melt))?;

                proofs_to_swap = new_proofs_to_swap;
                output_amounts = new_output_amounts;
                additional_amounts_to_melt = new_additional_amounts_to_melt;
            }

            if !proofs_to_swap.is_empty() && !output_amounts.is_empty() {
                // we need to do a swap to get a change
                println!("--> Doing swap to get some change");
                let (mut new_proofs, _fee) = self
                    .swap_proofs(&proofs_to_swap, Some(&output_amounts))
                    .context("swap proofs")
                    .inspect_err(|_| self.proofs.append(&mut proofs_to_melt))?;

                self.proofs.append(&mut new_proofs);

                self.save()?; // save newly received proofs
            }
        }

        // potential missing proofs and proofs paying fee
        let mut additional_proofs_to_melt = self
            .extract_proofs_with_amounts(&additional_amounts_to_melt)
            .inspect_err(|_| self.proofs.append(&mut proofs_to_melt))?;

        for proof in additional_proofs_to_melt.iter() {
            let proof_keyset_id = &proof.keyset_id;

            let proof_keyset = self
                .mint_keysets(false)?
                .by_id(proof_keyset_id)
                .ok_or(anyhow!("Missing keyset {}", proof_keyset_id))?;

            sum_fee_ppk += proof_keyset.input_fee_ppk;
        }

        proofs_to_melt.append(&mut additional_proofs_to_melt);

        let total_inputs_fee = sum_fee_ppk.div_ceil(1000);

        // total fee is higher than already included fee (inputs_fee)
        if total_inputs_fee < sum_fee_ppk.div_ceil(1000) {
            // rollback
            self.proofs.append(&mut proofs_to_melt);
            self.save()?;
            bail!(
                "Total fee {} is higher than the fee included in proofs {}",
                sum_fee_ppk.div_ceil(1000),
                total_inputs_fee
            );
        }

        Ok(proofs_to_melt)
    }

    pub fn prepare_cashu_token(&mut self, amount: u64) -> Result<(TokenV4, u64)> {
        let available_amounts = self.proofs().map(|p| p.amount).collect::<Vec<_>>();

        let have_total = available_amounts.iter().sum::<u64>();
        if have_total < amount {
            bail!("Insufficient funds");
        }

        let (proofs_to_spend, fee) = self.prepare_inputs_for_spend(amount)?;

        self.save()?;

        let token =
            TokenV4::new(&self.mint.url(), "sat", &proofs_to_spend).context("create V4 token")?;

        Ok((token, fee))
    }

    pub fn receive_via_cashu_token(&mut self, token: TokenV4) -> Result<(u64, u64)> {
        let amount = token.amount();

        if token.mint_url() != self.mint_url() {
            bail!(
                "Receiving from different mint is not supported. Token is from {}",
                token.mint_url()
            );
        }

        // get proofs from token and swap them for new
        let proofs = token.proofs();

        let (mut new_proofs, fee) = self.swap_proofs(&proofs, None).context("swap proofs")?;

        self.proofs.append(&mut new_proofs);

        self.save()?;

        Ok((amount, fee))
    }

    fn swap_proofs(
        &mut self,
        old_proofs: &[Proof],
        output_amounts: Option<&[u64]>,
    ) -> Result<(Vec<Proof>, u64)> {
        let mut proof_unit = String::new();

        // calculate fee
        let mut sum_fee_ppk = 0;
        for proof in old_proofs.iter() {
            let proof_keyset_id = &proof.keyset_id;

            let proof_keyset = self
                .mint_keysets(false)?
                .by_id(proof_keyset_id)
                .ok_or_else(|| anyhow!("Missing keyset {}", proof_keyset_id))?;

            if proof_unit.is_empty() {
                proof_unit = proof_keyset.unit.clone();
            }

            sum_fee_ppk += proof_keyset.input_fee_ppk;
        }

        let fee = sum_fee_ppk.div_ceil(1000);

        let amount_minus_fee = old_proofs.iter().map(|p| p.amount).sum::<u64>() - fee;

        let output_amounts = if let Some(output_amounts) = output_amounts {
            // swap amounts for change
            output_amounts.to_vec()
        } else {
            // swap proofs when receiving e-cash
            let mut output_amounts = Self::split_amount(amount_minus_fee);

            // In order to preserve privacy around the amount that a client might want to send to another user and keep the rest as change,
            // the client SHOULD ensure that the list requested outputs is ordered by amount in ascending order.
            // https://github.com/cashubtc/nuts/blob/main/03.md#swap-to-send
            output_amounts.sort();

            output_amounts
        };

        let active_keyset_info = self
            .mint_keysets(true)?
            .for_unit(&proof_unit)
            .ok_or_else(|| anyhow!("No active keyset for '{}'", proof_unit))?;
        let active_keyset_id = active_keyset_info.id;

        let active_keyset = self
            .mint_keys()?
            .by_id(&active_keyset_id)
            .ok_or_else(|| anyhow!("Mint did not provided active keys"))?;

        let active_keys = active_keyset.keys;

        let mut outputs = vec![];
        let mut secrets = VecDeque::new();

        for amount in output_amounts {
            let secret = Secret::generate();

            let (b_, r) = BlindedSecret::from_bytes(secret.as_bytes())?;

            let blinded_message = BlindedMessage::new(amount, &active_keyset_id, b_.clone());
            outputs.push(blinded_message);

            secrets.push_back(MintSecret { secret, r });
        }

        let blind_signatures = self.mint.do_swap(old_proofs, &outputs)?;

        let promises = blind_signatures.signatures;

        let mut new_proofs = vec![];
        for promise in promises {
            let amount = &promise.amount;
            let amount_key = active_keys
                .get(amount)
                .ok_or_else(|| anyhow!("Mint error: key for amount does not exist"))?
                .clone();

            let minting_secret = secrets
                .pop_front()
                .ok_or_else(|| anyhow!("Missing secret for amount: {}", amount))?;

            let r = &minting_secret.r;
            let amount_pubkey = &PublicKey::from_hex(amount_key)?;
            let secret = &minting_secret.secret;

            let proof = promise
                .construct_proof(r, amount_pubkey, secret)
                .context("construct proof")?;

            new_proofs.push(proof);
        }

        Ok((new_proofs, fee))
    }

    /// Get proofs with specified amounts and remove them from the wallet
    fn extract_proofs_with_amounts(&mut self, amounts: &[u64]) -> Result<Vec<Proof>> {
        let mut extracted_proofs = Vec::new();
        let mut amounts = amounts.to_vec();
        let amounts_len = amounts.len();

        self.proofs.retain(|p| {
            if let Some(index) = amounts.iter().position(|amount| amount == &p.amount) {
                amounts.swap_remove(index);
                extracted_proofs.push(p.clone());
                false
            } else {
                true
            }
        });

        if extracted_proofs.len() != amounts_len {
            // rollback
            self.proofs.append(&mut extracted_proofs);
            bail!("Failed to find proofs with corresponding amounts");
        }

        Ok(extracted_proofs)
    }

    fn split_amount(amount: u64) -> Vec<u64> {
        let amounts = (0..32).map(|x| 2u64.pow(x)).collect::<Vec<_>>();
        amounts
            .iter()
            .rev()
            .fold((Vec::new(), amount), |(mut acc, total), &amount| {
                if total >= amount {
                    acc.push(amount);
                }
                (acc, total % amount)
            })
            .0
    }

    /// Returns (input_proofs, outputs, amounts_to_spend). Used for Cashu token creation.
    fn prepare_amounts_for_swap_before_spend(
        &mut self,
        total_amount_to_spend: u64,
    ) -> Result<(Vec<Proof>, Vec<u64>, Vec<u64>)> {
        let mut available_amounts = self.proofs.iter().map(|p| p.amount).collect::<Vec<_>>();

        available_amounts.sort();

        let have_total = available_amounts.iter().sum::<u64>();
        assert!(have_total >= total_amount_to_spend);

        // first try to find combinations in 'have_amounts', so we would not need to do swap for a change
        if let Some(amounts_to_spend) =
            helpers::find_subset_sum(&available_amounts, total_amount_to_spend)
        {
            return Ok((vec![], vec![], amounts_to_spend));
        }

        let mut to_spend_acc = 0;
        let mut amounts_to_spend = vec![];

        let mut last_amount = 0;
        let mut last_proof = None;

        for amount in available_amounts.iter() {
            to_spend_acc += *amount;
            if to_spend_acc < total_amount_to_spend {
                amounts_to_spend.push(*amount);
            } else {
                last_amount = *amount;
                last_proof = Some(
                    self.extract_proofs_with_amounts(&[last_amount])?
                        .first()
                        .expect("proof surely exist")
                        .clone(),
                );

                to_spend_acc -= last_amount;
                break;
            }
        }

        if last_proof.is_none() {
            bail!("failed to find proof");
        }
        let last_proof = last_proof.expect("proof was found");

        let missing_amount = total_amount_to_spend - to_spend_acc;

        let num_inputs = 1;
        let last_proof_keyset_id = last_proof.keyset_id.clone();

        let last_proof_keyset = self
            .mint_keysets(false)
            .inspect_err(|_| self.proofs.push(last_proof.clone()))?
            .by_id(&last_proof_keyset_id)
            .ok_or_else(|| anyhow!("Missing keyset {}", last_proof_keyset_id))
            .inspect_err(|_| self.proofs.push(last_proof.clone()))?;

        let total_fee = (num_inputs * last_proof_keyset.input_fee_ppk).div_ceil(1000);

        if (last_amount - missing_amount) < total_fee {
            bail!(
                "Insufficient funds, fee {} exceeds the amount for swap {}",
                total_fee,
                last_amount - missing_amount
            )
        }

        let mut missing_change = Self::split_amount(missing_amount);

        let mut needed_change_amounts =
            Self::split_amount(last_amount - missing_amount - total_fee);
        needed_change_amounts.extend_from_slice(&missing_change);

        assert_eq!(
            last_amount,
            needed_change_amounts.iter().sum::<u64>() + total_fee
        );

        // we need to send 'amounts_to_spend' + 'missing_change'
        amounts_to_spend.append(&mut missing_change);

        assert_eq!(amounts_to_spend.iter().sum::<u64>(), total_amount_to_spend);

        let input_proofs = vec![last_proof];

        Ok((input_proofs, needed_change_amounts, amounts_to_spend))
    }

    /// Extracts and returns proofs to be spend and potential swap fee. Used for Cashu token creation.
    fn prepare_inputs_for_spend(&mut self, amount: u64) -> Result<(Vec<Proof>, u64)> {
        let (input_proofs, output_amounts, amounts_to_spend) =
            self.prepare_amounts_for_swap_before_spend(amount)?;

        let mut swap_fee = 0;

        if !input_proofs.is_empty() && !output_amounts.is_empty() {
            // we need to do a swap to get a change
            let (mut new_proofs, fee) = self
                .swap_proofs(&input_proofs, Some(&output_amounts))
                .context("swap proofs")?;
            swap_fee = fee;

            self.proofs.append(&mut new_proofs);

            self.save()?;
        }

        let proofs = self
            .extract_proofs_with_amounts(&amounts_to_spend)
            .context("find proofs with required amounts")?;

        Ok((proofs, swap_fee))
    }

    fn calculate_number_of_blank_outputs(fee_reserve: u64) -> u32 {
        if fee_reserve == 0 {
            return 0;
        }
        1.max((fee_reserve).ilog2() + 1)
    }

    fn create_mint_quote(&self, amount: u64) -> Result<MintQuote> {
        let quote = self
            .mint
            .create_mint_quote(amount)
            .context("create_mint_quote")?;
        Ok(quote)
    }

    fn check_mint_quote(&self, quote_id: &str) -> Result<MintQuote> {
        let quote = self
            .mint
            .get_mint_quote(quote_id)
            .context("get_mint_quote")?;
        Ok(quote)
    }

    fn create_melt_quote(&self, invoice: &str) -> Result<MeltQuote> {
        let quote = self
            .mint
            .create_melt_quote(invoice)
            .context("create_melt_quote")?;
        Ok(quote)
    }

    fn load(name: &str, password: &str) -> Result<Self> {
        let decryption_key = password::derive_encryption_key(password, name)?;

        let path = PathBuf::from(WALLETS_DIR).join(Self::filename(name));
        let mut w = file::load(path.as_path(), &decryption_key).context("load wallet file")?;

        w.encryption_key = decryption_key;

        Ok(w)
    }

    pub fn save(&self) -> Result<()> {
        let path = PathBuf::from(WALLETS_DIR).join(Self::filename(&self.name));
        file::save(self, path.as_path(), &self.encryption_key).context("save wallet file")?;
        Ok(())
    }

    fn filename(wallet_name: &str) -> String {
        let mut filename = wallet_name.to_string();
        filename.push_str(WALLET_FILE_EXT);
        filename
    }
}

#[expect(dead_code)]
#[derive(Default, Debug)]
struct MintSecrets {
    keyset_id: String,
    secrets: Vec<MintSecret>,
}

#[derive(Debug)]
struct MintSecret {
    pub secret: Secret,
    pub r: SecretKey,
}

mod password {
    use super::*;

    use argon2::{
        Argon2,
        password_hash::{PasswordHash, PasswordVerifier},
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };

    pub(crate) fn is_valid_for_wallet(password: &str, wallet_name: &str) -> Result<bool> {
        let mut filename = wallet_name.to_string();
        filename.push_str(".pw");

        let path = PathBuf::from(WALLETS_DIR).join(filename);
        let mut file =
            File::open(&path).with_context(|| format!("open file {}", path.display()))?;

        let mut pwd_hash = String::new();
        file.read_to_string(&mut pwd_hash)
            .context("read pwd hash from file")?;

        let parsed_hash = PasswordHash::new(&pwd_hash)?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            return Ok(true);
        }

        Ok(false)
    }

    pub(crate) fn save(wallet_name: &str, password: &str) -> Result<()> {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        // Hash password to PHC string ($argon2id$v=19$...)
        let pwd_hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        let mut filename = wallet_name.to_string();
        filename.push_str(".pw");

        let path = PathBuf::from(WALLETS_DIR).join(filename);

        let dir = path.parent().unwrap();
        if !dir.exists() {
            std::fs::create_dir(dir).with_context(|| format!("create dir {}", dir.display()))?;
        }

        let mut file =
            File::create(&path).with_context(|| format!("create file {}", path.display()))?;

        file.write_all(pwd_hash.as_bytes())
            .context("write password hash to file")?;

        Ok(())
    }

    pub(crate) fn derive_encryption_key(password: &str, wallet_name: &str) -> Result<[u8; 32]> {
        let salt = wallet_name.repeat(3);

        let mut encryption_key = [0u8; 32];
        Argon2::default().hash_password_into(
            password.as_bytes(),
            salt.as_bytes(),
            &mut encryption_key,
        )?;

        Ok(encryption_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_amount() {
        assert_eq!(Wallet::split_amount(1), vec![1]);
        assert_eq!(Wallet::split_amount(2), vec![2]);
        assert_eq!(Wallet::split_amount(3), vec![2, 1]);
        assert_eq!(Wallet::split_amount(11), vec![8, 2, 1]);
        assert_eq!(Wallet::split_amount(255), vec![128, 64, 32, 16, 8, 4, 2, 1]);
    }

    #[test]
    fn test_calculate_number_of_blank_outputs() {
        assert_eq!(Wallet::calculate_number_of_blank_outputs(0), 0);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(1), 1);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(2), 2);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(3), 2);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(4), 3);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(7), 3);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(8), 4);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(900), 10);
        assert_eq!(Wallet::calculate_number_of_blank_outputs(1000), 10);
    }
}
