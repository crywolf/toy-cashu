use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::cashu::{
    BlindedMessage, BlindedSecret, Proof,
    crypto::{PublicKey, Secret, SecretKey},
    types::{Keys, Keysets, MintQuote, QuoteState},
};
use crate::file;
use crate::mint::{Mint, MintInfo};

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

    pub fn mint(&self) -> String {
        self.mint.url()
    }

    pub fn mint_info(&mut self) -> Result<MintInfo> {
        let mut info = self.mint.get_info().cloned()?;
        info.url = self.mint();
        Ok(info)
    }

    pub fn mint_keys(&self) -> Result<Keys> {
        self.mint.get_keys()
    }

    pub fn mint_keysets(&self, only_active: bool) -> Result<Keysets> {
        let mut ks = self.mint.get_keysets().context("get_keysets")?;
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

            let active_keysets = self.mint_keysets(true)?;

            let active_ks_for_sats = active_keysets.keysets.into_iter().find(|s| s.unit == unit);
            if let Some(active_key_set) = active_ks_for_sats {
                let keyset_id = active_key_set.id;
                let active_keys = self.mint_keys()?;
                let active_keyset = active_keys
                    .by_id(keyset_id.clone())
                    .ok_or(anyhow!("Mint did not provided active keys"))?;

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

                let blind_signatures = self.mint.do_minting(quote_id, outputs)?;

                let promises = blind_signatures.signatures;

                let mut minted_amounts = vec![];
                for promise in promises {
                    let amount = &promise.amount;
                    let amount_key = active_keys
                        .get(amount)
                        .ok_or(anyhow!("Mint error: key for amount does not exist"))?
                        .clone();

                    let minting_secret = minting_secrets
                        .get(amount)
                        .ok_or(anyhow!("Missing secret for amount: {}", amount))?;

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
                bail!("No active keyset");
            }
        } else {
            bail!("Invoice not paid");
        }
    }

    pub fn swap_tokens(&mut self, input_amount: u64, output_amounts: &[u64]) -> Result<()> {
        let (proof_index, proof) = self
            .proofs
            .iter()
            .enumerate()
            .find(|(_, p)| p.amount == input_amount)
            .ok_or(anyhow!("Missing proof for amount {}", input_amount))?;

        let inputs = vec![proof.clone()];

        let input_unit = "sat"; // TODO

        let active_keysets = self.mint_keysets(true)?;

        let active_ks_for_sats = active_keysets
            .keysets
            .into_iter()
            .find(|s| s.unit == input_unit);
        if let Some(active_key_set) = active_ks_for_sats {
            let keyset_id = active_key_set.id;
            let active_keys = self.mint_keys()?;
            let active_keyset = active_keys
                .by_id(keyset_id.clone())
                .ok_or(anyhow!("Mint did not provided active keys"))?;

            let active_keys = active_keyset.keys;

            let mut outputs = vec![];
            let mut secrets = VecDeque::new();

            for &amount in output_amounts {
                let secret = Secret::generate();

                let (b_, r) = BlindedSecret::from_bytes(secret.as_bytes())?;

                let blinded_message = BlindedMessage::new(amount, &keyset_id, b_.clone());
                outputs.push(blinded_message);

                secrets.push_back(MintSecret { secret, r });
            }

            let blind_signatures = self.mint.do_swap(inputs, outputs)?;

            let promises = blind_signatures.signatures;

            for promise in promises {
                let amount = &promise.amount;
                let amount_key = active_keys
                    .get(amount)
                    .ok_or(anyhow!("Mint error: key for amount does not exist"))?
                    .clone();

                let minting_secret = secrets
                    .pop_front()
                    .ok_or(anyhow!("Missing secret for amount: {}", amount))?;

                let r = &minting_secret.r;
                let amount_pubkey = &PublicKey::from_hex(amount_key)?;
                let secret = &minting_secret.secret;
                let proof = promise
                    .construct_proof(r, amount_pubkey, secret)
                    .context("construct proof")?;
                self.proofs.push(proof);
            }

            // remove melted (swapped out) proof from wallet
            self.proofs.remove(proof_index);

            self.save()?;
        } else {
            bail!("No active keyset");
        }

        Ok(())
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

    fn load(name: &str, password: &str) -> Result<Self> {
        let decryption_key = password::derive_encryption_key(password, name)?;

        let path = PathBuf::from(WALLETS_DIR).join(Self::filename(name));
        let mut w = file::load(path.as_path(), &decryption_key).context("load wallet file")?;

        w.encryption_key = decryption_key;

        Ok(w)
    }

    fn save(&self) -> Result<()> {
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
}
