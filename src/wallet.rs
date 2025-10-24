use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    file,
    mint::{Keys, Keysets, Mint},
};

const WALLETS_DIR: &str = ".wallets";
const WALLET_FILE_EXT: &str = ".bin";

#[derive(Deserialize, Serialize)]
pub struct Wallet {
    pub name: String,
    #[serde(flatten)]
    mint: Mint,
    proofs: Vec<String>,
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
            proofs: vec![],
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
        Ok(w)
    }

    pub fn mint(&self) -> String {
        self.mint.url()
    }

    pub fn mint_info(&self) -> Result<String> {
        self.mint.get_info()
    }

    pub fn mint_keys(&self) -> Result<Keys> {
        self.mint.get_keys()
    }

    pub fn mint_keysets(&self) -> Result<Keysets> {
        self.mint.get_keysets()
    }

    pub fn balance(&self) -> usize {
        self.proofs.len() // TODO
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
