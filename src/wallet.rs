use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::file;

const WALLETS_DIR: &str = ".wallets";
const WALLET_FILE_EXT: &str = ".json";

#[derive(Debug, Deserialize, Serialize)]
pub struct Wallet {
    pub name: String,
    mint: String,
    proofs: Vec<String>,
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

        Password::save(name, password)?;

        let w = Self {
            name: name.to_owned(),
            mint: mint.to_owned(),
            proofs: vec![],
        };

        w.save()
            .with_context(|| format!("save newly created wallet '{}'", name))?;

        let w = Self::load(name).with_context(|| format!("load wallet {}", name))?;
        Ok(w)
    }

    pub fn open(name: &str, password: &str) -> Result<Self> {
        let file = PathBuf::from(WALLETS_DIR).join(Self::filename(name));

        if !file.exists() {
            bail!("Wallet {} does not exist!", name);
        }

        if !Password::is_valid_for_wallet(password, name).context("validate password")? {
            bail!("Invalid password!");
        }

        let w = Self::load(name).with_context(|| format!("load wallet {}", name))?;
        Ok(w)
    }

    pub fn balance(&self) -> usize {
        self.proofs.len() // TODO
    }

    fn load(name: &str) -> Result<Self> {
        let path = PathBuf::from(WALLETS_DIR).join(Self::filename(name));
        let w = file::load(path.as_path()).context("load wallet file")?;
        Ok(w)
    }

    fn save(&self) -> Result<()> {
        let path = PathBuf::from(WALLETS_DIR).join(Self::filename(&self.name));
        file::save(self, path.as_path()).context("save wallet file")?;
        Ok(())
    }

    fn filename(wallet_name: &str) -> String {
        let mut filename = wallet_name.to_string();
        filename.push_str(WALLET_FILE_EXT);
        filename
    }
}

struct Password;

impl Password {
    fn is_valid_for_wallet(password: &str, wallet_name: &str) -> Result<bool> {
        let mut filename = wallet_name.to_string();
        filename.push_str(".pw");

        let path = PathBuf::from(WALLETS_DIR).join(filename);
        let mut file =
            File::open(&path).with_context(|| format!("open file {}", path.display()))?;

        let mut pwd_hash = String::new();
        file.read_to_string(&mut pwd_hash)
            .context("read pwd hash from file")?;

        if password_auth::verify_password(password, &pwd_hash).is_ok() {
            return Ok(true);
        }

        Ok(false)
    }

    fn save(wallet_name: &str, password: &str) -> Result<()> {
        let pwd_hash = password_auth::generate_hash(password);

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
}
