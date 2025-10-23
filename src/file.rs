use std::{fs::File, path::Path};

use anyhow::{Context, Result};

use crate::wallet::Wallet;

/// Load and decrypt wallet data from disk
pub fn load(path: &Path, decryption_key: &[u8]) -> Result<Wallet> {
    let file = File::open(path).with_context(|| format!("open file {}", path.display()))?;

    let decryptor = age::Decryptor::new(file)?;

    let passphrase = age::secrecy::SecretString::from(hex::encode(decryption_key));

    let reader =
        decryptor.decrypt(std::iter::once(&age::scrypt::Identity::new(passphrase) as _))?;

    let w = serde_json::from_reader(reader).context("deserialize from file")?;

    Ok(w)
}

/// Encrypt and save wallet data to disk
pub fn save(w: &Wallet, path: &Path, encryption_key: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap();
    if !dir.exists() {
        std::fs::create_dir(dir).with_context(|| format!("create dir {}", dir.display()))?;
    }

    let mut file = File::create(path).with_context(|| format!("create file {}", path.display()))?;

    let passphrase = age::secrecy::SecretString::from(hex::encode(encryption_key));

    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut encryptor_writer = encryptor
        .wrap_output(&mut file)
        .context("write encryption header")?;

    serde_json::to_writer(&mut encryptor_writer, w)
        .context("serialize wallet data to encrypted file")?;
    encryptor_writer
        .finish()
        .context("finish writing of encrypted file")?;

    Ok(())
}
