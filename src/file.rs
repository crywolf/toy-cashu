use std::{fs::File, path::Path};

use anyhow::{Context, Result};

use crate::wallet::Wallet;

pub fn load(path: &Path) -> Result<Wallet> {
    let file = File::open(path).with_context(|| format!("open file {}", path.display()))?;

    // TODO decrypt
    let w = serde_json::from_reader(file).context("deserialize from file")?;

    Ok(w)
}

pub fn save(w: &Wallet, path: &Path) -> Result<()> {
    let dir = path.parent().unwrap();
    if !dir.exists() {
        std::fs::create_dir(dir).with_context(|| format!("create dir {}", dir.display()))?;
    }

    let file = File::create(path).with_context(|| format!("create file {}", path.display()))?;

    // TODO encrypt
    serde_json::to_writer(file, w).context("serialize to file")?;

    Ok(())
}
