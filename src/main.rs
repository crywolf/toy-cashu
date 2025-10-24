use anyhow::bail;
use rpassword::prompt_password;

use crate::cli::Command;
use crate::wallet::Wallet;

mod cli;
mod file;
mod mint;
mod repl;
mod wallet;

fn main() -> anyhow::Result<()> {
    let cli = cli::parse();

    match &cli.command {
        Command::List => {
            for (i, name) in Wallet::names_list()?.iter().enumerate() {
                println!("{}. {}", i + 1, name);
            }
        }
        Command::Create { wallet_name, mint } => {
            let password = prompt_password("Set walled password: ").unwrap();
            let password = password.trim();

            let password_again = prompt_password("Password again: ").unwrap();
            let password_again = password_again.trim();

            if password != password_again {
                bail!("Password mismatch, aborting...");
            }

            let wallet = Wallet::create(wallet_name, mint, password)?;

            repl::start(wallet)?;
        }
        Command::Open { wallet_name } => {
            let password = prompt_password("Wallet password: ").unwrap();
            let password = password.trim();

            let wallet = Wallet::open(wallet_name, password)?;

            repl::start(wallet)?;
        }
    }

    Ok(())
}
