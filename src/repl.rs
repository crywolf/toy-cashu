use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::wallet::Wallet;

pub fn start(wallet: Wallet) -> Result<()> {
    let wallet = Repl { wallet };
    loop {
        let line = wallet.readline()?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match wallet.respond(line) {
            Ok(quit) => {
                if quit {
                    break;
                }
            }
            Err(err) => {
                writeln!(std::io::stdout(), "{err:?}")?;
                std::io::stdout().flush()?;
            }
        }
    }

    Ok(())
}

struct Repl {
    wallet: Wallet,
}

impl Repl {
    fn respond(&self, line: &str) -> Result<bool> {
        let args = line.split_whitespace();
        let cli = Cli::try_parse_from(args)?;
        match cli.command {
            Command::Balance => {
                writeln!(std::io::stdout(), "{}", self.wallet.balance())?;
                std::io::stdout().flush()?;
            }
            Command::WalletInfo => {
                let w = &self.wallet;
                writeln!(std::io::stdout(), "name: {}, mint: {}", w.name, w.mint())?;
                std::io::stdout().flush()?;
            }
            Command::MintInfo => {
                writeln!(std::io::stdout(), "{}", self.wallet.mint_info()?)?;
                std::io::stdout().flush()?;
            }
            Command::MintKeys => {
                writeln!(std::io::stdout(), "{:#?}", self.wallet.mint_keys()?)?;
                std::io::stdout().flush()?;
            }
            Command::MintKeysets => {
                writeln!(std::io::stdout(), "{:#?}", self.wallet.mint_keysets()?)?;
                std::io::stdout().flush()?;
            }
            Command::Exit | Command::Quit => {
                writeln!(std::io::stdout(), "Exiting ...")?;
                std::io::stdout().flush()?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn readline(&self) -> Result<String> {
        write!(std::io::stdout(), "{}> ", self.wallet.name)?;
        std::io::stdout().flush()?;
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        Ok(buffer)
    }
}

#[derive(Debug, Parser)]
#[command(multicall = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Display total balance
    Balance,
    /// Display wallet info
    #[command(name = "info")]
    WalletInfo,
    /// Get info about mint
    MintInfo,
    /// Get mint keys
    #[command(name = "keys")]
    MintKeys,
    /// Get mint keysets
    #[command(name = "keysets")]
    MintKeysets,
    Exit,
    Quit,
}
