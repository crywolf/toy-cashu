use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::wallet::Wallet;

pub fn start(wallet: Wallet) -> Result<()> {
    let mut repl = Repl { wallet };
    loop {
        let line = repl.readline()?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match repl.respond(line) {
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
    fn respond(&mut self, line: &str) -> Result<bool> {
        let args = line.split_whitespace();
        let cli = Cli::try_parse_from(args)?;
        match cli.command {
            Command::Balance => {
                writeln!(std::io::stdout(), "  Total: {}", self.wallet.balance())?;
                let mut amounts = self.wallet.proofs().map(|p| p.amount).collect::<Vec<_>>();
                amounts.sort();
                amounts.reverse();
                writeln!(std::io::stdout(), "  Amounts: {:?}", amounts)?;
                std::io::stdout().flush()?;
            }
            Command::WalletInfo => {
                let w = &self.wallet;
                writeln!(std::io::stdout(), "  name: {}, mint: {}", w.name, w.mint())?;
                std::io::stdout().flush()?;
            }
            Command::MintInfo => {
                let info = self.wallet.mint_info()?;
                writeln!(
                    std::io::stdout(),
                    "  name: {}, url: {}, pubkey: {}",
                    info.name,
                    info.url,
                    info.pubkey
                )?;
                std::io::stdout().flush()?;
            }
            Command::MintKeys => {
                writeln!(std::io::stdout(), "{:#?}", self.wallet.mint_keys()?)?;
                std::io::stdout().flush()?;
            }
            Command::MintKeysets => {
                writeln!(std::io::stdout(), "{:#?}", self.wallet.mint_keysets(false)?)?;
                std::io::stdout().flush()?;
            }
            Command::MintTokens { sats } => {
                let mut amounts = self.wallet.mint_tokens(sats)?;
                amounts.sort();
                amounts.reverse();
                writeln!(std::io::stdout(), "  Minted amounts: {:?}", amounts)?;
                std::io::stdout().flush()?;
            }
            Command::SwapTokens {
                inputs,
                mut outputs,
            } => {
                write!(std::io::stdout(), "  Confirm swap: ")?;
                writeln!(std::io::stdout(), "{:?} -> {:?}", inputs, outputs)?;
                write!(std::io::stdout(), "  (y/n): ")?;
                std::io::stdout().flush()?;

                let mut buf = String::new();
                std::io::stdin().read_line(&mut buf)?;
                let buf = buf.trim().to_lowercase();
                if !buf.starts_with("y") {
                    writeln!(std::io::stdout(), "  Swap cancelled")?;
                    return Ok(false);
                }

                self.wallet.swap_tokens(&inputs, &mut outputs)?;
                self.wallet.save()?;

                writeln!(
                    std::io::stdout(),
                    "  Swap {:?} -> {:?} finished successfully",
                    inputs,
                    outputs
                )?;
                std::io::stdout().flush()?;
            }
            Command::Exit | Command::Quit => {
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
    /// Display wallet balance
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
    /// Mint tokens
    #[command(name = "mint")]
    MintTokens {
        /// Amount in sats
        sats: u64,
    },
    /// Swap tokens (manually)
    #[command(name = "swap")]
    SwapTokens {
        /// Inputs in sats
        #[arg(short, long, required = true)]
        inputs: Vec<u64>,
        /// Outputs in sats
        #[arg(short, long, required = true)]
        outputs: Vec<u64>,
    },
    Exit,
    Quit,
}
