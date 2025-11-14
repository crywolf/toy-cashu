use std::{io::Write, str::FromStr};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{cashu, wallet::Wallet};

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
    /// Generate Cashu V4 token
    Send {
        /// Amount in sats
        sats: u64,
    },
    /// Receive via Cashu V4 token
    Receive {
        /// Cashu V4 token
        token: String,
    },
    /// Swap token amounts (manually)
    #[command(name = "swap")]
    SwapTokenAmounts {
        /// Input amounts in sats
        #[arg(short, long, required = true)]
        inputs: Vec<u64>,
        /// Output amounts in sats
        #[arg(short, long, required = true)]
        outputs: Vec<u64>,
    },
    Exit,
    Quit,
}

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
                if err.downcast_ref::<clap::Error>().is_some() {
                    writeln!(std::io::stdout(), "  {err:?}")?;
                } else {
                    writeln!(std::io::stdout(), "  error: {err:?}")?;
                }
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
                writeln!(
                    std::io::stdout(),
                    "  Name: {}, Mint: {}",
                    w.name,
                    w.mint_url()
                )?;
                std::io::stdout().flush()?;
            }
            Command::MintInfo => {
                let info = self.wallet.mint_info()?;
                writeln!(
                    std::io::stdout(),
                    "  Name: {}, Url: {}, Version: {}\n  Pubkey: {}",
                    info.name,
                    info.url,
                    info.version,
                    info.pubkey,
                )?;
                let mut nuts = info
                    .nuts
                    .iter()
                    .filter(|(_, nut)| nut.is_active())
                    .map(|(nut, _)| nut)
                    .collect::<Vec<_>>();
                nuts.sort();
                writeln!(std::io::stdout(), "  Supported NUTs: {:?}", nuts)?;
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
            Command::Send { sats } => {
                let (token, fee) = self.wallet.prepare_cashu_token(sats)?;
                writeln!(std::io::stdout(), "  Token: {}", token)?;
                writeln!(std::io::stdout(), "  Fee: {} sat", fee)?;
                std::io::stdout().flush()?;
            }
            Command::Receive { token } => {
                let token = cashu::TokenV4::from_str(&token).context("parse token")?;
                let (amount, fee) = self.wallet.receive_via_cashu_token(token)?;
                writeln!(
                    std::io::stdout(),
                    "  Received: {} sats (fee: {} sat)",
                    amount - fee,
                    fee
                )?;
                std::io::stdout().flush()?;
            }
            Command::SwapTokenAmounts { inputs, outputs } => {
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

                self.wallet.swap_token_amounts(&inputs, &outputs)?;
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
