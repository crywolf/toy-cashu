use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print names of available wallets
    List,
    /// Open specified wallet
    Open {
        /// Wallet name
        wallet_name: String,
    },
    /// Create new wallet
    Create {
        /// Wallet name
        wallet_name: String,
        /// Mint URL
        mint: String,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}
