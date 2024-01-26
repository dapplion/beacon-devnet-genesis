use anyhow::Result;
use beacon_devnet_genesis::{run, Cli};
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();

    run(cli)
}
