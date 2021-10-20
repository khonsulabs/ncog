use structopt::StructOpt;

use crate::{cli::Args, schema::Keyserver};

mod cli;
mod schema;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::from_args() {
        Args::Db(command) => command.execute().await,
        Args::Account(command) => command.execute().await,
    }
}
