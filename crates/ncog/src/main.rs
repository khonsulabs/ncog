#![forbid(unsafe_code)]
#![warn(
    // TODO clippy::cargo,
    // TODO missing_docs,
    // clippy::missing_docs_in_private_items,
    clippy::pedantic,
    future_incompatible,
    rust_2018_idioms,
)]
#![allow(
    clippy::missing_errors_doc, // TODO clippy::missing_errors_doc
    clippy::missing_panics_doc, // TODO clippy::missing_panics_doc
    clippy::option_if_let_else,
    clippy::module_name_repetitions,
)]

use structopt::StructOpt;

use crate::cli::Args;

mod cli;
mod server;
mod webserver;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    Args::from_args().execute().await
}
