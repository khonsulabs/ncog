use khonsu_tools::{
    anyhow,
    code_coverage::{self, CodeCoverage},
    devx_cmd::{self, run},
};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub enum Commands {
    GenerateCodeCoverageReport {
        #[structopt(long = "install-dependencies")]
        install_dependencies: bool,
    },
    BuildWebapp,
}

fn main() -> anyhow::Result<()> {
    let command = Commands::from_args();
    match command {
        Commands::GenerateCodeCoverageReport {
            install_dependencies,
        } => CodeCoverage::<CoverageConfig>::execute(install_dependencies),
        Commands::BuildWebapp => build_web_app(),
    }
}

struct CoverageConfig;

impl code_coverage::Config for CoverageConfig {}

fn build_web_app() -> anyhow::Result<()> {
    run!(
        "cargo",
        "build",
        "--package",
        "ncog-webapp",
        "--target",
        "wasm32-unknown-unknown",
        "--target-dir",
        "target/wasm",
    )?;
    execute_wasm_bindgen(
        "target/wasm/wasm32-unknown-unknown/debug/ncog_webapp.wasm",
        "crates/ncog-webapp/pkg/",
    )?;

    Ok(())
}

fn execute_wasm_bindgen(wasm_path: &str, out_path: &str) -> Result<(), devx_cmd::Error> {
    println!("Executing wasm-bindgen (cargo install wasm-bindgen if you don't have this)");
    run!(
        "wasm-bindgen",
        wasm_path,
        "--target",
        "web",
        "--out-dir",
        out_path,
        "--remove-producers-section"
    )
}
