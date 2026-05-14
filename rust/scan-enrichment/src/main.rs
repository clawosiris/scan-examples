use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "scan-enrich-results")]
#[command(about = "Enrich OpenVAS scanner results with VT, Notus, and optional SCAP metadata")]
struct Cli {
    #[arg(long)]
    results: PathBuf,
    #[arg(long = "vt-metadata")]
    vt_metadata: Option<PathBuf>,
    #[arg(long = "notus-path")]
    notus_path: Option<PathBuf>,
    #[arg(long = "scap-path")]
    scap_path: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.vt_metadata.is_none() && cli.notus_path.is_none() {
        anyhow::bail!("at least one of --vt-metadata or --notus-path is required");
    }
    scan_enrichment::run_cli(
        &cli.results,
        cli.vt_metadata.as_deref(),
        cli.notus_path.as_deref(),
        cli.scap_path.as_deref(),
        cli.output.as_deref(),
    )
}
