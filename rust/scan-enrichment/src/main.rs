use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

/// Command-line arguments for the standalone scan enrichment binary.
#[derive(Parser, Debug)]
#[command(name = "scan-enrich-results")]
#[command(about = "Enrich OpenVAS scanner results with VT, Notus, and optional SCAP metadata")]
struct Cli {
    /// Path to the raw scanner results JSON file (plain JSON or `.gz`).
    #[arg(long)]
    results: PathBuf,
    /// Path to `vt-metadata.json` or a feed directory containing it.
    #[arg(long = "vt-metadata")]
    vt_metadata: Option<PathBuf>,
    /// Path to a Notus advisory file or directory.
    #[arg(long = "notus-path")]
    notus_path: Option<PathBuf>,
    /// Optional path to SCAP CVE JSON data used to expand referenced CVEs.
    #[arg(long = "scap-path")]
    scap_path: Option<PathBuf>,
    /// Optional destination file for the enriched JSON payload.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Parse CLI arguments, validate the requested metadata sources, and run enrichment.
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
