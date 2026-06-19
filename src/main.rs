use anyhow::Result;
use clap::{Parser, ValueEnum};
use colored::Colorize;
use std::path::{Path, PathBuf};

use soroban_upgrade_safeguard::{
    diff, loader, parser, report, spec,
    suppression::{SuppressionConfig, DEFAULT_CONFIG_FILE},
};

/// Output format for the safety report.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    /// Colored, human-readable report (default).
    #[default]
    Text,
    /// A single machine-readable JSON document for CI and dashboards.
    Json,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    // Two usage modes:
    //   1. Local:  soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
    //   2. RPC:    soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]"
)]
struct Args {
    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode
    #[arg(value_name = "WASM", num_args = 1..=2)]
    wasm_paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    /// Path to a suppression config acknowledging known, intentional breaking
    /// changes. When omitted, `.safeguard.toml` in the current directory is
    /// used if present; otherwise no suppressions are applied.
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let json = args.format == OutputFormat::Json;

    // Resolve the two usage modes:
    //   - 2 positional args => local-vs-local comparison
    //   - 1 positional arg  + --contract-id/--rpc-url => RPC-vs-local comparison
    let (old_source, new_wasm_path) = match (args.wasm_paths.len(), &args.contract_id) {
        (2, None) => (None, &args.wasm_paths[1]),          // local mode
        (1, Some(_)) => (args.contract_id.as_deref(), &args.wasm_paths[0]), // RPC mode
        (2, Some(_)) => {
            anyhow::bail!(
                "When using --contract-id, provide only the NEW_WASM path as a positional argument"
            );
        }
        (1, None) => {
            anyhow::bail!(
                "Missing OLD_WASM path. Provide two WASM files, or use --contract-id and --rpc-url \
                 to fetch the old contract from chain.\n\n\
                 Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
            );
        }
        _ => {
            anyhow::bail!("Expected 1 or 2 WASM path arguments");
        }
    };

    // In JSON mode, decorative progress goes to stderr so stdout stays a
    // single, pristine JSON document. In text mode it stays on stdout
    // exactly as before.
    let progress = |line: String| {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    progress("🔍 Soroban Upgrade Safeguard".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

    progress(format!(
        "\n{}",
        "📦 Loading and Parsing contracts...".cyan().bold()
    ));

    // Old WASM — from file or from RPC
    let old = if let Some(contract_id) = old_source {
        let rpc_url = args.rpc_url.as_ref().unwrap();
        loader::fetch_wasm_from_rpc(contract_id, rpc_url)?
    } else {
        loader::load_wasm(&args.wasm_paths[0])?
    };
    let old_meta = parser::extract_metadata(&old.bytes)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old.path,
        old.bytes.len()
    ));
    progress(format!("     └─ {}", old_spec.summary().dimmed()));

    // New WASM
    let new = loader::load_wasm(new_wasm_path)?;
    let new_meta = parser::extract_metadata(&new.bytes)?;
    let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ New:".green().bold(),
        new.path,
        new.bytes.len()
    ));
    progress(format!("     └─ {}", new_spec.summary().dimmed()));

    // Run comparison
    progress(format!(
        "\n{}",
        "🔬 Analyzing structural compatibility...".cyan().bold()
    ));
    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    // Load suppression config: an explicit --config must exist; otherwise fall
    // back to `.safeguard.toml` in the working directory if it happens to be
    // present. With neither, an empty config preserves today's behavior.
    let suppressions = match &args.config {
        Some(path) => SuppressionConfig::load_from_path(path)?,
        None => {
            SuppressionConfig::load_optional(Path::new(DEFAULT_CONFIG_FILE))?.unwrap_or_default()
        }
    };
    if !suppressions.rules.is_empty() {
        progress(format!(
            "\n{} {} suppression rule(s) loaded",
            "🔕".to_string(),
            suppressions.rules.len()
        ));
    }

    // Generate Safety Report
    let safety_report = report::SafetyReport::with_suppressions(&diff_report, &suppressions);

    if json {
        // Single JSON document to stdout; no decorative text, no ANSI codes.
        println!(
            "{}",
            serde_json::to_string_pretty(&safety_report.to_json())?
        );
    } else {
        println!("{}", safety_report.generate_summary_text());
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}
