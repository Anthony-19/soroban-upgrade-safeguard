use anyhow::{Context, Result};
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
    /// Markdown document suitable for PR descriptions and comments.
    Markdown,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    // Four usage modes:
    //   1. Local:      soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]
    //   2. RPC:        soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]
    //   3. Manifest:   soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]
    //   4. Dir Scan:   soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]"
)]
struct Args {
    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode
    #[arg(value_name = "WASM", num_args = 0..=2)]
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

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    strict: bool,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    manifest: Option<PathBuf>,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    new_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 1. Identify which mode we are running:
    //    - Batch Manifest Mode
    //    - Batch Directory Mode
    //    - Single Contract Pair Mode
    let is_batch = args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some());

    if args.manifest.is_some() && (args.old_dir.is_some() || args.new_dir.is_some()) {
        anyhow::bail!("Cannot specify both --manifest and --old-dir/--new-dir at the same time");
    }

    if is_batch && !args.wasm_paths.is_empty() {
        anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
    }

    // In JSON or Markdown mode, decorative progress goes to stderr so stdout
    // stays a single, pristine document. In text mode it stays on stdout
    // exactly as before.
    let clean_stdout = args.format == OutputFormat::Json || args.format == OutputFormat::Markdown;
    let progress = |line: String| {
        if clean_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    // Load suppression config: an explicit --config must exist; otherwise fall
    // back to `.safeguard.toml` in the working directory if it happens to be
    // present. With neither, an empty config preserves today's behavior.
    let suppressions = match &args.config {
        Some(path) => SuppressionConfig::load_from_path(path)?,
        None => {
            SuppressionConfig::load_optional(Path::new(DEFAULT_CONFIG_FILE))?.unwrap_or_default()
        }
    };

    if is_batch {
        let pairs = if let Some(manifest_path) = &args.manifest {
            parse_manifest(manifest_path)?
        } else {
            scan_directories(args.old_dir.as_ref().unwrap(), args.new_dir.as_ref().unwrap())?
        };

        progress("🔍 Soroban Upgrade Safeguard (Batch Mode)".to_string());
        progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
        progress(format!(
            "Loaded {} pair(s) for comparison.\n",
            pairs.len()
        ));

        let mut results = std::collections::BTreeMap::new();
        let mut overall_safe = true;

        for (i, pair) in pairs.iter().enumerate() {
            let default_name = format!("pair_{}", i + 1);
            let contract_name = pair.name.clone().unwrap_or_else(|| {
                pair.new.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.to_string())
                    .unwrap_or(default_name)
            });

            progress(format!(
                "📦 [{}/{}] Comparing contract pair: {}",
                i + 1,
                pairs.len(),
                contract_name.bold()
            ));

            let old_wasm = loader::load_wasm(&pair.old)?;
            let new_wasm = loader::load_wasm(&pair.new)?;

            let report = compare_contracts(
                &old_wasm.bytes,
                &old_wasm.path,
                &new_wasm.bytes,
                &new_wasm.path,
                &suppressions,
                args.explain,
                args.strict,
                &progress,
            )?;

            if !report.is_safe {
                overall_safe = false;
            }

            results.insert(contract_name, report);
            progress("\n----------------------------------------\n".to_string());
        }

        match args.format {
            OutputFormat::Json => {
                let mut results_json = serde_json::Map::new();
                for (name, report) in &results {
                    results_json.insert(name.clone(), serde_json::to_value(report.to_json())?);
                }

                let batch_json = serde_json::json!({
                    "is_safe": overall_safe,
                    "strict": args.strict,
                    "total_pairs": pairs.len(),
                    "results": results_json,
                });

                println!("{}", serde_json::to_string_pretty(&batch_json)?);
            }
            OutputFormat::Markdown => {
                let mut markdown = String::new();
                markdown.push_str("# Soroban Upgrade Safety Report (Batch Mode)\n\n");
                
                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)"
                } else {
                    "❌ FAILED (Some contracts have breaking changes)"
                };
                markdown.push_str(&format!("## Status: {}\n\n", status));
                markdown.push_str("### Summary\n\n");
                markdown.push_str("| Contract | Status | Critical | Warning | Info | Suppressed |\n");
                markdown.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

                for (name, report) in &results {
                    let status_str = if report.is_safe { "✅ PASSED" } else { "❌ FAILED" };
                    markdown.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        name,
                        status_str,
                        report.critical_count,
                        report.warning_count,
                        report.info_count,
                        report.suppressed_count
                    ));
                }

                markdown.push_str("\n---\n\n");

                for (name, report) in &results {
                    markdown.push_str(&format!("## Details: {}\n\n", name));
                    let report_md = report.generate_summary_markdown();
                    let stripped_md = report_md.replace("# Soroban Upgrade Safety Report\n\n", "");
                    markdown.push_str(&stripped_md);
                    markdown.push_str("\n---\n\n");
                }

                println!("{}", markdown);
            }
            OutputFormat::Text => {
                println!("========================================");
                println!("    SOROBAN BATCH SAFETY REPORT");
                println!("========================================");

                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)".green().bold()
                } else {
                    "❌ FAILED (Some contracts have breaking changes)".red().bold()
                };
                println!("Overall Status: {}\n", status);

                println!("Summary of Contracts:");
                for (name, report) in &results {
                    let status_str = if report.is_safe {
                        "✅ PASSED".green()
                    } else {
                        "❌ FAILED".red().bold()
                    };
                    println!(
                        "  - {}: {} ({} critical, {} warnings, {} info, {} suppressed)",
                        name.bold(),
                        status_str,
                        report.critical_count,
                        report.warning_count,
                        report.info_count,
                        report.suppressed_count
                    );
                }

                println!("\n========================================\n");

                for (name, report) in &results {
                    println!("=== Contract: {} ===", name.bold().magenta());
                    println!("{}", report.generate_summary_text(args.explain));
                    println!("========================================\n");
                }
            }
        }

        if !overall_safe {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Resolve the two usage modes for single pair:
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
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                 Or use batch mode:\n       \
                 soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                 soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
            );
        }
        _ => {
            anyhow::bail!(
                "Expected 1 or 2 WASM path arguments.\n\n\
                 Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                 Or use batch mode:\n       \
                 soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                 soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
            );
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

    // New WASM
    let new = loader::load_wasm(new_wasm_path)?;

    if !suppressions.rules.is_empty() {
        progress(format!(
            "\n{} {} suppression rule(s) loaded",
            "🔕".to_string(),
            suppressions.rules.len()
        ));
    }

    // Generate Safety Report using the factored helper
    let safety_report = compare_contracts(
        &old.bytes,
        &old.path,
        &new.bytes,
        &new.path,
        &suppressions,
        args.explain,
        args.strict,
        &progress,
    )?;

    match args.format {
        OutputFormat::Json => {
            // Single JSON document to stdout; no decorative text, no ANSI codes.
            println!(
                "{}",
                serde_json::to_string_pretty(&safety_report.to_json())?
            );
        }
        OutputFormat::Markdown => {
            println!("{}", safety_report.generate_summary_markdown());
        }
        OutputFormat::Text => {
            println!("{}", safety_report.generate_summary_text(args.explain));
        }
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}

#[derive(serde::Deserialize, Clone, Debug)]
struct ContractPair {
    old: PathBuf,
    new: PathBuf,
    name: Option<String>,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct Manifest {
    pairs: Vec<ContractPair>,
}

/// Helper function to run comparison for a single pair.
fn compare_contracts(
    old_bytes: &[u8],
    old_path: &str,
    new_bytes: &[u8],
    new_path: &str,
    suppressions: &SuppressionConfig,
    explain: bool,
    strict: bool,
    progress: &impl Fn(String),
) -> Result<report::SafetyReport> {
    let old_meta = parser::extract_metadata(old_bytes)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old_path,
        old_bytes.len()
    ));
    progress(format!("     └─ {}", old_spec.summary().dimmed()));

    let new_meta = parser::extract_metadata(new_bytes)?;
    let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ New:".green().bold(),
        new_path,
        new_bytes.len()
    ));
    progress(format!("     └─ {}", new_spec.summary().dimmed()));

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

    Ok(report::SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        explain,
        strict,
    ))
}

fn parse_manifest(path: &Path) -> Result<Vec<ContractPair>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

    // Try TOML, then JSON
    if let Ok(manifest) = toml::from_str::<Manifest>(&content) {
        return Ok(manifest.pairs);
    }
    if let Ok(manifest) = serde_json::from_str::<Manifest>(&content) {
        return Ok(manifest.pairs);
    }

    anyhow::bail!(
        "Failed to parse manifest '{}' as either TOML or JSON.",
        path.display()
    )
}

fn scan_directories(old_dir: &Path, new_dir: &Path) -> Result<Vec<ContractPair>> {
    if !old_dir.is_dir() {
        anyhow::bail!("Old directory '{}' is not a directory", old_dir.display());
    }
    if !new_dir.is_dir() {
        anyhow::bail!("New directory '{}' is not a directory", new_dir.display());
    }

    let mut pairs = Vec::new();
    for entry in std::fs::read_dir(old_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm") {
            let filename = path.file_name().unwrap();
            let new_path = new_dir.join(filename);
            if new_path.exists() {
                let name = path.file_stem().and_then(|s| s.to_str()).map(String::from);
                pairs.push(ContractPair {
                    old: path,
                    new: new_path,
                    name,
                });
            } else {
                eprintln!(
                    "⚠️  Warning: Match not found for '{}' in new directory '{}'",
                    filename.to_string_lossy(),
                    new_dir.display()
                );
            }
        }
    }

    if pairs.is_empty() {
        anyhow::bail!(
            "No matching .wasm contract pairs found between '{}' and '{}'",
            old_dir.display(),
            new_dir.display()
        );
    }

    Ok(pairs)
}
