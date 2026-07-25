use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use soroban_upgrade_safeguard::{
    color::should_disable_color,
    config::{Args, OutputFormat, ResolvedConfig, RunMode},
    diff,
    limits::{find_limit_error, ResourcePolicy},
    loader, parser, report, spec,
    suppression::SuppressionConfig,
};

/// Exit codes:
/// - `0`: safe (no breaking changes, or all suppressed).
/// - `1`: breaking changes detected, or a generic/IO/parse error.
/// - `2`: a resource-limit violation on untrusted input (distinct so CI can tell
///   "input was rejected as adversarial" apart from "the upgrade is unsafe").
fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            if let Some(limit_err) = find_limit_error(&err) {
                eprintln!("⛔ Resource limit exceeded: {limit_err}");
                eprintln!(
                    "   The input was rejected as potentially adversarial before it could \
                     exhaust memory or the stack."
                );
                eprintln!(
                    "   Raise the relevant limit via the [limits] table in .safeguard.toml or a \
                     --max-* flag (see README)."
                );
                std::process::exit(2);
            }
            // Preserve anyhow's full error-chain formatting for everything else.
            eprintln!("Error: {err:?}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let config = ResolvedConfig::resolve(args)?;

    if should_disable_color(
        config.no_color,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    }

    let mode = config.validate_and_resolve_mode()?;
    let is_batch = matches!(mode, RunMode::Manifest | RunMode::DirScan);

    // In JSON or Markdown mode, decorative progress goes to stderr so stdout
    // stays a single, pristine document. In text mode it stays on stdout
    // exactly as before.
    let clean_stdout = config.format == OutputFormat::Json || config.format == OutputFormat::Markdown;
    let progress = |line: String| {
        if clean_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    let suppressions = &config.suppressions;
    let policy = &config.policy;

    if is_batch {
        let pairs = if let Some(manifest_path) = &config.manifest {
            parse_manifest(manifest_path)?
        } else {
            scan_directories(
                config.old_dir.as_ref().unwrap(),
                config.new_dir.as_ref().unwrap(),
            )?
        };

        progress("🔍 Soroban Upgrade Safeguard (Batch Mode)".to_string());
        progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
        progress(format!("Loaded {} pair(s) for comparison.\n", pairs.len()));

        let mut results = std::collections::BTreeMap::new();
        let mut failed: std::collections::BTreeMap<String, PairFailure> =
            std::collections::BTreeMap::new();
        let mut overall_safe = true;
        let mut any_limit_violation = false;

        for (i, pair) in pairs.iter().enumerate() {
            let default_name = format!("pair_{}", i + 1);
            let contract_name = pair.name.clone().unwrap_or_else(|| {
                pair.new
                     .file_name()
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

            // Per-pair policy: a pair that trips a resource limit (or otherwise
            // errors) fails only that pair — it must not abort the whole batch,
            // so its result is recorded and the loop continues.
            let outcome = (|| -> Result<report::SafetyReport> {
                let old_wasm = loader::load_wasm(&pair.old)?;
                let new_wasm = loader::load_wasm(&pair.new)?;
                compare_contracts(
                    &ContractComparison {
                        old_bytes: &old_wasm.bytes,
                        old_path: &old_wasm.path,
                        new_bytes: &new_wasm.bytes,
                        new_path: &new_wasm.path,
                        suppressions,
                        explain: config.explain,
                        strict: config.strict,
                        policy,
                    },
                    &progress,
                )
            })();

            match outcome {
                Ok(report) => {
                    if !report.is_safe {
                        overall_safe = false;
                    }
                    results.insert(contract_name, report);
                }
                Err(err) => {
                    overall_safe = false;
                    let limit = find_limit_error(&err);
                    let is_limit = limit.is_some();
                    if is_limit {
                        any_limit_violation = true;
                    }
                    let message = match limit {
                        Some(limit_err) => limit_err.to_string(),
                        None => format!("{err:#}"),
                    };
                    progress(format!(
                        "  {} {}",
                        if is_limit {
                            "⛔ Resource limit exceeded:".red().bold()
                        } else {
                            "⚠️  Failed:".red().bold()
                        },
                        message
                    ));
                    failed.insert(contract_name, PairFailure { message, is_limit });
                }
            }

            progress("\n----------------------------------------\n".to_string());
        }

        match config.format {
            OutputFormat::Json => {
                let mut results_json = serde_json::Map::new();
                for (name, report) in &results {
                    results_json.insert(name.clone(), serde_json::to_value(report.to_json())?);
                }

                let mut failed_json = serde_json::Map::new();
                for (name, failure) in &failed {
                    failed_json.insert(
                        name.clone(),
                        serde_json::json!({
                            "error": failure.message,
                            "limit_violation": failure.is_limit,
                        }),
                    );
                }

                let batch_json = serde_json::json!({
                    "is_safe": overall_safe,
                    "strict": config.strict,
                    "total_pairs": pairs.len(),
                    "limit_violation": any_limit_violation,
                    "results": results_json,
                    "failed": failed_json,
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
                markdown
                    .push_str("| Contract | Status | Critical | Warning | Info | Suppressed |\n");
                markdown.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

                for (name, report) in &results {
                    let status_str = if report.is_safe {
                        "✅ PASSED"
                    } else {
                        "❌ FAILED"
                    };
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

                for (name, failure) in &failed {
                    let status_str = if failure.is_limit {
                        "⛔ ERROR (limit)"
                    } else {
                        "⛔ ERROR"
                    };
                    markdown.push_str(&format!(
                        "| {} | {} | — | — | — | — |\n",
                        name, status_str
                    ));
                }

                markdown.push_str("\n---\n\n");

                if !failed.is_empty() {
                    markdown.push_str("### Errored Pairs\n\n");
                    for (name, failure) in &failed {
                        markdown.push_str(&format!("- **{}**: {}\n", name, failure.message));
                    }
                    markdown.push_str("\n---\n\n");
                }

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
                    "❌ FAILED (Some contracts have breaking changes)"
                        .red()
                        .bold()
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
                for (name, failure) in &failed {
                    let status_str = if failure.is_limit {
                        "⛔ ERROR (resource limit)".red().bold()
                    } else {
                        "⛔ ERROR".red().bold()
                    };
                    println!("  - {}: {} — {}", name.bold(), status_str, failure.message);
                }

                println!("\n========================================\n");

                for (name, report) in &results {
                    println!("=== Contract: {} ===", name.bold().magenta());
                    println!("{}", report.generate_summary_text(config.explain));
                    println!("========================================\n");
                }
            }
        }

        // Exit precedence: a resource-limit violation (2) dominates ordinary
        // breaking changes / failures (1), so CI can special-case adversarial
        // input. All safe and no errors → success (0).
        if any_limit_violation {
            std::process::exit(2);
        }
        if !overall_safe {
            std::process::exit(1);
        }

        let total_suppressed_criticals: usize = results.values().map(|r| r.suppressed_critical_count).sum();
        if total_suppressed_criticals > 0 {
            eprintln!(
                "{}",
                format!(
                    "⚠️  SECURITY NOTICE: The gate passed because {} Critical breaking changes were suppressed. Ensure these suppressions are fully reviewed and authorized.",
                    total_suppressed_criticals
                )
                .red()
                .bold()
            );
        }

        return Ok(());
    }

    // Resolve the two usage modes for single pair:
    //   - 2 positional args => local-vs-local comparison
    //   - 1 positional arg  + --contract-id/--rpc-url => RPC-vs-local comparison
    let (old_source, new_wasm_path) = match (config.wasm_paths.len(), &config.contract_id) {
        (2, None) => (None, &config.wasm_paths[1]), // local mode
        (1, Some(_)) => (config.contract_id.as_deref(), &config.wasm_paths[0]), // RPC mode
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
            anyhow::bail!(
                "Expected 1 or 2 WASM path arguments.\n\n\
                 Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
            );
        }
    };

    progress("🔍 Soroban Upgrade Safeguard".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

    progress(format!(
        "\n{}",
        "📦 Loading and Parsing contracts...".cyan().bold()
    ));

    // Old WASM — from file or from RPC. RPC-fetched bytes are subject to the
    // same resource policy as file input.
    let old = if let Some(contract_id) = old_source {
        let rpc_url = config.rpc_url.as_ref().unwrap();
        let module = loader::fetch_wasm_from_rpc_with_policy(contract_id, rpc_url, policy)?;

        // If the caller pinned an expected hash, verify it now against the hash
        // that was verified on-chain during the RPC fetch.
        if let Some(expected_hex) = &config.expected_wasm_hash {
            let expected_bytes = hex::decode(expected_hex)
                .context("--expected-wasm-hash must be a valid hex string")?;
            let actual = module
                .verified_hash
                .as_ref()
                .map(|h| h.as_slice())
                .unwrap_or(&[]);
            if actual != expected_bytes.as_slice() {
                anyhow::bail!(
                    "Hash mismatch: expected on-chain WASM hash {}, but fetched hash was {}",
                    expected_hex,
                    module
                        .verified_hash
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".to_string()),
                );
            }
        }

        module
    } else {
        loader::load_wasm(&config.wasm_paths[0])?
    };

    // New WASM
    let new = loader::load_wasm(new_wasm_path)?;

    if !suppressions.rules.is_empty() {
        progress(format!(
            "\n🔕 {} suppression rule(s) loaded",
            suppressions.rules.len()
        ));
    }

    // Generate Safety Report using the factored helper
    let safety_report = compare_contracts(
        &ContractComparison {
            old_bytes: &old.bytes,
            old_path: &old.path,
            new_bytes: &new.bytes,
            new_path: &new.path,
            suppressions,
            explain: config.explain,
            strict: config.strict,
            policy,
        },
        &progress,
    )?;

    match config.format {
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
            println!("{}", safety_report.generate_summary_text(config.explain));
        }
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    } else if safety_report.suppressed_critical_count > 0 {
        eprintln!(
            "{}",
            format!(
                "⚠️  SECURITY NOTICE: The gate passed because {} Critical breaking changes were suppressed. Ensure these suppressions are fully reviewed and authorized.",
                safety_report.suppressed_critical_count
            )
            .red()
            .bold()
        );
    }

    Ok(())
}

#[derive(serde::Deserialize, Clone, Debug)]
struct ContractPair {
    old: PathBuf,
    new: PathBuf,
    name: Option<String>,
}

/// A batch pair that could not be compared. Recorded so one bad pair fails only
/// itself; `is_limit` distinguishes an adversarial-input rejection (exit 2) from
/// an ordinary failure such as a missing or malformed file.
struct PairFailure {
    message: String,
    is_limit: bool,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct Manifest {
    pairs: Vec<ContractPair>,
}

struct ContractComparison<'a> {
    old_bytes: &'a [u8],
    old_path: &'a str,
    new_bytes: &'a [u8],
    new_path: &'a str,
    suppressions: &'a SuppressionConfig,
    explain: bool,
    strict: bool,
    policy: &'a ResourcePolicy,
}

/// Helper function to run comparison for a single pair.
fn compare_contracts(
    comparison: &ContractComparison<'_>,
    progress: &impl Fn(String),
) -> Result<report::SafetyReport> {
    let ContractComparison {
        old_bytes,
        old_path,
        new_bytes,
        new_path,
        suppressions,
        explain,
        strict,
        policy,
    } = comparison;
    let old_meta = parser::extract_metadata_with_policy(old_bytes, policy)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old_path,
        old_bytes.len()
    ));
    progress(format!("     └─ {}", old_spec.summary().dimmed()));

    let new_meta = parser::extract_metadata_with_policy(new_bytes, policy)?;
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
    let mut diff_report = diff::compare_with_policy(&old_spec, &new_spec, policy)?;
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    Ok(report::SafetyReport::with_suppressions(
        &diff_report,
        suppressions,
        *explain,
        *strict,
        policy,
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
