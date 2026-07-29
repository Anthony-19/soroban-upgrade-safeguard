use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use soroban_upgrade_safeguard::{
    color::{should_disable_color, ColorMode},
    diff, loader, parser,
    render::RenderableReport,
    report, spec,
    spec_json::ExtractedSpec,
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

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Markdown => write!(f, "markdown"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => Err(format!("Unknown format '{s}'. Supported: text, json, markdown")),
        }
    }
}

impl OutputFormat {
    fn file_extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
            OutputFormat::Text => "txt",
        }
    }
}

/// A single output specification: a format and an optional file path.
/// When `path` is `None`, output goes to stdout.
#[derive(Clone, Debug)]
struct OutputSpec {

    format: OutputFormat,
    path: Option<PathBuf>,
}

impl std::str::FromStr for OutputSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((fmt, path)) = s.split_once(':') {
            let format: OutputFormat =
                fmt.parse().map_err(|_| {
                    format!(
                        "Invalid format '{fmt}'. Supported: text, json, markdown"
                    )
                })?;
            Ok(OutputSpec {
                format,
                path: Some(PathBuf::from(path)),
            })
        } else {
            let format: OutputFormat = s.parse().map_err(|_| {
                format!(
                    "Invalid format '{s}'. Use 'format:path' or one of: text, json, markdown"
                )
            })?;
            Ok(OutputSpec {
                format,
                path: None,
            })
        }
    }
}

/// Output format for a re-rendered report. JSON is excluded: re-rendering a
/// stored JSON document as JSON would be a no-op copy.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum RenderFormat {
    /// Colored, human-readable report (default).
    #[default]
    Text,
    /// Markdown document suitable for PR descriptions and comments.
    Markdown,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]\n       \
                      soroban-upgrade-safeguard extract <WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard render <REPORT_JSON> [OPTIONS]",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
)]
struct Args {
    /// Subcommand, when not running a comparison
    #[command(subcommand)]
    command: Option<Command>,

    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode.
    /// Use - to read one WASM from stdin.
    #[arg(value_name = "WASM", num_args = 0..=2)]
    wasm_paths: Vec<PathBuf>,

    /// Output format for stdout. Omit or use --output for file output.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Output specification(s) in FORMAT:PATH format (e.g. json:report.json).
    /// Can be specified multiple times. FORMAT is one of: text, json, markdown.
    #[arg(long, value_name = "FORMAT:PATH", num_args = 1)]
    output: Vec<OutputSpec>,

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

    /// Do not load any suppression config, including the default .safeguard.toml.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    strict: bool,

    /// Do not color output
    #[arg(long)]
    no_color: bool,

    /// Suppress decorative and progress output; the report and exit code are unchanged.
    #[arg(long)]
    quiet: bool,

    /// Control when ANSI color is used. --no-color overrides this option.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Allow HTTP connections for RPC when the host is localhost/127.0.0.1.
    /// Without this flag only HTTPS URLs are accepted.
    #[arg(long)]
    allow_http_local: bool,

    /// Expected SHA-256 hash (hex) of the on-chain WASM baseline.
    #[arg(long, value_name = "HEX_HASH")]
    expected_wasm_hash: Option<String>,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    manifest: Option<PathBuf>,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    new_dir: Option<PathBuf>,

    /// Directory to write one report file per contract into, using the selected format
    #[arg(
        long = "per-contract-output-dir",
        alias = "report-dir",
        alias = "output-dir",
        alias = "per-contract-report-dir",
        alias = "per-contract-reports-dir",
        alias = "batch-output-dir",
        value_name = "DIR"
    )]
    per_contract_output_dir: Option<PathBuf>,

    /// Watch mode: re-run comparison when input files change
    #[arg(long)]
    watch: bool,

    /// Suppress timestamps in report output for deterministic/snapshot testing
    #[arg(long)]
    no_timestamp: bool,

    /// Sample storage entries and perform empirical validation.
    #[arg(long)]
    empirical: bool,

    /// Path to a JSON file containing captured ledger/storage entries for offline validation.
    #[arg(long, value_name = "EMPIRICAL_FILE")]
    empirical_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Dump a single contract's decoded spec as JSON
    Extract(ExtractArgs),
    /// Re-render a previously saved JSON report in another format
    Render(RenderArgs),
}

/// `extract`: decode one build and emit its interface.
#[derive(ClapArgs, Debug)]
struct ExtractArgs {
    /// WASM file to decode. Omit when using --contract-id/--rpc-url.
    #[arg(value_name = "WASM")]
    wasm: Option<PathBuf>,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    /// Print only the interface hash, with no other output.
    #[arg(long)]
    hash_only: bool,
}

/// `render`: turn a stored JSON report back into a human format.
#[derive(ClapArgs, Debug)]
struct RenderArgs {
    /// Path to a JSON report previously written with --format json, or `-` to
    /// read it from stdin.
    #[arg(value_name = "REPORT_JSON")]
    report: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = RenderFormat::Text)]
    format: RenderFormat,

    /// Print the remediation guidance stored in the report, if it has any.
    #[arg(long)]
    explain: bool,

    /// Do not color output
    #[arg(long)]
    no_color: bool,
}

/// Decode one build and emit its interface as JSON, or just its hash.
fn run_extract(args: &ExtractArgs) -> Result<()> {
    let build = match (&args.wasm, &args.contract_id) {
        (Some(path), None) => loader::load_wasm(path)?,
        (None, Some(contract_id)) => {
            let rpc_url = args
                .rpc_url
                .as_ref()
                .expect("clap requires --rpc-url alongside --contract-id");
            loader::fetch_wasm_from_rpc(contract_id, rpc_url)?
        }
        (Some(_), Some(_)) => anyhow::bail!(
            "Provide either a WASM path or --contract-id, not both.\n\n\
             Usage: soroban-upgrade-safeguard extract <WASM>\n       \
             soroban-upgrade-safeguard extract --contract-id <ID> --rpc-url <URL>"
        ),
        (None, None) => anyhow::bail!(
            "Missing WASM path.\n\n\
             Usage: soroban-upgrade-safeguard extract <WASM>\n       \
             soroban-upgrade-safeguard extract --contract-id <ID> --rpc-url <URL>"
        ),
    };

    let metadata = parser::extract_metadata(&build.bytes)?;
    let contract_spec = spec::ContractSpec::from_entries(&metadata.spec);

    if args.hash_only {
        println!("{}", contract_spec.interface_hash());
        return Ok(());
    }

    let extracted = ExtractedSpec::new(&build.path, &metadata, &contract_spec);
    println!("{}", serde_json::to_string_pretty(&extracted)?);
    Ok(())
}

/// Re-render a stored JSON report as text or Markdown.
fn run_render(args: &RenderArgs) -> Result<()> {
    let raw = if args.report == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("Failed to read report from stdin")?
    } else {
        std::fs::read_to_string(&args.report)
            .with_context(|| format!("Failed to read report file: {}", args.report.display()))?
    };

    if should_disable_color(
        args.no_color,
        ColorMode::Auto,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    }

    let report = RenderableReport::from_json_str(&raw).with_context(|| {
        format!(
            "Failed to read the saved report at '{}'",
            args.report.display()
        )
    })?;

    match args.format {
        RenderFormat::Text => println!("{}", report.to_text(args.explain)),
        RenderFormat::Markdown => println!("{}", report.to_markdown()),
    }

    if !report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    match &args.command {
        Some(Command::Extract(extract_args)) => return run_extract(extract_args),
        Some(Command::Render(render_args)) => return run_render(render_args),
        None => {}
    }

    if should_disable_color(
        args.no_color,
        args.color,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    } else if args.color == ColorMode::Always {
        colored::control::set_override(true);
    }

    let is_batch = args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some());

    if args.manifest.is_some() && (args.old_dir.is_some() || args.new_dir.is_some()) {
        anyhow::bail!("Cannot specify both --manifest and --old-dir/--new-dir at the same time");
    }

    if is_batch && !args.wasm_paths.is_empty() {
        anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
    }

    // Determine stdout format: use --format if given, or "text" as default
    // (only used when no --output flags target stdout).
    let stdout_format = args.format.unwrap_or(OutputFormat::Text);

    // Build the list of outputs:
    // - If --format is given and no --output targets stdout, add stdout output for --format.
    // - If no --output at all, fallback to --format (or Text) to stdout.
    let outputs: Vec<OutputSpec> = if !args.output.is_empty() {
        // User specified explicit outputs; --format still controls stdout if not
        // already covered by an --output spec.
        let has_stdout = args.output.iter().any(|o| o.path.is_none());
        let mut outputs = args.output.clone();
        if !has_stdout {
            // Add --format (or text) as stdout output
            outputs.push(OutputSpec {
                format: stdout_format,
                path: None,
            });
        }
        outputs
    } else {
        vec![OutputSpec {
            format: stdout_format,
            path: None,
        }]
    };

    let has_non_stdout = outputs.iter().any(|o| o.path.is_some());
    // Decorative progress goes to stderr when stdout is clean (JSON/Markdown to file
    // or when stdout format would produce a clean document), or when any file output
    // is requested alongside stdout in a clean format.
    let stdout_is_clean = outputs.iter().any(|o| o.path.is_none())
        && (stdout_format == OutputFormat::Json || stdout_format == OutputFormat::Markdown);
    let clean_stdout = stdout_is_clean || has_non_stdout;
    let progress = |line: String| {
        if args.quiet {
            return;
        }
        if clean_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    let suppressions = if args.no_config {
        SuppressionConfig::default()
    } else {
        match &args.config {
            Some(path) => SuppressionConfig::load_from_path(path)?,
            None => {
                SuppressionConfig::load_optional(Path::new(DEFAULT_CONFIG_FILE))?
                    .unwrap_or_default()
            }
        }
    };

    if is_batch {
        return run_batch(&args, &outputs, &suppressions, &progress);
    }

    run_single(&args, &outputs, &suppressions, &progress)
}

fn run_batch(
    args: &Args,
    outputs: &[OutputSpec],
    suppressions: &SuppressionConfig,
    progress: &dyn Fn(String),
) -> Result<()> {
    let (pairs, mut gaps) = if let Some(manifest_path) = &args.manifest {
        (parse_manifest(manifest_path)?, Vec::new())
    } else {
        scan_directories(
            args.old_dir.as_ref().unwrap(),
            args.new_dir.as_ref().unwrap(),
        )?
    };

    progress("🔍 Soroban Upgrade Safeguard (Batch Mode)".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
    progress(format!(
        "Loaded {} pair(s) for comparison. {} old-only contract(s) will be flagged.\n",
        pairs.len(),
        gaps.len()
    ));

    let mut results = std::collections::BTreeMap::new();
    let mut overall_safe = true;
    let mut seen_names = std::collections::BTreeSet::new();
    let gap_count = gaps.len();
    let total = pairs.len() + gap_count;

    // Process each gap (old contract missing from new directory) as a Critical failure
    for gap in gaps.drain(..) {
        if !seen_names.insert(gap.name.clone()) {
            anyhow::bail!(
                "Duplicate contract name '{}' found in batch input; names must be unique",
                gap.name
            );
        }
        progress(format!(
            "📦 [{}/{}] Gap: '{}' exists in old directory but NOT in new directory",
            results.len() + 1,
            total,
            gap.name.bold().red()
        ));

        let gap_report = report::SafetyReport {
            critical_count: 1,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            total_findings: 1,
            is_safe: false,
            strict: args.strict,
            critical_root_count: 1,
            cascade_critical_count: 0,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: args.no_timestamp,
            old_spec_summary: None,
            new_spec_summary: Some("(contract missing from new deployment)".to_string()),
            scope: report::AnalysisScope::default(),
            metrics: None,
            findings_by_category: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "contract-missing-from-new".to_string(),
                    vec![report::ReportedFinding {
                        finding: diff::Finding {
                            severity: diff::Severity::Critical,
                            category: "contract-missing-from-new".to_string(),
                            message: format!(
                                "'{}' exists in the old directory but was not found in the new directory. \
                                 This contract would be removed from the deployment, breaking all clients \
                                 that depend on it.",
                                gap.name
                            ),
                            type_name: None,
                            target: Some(gap.name.clone()),
                            root_target: None,
                        },
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(format!(
                            "Ensure the .wasm for '{}' is present in the new directory, or add it to \
                             the --suppressions file if removal is intentional.",
                            gap.name
                        )),
                    }],
                );
                map
            },
        };

        render_to_outputs(&gap_report, outputs, args.explain, Some(&gap.name), progress)?;

        if let Some(output_dir) = args.per_contract_output_dir.as_deref() {
            let content = render_single(&gap_report, args.format.unwrap_or(OutputFormat::Text), args.explain)?;
            write_report_file(output_dir, &gap.name, args.format.unwrap_or(OutputFormat::Text), &content)?;
        }

        results.insert(gap.name, gap_report);
        overall_safe = false;
    }

    // Process each regular pair with error-handling (per-pair failures do not abort the batch)
    for (i, pair) in pairs.iter().enumerate() {
        let default_name = format!("pair_{}", i + 1);
        let contract_name = pair.name.clone().unwrap_or_else(|| {
            pair.new
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_string())
                .unwrap_or(default_name)
        });

        if !seen_names.insert(contract_name.clone()) {
            anyhow::bail!(
                "Duplicate contract name '{}' found in batch input; names must be unique",
                contract_name
            );
        }

        progress(format!(
            "📦 [{}/{}] Comparing contract pair: {}",
            i + 1 + gaps.len(),
            total,
            contract_name.bold()
        ));

        let report = match (loader::load_wasm(&pair.old), loader::load_wasm(&pair.new)) {
            (Ok(old_wasm), Ok(new_wasm)) => {
                match compare_contracts(
                    &ContractComparison {
                        old_bytes: &old_wasm.bytes,
                        old_path: &old_wasm.path,
                        new_bytes: &new_wasm.bytes,
                        new_path: &new_wasm.path,
                        suppressions,
                        explain: args.explain,
                        strict: args.strict,
                        no_timestamp: args.no_timestamp,
                        empirical: args.empirical || args.empirical_file.is_some(),
                        empirical_file: args.empirical_file.as_deref(),
                        contract_id: None,
                        rpc_url: None,
                    },
                    progress,
                ) {
                    Ok(report) => report,
                    Err(e) => {
                        progress(format!(
                            "  ⚠️  Comparison failed for '{}': {}",
                            contract_name,
                            e.to_string().red()
                        ));
                        synthesize_error_report(&contract_name, &e.to_string(), args.strict, args.no_timestamp)
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                progress(format!(
                    "  ⚠️  Failed to load contract files for '{}': {}",
                    contract_name,
                    e.to_string().red()
                ));
                synthesize_error_report(&contract_name, &e.to_string(), args.strict, args.no_timestamp)
            }
        };

        if !report.is_safe() {
            overall_safe = false;
        }

        render_to_outputs(&report, outputs, args.explain, Some(&contract_name), progress)?;

        if let Some(output_dir) = args.per_contract_output_dir.as_deref() {
            let content = render_single(&report, args.format.unwrap_or(OutputFormat::Text), args.explain)?;
            write_report_file(output_dir, &contract_name, args.format.unwrap_or(OutputFormat::Text), &content)?;
        }

        results.insert(contract_name, report);
        progress("\n----------------------------------------\n".to_string());
    }

    render_batch_summary(&results, overall_safe, total, args.strict, outputs, progress)?;

    if !overall_safe {
        std::process::exit(1);
    }

    Ok(())
}

fn synthesize_error_report(name: &str, error_message: &str, strict: bool, no_timestamp: bool) -> report::SafetyReport {
    report::SafetyReport {
        critical_count: 1,
        warning_count: 0,
        info_count: 0,
        suppressed_count: 0,
        suppressed_critical_count: 0,
        suppressed_warning_count: 0,
        suppressed_info_count: 0,
        total_findings: 1,
        is_safe: false,
        strict,
        critical_root_count: 1,
        cascade_critical_count: 0,
        old_interface_hash: None,
        new_interface_hash: None,
        no_timestamp,
        old_spec_summary: None,
        new_spec_summary: Some("(analysis failed)".to_string()),
        scope: report::AnalysisScope::default(),
        metrics: None,
        findings_by_category: {
            let mut map = std::collections::HashMap::new();
            map.insert(
                "analysis-error".to_string(),
                vec![report::ReportedFinding {
                    finding: diff::Finding {
                        severity: diff::Severity::Critical,
                        category: "analysis-error".to_string(),
                        message: format!(
                            "Analysis of '{}' failed: {}", name, error_message
                        ),
                        type_name: None,
                        target: Some(name.to_string()),
                        root_target: None,
                    },
                    suppressed: false,
                    suppression_reason: None,
                    remediation: Some(
                        "Check the contract paths and ensure both WASM files exist and are valid Soroban contracts.".to_string()
                    ),
                }],
            );
            map
        },
    }
}

fn render_batch_summary(
    results: &std::collections::BTreeMap<String, report::SafetyReport>,
    overall_safe: bool,
    total_pairs: usize,
    strict: bool,
    outputs: &[OutputSpec],
    progress: &dyn Fn(String),
) -> Result<()> {
    for output in outputs {
        let content = match output.format {
            OutputFormat::Json => {
                let mut results_json = serde_json::Map::new();
                for (name, report) in results {
                    results_json.insert(name.clone(), serde_json::to_value(report.to_json())?);
                }
                let batch_json = serde_json::json!({
                    "is_safe": overall_safe,
                    "strict": strict,
                    "total_pairs": total_pairs,
                    "results": results_json,
                });
                serde_json::to_string_pretty(&batch_json)?
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

                for (name, report) in results {
                    let status_str = if report.is_safe() { "✅ PASSED" } else { "❌ FAILED" };
                    markdown.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        name, status_str, report.critical_count(), report.warning_count(),
                        report.info_count(), report.suppressed_count()
                    ));
                }

                markdown.push_str("\n---\n\n");

                for (name, report) in results {
                    markdown.push_str(&format!("## Details: {}\n\n", name));
                    let report_md = report.generate_summary_markdown();
                    let stripped_md = report_md.replace("# Soroban Upgrade Safety Report\n\n", "");
                    markdown.push_str(&stripped_md);
                    markdown.push_str("\n---\n\n");
                }

                markdown
            }
            OutputFormat::Text => {
                let mut text = String::new();
                text.push_str("========================================\n");
                text.push_str("    SOROBAN BATCH SAFETY REPORT\n");
                text.push_str("========================================\n");

                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)".green().bold().to_string()
                } else {
                    "❌ FAILED (Some contracts have breaking changes)".red().bold().to_string()
                };
                text.push_str(&format!("Overall Status: {}\n\n", status));

                text.push_str("Summary of Contracts:\n");
                for (name, report) in results {
                    let status_str = if report.is_safe() {
                        "✅ PASSED".green().to_string()
                    } else {
                        "❌ FAILED".red().bold().to_string()
                    };
                    text.push_str(&format!(
                        "  - {}: {} ({} critical, {} warnings, {} info, {} suppressed)\n",
                        name.bold(),
                        status_str,
                        report.critical_count(),
                        report.warning_count(),
                        report.info_count(),
                        report.suppressed_count()
                    ));
                }

                text.push_str("\n========================================\n\n");

                for (name, report) in results {
                    text.push_str(&format!("=== Contract: {} ===\n", name.bold().magenta()));
                    text.push_str(&report.generate_summary_text(false));
                    text.push_str("========================================\n\n");
                }

                text
            }
        };

        emit_output(output, &content)?;
        if output.path.is_none() && output.format != OutputFormat::Text {
            progress(format!("  {} batch report written to stdout", output.format.to_string().to_lowercase()));
        } else if let Some(path) = &output.path {
            progress(format!("  batch report written to {}", path.display()));
        }
    }

    Ok(())
}

fn run_single(
    args: &Args,
    outputs: &[OutputSpec],
    suppressions: &SuppressionConfig,
    progress: &dyn Fn(String),
) -> Result<()> {
    let (old_source, new_wasm_path) = match (args.wasm_paths.len(), &args.contract_id) {
        (2, None) => (None, &args.wasm_paths[1]),
        (1, Some(_)) => (args.contract_id.as_deref(), &args.wasm_paths[0]),
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

    if old_source.is_none()
        && is_stdin_wasm_path(&args.wasm_paths[0])
        && is_stdin_wasm_path(new_wasm_path)
    {
        anyhow::bail!(
            "Cannot use '-' for both OLD_WASM and NEW_WASM because stdin can only be read once. \
             Provide one side as a file path."
        );
    }

    // Collect the actual file paths for watch mode
    let watch_paths: Vec<PathBuf> = if args.watch {
        let mut paths = Vec::new();
        if !is_batch_mode(args) {
            if old_source.is_none() && args.wasm_paths.len() >= 1 {
                let p = args.wasm_paths[0].clone();
                if !is_stdin_wasm_path(&p) {
                    paths.push(p);
                }
            }
            let p = new_wasm_path.clone();
            if !is_stdin_wasm_path(&p) {
                paths.push(p);
            }
        }
        paths
    } else {
        Vec::new()
    };

    let run_comparison = |progress: &dyn Fn(String)| -> Result<bool> {
        progress("🔍 Soroban Upgrade Safeguard".to_string());
        progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

        progress(format!(
            "\n{}",
            "📦 Loading and Parsing contracts...".cyan().bold()
        ));

        let old = if let Some(contract_id) = old_source {
            let rpc_url = args.rpc_url.as_ref().unwrap();
            loader::fetch_wasm_from_rpc(contract_id, rpc_url)?
        } else {
            load_positional_wasm(&args.wasm_paths[0])?
        };

        let new = load_positional_wasm(new_wasm_path)?;

        if !suppressions.rules.is_empty() {
            progress(format!(
                "\n🔕 {} suppression rule(s) loaded",
                suppressions.rules.len()
            ));
        }

        let safety_report = compare_contracts(
            &ContractComparison {
                old_bytes: &old.bytes,
                old_path: &old.path,
                new_bytes: &new.bytes,
                new_path: &new.path,
                suppressions,
                explain: args.explain,
                strict: args.strict,
                no_timestamp: args.no_timestamp,
                empirical: args.empirical || args.empirical_file.is_some(),
                empirical_file: args.empirical_file.as_deref(),
                contract_id: old_source,
                rpc_url: args.rpc_url.as_deref(),
            },
            progress,
        )?;

        render_to_outputs(&safety_report, outputs, args.explain, None, progress)?;

        let is_safe = safety_report.is_safe();
        if !is_safe {
            return Ok(false);
        }
        Ok(true)
    };

    let is_safe = run_comparison(&progress)?;

    if args.watch && !watch_paths.is_empty() {
        run_watch_mode(&watch_paths, args, outputs, suppressions, run_comparison)?;
    } else if args.watch {
        eprintln!("Warning: --watch requires local file paths (stdin or RPC sources not supported)");
    }

    if !is_safe {
        std::process::exit(1);
    }

    Ok(())
}

fn is_batch_mode(args: &Args) -> bool {
    args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some())
}

fn render_to_outputs(
    report: &report::SafetyReport,
    outputs: &[OutputSpec],
    explain: bool,
    contract_name: Option<&str>,
    progress: &dyn Fn(String),
) -> Result<()> {
    for output in outputs {
        let content = render_single(report, output.format, explain)?;
        emit_output(output, &content)?;

        if let Some(ref path) = output.path {
            let label = contract_name
                .map(|n| format!("{}.{}", n, output.format.file_extension()))
                .unwrap_or_else(|| path.to_string_lossy().to_string());
            progress(format!("  report written to {}", label));
        }
    }
    Ok(())
}

fn render_single(report: &report::SafetyReport, format: OutputFormat, explain: bool) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&report.to_json())?),
        OutputFormat::Markdown => Ok(report.generate_summary_markdown()),
        OutputFormat::Text => Ok(report.generate_summary_text(explain)),
    }
}

fn emit_output(spec: &OutputSpec, content: &str) -> Result<()> {
    match &spec.path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let temp_path = path.with_extension(format!(
                "{}.tmp",
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("tmp")
            ));
            std::fs::write(&temp_path, content)?;
            std::fs::rename(&temp_path, path)?;
        }
        None => {
            println!("{content}");
        }
    }
    Ok(())
}

/// Watch mode: monitor input files and re-run on changes.
#[cfg(feature = "watch")]
fn run_watch_mode(
    watch_paths: &[PathBuf],
    _args: &Args,
    _outputs: &[OutputSpec],
    _suppressions: &SuppressionConfig,
    run_comparison: impl Fn(&impl Fn(String)) -> Result<bool>,
) -> Result<()> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            tx.send(event).ok();
        }
    })
    .map_err(|e| anyhow::anyhow!("Failed to create file watcher: {e}"))?;

    for path in watch_paths {
        watcher
            .watch(path, notify::RecursiveMode::NonRecursive)
            .unwrap_or_else(|e| {
                eprintln!("Warning: cannot watch {}: {e}", path.display());
            });
    }

    eprintln!("\n👀 Watch mode active. Waiting for file changes... (Ctrl+C to stop)\n");

    let mut last_event = std::time::Instant::now();
    let debounce_ms = 300;

    loop {
        match rx.recv_timeout(Duration::from_millis(debounce_ms)) {
            Ok(_event) => {
                last_event = std::time::Instant::now();
                // Brief debounce window: wait for more events
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(_) => {
                            last_event = std::time::Instant::now();
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(anyhow::anyhow!("File watcher channel disconnected"));
                        }
                    }
                }

                // Check that watched files exist before re-running
                let all_exist = watch_paths.iter().all(|p| p.exists());
                if !all_exist {
                    eprintln!("⚠️  Watched file(s) missing, waiting for them to reappear...");
                    // Poll until files exist or timeout
                    let start = std::time::Instant::now();
                    let timeout = Duration::from_secs(30);
                    loop {
                        if watch_paths.iter().all(|p| p.exists()) {
                            break;
                        }
                        if start.elapsed() > timeout {
                            eprintln!("⚠️  Timed out waiting for files to reappear");
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }

                // Clear terminal
                print!("\x1B[2J\x1B[H");

                let progress = |line: String| {
                    eprintln!("{line}");
                };

                eprintln!("🔄 Change detected, re-running comparison...\n");

                match run_comparison(&progress) {
                    Ok(safe) => {
                        if safe {
                            eprintln!("\n✅ Comparison passed");
                        } else {
                            eprintln!("\n❌ Comparison failed (breaking changes detected)");
                        }
                    }
                    Err(e) => {
                        eprintln!("\n⚠️  Error during comparison: {e:#}");
                    }
                }

                eprintln!("\n👀 Watch mode active. Waiting for file changes... (Ctrl+C to stop)\n");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No event - if this is the first run, just continue
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!("File watcher channel disconnected"));
            }
        }
    }
}

#[cfg(not(feature = "watch"))]
fn run_watch_mode(
    _watch_paths: &[PathBuf],
    _args: &Args,
    _outputs: &[OutputSpec],
    _suppressions: &SuppressionConfig,
    _run_comparison: impl Fn(&dyn Fn(String)) -> Result<bool>,
) -> Result<()> {
    eprintln!("Warning: --watch is not available in this build. Rebuild with the 'watch' feature enabled.");
    Ok(())
}

fn is_stdin_wasm_path(path: &Path) -> bool {
    path == Path::new("-")
}

fn load_positional_wasm(path: &Path) -> Result<loader::WasmModule> {
    if is_stdin_wasm_path(path) {
        let mut stdin = std::io::stdin().lock();
        Ok(loader::load_wasm_from_stdin(&mut stdin)?)
    } else {
        Ok(loader::load_wasm(path)?)
    }
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

struct ContractComparison<'a> {
    old_bytes: &'a [u8],
    old_path: &'a str,
    new_bytes: &'a [u8],
    new_path: &'a str,
    suppressions: &'a SuppressionConfig,
    explain: bool,
    strict: bool,
    no_timestamp: bool,
    empirical: bool,
    empirical_file: Option<&'a Path>,
    contract_id: Option<&'a str>,
    rpc_url: Option<&'a str>,
}

fn compare_contracts(
    comparison: &ContractComparison<'_>,
    progress: &dyn Fn(String),
) -> Result<report::SafetyReport> {
    let ContractComparison {
        old_bytes,
        old_path,
        new_bytes,
        new_path,
        suppressions,
        explain,
        strict,
        no_timestamp,
        empirical,
        empirical_file,
        contract_id,
        rpc_url,
    } = comparison;
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

    let mut report = report::SafetyReport::with_suppressions(&diff_report, suppressions, *explain, *strict)
        .with_interface_hashes(old_spec.interface_hash(), new_spec.interface_hash());

    report.no_timestamp = *no_timestamp;

    let mut empirical_findings = Vec::new();
    let mut is_empirical = false;

    if *empirical {
        is_empirical = true;
        let mut entries = Vec::new();

        if let Some(file_path) = empirical_file {
            progress(format!("📖 Loading empirical storage entries from: {}", file_path.display()));
            match soroban_upgrade_safeguard::empirical::load_empirical_entries(file_path) {
                Ok(loaded) => {
                    progress(format!("✅ Loaded {} storage entries from file", loaded.len()));
                    entries = loaded;
                }
                Err(e) => {
                    progress(format!("❌ Failed to load empirical storage file: {}", e));
                    return Err(anyhow::anyhow!("Empirical validation error: {}", e));
                }
            }
        } else if let (Some(cid), Some(rpc)) = (contract_id, rpc_url) {
            progress(format!("🌐 Fetching contract instance storage from RPC..."));
            match loader::fetch_instance_storage_from_rpc(cid, rpc) {
                Ok(loaded) => {
                    progress(format!("✅ Fetched {} instance storage entries from RPC", loaded.len()));
                    entries = loaded;
                }
                Err(e) => {
                    progress(format!("⚠️  Failed to fetch instance storage from RPC: {}", e));
                    progress(format!("Limits: Stellar RPC does not support wildcard ledger enumeration. Degrading gracefully."));
                }
            }
        } else {
            progress(format!("⚠️  Empirical mode requested, but no local file (--empirical-file) or RPC source (--contract-id and --rpc-url) was provided."));
        }

        // Run empirical checks
        let structural_findings: Vec<diff::Finding> = diff_report.findings.clone();
        empirical_findings = soroban_upgrade_safeguard::empirical::run_empirical_check(
            &old_spec,
            &new_spec,
            &entries,
            &structural_findings,
        );
    }

    report.empirical = is_empirical;
    report.empirical_findings = empirical_findings;

    if report.empirical_findings.iter().any(|ef| !ef.is_success) {
        report.is_safe = false;
    }

    Ok(report)
}

fn parse_manifest(path: &Path) -> Result<Vec<ContractPair>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

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

#[allow(dead_code)]
struct GapContract {
    name: String,
    old_path: PathBuf,
}

fn scan_directories(old_dir: &Path, new_dir: &Path) -> Result<(Vec<ContractPair>, Vec<GapContract>)> {
    if !old_dir.is_dir() {
        anyhow::bail!("Old directory '{}' is not a directory", old_dir.display());
    }
    if !new_dir.is_dir() {
        anyhow::bail!("New directory '{}' is not a directory", new_dir.display());
    }

    let mut pairs = Vec::new();
    let mut gaps = Vec::new();
    for entry in std::fs::read_dir(old_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("wasm") {
            let filename = path.file_name().unwrap();
            let new_path = new_dir.join(filename);
            let name = path.file_stem().and_then(|s| s.to_str()).map(String::from);
            if new_path.exists() {
                pairs.push(ContractPair {
                    old: path,
                    new: new_path,
                    name,
                });
            } else {
                let gap_name = name.unwrap_or_else(|| filename.to_string_lossy().to_string());
                gaps.push(GapContract {
                    name: gap_name,
                    old_path: path,
                });
            }
        }
    }

    if pairs.is_empty() && gaps.is_empty() {
        anyhow::bail!(
            "No .wasm files found in '{}'",
            old_dir.display()
        );
    }

    Ok((pairs, gaps))
}

fn render_report(
    report: &report::SafetyReport,
    format: OutputFormat,
    explain: bool,
) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&report.to_json())?),
        OutputFormat::Markdown => Ok(report.generate_summary_markdown()),
        OutputFormat::Text => Ok(report.generate_summary_text(explain)),
    }
}

fn write_report_file(
    output_dir: &Path,
    contract_name: &str,
    format: OutputFormat,
    content: &str,
) -> Result<()> {
    let filename = sanitize_report_filename(contract_name, format);
    let output_path = output_dir.join(filename);
    let temp_path = output_path.with_extension(format!(
        "{}.tmp",
        output_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("tmp")
    ));

    std::fs::create_dir_all(output_dir)?;
    std::fs::write(&temp_path, content)?;
    std::fs::rename(&temp_path, &output_path)?;
    Ok(())
}

fn sanitize_report_filename(contract_name: &str, format: OutputFormat) -> PathBuf {
    let mut sanitized = String::new();
    for ch in contract_name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        sanitized = "contract".to_string();
    }

    let extension = match format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "md",
        OutputFormat::Text => "txt",
    };

    let mut path = PathBuf::from(sanitized);
    path.set_extension(extension);
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_spec_from_str_format_only() {
        let spec: OutputSpec = "json".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Json);
        assert!(spec.path.is_none());
    }

    #[test]
    fn test_output_spec_from_str_format_with_path() {
        let spec: OutputSpec = "json:report.json".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Json);
        assert_eq!(spec.path.unwrap(), PathBuf::from("report.json"));
    }

    #[test]
    fn test_output_spec_from_str_markdown_with_path() {
        let spec: OutputSpec = "markdown:docs/report.md".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Markdown);
        assert_eq!(spec.path.unwrap(), PathBuf::from("docs/report.md"));
    }

    #[test]
    fn test_output_spec_from_str_invalid_format() {
        let result: Result<OutputSpec, String> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_output_spec_from_str_invalid_format_in_pair() {
        let result: Result<OutputSpec, String> = "invalid:path.txt".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_file_extension() {
        assert_eq!(OutputFormat::Json.file_extension(), "json");
        assert_eq!(OutputFormat::Markdown.file_extension(), "md");
        assert_eq!(OutputFormat::Text.file_extension(), "txt");
    }

    #[test]
    fn test_output_spec_default() {
        let spec: OutputSpec = "text".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Text);
        assert!(spec.path.is_none());
    }
}
