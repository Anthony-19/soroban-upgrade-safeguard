use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::limits::{LimitsConfig, ResourcePolicy};
use crate::suppression::{SuppressionConfig, SuppressionRule};

/// Output format for the safety report.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Markdown,
}

#[derive(clap::Parser, Debug, Clone)]
#[command(
    author,
    version,
    about,
    long_about = None,
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]"
)]
pub struct Args {
    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode
    #[arg(value_name = "WASM", num_args = 0..=2)]
    pub wasm_paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    pub contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    pub rpc_url: Option<String>,

    /// Path to a suppression config acknowledging known, intentional breaking
    /// changes. When omitted, `.safeguard.toml` in the current directory is
    /// used if present; otherwise no suppressions are applied.
    #[arg(long, value_name = "CONFIG")]
    pub config: Option<PathBuf>,

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    pub explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    pub strict: bool,

    /// Do not color output
    #[arg(long)]
    pub no_color: bool,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    pub manifest: Option<PathBuf>,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    pub old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    pub new_dir: Option<PathBuf>,

    /// Maximum XDR decode depth per entry. Overrides `[limits]` in the config
    /// file and the built-in default. Guards against stack-overflow inputs.
    #[arg(long, value_name = "N")]
    pub max_xdr_depth: Option<u32>,

    /// Maximum bytes decoded per WASM custom section. Overrides `[limits]` and
    /// the default. Guards against oversized-length allocation inputs.
    #[arg(long, value_name = "BYTES")]
    pub max_xdr_len: Option<usize>,

    /// Maximum decoded spec entries, summed across all sections. Overrides
    /// `[limits]` and the default.
    #[arg(long, value_name = "N")]
    pub max_entries: Option<usize>,

    /// Maximum recursive type-walk depth (equality, rendering, cascade
    /// detection). Overrides `[limits]` and the default.
    #[arg(long, value_name = "N")]
    pub max_walk_depth: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub format: Option<OutputFormat>,
    pub explain: Option<bool>,
    pub strict: Option<bool>,
    pub no_color: Option<bool>,
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    pub contract_id: Option<String>,
    pub rpc_url: Option<String>,
    pub manifest: Option<PathBuf>,
    pub old_dir: Option<PathBuf>,
    pub new_dir: Option<PathBuf>,
    pub wasm_paths: Option<Vec<PathBuf>>,
    pub limits: Option<LimitsConfig>,
    #[serde(default, rename = "suppress")]
    pub suppress: Vec<SuppressionRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedConfig {
    pub wasm_paths: Vec<PathBuf>,
    pub contract_id: Option<String>,
    pub rpc_url: Option<String>,
    pub config: Option<PathBuf>,
    pub format: OutputFormat,
    pub explain: bool,
    pub strict: bool,
    pub no_color: bool,
    pub manifest: Option<PathBuf>,
    pub old_dir: Option<PathBuf>,
    pub new_dir: Option<PathBuf>,
    pub policy: ResourcePolicy,
    pub suppressions: SuppressionConfig,
}

impl ResolvedConfig {
    pub fn resolve(args: Args) -> Result<Self> {
        // 1. Identify config file path
        let config_file_path = match &args.config {
            Some(path) => Some(path.clone()),
            None => {
                let default_path = Path::new(crate::suppression::DEFAULT_CONFIG_FILE);
                if default_path.exists() {
                    Some(default_path.to_path_buf())
                } else {
                    None
                }
            }
        };

        // 2. Load file if present
        let file_config = if let Some(path) = &config_file_path {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read configuration file '{}'", path.display()))?;
            let parsed: FileConfig = toml::from_str(&content)
                .with_context(|| format!("Invalid configuration file '{}'", path.display()))?;
            Some(parsed)
        } else {
            None
        };

        let base_dir = config_file_path.as_ref()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| Path::new("."));

        // 3. Layer settings (CLI > Env > Config File > Defaults)
        let contract_id = args.contract_id.clone()
            .or_else(|| env_string("SAFEGUARD_CONTRACT_ID"))
            .or_else(|| file_config.as_ref().and_then(|fc| fc.contract_id.clone()));

        let rpc_url = args.rpc_url.clone()
            .or_else(|| env_string("SAFEGUARD_RPC_URL"))
            .or_else(|| file_config.as_ref().and_then(|fc| fc.rpc_url.clone()));

        let manifest = args.manifest.clone()
            .or_else(|| env_path("SAFEGUARD_MANIFEST"))
            .or_else(|| {
                file_config.as_ref()
                    .and_then(|fc| fc.manifest.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let old_dir = args.old_dir.clone()
            .or_else(|| env_path("SAFEGUARD_OLD_DIR"))
            .or_else(|| {
                file_config.as_ref()
                    .and_then(|fc| fc.old_dir.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let new_dir = args.new_dir.clone()
            .or_else(|| env_path("SAFEGUARD_NEW_DIR"))
            .or_else(|| {
                file_config.as_ref()
                    .and_then(|fc| fc.new_dir.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let wasm_paths = if !args.wasm_paths.is_empty() {
            args.wasm_paths.clone()
        } else if let Some(paths) = env_path_list("SAFEGUARD_WASM_PATHS") {
            paths
        } else if let Some(fc) = &file_config {
            fc.wasm_paths.clone()
                .unwrap_or_default()
                .into_iter()
                .map(|p| resolve_path(base_dir, p))
                .collect()
        } else {
            Vec::new()
        };

        let format = if args.format != OutputFormat::default() {
            args.format
        } else if let Some(fmt) = env_format("SAFEGUARD_FORMAT") {
            fmt
        } else if let Some(fc) = &file_config {
            fc.format.unwrap_or_default()
        } else {
            OutputFormat::default()
        };

        let explain = args.explain
            || env_bool("SAFEGUARD_EXPLAIN").unwrap_or(false)
            || file_config.as_ref().and_then(|fc| fc.explain).unwrap_or(false);

        let strict = args.strict
            || env_bool("SAFEGUARD_STRICT").unwrap_or(false)
            || file_config.as_ref().and_then(|fc| fc.strict).unwrap_or(false);

        let no_color = args.no_color
            || env_bool("SAFEGUARD_NO_COLOR").unwrap_or(false)
            || env_bool("NO_COLOR").unwrap_or(false)
            || file_config.as_ref().and_then(|fc| fc.no_color).unwrap_or(false);

        // Policy limits resolution
        let mut policy = ResourcePolicy::default();
        if let Some(fc) = &file_config {
            if let Some(limits) = &fc.limits {
                policy = limits.apply_to(policy);
            }
        }
        if let Some(v) = env_u32("SAFEGUARD_MAX_XDR_DEPTH") {
            policy.max_xdr_depth = v;
        }
        if let Some(v) = env_usize("SAFEGUARD_MAX_XDR_LEN") {
            policy.max_xdr_len = v;
        }
        if let Some(v) = env_usize("SAFEGUARD_MAX_ENTRIES") {
            policy.max_entries = v;
        }
        if let Some(v) = env_usize("SAFEGUARD_MAX_WALK_DEPTH") {
            policy.max_walk_depth = v;
        }
        if let Some(v) = args.max_xdr_depth {
            policy.max_xdr_depth = v;
        }
        if let Some(v) = args.max_xdr_len {
            policy.max_xdr_len = v;
        }
        if let Some(v) = args.max_entries {
            policy.max_entries = v;
        }
        if let Some(v) = args.max_walk_depth {
            policy.max_walk_depth = v;
        }

        // Suppressions config resolution
        let mut suppressions = SuppressionConfig::default();
        if let Some(fc) = &file_config {
            suppressions.max_suppressions = fc.max_suppressions;
            suppressions.allow_targetless = fc.allow_targetless;
            suppressions.rules = fc.suppress.clone();
        }
        if let Some(v) = env_usize("SAFEGUARD_MAX_SUPPRESSIONS") {
            suppressions.max_suppressions = Some(v);
        }
        if let Some(v) = env_bool("SAFEGUARD_ALLOW_TARGETLESS") {
            suppressions.allow_targetless = Some(v);
        }

        suppressions.validate()?;

        Ok(Self {
            wasm_paths,
            contract_id,
            rpc_url,
            config: config_file_path,
            format,
            explain,
            strict,
            no_color,
            manifest,
            old_dir,
            new_dir,
            policy,
            suppressions,
        })
    }

    /// Centralized mode detection and validation.
    /// Ensures there are no conflicting options, missing dependencies, or invalid positional arg counts.
    pub fn validate_and_resolve_mode(&self) -> Result<RunMode> {
        let has_manifest = self.manifest.is_some();
        let has_dir_scan = self.old_dir.is_some() || self.new_dir.is_some();
        let has_rpc = self.contract_id.is_some() || self.rpc_url.is_some();

        if has_manifest && has_dir_scan {
            anyhow::bail!("Cannot specify both --manifest and --old-dir/--new-dir at the same time");
        }

        // Verify rpc settings are co-dependent
        if self.contract_id.is_some() != self.rpc_url.is_some() {
            anyhow::bail!("Both --contract-id and --rpc-url must be specified together");
        }

        // Check if batch mode is used
        let is_batch = has_manifest || has_dir_scan;
        if is_batch && !self.wasm_paths.is_empty() {
            anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
        }

        if has_manifest {
            Ok(RunMode::Manifest)
        } else if has_dir_scan {
            if self.old_dir.is_none() || self.new_dir.is_none() {
                anyhow::bail!("Both --old-dir and --new-dir must be specified together for directory scanning");
            }
            Ok(RunMode::DirScan)
        } else if has_rpc {
            // RPC Mode: exactly 1 positional WASM path (the new one)
            match self.wasm_paths.len() {
                1 => Ok(RunMode::Rpc),
                2 => anyhow::bail!("When using --contract-id, provide only the NEW_WASM path as a positional argument"),
                _ => anyhow::bail!(
                    "Expected exactly 1 positional WASM path when using --contract-id.\n\n\
                     Usage: soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
                ),
            }
        } else {
            // Local Mode: exactly 2 positional WASM paths
            match self.wasm_paths.len() {
                2 => Ok(RunMode::Local),
                1 => anyhow::bail!(
                    "Missing OLD_WASM path. Provide two WASM files, or use --contract-id and --rpc-url \
                     to fetch the old contract from chain.\n\n\
                     Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                     soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
                ),
                _ => anyhow::bail!(
                    "Expected 2 WASM path arguments.\n\n\
                     Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                     soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                     Or use batch mode:\n       \
                     soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                     soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
                ),
            }
        }
    }
}

/// The detected operating mode of the safeguard execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    Local,
    Rpc,
    Manifest,
    DirScan,
}

fn resolve_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn env_bool(var_name: &str) -> Option<bool> {
    std::env::var(var_name).ok().and_then(|val| {
        let val_lower = val.to_lowercase();
        if val_lower == "true" || val_lower == "1" {
            Some(true)
        } else if val_lower == "false" || val_lower == "0" {
            Some(false)
        } else {
            None
        }
    })
}

fn env_usize(var_name: &str) -> Option<usize> {
    std::env::var(var_name).ok().and_then(|val| val.parse().ok())
}

fn env_u32(var_name: &str) -> Option<u32> {
    std::env::var(var_name).ok().and_then(|val| val.parse().ok())
}

fn env_string(var_name: &str) -> Option<String> {
    std::env::var(var_name).ok().filter(|s| !s.is_empty())
}

fn env_path(var_name: &str) -> Option<PathBuf> {
    std::env::var_os(var_name).map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

fn env_path_list(var_name: &str) -> Option<Vec<PathBuf>> {
    std::env::var(var_name).ok().filter(|s| !s.is_empty()).map(|s| {
        s.split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(PathBuf::from)
            .collect()
    })
}

fn env_format(var_name: &str) -> Option<OutputFormat> {
    std::env::var(var_name).ok().and_then(|val| {
        match val.to_lowercase().as_str() {
            "text" => Some(OutputFormat::Text),
            "json" => Some(OutputFormat::Json),
            "markdown" => Some(OutputFormat::Markdown),
            _ => None,
        }
    })
}
