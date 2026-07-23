use std::fs;
use std::env;
use std::path::PathBuf;
use std::sync::Mutex;

use soroban_upgrade_safeguard::config::{Args, ResolvedConfig, RunMode, OutputFormat};
use soroban_upgrade_safeguard::limits::ResourcePolicy;

// Global lock to serialize test execution and prevent environment variable race conditions
static ENV_LOCK: Mutex<()> = Mutex::new(());

// Helper to clear environment variables that might interfere with tests.
fn clear_safeguard_env() {
    let vars = [
        "SAFEGUARD_STRICT",
        "SAFEGUARD_EXPLAIN",
        "SAFEGUARD_NO_COLOR",
        "NO_COLOR",
        "SAFEGUARD_FORMAT",
        "SAFEGUARD_CONTRACT_ID",
        "SAFEGUARD_RPC_URL",
        "SAFEGUARD_MANIFEST",
        "SAFEGUARD_OLD_DIR",
        "SAFEGUARD_NEW_DIR",
        "SAFEGUARD_WASM_PATHS",
        "SAFEGUARD_MAX_XDR_DEPTH",
        "SAFEGUARD_MAX_XDR_LEN",
        "SAFEGUARD_MAX_ENTRIES",
        "SAFEGUARD_MAX_WALK_DEPTH",
        "SAFEGUARD_MAX_SUPPRESSIONS",
        "SAFEGUARD_ALLOW_TARGETLESS",
    ];
    for var in &vars {
        env::remove_var(var);
    }
}

#[test]
fn test_default_config_resolution() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // Default arguments
    let args = Args {
        wasm_paths: vec![PathBuf::from("old.wasm"), PathBuf::from("new.wasm")],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: None,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.wasm_paths, vec![PathBuf::from("old.wasm"), PathBuf::from("new.wasm")]);
    assert_eq!(resolved.format, OutputFormat::Text);
    assert_eq!(resolved.explain, false);
    assert_eq!(resolved.strict, false);
    assert_eq!(resolved.no_color, false);
    assert_eq!(resolved.policy.max_xdr_depth, ResourcePolicy::default().max_xdr_depth);
}

#[test]
fn test_cli_overrides_env_and_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_cli_overrides.toml");

    fs::write(
        &config_path,
        r#"
        strict = false
        explain = false
        [limits]
        max_xdr_depth = 10
        "#,
    ).unwrap();

    // Env vars set values to false/low limits
    env::set_var("SAFEGUARD_STRICT", "false");
    env::set_var("SAFEGUARD_EXPLAIN", "false");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "20");

    // CLI overrides everything to true / high limits
    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Json,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: true, // CLI wins (true)
        strict: true,  // CLI wins (true)
        no_color: true,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: Some(30), // CLI wins (30)
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.policy.max_xdr_depth, 30);

    clear_safeguard_env();
}

#[test]
fn test_env_overrides_file() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_env_overrides.toml");

    fs::write(
        &config_path,
        r#"
        strict = false
        explain = false
        [limits]
        max_xdr_depth = 10
        "#,
    ).unwrap();

    // Env vars set values
    env::set_var("SAFEGUARD_STRICT", "true");
    env::set_var("SAFEGUARD_EXPLAIN", "true");
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "20");

    // CLI has None/false, so Env overrides File
    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Json,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.strict, true);
    assert_eq!(resolved.explain, true);
    assert_eq!(resolved.policy.max_xdr_depth, 20);

    clear_safeguard_env();
}

#[test]
fn test_relative_path_resolution() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_relative_paths.toml");

    // Write config file with relative paths
    fs::write(
        &config_path,
        r#"
        manifest = "manifest_rel.toml"
        old_dir = "old_rel"
        new_dir = "new_rel"
        wasm_paths = ["a.wasm", "b.wasm"]
        "#,
    ).unwrap();

    let parent = config_path.parent().unwrap().canonicalize().unwrap();

    // Create dummy files/directories so canonicalize succeeds
    fs::write(parent.join("manifest_rel.toml"), "").unwrap();
    fs::create_dir_all(parent.join("old_rel")).unwrap();
    fs::create_dir_all(parent.join("new_rel")).unwrap();
    fs::write(parent.join("a.wasm"), "").unwrap();
    fs::write(parent.join("b.wasm"), "").unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();

    assert_eq!(
        resolved.manifest.unwrap().canonicalize().unwrap(),
        parent.join("manifest_rel.toml").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.old_dir.unwrap().canonicalize().unwrap(),
        parent.join("old_rel").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.new_dir.unwrap().canonicalize().unwrap(),
        parent.join("new_rel").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.wasm_paths[0].canonicalize().unwrap(),
        parent.join("a.wasm").canonicalize().unwrap()
    );
    assert_eq!(
        resolved.wasm_paths[1].canonicalize().unwrap(),
        parent.join("b.wasm").canonicalize().unwrap()
    );
}

#[test]
fn test_mode_resolutions() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. Local Mode
    let config_local = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("a.wasm"), PathBuf::from("b.wasm")],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert_eq!(config_local.validate_and_resolve_mode().unwrap(), RunMode::Local);

    // 2. RPC Mode
    let config_rpc = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: Some("C123".to_string()),
        rpc_url: Some("http://localhost".to_string()),
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert_eq!(config_rpc.validate_and_resolve_mode().unwrap(), RunMode::Rpc);

    // 3. Manifest Mode
    let config_manifest = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: Some(PathBuf::from("manifest.toml")),
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert_eq!(config_manifest.validate_and_resolve_mode().unwrap(), RunMode::Manifest);

    // 4. DirScan Mode
    let config_dir = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: Some(PathBuf::from("old")),
        new_dir: Some(PathBuf::from("new")),
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert_eq!(config_dir.validate_and_resolve_mode().unwrap(), RunMode::DirScan);
}

#[test]
fn test_invalid_mode_combinations() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // Manifest and DirScan specified together
    let config_conflict = ResolvedConfig {
        wasm_paths: vec![],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: Some(PathBuf::from("manifest.toml")),
        old_dir: Some(PathBuf::from("old")),
        new_dir: Some(PathBuf::from("new")),
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert!(config_conflict.validate_and_resolve_mode().is_err());

    // RPC missing rpc_url
    let config_missing_rpc = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: Some("C123".to_string()),
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert!(config_missing_rpc.validate_and_resolve_mode().is_err());

    // Local missing old WASM path
    let config_missing_wasm = ResolvedConfig {
        wasm_paths: vec![PathBuf::from("b.wasm")],
        contract_id: None,
        rpc_url: None,
        config: None,
        format: OutputFormat::Text,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        policy: ResourcePolicy::default(),
        suppressions: Default::default(),
    };
    assert!(config_missing_wasm.validate_and_resolve_mode().is_err());
}

#[test]
fn test_unknown_fields_rejection() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_unknown_fields.toml");

    // TOML config file with unknown keys
    fs::write(
        &config_path,
        r#"
        strict = false
        unknown_key_name_invalid = "hello"
        "#,
    ).unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    assert!(ResolvedConfig::resolve(args).is_err());
}

#[test]
fn test_env_parsing_edge_cases() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();

    // 1. SAFEGUARD_WASM_PATHS contains spaces and empty elements
    env::set_var("SAFEGUARD_WASM_PATHS", "  a.wasm , ,  b.wasm ");
    // 2. Limits env vars contain non-integers (should be ignored / fallback to defaults)
    env::set_var("SAFEGUARD_MAX_XDR_DEPTH", "notaninteger");
    // 3. Boolean env vars contain garbage (should fallback to false)
    env::set_var("SAFEGUARD_STRICT", "garbage");
    // 4. SAFEGUARD_FORMAT contains garbage (should fallback to default)
    env::set_var("SAFEGUARD_FORMAT", "yaml");

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: None,
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.wasm_paths, vec![PathBuf::from("a.wasm"), PathBuf::from("b.wasm")]);
    assert_eq!(resolved.policy.max_xdr_depth, ResourcePolicy::default().max_xdr_depth);
    assert_eq!(resolved.strict, false);
    assert_eq!(resolved.format, OutputFormat::Text);

    clear_safeguard_env();
}

#[test]
fn test_file_config_partial_deserialization() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_partial_deserialization.toml");

    fs::write(
        &config_path,
        r#"
        no_color = true
        [limits]
        max_entries = 555
        "#,
    ).unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: false,
        strict: false,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: None,
        max_xdr_len: None,
        max_entries: None,
        max_walk_depth: None,
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    assert_eq!(resolved.no_color, true);
    assert_eq!(resolved.policy.max_entries, 555);
    // Other values should fall back to default
    assert_eq!(resolved.policy.max_xdr_depth, ResourcePolicy::default().max_xdr_depth);
}

#[test]
fn test_verdict_settings_mapping() {
    let _guard = ENV_LOCK.lock().unwrap();
    clear_safeguard_env();
    let temp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let config_path = temp_dir.join("config_verdict_settings.toml");

    fs::write(
        &config_path,
        r#"
        max_suppressions = 999
        allow_targetless = true
        "#,
    ).unwrap();

    let args = Args {
        wasm_paths: vec![],
        format: OutputFormat::Text,
        contract_id: None,
        rpc_url: None,
        config: Some(config_path),
        explain: true,
        strict: true,
        no_color: false,
        manifest: None,
        old_dir: None,
        new_dir: None,
        max_xdr_depth: Some(15),
        max_xdr_len: Some(8888),
        max_entries: Some(777),
        max_walk_depth: Some(66),
    };

    let resolved = ResolvedConfig::resolve(args).unwrap();
    let diff_report = soroban_upgrade_safeguard::diff::DiffReport::default();
    let report = soroban_upgrade_safeguard::report::SafetyReport::with_suppressions(
        &diff_report,
        &resolved.suppressions,
        resolved.explain,
        resolved.strict,
        &resolved.policy,
    );

    assert_eq!(report.settings.strict, true);
    assert_eq!(report.settings.explain, true);
    assert_eq!(report.settings.max_suppressions, Some(999));
    assert_eq!(report.settings.allow_targetless, Some(true));
    assert_eq!(report.settings.max_xdr_depth, 15);
    assert_eq!(report.settings.max_xdr_len, 8888);
    assert_eq!(report.settings.max_entries, 777);
    assert_eq!(report.settings.max_walk_depth, 66);
}
