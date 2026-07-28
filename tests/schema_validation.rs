//! JSON Schema for the report output (issue #128).
//!
//! The schema is DERIVED from the serializer types (`SafetyReportJson` and the
//! batch document mirrored by `BatchReport` below) so it cannot drift away from
//! what the tool actually emits. Two guarantees are enforced here:
//!
//! 1. `schemas_match_the_types` — the committed `schema/*.json` files equal what
//!    the derive produces now. Run with `UPDATE_SCHEMA=1` to regenerate them
//!    after intentionally changing an output type.
//! 2. `*_output_matches_schema` — real JSON emitted by the built binary (a plain
//!    run, a run with suppressed findings, a run with `--explain`, and a batch
//!    run) validates against the committed schema.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use schemars::JsonSchema;
use serde_json::Value;
use soroban_upgrade_safeguard::report::SafetyReportJson;

const BIN: &str = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn wasm(name: &str) -> PathBuf {
    manifest_dir().join("tests").join("wasm").join(name)
}

fn schema_path(name: &str) -> PathBuf {
    manifest_dir().join("schema").join(name)
}

// ---------------------------------------------------------------------------
// Batch document shape.
//
// The batch JSON is assembled ad hoc in main.rs (there is no serializer struct),
// so this owned mirror exists purely to derive its schema. It reuses the derived
// `SafetyReportJson` schema for each per-contract result, guaranteeing the batch
// and single-pair shapes stay consistent. `schemas_match_the_types` + the batch
// validation test together catch any drift between this mirror and real output.
// ---------------------------------------------------------------------------
#[derive(JsonSchema)]
#[allow(dead_code)]
struct BatchReport<'a> {
    is_safe: bool,
    strict: bool,
    total_pairs: usize,
    limit_violation: bool,
    recommended_bump: String,
    results: BTreeMap<String, SafetyReportJson<'a>>,
    failed: BTreeMap<String, FailedPair>,
    cross_contract_findings: BTreeMap<String, Vec<Value>>,
    dependency_findings: Vec<Value>,
}

#[derive(JsonSchema)]
#[allow(dead_code)]
struct FailedPair {
    error: String,
    limit_violation: bool,
}

fn derived_schema<T: JsonSchema>() -> Value {
    let root = schemars::gen::SchemaGenerator::default().into_root_schema_for::<T>();
    let mut value = serde_json::to_value(root).expect("schema serializes");
    constrain_recommended_bump(&mut value);
    value
}

/// `recommended_bump` is a plain string in the types but only ever takes one of
/// three values; constrain it to the allowed set wherever it appears (including
/// inside the embedded single-pair definition of the batch schema).
fn constrain_recommended_bump(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(props)) = map.get_mut("properties") {
                if props.contains_key("recommended_bump") {
                    props.insert(
                        "recommended_bump".to_string(),
                        serde_json::json!({
                            "type": "string",
                            "enum": ["major", "minor", "patch"],
                        }),
                    );
                }
            }
            for v in map.values_mut() {
                constrain_recommended_bump(v);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(constrain_recommended_bump),
        _ => {}
    }
}

fn pretty(value: &Value) -> String {
    let mut s = serde_json::to_string_pretty(value).expect("pretty json");
    s.push('\n');
    s
}

#[test]
fn schemas_match_the_types() {
    let cases = [
        (
            "report.schema.json",
            derived_schema::<SafetyReportJson<'static>>(),
        ),
        (
            "batch-report.schema.json",
            derived_schema::<BatchReport<'static>>(),
        ),
    ];

    for (name, generated) in cases {
        let path = schema_path(name);
        if std::env::var_os("UPDATE_SCHEMA").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, pretty(&generated)).unwrap();
            continue;
        }
        let committed: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("read {}: {e} (run with UPDATE_SCHEMA=1)", path.display())
            }))
            .expect("committed schema is valid json");
        assert_eq!(
            committed, generated,
            "{name} is out of date with the output types — re-run with UPDATE_SCHEMA=1"
        );
    }
}

fn load_schema(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(schema_path(name)).expect("read schema"))
        .expect("schema is valid json")
}

fn validate(schema: &Value, instance: &Value, ctx: &str) {
    let compiled = jsonschema::JSONSchema::compile(schema).expect("committed schema compiles");
    // Materialize any errors into owned strings before `compiled` drops (the
    // error iterator borrows it).
    let details: Vec<String> = match compiled.validate(instance) {
        Ok(()) => Vec::new(),
        Err(errors) => errors
            .map(|e| format!("  - {e} (at {})", e.instance_path))
            .collect(),
    };
    assert!(
        details.is_empty(),
        "{ctx}: emitted JSON does not satisfy the committed schema:\n{}",
        details.join("\n")
    );
}

fn run_json(args: &[&str]) -> Value {
    let output = Command::new(BIN)
        .args(args)
        .output()
        .expect("run the binary");
    // A run that finds breaking changes exits 1; both 0 and 1 still print a
    // complete JSON document to stdout, which is what we validate.
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}); status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

#[test]
fn single_pair_output_matches_schema() {
    let schema = load_schema("report.schema.json");
    let v1 = wasm("v1.wasm");
    let v2 = wasm("v2.wasm");
    let (v1, v2) = (v1.to_str().unwrap(), v2.to_str().unwrap());

    // Plain run.
    let plain = run_json(&[v1, v2, "--format", "json"]);
    validate(&schema, &plain, "plain single-pair");

    // Run with `--explain`, which adds `remediation` to findings.
    let explained = run_json(&[v1, v2, "--format", "json", "--explain"]);
    assert!(
        pretty(&explained).contains("remediation"),
        "--explain output should carry remediation guidance"
    );
    validate(&schema, &explained, "--explain single-pair");

    // Run with a suppression config, which marks findings suppressed and adds
    // the `suppressed`/`suppression_*` fields. Both suppressed targets below are
    // real findings in the v1 -> v2 comparison.
    let config = concat!(
        "[[suppress]]\n",
        "category = \"Struct Field Removed\"\n",
        "target = \"ConfigData.threshold\"\n",
        "reason = \"planned migration\"\n",
        "\n",
        "[[suppress]]\n",
        "category = \"Function Signature Changed\"\n",
        "target = \"initialize\"\n",
        "reason = \"intentional re-init\"\n",
    );
    let config_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("suppress.safeguard.toml");
    std::fs::write(&config_path, config).unwrap();
    let suppressed = run_json(&[
        v1,
        v2,
        "--format",
        "json",
        "--config",
        config_path.to_str().unwrap(),
    ]);
    assert!(
        suppressed["suppressed_count"].as_u64().unwrap_or(0) >= 2,
        "expected at least two suppressed findings, got {}",
        suppressed["suppressed_count"]
    );
    validate(&schema, &suppressed, "suppressed single-pair");
}

#[test]
fn batch_output_matches_schema() {
    let schema = load_schema("batch-report.schema.json");

    // Directory batch mode compares files with matching names across two dirs.
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("batch");
    let old_dir = tmp.join("old");
    let new_dir = tmp.join("new");
    std::fs::create_dir_all(&old_dir).unwrap();
    std::fs::create_dir_all(&new_dir).unwrap();
    std::fs::copy(wasm("v1.wasm"), old_dir.join("token.wasm")).unwrap();
    std::fs::copy(wasm("v2.wasm"), new_dir.join("token.wasm")).unwrap();

    let batch = run_json(&[
        "--old-dir",
        old_dir.to_str().unwrap(),
        "--new-dir",
        new_dir.to_str().unwrap(),
        "--format",
        "json",
    ]);
    validate(&schema, &batch, "batch");
}
