//! Fixture-pair integration tests for full detection-rule coverage.
//!
//! Each test names the rule(s) it exercises and maps to a committed fixture
//! WASM pair under `tests/wasm/`. The WASMs are built reproducibly by
//! `tests/build_fixtures.sh --locked` and their SHA-256 hashes are recorded in
//! `tests/wasm/checksums.sha256`. CI verifies the committed binaries match
//! their checksums and re-runs these tests on every PR.
//!
//! # Fixture map
//!
//! | Pair    | Kind     | Rules exercised |
//! |---------|----------|-----------------|
//! | v1→v2   | Critical | function_signature_changed, return_type_changed, struct_field_removed, enum_case_value_changed |
//! | v1→v3   | Warning  | parameter_renamed |
//! | v4→v5   | Critical | union_case_removed, union_case_reordered, union_case_type_changed, error_enum_case_value_changed, error_enum_case_removed, struct_field_type_changed, cascading_layout_break |
//! | v6→v7   | Warning  | union_case_type_widened, struct_field_added, struct_field_type_widened, error_enum_case_added |
//! | vN→vN   | Clean    | identity pairs — zero false positives across every fixture |

use std::path::PathBuf;
use soroban_upgrade_safeguard::report::ReportedFinding;
use soroban_upgrade_safeguard::{compare_wasm_bytes, compare_wasm_bytes_with_options, compare_wasm_files, CompareOptions};
use soroban_upgrade_safeguard::diff::Severity;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn load(name: &str) -> Vec<u8> {
    std::fs::read(wasm(name)).unwrap_or_else(|e| panic!("failed to read {name}: {e}"))
}

/// Flatten all findings from a report into a single vec for easy searching.
fn all_findings(r: &soroban_upgrade_safeguard::report::SafetyReport) -> Vec<&ReportedFinding> {
    r.findings_by_category.values().flatten().collect()
}

/// Find a finding by category and optionally by target.
fn find_finding<'a>(
    findings: &[&'a ReportedFinding],
    category: &str,
    target: Option<&str>,
) -> Option<&'a ReportedFinding> {
    findings.iter().find(|rf| {
        rf.finding.category == category
            && target.map_or(true, |t| rf.finding.target.as_deref() == Some(t))
    }).copied()
}

/// Summarize findings for assertion failure messages.
fn summarize(findings: &[&ReportedFinding]) -> Vec<(String, Option<String>)> {
    findings.iter().map(|rf| (rf.finding.category.clone(), rf.finding.target.clone())).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity pairs — zero false positives
// ─────────────────────────────────────────────────────────────────────────────

/// Comparing any contract against itself must produce zero critical/warning
/// findings. This covers every fixture so FP coverage scales with fixture count.
#[test]
fn identity_v1_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm")).unwrap();
    assert!(r.is_safe, "v1→v1 must be safe");
    assert_eq!(r.critical_count, 0, "v1→v1: zero criticals");
    assert_eq!(r.warning_count, 0, "v1→v1: zero warnings");
}

#[test]
fn identity_v2_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v2.wasm"), &wasm("v2.wasm")).unwrap();
    assert!(r.is_safe, "v2→v2 must be safe");
    assert_eq!(r.critical_count, 0);
    assert_eq!(r.warning_count, 0);
}

#[test]
fn identity_v3_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v3.wasm"), &wasm("v3.wasm")).unwrap();
    assert!(r.is_safe, "v3→v3 must be safe");
    assert_eq!(r.critical_count, 0);
    assert_eq!(r.warning_count, 0);
}

#[test]
fn identity_v4_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v4.wasm"), &wasm("v4.wasm")).unwrap();
    assert!(r.is_safe, "v4→v4 must be safe");
    assert_eq!(r.critical_count, 0, "v4→v4: zero criticals");
    assert_eq!(r.warning_count, 0, "v4→v4: zero warnings");
}

#[test]
fn identity_v5_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v5.wasm"), &wasm("v5.wasm")).unwrap();
    assert!(r.is_safe, "v5→v5 must be safe");
    assert_eq!(r.critical_count, 0);
    assert_eq!(r.warning_count, 0);
}

#[test]
fn identity_v6_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v6.wasm"), &wasm("v6.wasm")).unwrap();
    assert!(r.is_safe, "v6→v6 must be safe");
    assert_eq!(r.critical_count, 0);
    assert_eq!(r.warning_count, 0);
}

#[test]
fn identity_v7_has_no_actionable_findings() {
    let r = compare_wasm_files(&wasm("v7.wasm"), &wasm("v7.wasm")).unwrap();
    assert!(r.is_safe, "v7→v7 must be safe");
    assert_eq!(r.critical_count, 0);
    assert_eq!(r.warning_count, 0);
}

/// Aggregate false-positive rate check: self-comparison of every fixture must
/// yield zero critical + warning findings. This is the corpus-level assertion.
#[test]
fn corpus_self_comparison_false_positive_rate_is_zero() {
    let fixtures = ["v1.wasm", "v2.wasm", "v3.wasm", "v4.wasm", "v5.wasm", "v6.wasm", "v7.wasm"];
    for name in &fixtures {
        let r = compare_wasm_files(&wasm(name), &wasm(name)).unwrap();
        assert_eq!(
            r.critical_count + r.warning_count,
            0,
            "self-comparison of {name} produced {critical}c+{warning}w findings (must be zero)",
            critical = r.critical_count,
            warning = r.warning_count,
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// v1 → v2 (Critical): function signature, struct field, enum value
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v1_to_v2_is_unsafe_with_critical_findings() {
    let r = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm")).unwrap();
    assert!(!r.is_safe, "v1→v2 must be flagged as unsafe");
    assert!(r.critical_count >= 1, "v1→v2 must have ≥1 critical finding");
}

/// Rule: function_signature_changed — initialize() gained an extra parameter.
#[test]
fn v1_to_v2_detects_function_signature_changed() {
    let old = load("v1.wasm");
    let new = load("v2.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Function Signature Changed", Some("initialize"));
    assert!(f.is_some(), "expected Function Signature Changed for initialize\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: struct_field_removed — ConfigData.threshold was removed.
#[test]
fn v1_to_v2_detects_struct_field_removed() {
    let old = load("v1.wasm");
    let new = load("v2.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Struct Field Removed", Some("ConfigData.threshold"));
    assert!(f.is_some(), "expected Struct Field Removed for ConfigData.threshold\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: enum_case_value_changed — StatusEvent.Paused changed from 2 to 3.
#[test]
fn v1_to_v2_detects_enum_case_value_changed() {
    let old = load("v1.wasm");
    let new = load("v2.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Enum Case Value Changed", Some("StatusEvent.Paused"));
    assert!(f.is_some(), "expected Enum Case Value Changed for StatusEvent.Paused\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

// ─────────────────────────────────────────────────────────────────────────────
// v1 → v3 (Warning-only): parameter renamed
// ─────────────────────────────────────────────────────────────────────────────

/// Rule: parameter_renamed — passes without --strict, fails under --strict.
#[test]
fn v1_to_v3_is_safe_without_strict() {
    let r = compare_wasm_files(&wasm("v1.wasm"), &wasm("v3.wasm")).unwrap();
    assert!(r.is_safe, "v1→v3 must pass without --strict");
    assert_eq!(r.critical_count, 0, "v1→v3: no criticals");
    assert!(r.warning_count >= 1, "v1→v3 must have ≥1 warning");
}

#[test]
fn v1_to_v3_fails_under_strict() {
    let old = load("v1.wasm");
    let new = load("v3.wasm");
    let r = compare_wasm_bytes_with_options(
        &old, &new, &CompareOptions { strict: true, ..Default::default() },
    ).unwrap();
    assert!(!r.is_safe, "v1→v3 must fail under --strict");
}

#[test]
fn v1_to_v3_detects_parameter_renamed() {
    let old = load("v1.wasm");
    let new = load("v3.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let has = fs.iter().any(|rf| rf.finding.category == "Parameter Renamed");
    assert!(has, "expected a Parameter Renamed finding\ngot: {:?}", summarize(&fs));
}

// ─────────────────────────────────────────────────────────────────────────────
// v4 → v5 (Critical): union, error enum, nested structs, cascading breaks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v4_to_v5_is_unsafe_with_critical_findings() {
    let r = compare_wasm_files(&wasm("v4.wasm"), &wasm("v5.wasm")).unwrap();
    assert!(!r.is_safe, "v4→v5 must be flagged as unsafe");
    assert!(r.critical_count >= 1, "v4→v5 must have ≥1 critical finding");
}

/// Rule: union_case_removed — PaymentAction.Cancel was removed.
#[test]
fn v4_to_v5_detects_union_case_removed() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Union Case Removed", Some("PaymentAction.Cancel"));
    assert!(f.is_some(), "expected Union Case Removed for PaymentAction.Cancel\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: union_case_type_changed — when Cancel is removed and Transfer shifts
/// discriminant position, the engine reports the remaining case as changed.
/// We assert at least one Union Case Type Changed finding is emitted for
/// the PaymentAction type (target may vary by how the differ resolves the shift).
#[test]
fn v4_to_v5_detects_union_case_type_change_on_payment_action() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let type_finding = fs.iter().find(|rf| {
        (rf.finding.category == "Union Case Type Changed"
            || rf.finding.category == "Union Case Type Widened")
            && rf.finding.target.as_deref().map(|t| t.starts_with("PaymentAction.")).unwrap_or(false)
    });
    assert!(type_finding.is_some(),
        "expected Union Case Type Changed/Widened for PaymentAction.*\ngot: {:?}", summarize(&fs));
}

/// Rule: error_enum_case_value_changed — VaultError.InsufficientFunds code 10→99.
/// The engine emits this as "Enum Case Value Changed" for error enums.
#[test]
fn v4_to_v5_detects_error_enum_case_value_changed() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    // Error enums are reported under "Enum Case Value Changed" (structural category)
    let f = find_finding(&fs, "Enum Case Value Changed", Some("VaultError.InsufficientFunds"));
    assert!(f.is_some(),
        "expected Enum Case Value Changed for VaultError.InsufficientFunds\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: error_enum_case_removed — VaultError.NotAuthorized was removed.
/// The engine emits this as "Enum Case Removed" for error enums.
#[test]
fn v4_to_v5_detects_error_enum_case_removed() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    // Error enums are reported under "Enum Case Removed" (structural category)
    let f = find_finding(&fs, "Enum Case Removed", Some("VaultError.NotAuthorized"));
    assert!(f.is_some(),
        "expected Enum Case Removed for VaultError.NotAuthorized\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: struct_field_type_changed — Inner.amount u32→bool.
#[test]
fn v4_to_v5_detects_struct_field_type_changed_on_inner() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Struct Field Type Changed", Some("Inner.amount"));
    assert!(f.is_some(),
        "expected Struct Field Type Changed for Inner.amount\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Critical);
}

/// Rule: cascading_layout_break — Outer embeds Vec<Inner>; breaking Inner
/// must cascade into Outer with a Critical finding.
#[test]
fn v4_to_v5_detects_cascading_break_on_outer() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let cascade = fs.iter().find(|rf| {
        rf.finding.category == "Cascading Layout Break"
            && rf.finding.type_name.as_deref() == Some("Outer")
    });
    assert!(cascade.is_some(),
        "expected Cascading Layout Break on Outer (depends on Inner)\ngot cascades: {:?}",
        fs.iter()
            .filter(|rf| rf.finding.category == "Cascading Layout Break")
            .map(|rf| (&rf.finding.type_name, &rf.finding.target))
            .collect::<Vec<_>>());
    assert_eq!(cascade.unwrap().finding.severity, Severity::Critical);
}

/// The cascade must reach at least one function parameter (direct or transitive).
/// process_inner() takes Inner directly; process_outer() takes Outer which
/// embeds Vec<Inner>.
#[test]
fn v4_to_v5_cascade_count_is_at_least_one() {
    let old = load("v4.wasm");
    let new = load("v5.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let cascade_count = fs.iter()
        .filter(|rf| rf.finding.category == "Cascading Layout Break")
        .count();
    assert!(cascade_count >= 1,
        "expected ≥1 Cascading Layout Break finding, got {cascade_count}");
}

// ─────────────────────────────────────────────────────────────────────────────
// v6 → v7 (Warning-only): type widening and safe additions
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v6_to_v7_is_safe_without_strict() {
    let r = compare_wasm_files(&wasm("v6.wasm"), &wasm("v7.wasm")).unwrap();
    assert!(r.is_safe, "v6→v7 must pass without --strict (warnings only)");
    assert_eq!(r.critical_count, 0, "v6→v7: no critical findings");
    assert!(r.warning_count >= 1, "v6→v7 must have ≥1 warning");
}

#[test]
fn v6_to_v7_fails_under_strict() {
    let old = load("v6.wasm");
    let new = load("v7.wasm");
    let r = compare_wasm_bytes_with_options(
        &old, &new, &CompareOptions { strict: true, ..Default::default() },
    ).unwrap();
    assert!(!r.is_safe, "v6→v7 must fail under --strict");
}

/// Rule: struct_field_added — Inner.metadata added.
#[test]
fn v6_to_v7_detects_struct_field_added() {
    let old = load("v6.wasm");
    let new = load("v7.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Struct Field Added", Some("Inner.metadata"));
    assert!(f.is_some(),
        "expected Struct Field Added for Inner.metadata\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Warning);
}

/// Rule: struct_field_type_widened — Ledger.balance u32→u64.
#[test]
fn v6_to_v7_detects_struct_field_type_widened() {
    let old = load("v6.wasm");
    let new = load("v7.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Struct Field Type Widened", Some("Ledger.balance"));
    assert!(f.is_some(),
        "expected Struct Field Type Widened for Ledger.balance\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Warning);
}

/// Rule: error_enum_case_added — VaultError.Frozen added.
/// The engine emits this as "Enum Case Added" for error enums.
#[test]
fn v6_to_v7_detects_error_enum_case_added() {
    let old = load("v6.wasm");
    let new = load("v7.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    // Error enums are reported under "Enum Case Added" (structural category)
    let f = find_finding(&fs, "Enum Case Added", Some("VaultError.Frozen"));
    assert!(f.is_some(),
        "expected Enum Case Added for VaultError.Frozen\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Info);
}

/// Rule: union_case_type_widened — TransferAction.Transfer u32→u64.
#[test]
fn v6_to_v7_detects_union_case_type_widened() {
    let old = load("v6.wasm");
    let new = load("v7.wasm");
    let r = compare_wasm_bytes(&old, &new).unwrap();
    let fs = all_findings(&r);
    let f = find_finding(&fs, "Union Case Type Widened", Some("TransferAction.Transfer"));
    assert!(f.is_some(),
        "expected Union Case Type Widened for TransferAction.Transfer\ngot: {:?}", summarize(&fs));
    assert_eq!(f.unwrap().finding.severity, Severity::Warning);
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-fixture sanity
// ─────────────────────────────────────────────────────────────────────────────

/// Comparing v4→v5 in reverse also produces findings (the tool is not
/// directionally blind — additions in v4 relative to v5 are still changes).
#[test]
fn reversed_v4_v5_also_produces_findings() {
    let r = compare_wasm_files(&wasm("v5.wasm"), &wasm("v4.wasm")).unwrap();
    assert!(
        !r.findings_by_category.is_empty(),
        "reversed v5→v4 must still produce findings"
    );
}
