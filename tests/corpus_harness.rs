//! Corpus harness — rule-level coverage and false-positive measurement.
//!
//! Each contract pair is built directly from XDR types (no Soroban SDK, no
//! toolchain, no network). Fast (< 1 ms per pair), deterministic, any machine.
//!
//! Coverage: every rule in src/rules.rs not already pinned by a WASM fixture
//! pair in fixture_coverage.rs gets at least one test here.
//!
//! False-positive rate: `corpus_false_positive_rate_is_zero` compares every
//! corpus spec against itself — zero critical+warning findings required.
//!
//! Runtime budget: `corpus_runtime_budget` runs 100 iterations of the largest
//! pair and asserts completion under 1 second.

use std::time::Instant;

use soroban_upgrade_safeguard::diff::{compare, Severity};
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeUdt,
    ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0,
    StringM, VecM,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn fn_spec(
    name: &str,
    inputs: Vec<(&str, ScSpecTypeDef)>,
    output: Option<ScSpecTypeDef>,
) -> ContractSpec {
    let mut spec = ContractSpec::default();
    let xdr_inputs: Vec<ScSpecFunctionInputV0> = inputs
        .into_iter()
        .map(|(n, t)| ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: n.try_into().unwrap(),
            type_: t,
        })
        .collect();
    let outs: Vec<ScSpecTypeDef> = output.into_iter().collect();
    spec.functions.insert(
        name.to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
            inputs: VecM::try_from(xdr_inputs).unwrap(),
            outputs: VecM::try_from(outs).unwrap(),
        },
    );
    spec
}

fn struct_spec(name: &str, fields: Vec<(&str, ScSpecTypeDef)>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    let xdr: Vec<ScSpecUdtStructFieldV0> = fields
        .into_iter()
        .map(|(n, t)| ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: n.try_into().unwrap(),
            type_: t,
        })
        .collect();
    spec.structs.insert(
        name.to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: VecM::try_from(xdr).unwrap(),
        },
    );
    spec
}

fn enum_spec(name: &str, cases: Vec<(&str, u32)>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    let xdr: Vec<ScSpecUdtEnumCaseV0> = cases
        .into_iter()
        .map(|(n, v)| ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: n.try_into().unwrap(),
            value: v,
        })
        .collect();
    spec.enums.insert(
        name.to_string(),
        ScSpecUdtEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(xdr).unwrap(),
        },
    );
    spec
}

fn error_enum_spec(name: &str, cases: Vec<(&str, u32)>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    let xdr: Vec<ScSpecUdtErrorEnumCaseV0> = cases
        .into_iter()
        .map(|(n, v)| ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: n.try_into().unwrap(),
            value: v,
        })
        .collect();
    spec.error_enums.insert(
        name.to_string(),
        ScSpecUdtErrorEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(xdr).unwrap(),
        },
    );
    spec
}

fn union_spec(name: &str, cases: Vec<ScSpecUdtUnionCaseV0>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    spec.unions.insert(
        name.to_string(),
        ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(cases).unwrap(),
        },
    );
    spec
}

fn void_case(name: &str) -> ScSpecUdtUnionCaseV0 {
    ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
        doc: StringM::default(),
        name: name.try_into().unwrap(),
    })
}

fn tuple_case(name: &str, types: Vec<ScSpecTypeDef>) -> ScSpecUdtUnionCaseV0 {
    ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
        doc: StringM::default(),
        name: name.try_into().unwrap(),
        type_: VecM::try_from(types).unwrap(),
    })
}

fn udt(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: name.try_into().unwrap(),
    })
}

// Query helpers — search across all findings in a SafetyReport.
fn has(r: &SafetyReport, cat: &str) -> bool {
    r.findings_by_category
        .values()
        .flatten()
        .any(|rf| rf.finding.category == cat)
}

fn has_target(r: &SafetyReport, cat: &str, target: &str) -> bool {
    r.findings_by_category.values().flatten().any(|rf| {
        rf.finding.category == cat && rf.finding.target.as_deref() == Some(target)
    })
}

fn sev(r: &SafetyReport, cat: &str, target: Option<&str>) -> Option<Severity> {
    r.findings_by_category
        .values()
        .flatten()
        .find(|rf| {
            rf.finding.category == cat
                && target.map_or(true, |t| rf.finding.target.as_deref() == Some(t))
        })
        .map(|rf| rf.finding.severity.clone())
}

fn dump(r: &SafetyReport) -> Vec<(String, Option<String>)> {
    r.findings_by_category
        .values()
        .flatten()
        .map(|rf| (rf.finding.category.clone(), rf.finding.target.clone()))
        .collect()
}

// ── function_removed / function_added ────────────────────────────────────────

#[test]
fn corpus_function_removed_is_critical() {
    let old = fn_spec("deposit", vec![("amount", ScSpecTypeDef::U64)], None);
    let new = ContractSpec::default();
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Function Removed", Some("deposit")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_function_added_is_info() {
    let old = ContractSpec::default();
    let new = fn_spec("withdraw", vec![("amount", ScSpecTypeDef::U64)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe);
    assert_eq!(
        sev(&r, "Function Added", Some("withdraw")),
        Some(Severity::Info),
        "{:?}",
        dump(&r)
    );
}

// ── parameter_reordered / type_changed / narrowed / signedness / widened ─────

#[test]
fn corpus_parameter_reordered_is_critical() {
    let old = fn_spec("swap", vec![("from", ScSpecTypeDef::U32), ("to", ScSpecTypeDef::U32)], None);
    let new = fn_spec("swap", vec![("to", ScSpecTypeDef::U32), ("from", ScSpecTypeDef::U32)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Parameter Reordered", None),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_parameter_type_changed_is_critical() {
    let old = fn_spec("flag", vec![("x", ScSpecTypeDef::U32)], None);
    let new = fn_spec("flag", vec![("x", ScSpecTypeDef::Bool)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Parameter Type Changed", None),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_parameter_type_narrowed_is_critical() {
    let old = fn_spec("store", vec![("val", ScSpecTypeDef::U64)], None);
    let new = fn_spec("store", vec![("val", ScSpecTypeDef::U32)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Parameter Type Narrowed", None),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_parameter_type_signedness_changed_is_critical() {
    let old = fn_spec("store", vec![("val", ScSpecTypeDef::U32)], None);
    let new = fn_spec("store", vec![("val", ScSpecTypeDef::I32)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Parameter Type Signedness Changed", None),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_parameter_type_widened_is_warning() {
    let old = fn_spec("store", vec![("val", ScSpecTypeDef::U32)], None);
    let new = fn_spec("store", vec![("val", ScSpecTypeDef::U64)], None);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe, "widening must pass without --strict");
    assert_eq!(
        sev(&r, "Parameter Type Widened", None),
        Some(Severity::Warning),
        "{:?}",
        dump(&r)
    );
}

// ── return_type_changed / narrowed / signedness / widened ─────────────────────

#[test]
fn corpus_return_type_changed_is_critical() {
    let old = fn_spec("balance", vec![], Some(ScSpecTypeDef::U64));
    let new = fn_spec("balance", vec![], Some(ScSpecTypeDef::Bool));
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Return Type Changed", Some("balance")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_return_type_narrowed_is_critical() {
    let old = fn_spec("balance", vec![], Some(ScSpecTypeDef::U64));
    let new = fn_spec("balance", vec![], Some(ScSpecTypeDef::U32));
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Return Type Narrowed", Some("balance")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_return_type_signedness_changed_is_critical() {
    let old = fn_spec("value", vec![], Some(ScSpecTypeDef::U32));
    let new = fn_spec("value", vec![], Some(ScSpecTypeDef::I32));
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Return Type Signedness Changed", Some("value")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_return_type_widened_is_warning() {
    let old = fn_spec("value", vec![], Some(ScSpecTypeDef::U32));
    let new = fn_spec("value", vec![], Some(ScSpecTypeDef::U64));
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe, "widening return must pass without --strict");
    assert_eq!(
        sev(&r, "Return Type Widened", Some("value")),
        Some(Severity::Warning),
        "{:?}",
        dump(&r)
    );
}

// ── struct_removed / added / field_reordered / narrowed / signedness ──────────

#[test]
fn corpus_struct_removed_is_critical() {
    let old = struct_spec("Config", vec![("owner", ScSpecTypeDef::Address)]);
    let r = SafetyReport::new(&compare(&old, &ContractSpec::default()));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Struct Removed", Some("Config")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_struct_added_is_info() {
    let new = struct_spec("Config", vec![("owner", ScSpecTypeDef::Address)]);
    let r = SafetyReport::new(&compare(&ContractSpec::default(), &new));
    assert!(r.is_safe);
    assert_eq!(
        sev(&r, "Struct Added", Some("Config")),
        Some(Severity::Info),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_struct_field_reordered_is_critical() {
    let old = struct_spec("Pair", vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)]);
    let new = struct_spec("Pair", vec![("b", ScSpecTypeDef::U64), ("a", ScSpecTypeDef::U32)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Struct Field Reordered", None),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_struct_field_type_narrowed_is_critical() {
    let old = struct_spec("Ledger", vec![("balance", ScSpecTypeDef::I128)]);
    let new = struct_spec("Ledger", vec![("balance", ScSpecTypeDef::I32)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Struct Field Type Narrowed", Some("Ledger.balance")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_struct_field_type_signedness_changed_is_critical() {
    let old = struct_spec("Counter", vec![("count", ScSpecTypeDef::U64)]);
    let new = struct_spec("Counter", vec![("count", ScSpecTypeDef::I64)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Struct Field Type Signedness Changed", Some("Counter.count")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

// ── enum_removed / added / case_removed / added / value_changed ───────────────

#[test]
fn corpus_enum_removed_is_critical() {
    let old = enum_spec("Status", vec![("Active", 1), ("Paused", 2)]);
    let r = SafetyReport::new(&compare(&old, &ContractSpec::default()));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Enum Removed", Some("Status")), Some(Severity::Critical), "{:?}", dump(&r));
}

#[test]
fn corpus_enum_added_is_info() {
    let new = enum_spec("Status", vec![("Active", 1)]);
    let r = SafetyReport::new(&compare(&ContractSpec::default(), &new));
    assert!(r.is_safe);
    assert_eq!(sev(&r, "Enum Added", Some("Status")), Some(Severity::Info), "{:?}", dump(&r));
}

#[test]
fn corpus_enum_case_removed_is_critical() {
    let old = enum_spec("Mode", vec![("Read", 1), ("Write", 2), ("Exec", 3)]);
    let new = enum_spec("Mode", vec![("Read", 1), ("Write", 2)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Enum Case Removed", Some("Mode.Exec")), Some(Severity::Critical), "{:?}", dump(&r));
}

#[test]
fn corpus_enum_case_added_is_info() {
    let old = enum_spec("Mode", vec![("Read", 1)]);
    let new = enum_spec("Mode", vec![("Read", 1), ("Write", 2)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe);
    assert_eq!(sev(&r, "Enum Case Added", Some("Mode.Write")), Some(Severity::Info), "{:?}", dump(&r));
}

#[test]
fn corpus_enum_case_value_changed_is_critical() {
    let old = enum_spec("Role", vec![("Admin", 1), ("User", 2)]);
    let new = enum_spec("Role", vec![("Admin", 1), ("User", 99)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Enum Case Value Changed", Some("Role.User")), Some(Severity::Critical), "{:?}", dump(&r));
}

// ── error_enum_removed / added / case_removed / value_changed / case_added ───

#[test]
fn corpus_error_enum_removed_is_critical() {
    let old = error_enum_spec("ContractError", vec![("BadInput", 1)]);
    let r = SafetyReport::new(&compare(&old, &ContractSpec::default()));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Error Enum Removed", Some("ContractError")), Some(Severity::Critical), "{:?}", dump(&r));
}

#[test]
fn corpus_error_enum_added_is_info() {
    let new = error_enum_spec("ContractError", vec![("BadInput", 1)]);
    let r = SafetyReport::new(&compare(&ContractSpec::default(), &new));
    assert!(r.is_safe);
    assert_eq!(sev(&r, "Error Enum Added", Some("ContractError")), Some(Severity::Info), "{:?}", dump(&r));
}

#[test]
fn corpus_error_enum_case_removed_is_critical() {
    let old = error_enum_spec("VaultErr", vec![("Overflow", 1), ("Underflow", 2)]);
    let new = error_enum_spec("VaultErr", vec![("Overflow", 1)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert!(has_target(&r, "Error Enum Case Removed", "VaultErr.Underflow"), "{:?}", dump(&r));
}

#[test]
fn corpus_error_enum_case_value_changed_is_critical() {
    let old = error_enum_spec("VaultErr", vec![("Overflow", 1)]);
    let new = error_enum_spec("VaultErr", vec![("Overflow", 99)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert!(has_target(&r, "Error Enum Case Value Changed", "VaultErr.Overflow"), "{:?}", dump(&r));
}

#[test]
fn corpus_error_enum_case_added_is_info() {
    let old = error_enum_spec("VaultErr", vec![("Overflow", 1)]);
    let new = error_enum_spec("VaultErr", vec![("Overflow", 1), ("DivByZero", 2)]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe);
    assert!(has_target(&r, "Error Enum Case Added", "VaultErr.DivByZero"), "{:?}", dump(&r));
}

// ── union_removed / added / case_added / reordered / narrowed / signedness ───

#[test]
fn corpus_union_removed_is_critical() {
    let old = union_spec("Cmd", vec![void_case("Halt")]);
    let r = SafetyReport::new(&compare(&old, &ContractSpec::default()));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Union Removed", Some("Cmd")), Some(Severity::Critical), "{:?}", dump(&r));
}

#[test]
fn corpus_union_added_is_info() {
    let new = union_spec("Cmd", vec![void_case("Run")]);
    let r = SafetyReport::new(&compare(&ContractSpec::default(), &new));
    assert!(r.is_safe);
    assert_eq!(sev(&r, "Union Added", Some("Cmd")), Some(Severity::Info), "{:?}", dump(&r));
}

#[test]
fn corpus_union_case_added_is_info() {
    let old = union_spec("Cmd", vec![void_case("Run")]);
    let new = union_spec("Cmd", vec![void_case("Run"), void_case("Stop")]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe);
    assert_eq!(sev(&r, "Union Case Added", Some("Cmd.Stop")), Some(Severity::Info), "{:?}", dump(&r));
}

#[test]
fn corpus_union_case_reordered_is_critical() {
    let old = union_spec("Op", vec![void_case("Add"), void_case("Sub")]);
    let new = union_spec("Op", vec![void_case("Sub"), void_case("Add")]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(sev(&r, "Union Case Reordered", None), Some(Severity::Critical), "{:?}", dump(&r));
}

#[test]
fn corpus_union_case_type_narrowed_is_critical() {
    let old = union_spec("Amount", vec![tuple_case("Value", vec![ScSpecTypeDef::I128])]);
    let new = union_spec("Amount", vec![tuple_case("Value", vec![ScSpecTypeDef::I32])]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Union Case Type Narrowed", Some("Amount.Value")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

#[test]
fn corpus_union_case_type_signedness_changed_is_critical() {
    let old = union_spec("Amount", vec![tuple_case("Value", vec![ScSpecTypeDef::U64])]);
    let new = union_spec("Amount", vec![tuple_case("Value", vec![ScSpecTypeDef::I64])]);
    let r = SafetyReport::new(&compare(&old, &new));
    assert!(!r.is_safe);
    assert_eq!(
        sev(&r, "Union Case Type Signedness Changed", Some("Amount.Value")),
        Some(Severity::Critical),
        "{:?}",
        dump(&r)
    );
}

// ── type_renamed / type_renamed_with_changes ──────────────────────────────────

/// Identical layout, different name — engine detects rename instead of remove+add.
#[test]
fn corpus_type_renamed_is_info() {
    let fields: Vec<ScSpecUdtStructFieldV0> = vec![
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "owner".try_into().unwrap(),
            type_: ScSpecTypeDef::Address,
        },
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "limit".try_into().unwrap(),
            type_: ScSpecTypeDef::U64,
        },
    ];
    let mk = |sname: &str| ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: sname.try_into().unwrap(),
        fields: VecM::try_from(fields.clone()).unwrap(),
    };
    let mut old = ContractSpec::default();
    old.structs.insert("OldConfig".into(), mk("OldConfig"));
    let mut new = ContractSpec::default();
    new.structs.insert("NewConfig".into(), mk("NewConfig"));

    let r = SafetyReport::new(&compare(&old, &new));
    assert!(r.is_safe, "pure rename must be safe; got: {:?}", dump(&r));
    assert!(has(&r, "Type Renamed"), "expected Type Renamed; got: {:?}", dump(&r));
}

/// Renamed struct whose layout also changed — must fire Type Renamed With Changes
/// or at minimum Type Renamed (engine may split into rename + field finding).
#[test]
fn corpus_type_renamed_with_changes_detected() {
    let mk = |sname: &str, wide: bool| ScSpecUdtStructV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: sname.try_into().unwrap(),
        fields: VecM::try_from(vec![
            ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: "value".try_into().unwrap(),
                type_: if wide { ScSpecTypeDef::U64 } else { ScSpecTypeDef::U32 },
            },
            ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: "tag".try_into().unwrap(),
                type_: ScSpecTypeDef::U32,
            },
        ])
        .unwrap(),
    };
    let mut old = ContractSpec::default();
    old.structs.insert("OldData".into(), mk("OldData", false));
    let mut new = ContractSpec::default();
    new.structs.insert("NewData".into(), mk("NewData", true));

    let r = SafetyReport::new(&compare(&old, &new));
    let detected = has(&r, "Type Renamed With Changes") || has(&r, "Type Renamed");
    assert!(detected, "expected Type Renamed[With Changes]; got: {:?}", dump(&r));
}

// ── documentation-changed (Info) ─────────────────────────────────────────────

#[test]
fn corpus_function_documentation_changed_is_info() {
    let mk = |d: &str| {
        let mut spec = ContractSpec::default();
        spec.functions.insert(
            "greet".into(),
            ScSpecFunctionV0 {
                doc: d.try_into().unwrap(),
                name: "greet".try_into().unwrap(),
                inputs: VecM::default(),
                outputs: VecM::default(),
            },
        );
        spec
    };
    let r = SafetyReport::new(&compare(&mk("Says hello."), &mk("Says hello to caller.")));
    assert!(r.is_safe);
    assert!(has_target(&r, "Function Documentation Changed", "greet"), "{:?}", dump(&r));
    assert_eq!(sev(&r, "Function Documentation Changed", Some("greet")), Some(Severity::Info));
}

#[test]
fn corpus_struct_documentation_changed_is_info() {
    let mk = |d: &str| {
        let mut spec = ContractSpec::default();
        spec.structs.insert(
            "Cfg".into(),
            ScSpecUdtStructV0 {
                doc: d.try_into().unwrap(),
                lib: StringM::default(),
                name: "Cfg".try_into().unwrap(),
                fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "x".try_into().unwrap(),
                    type_: ScSpecTypeDef::U32,
                }])
                .unwrap(),
            },
        );
        spec
    };
    let r = SafetyReport::new(&compare(&mk("Old doc."), &mk("New doc.")));
    assert!(r.is_safe);
    assert!(has_target(&r, "Struct Documentation Changed", "Cfg"), "{:?}", dump(&r));
}

#[test]
fn corpus_enum_documentation_changed_is_info() {
    let mk = |d: &str| {
        let mut spec = ContractSpec::default();
        spec.enums.insert(
            "Role".into(),
            ScSpecUdtEnumV0 {
                doc: d.try_into().unwrap(),
                lib: StringM::default(),
                name: "Role".try_into().unwrap(),
                cases: VecM::try_from(vec![ScSpecUdtEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Admin".try_into().unwrap(),
                    value: 1,
                }])
                .unwrap(),
            },
        );
        spec
    };
    let r = SafetyReport::new(&compare(&mk("Before."), &mk("After.")));
    assert!(r.is_safe);
    assert!(has_target(&r, "Enum Documentation Changed", "Role"), "{:?}", dump(&r));
}

// ── cascading break via nested UDT reference ──────────────────────────────────

/// Breaking Child (field type change) cascades into Parent which embeds Child.
#[test]
fn corpus_cascading_break_via_udt_field() {
    let mk = |child_wide: bool| {
        let mut spec = ContractSpec::default();
        spec.structs.insert(
            "Child".into(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Child".try_into().unwrap(),
                fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "x".try_into().unwrap(),
                    type_: if child_wide { ScSpecTypeDef::Bool } else { ScSpecTypeDef::U32 },
                }])
                .unwrap(),
            },
        );
        spec.structs.insert(
            "Parent".into(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Parent".try_into().unwrap(),
                fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "child".try_into().unwrap(),
                    type_: udt("Child"),
                }])
                .unwrap(),
            },
        );
        spec
    };

    let r = SafetyReport::new(&compare(&mk(false), &mk(true)));
    assert!(!r.is_safe);
    assert!(has_target(&r, "Struct Field Type Changed", "Child.x"), "{:?}", dump(&r));
    let cascade_on_parent = r.findings_by_category.values().flatten().any(|rf| {
        rf.finding.category == "Cascading Layout Break"
            && rf.finding.type_name.as_deref() == Some("Parent")
    });
    assert!(cascade_on_parent, "expected Cascading Layout Break on Parent; got: {:?}", dump(&r));
}

// ── corpus false-positive rate ────────────────────────────────────────────────

/// Every corpus spec compared against itself must yield zero critical+warning
/// findings. This is the quantified false-positive rate for identical contracts.
#[test]
fn corpus_false_positive_rate_is_zero() {
    let corpus: Vec<(&str, ContractSpec)> = vec![
        ("fn_deposit",   fn_spec("deposit",  vec![("amount", ScSpecTypeDef::U64)], None)),
        ("fn_withdraw",  fn_spec("withdraw", vec![("to", ScSpecTypeDef::Address)], Some(ScSpecTypeDef::U64))),
        ("struct_cfg",   struct_spec("Config",  vec![("owner", ScSpecTypeDef::Address), ("limit", ScSpecTypeDef::U64)])),
        ("struct_ctr",   struct_spec("Counter", vec![("count", ScSpecTypeDef::U64), ("epoch", ScSpecTypeDef::U32)])),
        ("enum_status",  enum_spec("Status", vec![("Active", 1), ("Paused", 2), ("Archived", 3)])),
        ("err_vault",    error_enum_spec("VaultError", vec![("Overflow", 1), ("Underflow", 2)])),
        ("union_cmd",    union_spec("Cmd", vec![
            void_case("Run"), void_case("Stop"),
            tuple_case("Pay", vec![ScSpecTypeDef::U64]),
        ])),
    ];
    for (name, spec) in &corpus {
        let r = SafetyReport::new(&compare(spec, spec));
        let cw = r.critical_count + r.warning_count;
        assert_eq!(
            cw, 0,
            "self-comparison of '{name}' produced {cw} critical/warning findings; got: {:?}",
            dump(&r)
        );
    }
}

// ── runtime budget ────────────────────────────────────────────────────────────

/// 100 iterations of a multi-type pair that exercises the cascade path must
/// finish in under 1 second total.
#[test]
fn corpus_runtime_budget_100_iters_under_1s() {
    let mk_spec = |widen: bool| {
        let inner_type = if widen { ScSpecTypeDef::U64 } else { ScSpecTypeDef::U32 };
        let mut spec = ContractSpec::default();
        spec.structs.insert(
            "Inner".into(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Inner".try_into().unwrap(),
                fields: VecM::try_from(vec![
                    ScSpecUdtStructFieldV0 {
                        doc: StringM::default(),
                        name: "x".try_into().unwrap(),
                        type_: inner_type,
                    },
                    ScSpecUdtStructFieldV0 {
                        doc: StringM::default(),
                        name: "y".try_into().unwrap(),
                        type_: ScSpecTypeDef::U64,
                    },
                ])
                .unwrap(),
            },
        );
        spec.structs.insert(
            "Outer".into(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Outer".try_into().unwrap(),
                fields: VecM::try_from(vec![
                    ScSpecUdtStructFieldV0 {
                        doc: StringM::default(),
                        name: "inner".try_into().unwrap(),
                        type_: udt("Inner"),
                    },
                    ScSpecUdtStructFieldV0 {
                        doc: StringM::default(),
                        name: "tag".try_into().unwrap(),
                        type_: ScSpecTypeDef::U32,
                    },
                ])
                .unwrap(),
            },
        );
        spec.enums.insert(
            "Role".into(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Role".try_into().unwrap(),
                cases: VecM::try_from(vec![
                    ScSpecUdtEnumCaseV0 {
                        doc: StringM::default(),
                        name: "Admin".try_into().unwrap(),
                        value: 1,
                    },
                    ScSpecUdtEnumCaseV0 {
                        doc: StringM::default(),
                        name: "User".try_into().unwrap(),
                        value: 2,
                    },
                ])
                .unwrap(),
            },
        );
        spec.functions.insert(
            "process".into(),
            ScSpecFunctionV0 {
                doc: StringM::default(),
                name: "process".try_into().unwrap(),
                inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "data".try_into().unwrap(),
                    type_: udt("Outer"),
                }])
                .unwrap(),
                outputs: VecM::try_from(vec![udt("Role")]).unwrap(),
            },
        );
        spec
    };

    let old = mk_spec(false);
    let new = mk_spec(true); // Inner.x widened — exercises full cascade path

    let start = Instant::now();
    for _ in 0..100 {
        let _ = compare(&old, &new);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 1,
        "100 corpus comparisons took {:?} (budget: 1 s) — possible performance regression",
        elapsed
    );
}
