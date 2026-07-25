use crate::classification::{ClassificationConfig, TypeClass};
use crate::mapper::LayoutMapper;
use crate::parser::ContractEnvMeta;
use crate::rename::{match_renames, Rename};
use crate::spec::ContractSpec;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

/// Severity of a detected issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// A single finding from the comparison analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    /// The name of the affected UDT (struct/enum/union), if this finding
    /// relates to a specific type.  Used by cascade-detection so it never
    /// needs to re-parse `message`.
    pub type_name: Option<String>,
    /// A stable, structured identifier for the exact entity this finding is
    /// about, independent of the human-readable `message`. It is the key used
    /// by the suppression config to match a finding precisely:
    ///
    /// - functions: the function name (e.g. `transfer`)
    /// - function parameters: `function.param` (e.g. `transfer.to`)
    /// - types (struct/enum removed/added, cascades): the type name (e.g. `Data`)
    /// - struct fields: `Type.field` (e.g. `Data.amount`)
    /// - enum cases: `Enum.case` (e.g. `Status.Active`)
    ///
    /// `None` for findings that are not tied to a single named entity (for
    /// example environment-metadata changes).
    pub target: Option<String>,
    /// How the affected user-defined type was classified (event vs. ordinary
    /// storage/interface type), when this finding is about a UDT.
    ///
    /// This is *display metadata only*. It never appears in [`Self::category`]
    /// and is never part of the suppression key, so a suppression rule keeps
    /// matching even if the classification later changes. `None` for findings
    /// not tied to a UDT (functions, parameters, environment metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<TypeClass>,
}

/// Holds all findings from a comparison of two contract specs.
#[derive(Debug, Default)]
pub struct DiffReport {
    pub findings: Vec<Finding>,
}

#[allow(dead_code)]
impl DiffReport {
    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count()
    }
}

/// Compare two contract specs and return a report of all findings.
///
/// Uses the default classification config, which treats every type as ordinary
/// storage (no event claims). Use [`compare_with_classification`] to supply an
/// explicit [`ClassificationConfig`].
pub fn compare(old: &ContractSpec, new: &ContractSpec) -> DiffReport {
    compare_with_classification(old, new, &ClassificationConfig::none())
}

/// Compare two contract specs, resolving event/storage classification via
/// `classification`.
///
/// Classification affects only the human-facing message, remediation, and the
/// per-finding `classification` metadata — never the structural `category` used
/// for suppression matching.
pub fn compare_with_classification(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
) -> DiffReport {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report);
    compare_structs(old, new, classification, &mut report);
    compare_enums(old, new, classification, &mut report);
    compare_unions(old, new, classification, &mut report);
    compare_error_enums(old, new, classification, &mut report);

    detect_cascading_layout_breaks(old, &mut report);

    report
}

/// Run the full structural diff bounded by `policy`.
///
/// This is the function the canonical pipeline ([`crate::lib`]) calls. It
/// runs the same stages as [`compare_with_classification`] but also enforces
/// the recursive type-walk depth limit from `policy`, returning a typed
/// [`crate::limits::LimitError`] when a type graph exceeds the configured
/// bound rather than overflowing the stack.
pub fn compare_with_policy(
    old: &ContractSpec,
    new: &ContractSpec,
    policy: &crate::limits::ResourcePolicy,
) -> Result<DiffReport, crate::limits::LimitError> {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report);
    compare_structs(old, new, &ClassificationConfig::none(), &mut report);
    compare_enums(old, new, &ClassificationConfig::none(), &mut report);
    compare_unions(old, new, &ClassificationConfig::none(), &mut report);
    compare_error_enums(old, new, &ClassificationConfig::none(), &mut report);

    // Cascade detection uses the LayoutMapper which enforces the walk-depth
    // limit. If the graph exceeds it we surface a LimitError rather than
    // overflowing the stack.
    detect_cascading_layout_breaks_with_policy(old, &mut report, policy)?;

    Ok(report)
}

/// Category label for duplicate spec entries that are byte-identical across sections.
pub const SPEC_DUPLICATE_CATEGORY: &str = "Spec Entry Duplicate";
/// Category label for duplicate spec entries that conflict (different definitions).
pub const SPEC_CONFLICT_CATEGORY: &str = "Spec Entry Conflict";

/// Inject findings for duplicate spec entries detected during `ContractSpec::from_entries_checked`.
///
/// Identical duplicates (same definition in multiple sections) become `Info`
/// findings unless `compat_duplicates` is `true`, in which case they are
/// silently dropped. Conflicting duplicates (different definitions) always
/// become `Critical` findings.
pub fn report_duplicate_spec_entries(
    side: &str,
    duplicates: &[crate::spec::DuplicateEntry],
    section_count: usize,
    report: &mut DiffReport,
    compat_duplicates: bool,
) {
    for dup in duplicates {
        if dup.is_identical {
            if compat_duplicates {
                continue;
            }
            report.findings.push(Finding {
                severity: Severity::Info,
                category: SPEC_DUPLICATE_CATEGORY.to_string(),
                message: format!(
                    "{} build: {} '{}' appears in {} of {} contractspecv0 section(s) with an \
                     identical definition. The WASM is non-canonical but safe to use.",
                    side,
                    dup.kind.label(),
                    dup.name,
                    dup.sections.len(),
                    section_count,
                ),
                type_name: Some(dup.name.clone()),
                target: Some(dup.name.clone()),
                classification: None,
            });
        } else {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: SPEC_CONFLICT_CATEGORY.to_string(),
                message: format!(
                    "{} build: {} '{}' has conflicting definitions across contractspecv0 \
                     sections {:?}. The spec is ambiguous and the build cannot be trusted.",
                    side,
                    dup.kind.label(),
                    dup.name,
                    dup.sections,
                ),
                type_name: Some(dup.name.clone()),
                target: Some(dup.name.clone()),
                classification: None,
            });
        }
    }
}

/// Compare two resolved storage schemas through the same diff engine used for
/// the exported interface, returning a `DiffReport` with the storage findings.
pub fn compare_storage_schemas(
    old: &crate::storage_schema::ResolvedStorageSchema,
    new: &crate::storage_schema::ResolvedStorageSchema,
) -> DiffReport {
    compare_with_classification(&old.spec, &new.spec, &ClassificationConfig::none())
}

/// Inject `Info` findings for schema references the resolver could not match
/// against the exported spec. These are not errors — they just cap the coverage
/// claim so the report cannot overstate what was verified.
pub fn report_unresolved_storage_references(
    unresolved: &[String],
    report: &mut DiffReport,
) {
    for name in unresolved {
        report.findings.push(Finding {
            severity: Severity::Info,
            category: ENVIRONMENT_CATEGORY.to_string(),
            message: format!(
                "Storage schema references type '{}' which could not be resolved against \
                 the exported spec. Coverage for this type is not guaranteed.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
    }
}

/// Category label for contract environment metadata findings.
pub const ENVIRONMENT_CATEGORY: &str = "Environment";

/// Every category string this crate can emit.
///
/// Categories are **purely structural**: they describe what changed in the
/// shape of the contract, never how a type was classified. There is no
/// `"Event …"` category — event-ness is reported separately in
/// [`Finding::classification`] and affects only wording and remediation. That
/// keeps a suppression key (`category` + `target`) stable across changes to the
/// classification config, so reclassifying a type can never silently suppress
/// or un-suppress a real breaking change.
///
/// Pre-1.0 event-flavored names are still accepted in suppression configs and
/// mapped onto these by [`crate::suppression::stable_category`].
///
/// This list is the single inventory the tests check against: every entry must
/// have remediation guidance, and every category literal emitted by this module
/// must appear here.
pub const ALL_CATEGORIES: &[&str] = &[
    ENVIRONMENT_CATEGORY,
    // Functions and their signatures.
    "Function Removed",
    "Function Added",
    "Function Documentation Changed",
    "Function Signature Changed",
    "Parameter Renamed",
    "Parameter Reordered",
    "Parameter Type Changed",
    "Return Type Changed",
    // Type identity.
    "Type Renamed",
    "Type Renamed With Changes",
    // Structs.
    "Struct Removed",
    "Struct Added",
    "Struct Documentation Changed",
    "Struct Field Removed",
    "Struct Field Added",
    "Struct Field Reordered",
    "Struct Field Type Changed",
    // Enums.
    "Enum Removed",
    "Enum Added",
    "Enum Documentation Changed",
    "Enum Case Removed",
    "Enum Case Added",
    "Enum Case Value Changed",
    // Unions.
    "Union Removed",
    "Union Added",
    "Union Case Removed",
    "Union Case Added",
    "Union Case Reordered",
    "Union Case Type Changed",
    // Error enums.
    "Error Enum Removed",
    "Error Enum Added",
    "Error Enum Case Removed",
    "Error Enum Case Added",
    "Error Enum Case Value Changed",
    // Cascades.
    "Cascading Layout Break",
    // Binary export section vs. declared spec.
    "Export Removed",
    "Export Added",
    "Export Spec Mismatch",
    // Duplicate / conflicting spec entries.
    "Spec Entry Duplicate",
    "Spec Entry Conflict",
];

/// Compare the binary export sections of two WASM builds.
///
/// A function present in the old binary's export section but absent from the new
/// one is a breaking change — callers that invoke by name will get a missing
/// export at runtime. A function present in the new binary but absent from the
/// old one is informational (new export available).
///
/// Additionally, any name that appears in the `contractspecv0` spec but NOT in
/// the binary's export section (or vice versa) indicates a spec/binary mismatch
/// that should be visible.
///
/// `old_exports` and `new_exports` are the `exported_function_names` sets from
/// [`crate::parser::SorobanMetadata`]. `old_spec_fns` and `new_spec_fns` are
/// the function name sets from the respective [`crate::spec::ContractSpec`].
pub fn compare_exports(
    old_exports: &std::collections::BTreeSet<String>,
    new_exports: &std::collections::BTreeSet<String>,
    old_spec_fns: &std::collections::HashSet<String>,
    new_spec_fns: &std::collections::HashSet<String>,
    report: &mut DiffReport,
) {
    // 1. Exports present in the old binary but removed in the new binary.
    for name in old_exports {
        if !new_exports.contains(name) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Export Removed".to_string(),
                message: format!(
                    "Exported function '{}' is present in the old binary but absent from \
                     the new binary. On-chain callers will get a missing-export error at runtime.",
                    name
                ),
                type_name: None,
                target: Some(name.clone()),
                classification: None,
            });
        }
    }

    // 2. Exports present in the new binary but absent from the old binary.
    for name in new_exports {
        if !old_exports.contains(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Export Added".to_string(),
                message: format!(
                    "New exported function '{}' appeared in the binary export section.",
                    name
                ),
                type_name: None,
                target: Some(name.clone()),
                classification: None,
            });
        }
    }

    // 3. Each build's declared spec must agree with the functions the binary
    // actually exports. Check both sides: an inconsistent baseline is useful
    // diagnostic information too, and an inconsistent candidate is unsafe.
    for (side, exports, spec_fns) in [
        ("old", old_exports, old_spec_fns),
        ("new", new_exports, new_spec_fns),
    ] {
        for name in spec_fns {
            if !exports.contains(name) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Export Spec Mismatch".to_string(),
                    message: format!(
                        "Function '{}' is declared in the {} contract spec but is NOT present in \
                         that binary's export section. Callers following the spec will fail at runtime.",
                        name, side
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    classification: None,
                });
            }
        }
        for name in exports {
            if !spec_fns.contains(name) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Export Spec Mismatch".to_string(),
                    message: format!(
                        "Function '{}' is exported by the {} binary but is NOT declared in \
                         that contract spec. The spec does not reflect all callable entry-points.",
                        name, side
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    classification: None,
                });
            }
        }
    }
}

/// Compare decoded environment metadata between two contract builds.
pub fn compare_env_metadata(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
    report: &mut DiffReport,
) {
    match (old, new) {
        (None, None) => {}
        (Some(old_meta), Some(new_meta)) if old_meta == new_meta => {}
        (old_meta, new_meta) => {
            let severity = env_metadata_change_severity(old_meta, new_meta);
            report.findings.push(Finding {
                severity,
                category: ENVIRONMENT_CATEGORY.to_string(),
                message: format_env_metadata_change(old_meta, new_meta),
                type_name: None,
                target: None,
                classification: None,
            });
        }
    }
}

fn env_metadata_change_severity(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
) -> Severity {
    let old_protocol = old.and_then(ContractEnvMeta::protocol_version);
    let new_protocol = new.and_then(ContractEnvMeta::protocol_version);

    if old_protocol.is_some() && new_protocol.is_some() && old_protocol != new_protocol {
        Severity::Warning
    } else {
        Severity::Info
    }
}

fn format_env_metadata_change(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
) -> String {
    match (old, new) {
        (None, Some(new_meta)) => format!(
            "Contract environment metadata appeared ({}).",
            new_meta.summary()
        ),
        (Some(old_meta), None) => format!(
            "Contract environment metadata was removed (was: {}).",
            old_meta.summary()
        ),
        (Some(old_meta), Some(new_meta)) => {
            if let (Some(old_proto), Some(new_proto)) =
                (old_meta.protocol_version(), new_meta.protocol_version())
            {
                if old_proto != new_proto {
                    return format!(
                        "Soroban protocol interface version changed from {} to {} \
                         (pre-release {} → {}).",
                        old_proto,
                        new_proto,
                        old_meta.pre_release_version().unwrap_or(0),
                        new_meta.pre_release_version().unwrap_or(0),
                    );
                }
            }

            format!(
                "Contract environment metadata changed from {} to {}.",
                old_meta.summary(),
                new_meta.summary()
            )
        }
        (None, None) => unreachable!("compare_env_metadata filters identical/absent pairs"),
    }
}

/// The human-facing noun used in a message for a type of the given class.
///
/// Only the *wording* varies with classification; the structural `category`
/// (e.g. `"Struct Field Removed"`) never does, so suppression keys stay stable
/// even if a type's classification later changes. See [`crate::classification`].
fn type_noun<'a>(class: TypeClass, storage: &'a str, event: &'a str) -> &'a str {
    match class {
        TypeClass::Event { .. } => event,
        TypeClass::Storage => storage,
    }
}

/// Append a heuristic-classification disclaimer to `message` when the class was
/// guessed from the type name rather than declared. Satisfies "the report labels
/// any heuristic classification as such."
fn with_heuristic_note(mut message: String, class: TypeClass) -> String {
    if class.is_heuristic() {
        message.push_str(
            " (classified as an event by the name heuristic; \
             declare it under [classification] to make this explicit)",
        );
    }
    message
}

/// The two sets of names consumed by detected renames: old names that should no
/// longer be reported as removed, and new names that should no longer be
/// reported as added.
fn rename_name_sets(renames: &[Rename]) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let old_names = renames.iter().map(|r| r.old_name.as_str()).collect();
    let new_names = renames.iter().map(|r| r.new_name.as_str()).collect();
    (old_names, new_names)
}

/// Emit the finding for a detected rename. An identical layout is informational
/// (`Type Renamed`); a rename that also changes fields is a warning
/// (`Type Renamed With Changes`) and is followed by the field-level diff so the
/// actual break is not buried. `kind` is the lowercase type kind (e.g. `struct`).
fn emit_rename_finding(rename: &Rename, kind: &str, class: TypeClass, report: &mut DiffReport) {
    let (severity, category, detail) = if rename.identical {
        (
            Severity::Info,
            "Type Renamed",
            "the layout is identical, so stored data stays compatible",
        )
    } else {
        (
            Severity::Warning,
            "Type Renamed With Changes",
            "the layout also changed; see the field-level findings below",
        )
    };
    report.findings.push(Finding {
        severity,
        category: category.to_string(),
        message: with_heuristic_note(
            format!(
                "{} '{}' appears to have been renamed to '{}' — {}.",
                capitalize(kind),
                rename.old_name,
                rename.new_name,
                detail
            ),
            class,
        ),
        // Anchor to the NEW name so cascade/field targets line up with the
        // surviving type.
        type_name: Some(rename.new_name.clone()),
        target: Some(rename.new_name.clone()),
        classification: Some(class),
    });
}

/// Uppercase the first ASCII character of a short, known-lowercase kind label.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Compare function signatures between old and new contract specs.
fn compare_functions(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    // Check for removed or changed functions
    for (name, old_fn) in &old.functions {
        match new.functions.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Function Removed".to_string(),
                    message: format!(
                        "Function '{}' was removed. Existing callers will break.",
                        name
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    classification: None,
                });
            }
            Some(new_fn) => {
                check_function_signature(name, old_fn, new_fn, report);
                // Compare function doc-strings and emit informational findings
                if old_fn.doc != new_fn.doc {
                    let old_doc_empty = old_fn.doc.to_string().is_empty();
                    let new_doc_empty = new_fn.doc.to_string().is_empty();
                    let message = if old_doc_empty && !new_doc_empty {
                        format!("Function '{}' documentation was added.", name)
                    } else if !old_doc_empty && new_doc_empty {
                        format!("Function '{}' documentation was removed.", name)
                    } else {
                        format!("Function '{}' documentation changed.", name)
                    };

                    report.findings.push(Finding {
                        severity: Severity::Info,
                        category: "Function Documentation Changed".to_string(),
                        message,
                        type_name: None,
                        target: Some(name.clone()),
                        classification: None,
                    });
                }
            }
        }
    }

    // Check for newly added functions (informational)
    for name in new.functions.keys() {
        if !old.functions.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Function Added".to_string(),
                message: format!("New function '{}' added.", name),
                type_name: None,
                target: Some(name.clone()),
                classification: None,
            });
        }
    }
}

/// Compare signatures of two functions with the same name.
fn check_function_signature(
    name: &str,
    old_fn: &ScSpecFunctionV0,
    new_fn: &ScSpecFunctionV0,
    report: &mut DiffReport,
) {
    // Check input count
    let old_inputs: &[ScSpecFunctionInputV0] = old_fn.inputs.as_ref();
    let new_inputs: &[ScSpecFunctionInputV0] = new_fn.inputs.as_ref();

    if old_inputs.len() != new_inputs.len() {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Function Signature Changed".to_string(),
            message: format!(
                "Function '{}': parameter count changed from {} to {}.",
                name,
                old_inputs.len(),
                new_inputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
            classification: None,
        });
        return; // No point comparing individual params if count differs
    }

    // Check each input parameter
    let old_names: Vec<String> = old_inputs
        .iter()
        .map(|input| input.name.to_string())
        .collect();
    let new_names: Vec<String> = new_inputs
        .iter()
        .map(|input| input.name.to_string())
        .collect();

    let old_names_set: std::collections::HashSet<String> = old_names.iter().cloned().collect();
    let new_names_set: std::collections::HashSet<String> = new_names.iter().cloned().collect();

    let is_reordered = old_names_set == new_names_set && old_names != new_names;

    if is_reordered {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Parameter Reordered".to_string(),
            message: format!(
                "Function '{}': parameters reordered. The set of parameter names is unchanged but their order differs.",
                name
            ),
            type_name: None,
            target: Some(name.to_string()),
            classification: None,
        });

        // Check for genuine type changes by matching parameter name.
        let new_by_name: std::collections::HashMap<String, &ScSpecTypeDef> = new_inputs
            .iter()
            .map(|input| (input.name.to_string(), &input.type_))
            .collect();

        for (i, old_input) in old_inputs.iter().enumerate() {
            let p_name = old_input.name.to_string();
            if let Some(new_type) = new_by_name.get(&p_name) {
                if !types_equal(&old_input.type_, new_type) {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Parameter Type Changed".to_string(),
                        message: format!(
                            "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                            name,
                            i,
                            p_name,
                            crate::mapper::type_to_string(&old_input.type_),
                            crate::mapper::type_to_string(new_type)
                        ),
                        type_name: None,
                        target: Some(format!("{}.{}", name, p_name)),
                        classification: None,
                    });
                }
            }
        }
    } else {
        // Fall back to original positional check
        for (i, (old_input, new_input)) in old_inputs.iter().zip(new_inputs.iter()).enumerate() {
            let old_name = old_input.name.to_string();
            let new_name = new_input.name.to_string();

            if old_name != new_name {
                report.findings.push(Finding {
                    severity: Severity::Warning,
                    category: "Parameter Renamed".to_string(),
                    message: format!(
                        "Function '{}': parameter {} renamed from '{}' to '{}'.",
                        name, i, old_name, new_name
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: None,
                });
            }

            if !types_equal(&old_input.type_, &new_input.type_) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Parameter Type Changed".to_string(),
                    message: format!(
                        "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                        name,
                        i,
                        old_name,
                        crate::mapper::type_to_string(&old_input.type_),
                        crate::mapper::type_to_string(&new_input.type_)
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: None,
                });
            }
        }
    }

    // Check output types
    let old_outputs: &[ScSpecTypeDef] = old_fn.outputs.as_ref();
    let new_outputs: &[ScSpecTypeDef] = new_fn.outputs.as_ref();

    if old_outputs.len() != new_outputs.len() {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Return Type Changed".to_string(),
            message: format!(
                "Function '{}': return type count changed from {} to {}.",
                name,
                old_outputs.len(),
                new_outputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
            classification: None,
        });
    } else {
        for (i, (old_out, new_out)) in old_outputs.iter().zip(new_outputs.iter()).enumerate() {
            if !types_equal(old_out, new_out) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Return Type Changed".to_string(),
                    message: format!(
                        "Function '{}': return type {} changed from `{}` to `{}`.",
                        name,
                        i,
                        crate::mapper::type_to_string(old_out),
                        crate::mapper::type_to_string(new_out)
                    ),
                    type_name: None,
                    target: Some(name.to_string()),
                    classification: None,
                });
            }
        }
    }
}

/// Compare two ScSpecTypeDef values for equality.
/// We use the PartialEq derive on the XDR types.
fn types_equal(a: &ScSpecTypeDef, b: &ScSpecTypeDef) -> bool {
    a == b
}

/// Compare struct definitions between old and new contract specs.
///
/// Types present under the same name in both specs are compared field-by-field.
/// Names that appear only on one side are run through structural rename
/// detection ([`match_renames`]) *before* being reported as removed/added, so a
/// renamed-but-compatible type is reported as a rename rather than a delete plus
/// an add.
fn compare_structs(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Types present in both specs (same name): compare in place.
    for (name, old_struct) in &old.structs {
        if let Some(new_struct) = new.structs.get(name) {
            let class = classification.classify(name);
            check_struct_fields(name, old_struct, new_struct, class, report);
            // Compare struct doc-strings (informational only)
            if old_struct.doc != new_struct.doc {
                let old_doc_empty = old_struct.doc.to_string().is_empty();
                let new_doc_empty = new_struct.doc.to_string().is_empty();
                let message = if old_doc_empty && !new_doc_empty {
                    format!("Struct '{}' documentation was added.", name)
                } else if !old_doc_empty && new_doc_empty {
                    format!("Struct '{}' documentation was removed.", name)
                } else {
                    format!("Struct '{}' documentation changed.", name)
                };

                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: "Struct Documentation Changed".to_string(),
                    message,
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    classification: Some(class),
                });
            }
        }
    }

    // 2. Names on only one side: try to pair them up as renames first.
    let removed: BTreeMap<String, &ScSpecUdtStructV0> = old
        .structs
        .iter()
        .filter(|(n, _)| !new.structs.contains_key(*n))
        .map(|(n, s)| (n.clone(), s))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtStructV0> = new
        .structs
        .iter()
        .filter(|(n, _)| !old.structs.contains_key(*n))
        .map(|(n, s)| (n.clone(), s))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let old_struct = removed[&rename.old_name];
        let new_struct = added[&rename.new_name];
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "struct", class, report);
        if !rename.identical {
            // Diff the renamed type under its NEW name so field targets are stable.
            check_struct_fields(&rename.new_name, old_struct, new_struct, class, report);
        }
    }

    // 3. Genuinely removed structs (not part of a rename).
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        let noun = type_noun(class, "Struct", "Event struct");
        let message = with_heuristic_note(
            format!(
                "{} '{}' was removed. Storage or systems relying on this type will break.",
                noun, name
            ),
            class,
        );
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Struct Removed".to_string(),
            message,
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added structs (not part of a rename).
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Struct Added".to_string(),
            message: format!("New struct '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }
}

/// Compare fields of two structs with the same name.
///
/// Soroban serializes struct fields by position order, so field reordering,
/// removal, or type changes all break storage layout compatibility.
///
/// `class` only affects the human-facing wording and per-finding metadata; the
/// structural `category` is identical for storage and event types so that a
/// suppression keyed on it keeps matching even if the classification flips.
fn check_struct_fields(
    name: &str,
    old_struct: &ScSpecUdtStructV0,
    new_struct: &ScSpecUdtStructV0,
    class: TypeClass,
    report: &mut DiffReport,
) {
    let old_fields: &[ScSpecUdtStructFieldV0] = old_struct.fields.as_ref();
    let new_fields: &[ScSpecUdtStructFieldV0] = new_struct.fields.as_ref();
    let msg_prefix = type_noun(class, "Struct", "Event schema");

    // Check for removed fields
    for old_field in old_fields {
        let old_name = old_field.name.to_string();
        let still_exists = new_fields.iter().any(|f| f.name.to_string() == old_name);
        if !still_exists {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Struct Field Removed".to_string(),
                message: with_heuristic_note(
                    format!(
                        "{} '{}': field '{}' was removed. Backwards compatibility is broken.",
                        msg_prefix, name, old_name
                    ),
                    class,
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: Some(class),
            });
        }
    }

    // Check fields that exist in both versions, by position
    for (i, (old_field, new_field)) in old_fields.iter().zip(new_fields.iter()).enumerate() {
        let old_name = old_field.name.to_string();
        let new_name = new_field.name.to_string();

        // Field at the same position has a different name — reordering detected
        if old_name != new_name {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Struct Field Reordered".to_string(),
                message: with_heuristic_note(
                    format!(
                        "{} '{}': field at position {} changed from '{}' to '{}'. \
                         Positional serialization breaks layout compatibility.",
                        msg_prefix, name, i, old_name, new_name
                    ),
                    class,
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: Some(class),
            });
        }

        // Field type changed
        if !types_equal(&old_field.type_, &new_field.type_) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Struct Field Type Changed".to_string(),
                message: with_heuristic_note(
                    format!(
                        "{} '{}': field '{}' (position {}) type changed from `{}` to `{}`.",
                        msg_prefix,
                        name,
                        old_name,
                        i,
                        crate::mapper::type_to_string(&old_field.type_),
                        crate::mapper::type_to_string(&new_field.type_)
                    ),
                    class,
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: Some(class),
            });
        }
    }

    // Check for new fields appended at the end
    if new_fields.len() > old_fields.len() {
        for new_field in &new_fields[old_fields.len()..] {
            report.findings.push(Finding {
                severity: Severity::Warning,
                category: "Struct Field Added".to_string(),
                message: format!(
                    "{} '{}': new field '{}' appended. \
                     Existing storage entries won't have this field — ensure migration handles defaults.",
                    msg_prefix,
                    name,
                    new_field.name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_field.name)),
                classification: Some(class),
            });
        }
    }
}

/// Compare enum definitions between old and new contract specs.
fn compare_enums(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Enums present in both specs (same name): compare in place.
    for (name, old_enum) in &old.enums {
        if let Some(new_enum) = new.enums.get(name) {
            let class = classification.classify(name);
            check_enum_cases(name, old_enum, new_enum, class, report);
            // Compare enum doc-strings (informational only)
            if old_enum.doc != new_enum.doc {
                let old_doc_empty = old_enum.doc.to_string().is_empty();
                let new_doc_empty = new_enum.doc.to_string().is_empty();
                let message = if old_doc_empty && !new_doc_empty {
                    format!("Enum '{}' documentation was added.", name)
                } else if !old_doc_empty && new_doc_empty {
                    format!("Enum '{}' documentation was removed.", name)
                } else {
                    format!("Enum '{}' documentation changed.", name)
                };

                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: "Enum Documentation Changed".to_string(),
                    message,
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    classification: Some(class),
                });
            }
        }
    }

    // 2. Names on only one side: try to pair them up as renames first.
    let removed: BTreeMap<String, &ScSpecUdtEnumV0> = old
        .enums
        .iter()
        .filter(|(n, _)| !new.enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtEnumV0> = new
        .enums
        .iter()
        .filter(|(n, _)| !old.enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let old_enum = removed[&rename.old_name];
        let new_enum = added[&rename.new_name];
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "enum", class, report);
        if !rename.identical {
            check_enum_cases(&rename.new_name, old_enum, new_enum, class, report);
        }
    }

    // 3. Genuinely removed enums.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        let noun = type_noun(class, "Enum", "Event enum");
        let message = with_heuristic_note(
            format!(
                "{} '{}' was removed. Data using this type will be invalid.",
                noun, name
            ),
            class,
        );
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Enum Removed".to_string(),
            message,
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added enums.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Enum Added".to_string(),
            message: format!("New enum '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }
}

/// Compare cases of two enums with the same name.
///
/// `class` affects only the message wording and per-finding metadata; the
/// structural `category` never varies with classification.
fn check_enum_cases(
    name: &str,
    old_enum: &ScSpecUdtEnumV0,
    new_enum: &ScSpecUdtEnumV0,
    class: TypeClass,
    report: &mut DiffReport,
) {
    let msg_prefix = type_noun(class, "Enum", "Event enum");
    let old_cases: &[ScSpecUdtEnumCaseV0] = old_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtEnumCaseV0] = new_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();

        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                // The case was removed entirely
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Enum Case Removed".to_string(),
                    message: with_heuristic_note(
                        format!(
                            "{} '{}': case '{}' (value: {}) was removed. \
                             On-chain data or events relying on this value will be invalid.",
                            msg_prefix, name, old_name, old_case.value
                        ),
                        class,
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: Some(class),
                });
            }
            Some(new_case) => {
                // The case exists, but did its integer value change?
                if old_case.value != new_case.value {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Enum Case Value Changed".to_string(),
                        message: with_heuristic_note(
                            format!(
                                "{} '{}': case '{}' value changed from {} to {}. \
                                 This breaks data serialization.",
                                msg_prefix, name, old_name, old_case.value, new_case.value
                            ),
                            class,
                        ),
                        type_name: Some(name.to_string()),
                        target: Some(format!("{}.{}", name, old_name)),
                        classification: Some(class),
                    });
                }
            }
        }
    }

    // Check for new enum cases (usually safe, but good to know)
    if new_cases.len() > old_cases.len() {
        for new_case in new_cases {
            let new_name = new_case.name.to_string();
            if !old_cases.iter().any(|c| c.name.to_string() == new_name) {
                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: "Enum Case Added".to_string(),
                    message: format!(
                        "{} '{}': new case '{}' (value {}) added.",
                        msg_prefix, name, new_name, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                    classification: Some(class),
                });
            }
        }
    }
}

/// Compare union definitions between old and new contract specs.
fn compare_unions(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Same-name unions: compare in place.
    for (name, old_union) in &old.unions {
        if let Some(new_union) = new.unions.get(name) {
            check_union_cases(name, old_union, new_union, report);
        }
    }

    // 2. One-sided names: pair renames before reporting delete/add.
    let removed: BTreeMap<String, &ScSpecUdtUnionV0> = old
        .unions
        .iter()
        .filter(|(n, _)| !new.unions.contains_key(*n))
        .map(|(n, u)| (n.clone(), u))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtUnionV0> = new
        .unions
        .iter()
        .filter(|(n, _)| !old.unions.contains_key(*n))
        .map(|(n, u)| (n.clone(), u))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "union", class, report);
        if !rename.identical {
            check_union_cases(
                &rename.new_name,
                removed[&rename.old_name],
                added[&rename.new_name],
                report,
            );
        }
    }

    // 3. Genuinely removed unions.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Union Removed".to_string(),
            message: format!(
                "Union '{}' was removed. Data using this type will be invalid.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added unions.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Union Added".to_string(),
            message: format!("New union '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }
}

/// Compare cases of two unions with the same name.
///
/// Soroban unions serialize cases by positional discriminant, so case reordering,
/// removal, or payload type changes all break layout compatibility.
fn check_union_cases(
    name: &str,
    old_union: &ScSpecUdtUnionV0,
    new_union: &ScSpecUdtUnionV0,
    report: &mut DiffReport,
) {
    let old_cases: &[ScSpecUdtUnionCaseV0] = old_union.cases.as_ref();
    let new_cases: &[ScSpecUdtUnionCaseV0] = new_union.cases.as_ref();

    for old_case in old_cases {
        let old_name = union_case_name(old_case);
        let still_exists = new_cases.iter().any(|c| union_case_name(c) == old_name);
        if !still_exists {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Union Case Removed".to_string(),
                message: format!(
                    "Union '{}': case '{}' was removed. Backwards compatibility is broken.",
                    name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: None,
            });
        }
    }

    for (i, (old_case, new_case)) in old_cases.iter().zip(new_cases.iter()).enumerate() {
        let old_name = union_case_name(old_case);
        let new_name = union_case_name(new_case);

        if old_name != new_name {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Union Case Reordered".to_string(),
                message: format!(
                    "Union '{}': case at position {} changed from '{}' to '{}'. \
                     Positional discriminant breaks layout compatibility.",
                    name, i, old_name, new_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: None,
            });
        }

        if !union_cases_equal(old_case, new_case) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Union Case Type Changed".to_string(),
                message: format!(
                    "Union '{}': case '{}' (position {}) type changed from `{}` to `{}`.",
                    name,
                    old_name,
                    i,
                    union_case_type_signature(old_case),
                    union_case_type_signature(new_case)
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: None,
            });
        }
    }

    if new_cases.len() > old_cases.len() {
        for new_case in &new_cases[old_cases.len()..] {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Union Case Added".to_string(),
                message: format!(
                    "Union '{}': new case '{}' ({}) added.",
                    name,
                    union_case_name(new_case),
                    union_case_type_signature(new_case)
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, union_case_name(new_case))),
                classification: None,
            });
        }
    }
}

fn union_case_name(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string(),
    }
}

fn union_case_type_signature(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(_) => "void".to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: Vec<String> = t.type_.iter().map(crate::mapper::type_to_string).collect();
            format!("({})", types.join(", "))
        }
    }
}

fn union_cases_equal(a: &ScSpecUdtUnionCaseV0, b: &ScSpecUdtUnionCaseV0) -> bool {
    match (a, b) {
        (ScSpecUdtUnionCaseV0::VoidV0(_), ScSpecUdtUnionCaseV0::VoidV0(_)) => true,
        (ScSpecUdtUnionCaseV0::TupleV0(a_tuple), ScSpecUdtUnionCaseV0::TupleV0(b_tuple)) => {
            let a_types: &[ScSpecTypeDef] = a_tuple.type_.as_ref();
            let b_types: &[ScSpecTypeDef] = b_tuple.type_.as_ref();
            a_types.len() == b_types.len()
                && a_types
                    .iter()
                    .zip(b_types.iter())
                    .all(|(left, right)| types_equal(left, right))
        }
        _ => false,
    }
}

/// Compare contract error enum definitions between old and new specs.
///
/// Error enums are never classified as events, so their findings carry
/// `classification: None`. Rename detection still applies: an error enum
/// renamed with an identical set of `name=value` cases is reported as a rename.
fn compare_error_enums(
    old: &ContractSpec,
    new: &ContractSpec,
    _classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Same name on both sides: compare cases.
    for (name, old_error_enum) in &old.error_enums {
        if let Some(new_error_enum) = new.error_enums.get(name) {
            check_error_enum_cases(name, old_error_enum, new_error_enum, report);
        }
    }

    // 2. One-sided names: detect renames before reporting removed/added.
    let removed: BTreeMap<String, &ScSpecUdtErrorEnumV0> = old
        .error_enums
        .iter()
        .filter(|(n, _)| !new.error_enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtErrorEnumV0> = new
        .error_enums
        .iter()
        .filter(|(n, _)| !old.error_enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        emit_rename_finding(rename, "error enum", TypeClass::Storage, report);
        if !rename.identical {
            check_error_enum_cases(
                &rename.new_name,
                removed[&rename.old_name],
                added[&rename.new_name],
                report,
            );
        }
    }

    // 3. Genuinely removed error enums.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Error Enum Removed".to_string(),
            message: format!(
                "Error enum '{}' was removed. Clients matching on these errors will break.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
    }

    // 4. Genuinely added error enums.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Error Enum Added".to_string(),
            message: format!("New error enum '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
    }
}

/// Compare cases of two error enums with the same name.
fn check_error_enum_cases(
    name: &str,
    old_error_enum: &ScSpecUdtErrorEnumV0,
    new_error_enum: &ScSpecUdtErrorEnumV0,
    report: &mut DiffReport,
) {
    let old_cases: &[ScSpecUdtErrorEnumCaseV0] = old_error_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtErrorEnumCaseV0] = new_error_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();
        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Error Enum Case Removed".to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' (value: {}) was removed. \
                         Clients matching on this error code will break.",
                        name, old_name, old_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: None,
                });
            }
            Some(new_case) if old_case.value != new_case.value => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Error Enum Case Value Changed".to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' value changed from {} to {}. \
                         This breaks error-code compatibility.",
                        name, old_name, old_case.value, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: None,
                });
            }
            _ => {}
        }
    }

    for new_case in new_cases {
        let new_name = new_case.name.to_string();
        if !old_cases.iter().any(|c| c.name.to_string() == new_name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Error Enum Case Added".to_string(),
                message: format!(
                    "Error enum '{}': new case '{}' (value {}) added.",
                    name, new_name, new_case.value
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_name)),
                classification: None,
            });
        }
    }
}

/// Uses dependency graphing to figure out if storage layout changes cascade to other types.
fn detect_cascading_layout_breaks(old: &ContractSpec, report: &mut DiffReport) {
    let old_mapper = LayoutMapper::new(old);
    let reverse_deps = old_mapper.build_reverse_dependencies();

    // Collect all UDTs that had a critical breaking change.
    // We read `type_name` directly — no message-text parsing needed.
    let mut broken_types = std::collections::HashSet::new();
    for finding in &report.findings {
        if finding.severity == Severity::Critical {
            if let Some(ref name) = finding.type_name {
                broken_types.insert(name.clone());
            }
        }
    }

    // A queue for transitive breaks
    let mut queue: Vec<String> = broken_types.into_iter().collect();
    let mut i = 0;
    let mut cascaded = std::collections::HashSet::new();

    while i < queue.len() {
        let current_broken_type = queue[i].clone();
        i += 1;

        if let Some(dependents) = reverse_deps.get(&current_broken_type) {
            for dep in dependents {
                // Ignore if it was the original broken type
                if !cascaded.contains(dep) {
                    cascaded.insert(dep.clone());
                    queue.push(dep.clone());

                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Cascading Layout Break".to_string(),
                        message: format!(
                            "Type '{}' layout is broken because it embeds modified type '{}'. \
                             Stored data for '{}' is no longer compatible.",
                            dep, current_broken_type, dep
                        ),
                        type_name: Some(dep.clone()),
                        target: Some(dep.clone()),
                        classification: None,
                    });
                }
            }
        }
    }
}

/// Policy-aware variant of [`detect_cascading_layout_breaks`].
///
/// Uses [`crate::mapper::LayoutMapper::new_with_policy`] so the walk is bounded
/// by `policy.max_walk_depth`. Returns a [`crate::limits::LimitError`] if the
/// type graph is deeper than the configured limit.
fn detect_cascading_layout_breaks_with_policy(
    old: &ContractSpec,
    report: &mut DiffReport,
    policy: &crate::limits::ResourcePolicy,
) -> Result<(), crate::limits::LimitError> {
    let old_mapper = LayoutMapper::new_with_policy(old, policy);
    let reverse_deps = old_mapper.try_build_reverse_dependencies()?;

    let mut broken_types = std::collections::HashSet::new();
    for finding in &report.findings {
        if finding.severity == Severity::Critical {
            if let Some(ref name) = finding.type_name {
                broken_types.insert(name.clone());
            }
        }
    }

    let mut queue: Vec<String> = broken_types.into_iter().collect();
    let mut i = 0;
    let mut cascaded = std::collections::HashSet::new();

    while i < queue.len() {
        let current_broken_type = queue[i].clone();
        i += 1;

        if let Some(dependents) = reverse_deps.get(&current_broken_type) {
            for dep in dependents {
                if !cascaded.contains(dep) {
                    cascaded.insert(dep.clone());
                    queue.push(dep.clone());

                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Cascading Layout Break".to_string(),
                        message: format!(
                            "Type '{}' layout is broken because it embeds modified type '{}'. \
                             Stored data for '{}' is no longer compatible.",
                            dep, current_broken_type, dep
                        ),
                        type_name: Some(dep.clone()),
                        target: Some(dep.clone()),
                        classification: None,
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};
    use stellar_xdr::curr::{ScEnvMetaEntry, ScSpecTypeUdt, StringM, VecM};

    #[test]
    fn exported_functions_detect_removals_additions_and_spec_mismatches() {
        let old_exports = BTreeSet::from(["legacy".to_string(), "old_only".to_string()]);
        let new_exports = BTreeSet::from(["legacy".to_string(), "new_only".to_string()]);
        let old_spec = HashSet::from(["legacy".to_string(), "declared_only_old".to_string()]);
        let new_spec = HashSet::from(["legacy".to_string(), "declared_only_new".to_string()]);
        let mut report = DiffReport::default();

        compare_exports(
            &old_exports,
            &new_exports,
            &old_spec,
            &new_spec,
            &mut report,
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == "Export Removed"
                && finding.target.as_deref() == Some("old_only")
                && finding.severity == Severity::Critical
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "Export Added"
                && finding.target.as_deref() == Some("new_only")
                && finding.severity == Severity::Info
        }));
        for target in [
            "declared_only_old",
            "old_only",
            "declared_only_new",
            "new_only",
        ] {
            assert!(report.findings.iter().any(|finding| {
                finding.category == "Export Spec Mismatch"
                    && finding.target.as_deref() == Some(target)
            }));
        }
    }

    /// Helper: build a minimal ContractSpec with the given structs.
    fn spec_with_structs(structs: Vec<(&str, Vec<(&str, ScSpecTypeDef)>)>) -> ContractSpec {
        let mut spec = ContractSpec::default();
        for (name, fields) in structs {
            let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
                .into_iter()
                .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: fname.try_into().unwrap(),
                    type_: ftype,
                })
                .collect();
            spec.structs.insert(
                name.to_string(),
                ScSpecUdtStructV0 {
                    doc: StringM::default(),
                    lib: StringM::default(),
                    name: name.try_into().unwrap(),
                    fields: VecM::try_from(xdr_fields).unwrap(),
                },
            );
        }
        spec
    }

    /// Helper: create a UDT type reference.
    fn udt(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    // ---------------------------------------------------------------
    // Test 1: cascade detection picks up broken types via type_name
    // ---------------------------------------------------------------
    #[test]
    fn cascade_detects_break_via_type_name() {
        // Old spec: Inner(value: u32), Outer(inner: Inner)
        let old = spec_with_structs(vec![
            ("Inner", vec![("value", ScSpecTypeDef::U32)]),
            ("Outer", vec![("inner", udt("Inner"))]),
        ]);
        // New spec: Inner has its field type changed -> triggers Critical
        let new = spec_with_structs(vec![
            ("Inner", vec![("value", ScSpecTypeDef::U64)]),
            ("Outer", vec![("inner", udt("Inner"))]),
        ]);

        let report = compare(&old, &new);

        // Inner should have a direct Critical finding
        let inner_critical = report.findings.iter().any(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Inner")
                && f.category != "Cascading Layout Break"
        });
        assert!(
            inner_critical,
            "Expected a direct critical finding for Inner"
        );

        // Outer should have a cascading break with clear dependency wording
        let outer_cascade = report.findings.iter().find(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Outer")
                && f.category == "Cascading Layout Break"
        });
        assert!(
            outer_cascade.is_some(),
            "Expected a cascading break for Outer"
        );
        let message = &outer_cascade.unwrap().message;
        assert!(
            !message.contains("broken safely"),
            "Cascade message must not use contradictory 'broken safely' phrasing"
        );
        assert!(
            message
                .contains("Type 'Outer' layout is broken because it embeds modified type 'Inner'"),
            "Unexpected cascade message: {message}"
        );
        assert!(
            message.contains("Stored data for 'Outer' is no longer compatible"),
            "Cascade message must explain storage impact: {message}"
        );
    }

    // ---------------------------------------------------------------
    // Test 2: changing a finding's message text does NOT affect cascade
    // ---------------------------------------------------------------
    #[test]
    fn cascade_is_message_independent() {
        // Old spec: Child(x: u32), Parent(child: Child)
        let old = spec_with_structs(vec![
            ("Child", vec![("x", ScSpecTypeDef::U32)]),
            ("Parent", vec![("child", udt("Child"))]),
        ]);

        // Build a report with a manually crafted finding whose message
        // is completely different from the production format, but whose
        // type_name is set correctly.
        let mut report = DiffReport::default();
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "TOTALLY CUSTOM CATEGORY".to_string(),
            message: "This message has no quotes and mentions no type prefix whatsoever."
                .to_string(),
            type_name: Some("Child".to_string()),
            target: Some("Child".to_string()),
            classification: None,
        });

        // Run cascade detection against the old spec
        detect_cascading_layout_breaks(&old, &mut report);

        // Parent should still be detected as cascaded
        let parent_cascade = report.findings.iter().any(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Parent")
                && f.category == "Cascading Layout Break"
        });
        assert!(
            parent_cascade,
            "Cascade should work regardless of message text"
        );
    }

    // ---------------------------------------------------------------
    // Test 3: function-level findings (type_name: None) do NOT
    //         trigger false cascades
    // ---------------------------------------------------------------
    #[test]
    fn function_findings_do_not_cascade() {
        let old = spec_with_structs(vec![("MyStruct", vec![("val", ScSpecTypeDef::U32)])]);

        let mut report = DiffReport::default();
        // Simulate a function-level Critical finding with type_name: None
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Function Removed".to_string(),
            message: "Function 'do_stuff' was removed.".to_string(),
            type_name: None,
            target: Some("do_stuff".to_string()),
            classification: None,
        });

        detect_cascading_layout_breaks(&old, &mut report);

        // Should still be just the one finding -- no cascade
        assert_eq!(
            report.findings.len(),
            1,
            "Function findings should not trigger cascades"
        );
    }

    // ---------------------------------------------------------------
    // Test 4: transitive cascades (A -> B -> C)
    // ---------------------------------------------------------------
    #[test]
    fn transitive_cascade_propagates() {
        // Leaf(x: u32), Mid(leaf: Leaf), Top(mid: Mid)
        let old = spec_with_structs(vec![
            ("Leaf", vec![("x", ScSpecTypeDef::U32)]),
            ("Mid", vec![("leaf", udt("Leaf"))]),
            ("Top", vec![("mid", udt("Mid"))]),
        ]);
        let new = spec_with_structs(vec![
            ("Leaf", vec![("x", ScSpecTypeDef::U64)]), // break
            ("Mid", vec![("leaf", udt("Leaf"))]),
            ("Top", vec![("mid", udt("Mid"))]),
        ]);

        let report = compare(&old, &new);

        let cascade_types: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.category == "Cascading Layout Break")
            .filter_map(|f| f.type_name.as_deref())
            .collect();

        assert!(
            cascade_types.contains(&"Mid"),
            "Mid should cascade from Leaf"
        );
        assert!(
            cascade_types.contains(&"Top"),
            "Top should cascade from Mid"
        );
    }

    // ---------------------------------------------------------------
    // Test 5: no regression in categories/severities for the basic
    //         struct-field-type-changed scenario
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_type_change_severity_and_category() {
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::I128)])]);

        let report = compare(&old, &new);

        let field_change = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed");
        assert!(field_change.is_some(), "Should detect field type change");

        let f = field_change.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.type_name.as_deref(), Some("Data"));
        // The `target` pinpoints the exact field (`Type.field`) so a
        // suppression keyed on it cannot over-apply to sibling fields.
        assert_eq!(f.target.as_deref(), Some("Data.amount"));
    }

    // ---------------------------------------------------------------
    // Test 6: findings carry a precise, structured `target` for every
    //         granularity (function, field, enum case, type).
    // ---------------------------------------------------------------
    #[test]
    fn findings_expose_precise_targets() {
        // Struct removed entirely -> target is the bare type name.
        let old = spec_with_structs(vec![("Gone", vec![("x", ScSpecTypeDef::U32)])]);
        let new = ContractSpec::default();
        let report = compare(&old, &new);
        let removed = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Removed")
            .expect("expected a struct-removed finding");
        assert_eq!(removed.target.as_deref(), Some("Gone"));

        // Struct field removed -> target is `Type.field`.
        let old = spec_with_structs(vec![(
            "Data",
            vec![("keep", ScSpecTypeDef::U32), ("drop", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_structs(vec![("Data", vec![("keep", ScSpecTypeDef::U32)])]);
        let report = compare(&old, &new);
        let field_removed = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Removed")
            .expect("expected a field-removed finding");
        assert_eq!(field_removed.target.as_deref(), Some("Data.drop"));
    }

    fn env_meta(protocol: u32, pre_release: u32) -> ContractEnvMeta {
        let version = ((protocol as u64) << 32) | (pre_release as u64);
        ContractEnvMeta {
            entries: vec![ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version)],
        }
    }

    #[test]
    fn struct_doc_change_produces_info() {
        let mut old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let mut new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);

        // Set differing docs
        old.structs.get_mut("Data").unwrap().doc = "old doc".try_into().unwrap();
        new.structs.get_mut("Data").unwrap().doc = "new doc".try_into().unwrap();

        let report = compare(&old, &new);

        let found = report.findings.iter().any(|f| {
            f.severity == Severity::Info
                && f.category == "Struct Documentation Changed"
                && f.type_name.as_deref() == Some("Data")
        });
        assert!(found, "Expected an info finding for struct doc change");

        // Ensure info findings do not influence safety
        let safety = crate::report::SafetyReport::new(&report);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }

    #[test]
    fn identical_struct_docs_produce_no_finding() {
        let mut old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let mut new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);

        // Same doc text
        old.structs.get_mut("Data").unwrap().doc = "doc".try_into().unwrap();
        new.structs.get_mut("Data").unwrap().doc = "doc".try_into().unwrap();

        let report = compare(&old, &new);
        // No findings expected
        assert!(
            report.findings.is_empty(),
            "Expected no findings when docs identical"
        );
    }

    #[test]
    fn identical_env_metadata_produces_no_finding() {
        let meta = env_meta(21, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&meta), Some(&meta), &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn env_metadata_protocol_change_is_warning() {
        let old = env_meta(21, 0);
        let new = env_meta(22, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.category, ENVIRONMENT_CATEGORY);
        assert!(finding
            .message
            .contains("protocol interface version changed"));
    }

    #[test]
    fn env_metadata_pre_release_only_change_is_info() {
        let old = env_meta(21, 0);
        let new = env_meta(21, 1);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, ENVIRONMENT_CATEGORY);
    }

    #[test]
    fn env_metadata_findings_do_not_affect_is_safe() {
        let old = env_meta(21, 0);
        let new = env_meta(22, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        let safety = crate::report::SafetyReport::new(&report);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }

    /// Helper: build a minimal ContractSpec with the given functions.
    fn spec_with_functions(functions: Vec<(&str, Vec<(&str, ScSpecTypeDef)>)>) -> ContractSpec {
        let mut spec = ContractSpec::default();
        for (name, inputs) in functions {
            let xdr_inputs: Vec<stellar_xdr::curr::ScSpecFunctionInputV0> = inputs
                .into_iter()
                .map(|(iname, itype)| stellar_xdr::curr::ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: iname.try_into().unwrap(),
                    type_: itype,
                })
                .collect();
            spec.functions.insert(
                name.to_string(),
                stellar_xdr::curr::ScSpecFunctionV0 {
                    doc: StringM::default(),
                    name: name.try_into().unwrap(),
                    inputs: VecM::try_from(xdr_inputs).unwrap(),
                    outputs: VecM::default(),
                },
            );
        }
        spec
    }

    #[test]
    fn param_reorder_same_type_produces_critical_finding() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("b", ScSpecTypeDef::U32), ("a", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let reorder_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Reordered");

        assert!(
            reorder_finding.is_some(),
            "Expected a Parameter Reordered finding"
        );
        let f = reorder_finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.message.contains("parameters reordered"));

        // Ensure no Parameter Renamed warnings are generated
        let rename_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Renamed")
            .count();
        assert_eq!(
            rename_findings, 0,
            "Should not double-count reorders as renames"
        );
    }

    #[test]
    fn param_pure_rename_produces_warning() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("x", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let rename_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Renamed");

        assert!(
            rename_finding.is_some(),
            "Expected a Parameter Renamed finding"
        );
        let f = rename_finding.unwrap();
        assert_eq!(f.severity, Severity::Warning);

        // Ensure no Parameter Reordered findings are generated
        let reorder_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Reordered")
            .count();
        assert_eq!(reorder_findings, 0);
    }

    #[test]
    fn param_type_change_produces_critical_finding() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::Bool), ("b", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let type_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Type Changed");

        assert!(
            type_finding.is_some(),
            "Expected a Parameter Type Changed finding"
        );
        let f = type_finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);

        // Ensure no Parameter Reordered findings are generated
        let reorder_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Reordered")
            .count();
        assert_eq!(reorder_findings, 0);
    }

    #[test]
    fn param_reorder_and_type_change_produces_both() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("b", ScSpecTypeDef::U32), ("a", ScSpecTypeDef::Bool)],
        )]);

        let report = compare(&old, &new);

        let reorder_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Reordered");
        assert!(
            reorder_finding.is_some(),
            "Expected a Parameter Reordered finding"
        );
        assert_eq!(reorder_finding.unwrap().severity, Severity::Critical);

        let type_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Type Changed");
        assert!(
            type_finding.is_some(),
            "Expected a Parameter Type Changed finding"
        );
        let tf = type_finding.unwrap();
        assert_eq!(tf.severity, Severity::Critical);
        assert!(tf.message.contains("parameter 0 ('a') type changed")); // Index in old is 0
    }
}
