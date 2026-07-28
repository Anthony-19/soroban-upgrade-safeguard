use crate::diff::Severity;

/// A single registered detection rule.
#[derive(Debug, Clone)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub label: &'static str,
    pub severity: Severity,
    pub guidance: &'static str,
}

pub const RULES: &[RuleDefinition] = &[
    RuleDefinition {
        id: "environment",
        label: "Environment",
        severity: Severity::Info,
        guidance: "Verify that the target network supports the new protocol version and adjust any SDK/tooling dependencies accordingly.",
    },
    RuleDefinition {
        id: "function_removed",
        label: "Function Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. If the function is no longer needed, deprecate it in client integrations. Otherwise, restore the function signature.",
    },
    RuleDefinition {
        id: "function_documentation_changed",
        label: "Function Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Ensure client/consumer integrations are aware of the updated documentation/behavior.",
    },
    RuleDefinition {
        id: "function_added",
        label: "Function Added",
        severity: Severity::Info,
        guidance: "No action required. Inform client integrations about the availability of the new function.",
    },
    RuleDefinition {
        id: "function_signature_changed",
        label: "Function Signature Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update call sites, SDKs, and tests to match the new parameter structure.",
    },
    RuleDefinition {
        id: "parameter_renamed",
        label: "Parameter Renamed",
        severity: Severity::Warning,
        guidance: "This is a breaking change for named-argument RPC systems. Update all client integrations to use the new parameter name.",
    },
    RuleDefinition {
        id: "parameter_reordered",
        label: "Parameter Reordered",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Reordering parameters breaks positional RPC invocation. Restore the original parameter order.",
    },
    RuleDefinition {
        id: "parameter_type_changed",
        label: "Parameter Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update caller arguments and client SDKs to match the new parameter type.",
    },
    RuleDefinition {
        id: "parameter_type_widened",
        label: "Parameter Type Widened",
        severity: Severity::Warning,
        guidance: "This is a widening numeric conversion — every old value fits in the new type without loss, but it is still a layout change. Update client SDKs to the new parameter type and confirm callers pass values that fit the new range.",
    },
    RuleDefinition {
        id: "parameter_type_narrowed",
        label: "Parameter Type Narrowed",
        severity: Severity::Critical,
        guidance: "This is a breaking, lossy change. Values that don't fit the narrower type will be truncated. Revert the narrowing or validate/migrate call sites before deploying.",
    },
    RuleDefinition {
        id: "parameter_type_signedness_changed",
        label: "Parameter Type Signedness Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing signedness reinterprets the underlying bits, which can turn valid values into unexpected ones. Revert the signedness change or carefully audit every caller.",
    },
    RuleDefinition {
        id: "parameter_documentation_changed",
        label: "Parameter Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Parameter documentation often pins down units or semantics (e.g. stroops vs. whole units) — confirm the new wording is accurate and update client-facing docs.",
    },
    RuleDefinition {
        id: "return_type_changed",
        label: "Return Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update caller expectations and client SDKs to match the new return type.",
    },
    RuleDefinition {
        id: "return_type_widened",
        label: "Return Type Widened",
        severity: Severity::Warning,
        guidance: "This is a widening numeric conversion — every old value fits in the new type without loss, but it is still a layout change. Update client SDKs that decode this return type.",
    },
    RuleDefinition {
        id: "return_type_narrowed",
        label: "Return Type Narrowed",
        severity: Severity::Critical,
        guidance: "This is a breaking, lossy change. Values that don't fit the narrower return type will be truncated. Revert the narrowing or update callers to handle the new range.",
    },
    RuleDefinition {
        id: "return_type_signedness_changed",
        label: "Return Type Signedness Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing signedness reinterprets the underlying bits of the returned value. Revert the signedness change or audit every caller that consumes this return value.",
    },
    RuleDefinition {
        id: "event_definition_removed",
        label: "Event Definition Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update or remove downstream event indexing or monitoring systems that consume this event.",
    },
    RuleDefinition {
        id: "struct_removed",
        label: "Struct Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Ensure no stored data or active interfaces reference this struct. If they do, restore the struct.",
    },
    RuleDefinition {
        id: "struct_documentation_changed",
        label: "Struct Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Ensure documentation changes are aligned with the struct's intended usage.",
    },
    RuleDefinition {
        id: "struct_added",
        label: "Struct Added",
        severity: Severity::Info,
        guidance: "No action required. New structs can be safely integrated into storage layouts or interface parameters.",
    },
    RuleDefinition {
        id: "struct_field_removed",
        label: "Struct Field Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Removing fields breaks serialized storage layouts. Restore the field or perform a state migration.",
    },
    RuleDefinition {
        id: "event_field_removed",
        label: "Event Field Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update event indexers and consumers that expect this field to be present.",
    },
    RuleDefinition {
        id: "struct_field_reordered",
        label: "Struct Field Reordered",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Reordering fields breaks positional serialization layouts. Restore the original field order.",
    },
    RuleDefinition {
        id: "event_field_reordered",
        label: "Event Field Reordered",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update event indexers and consumers to handle the new positional field order.",
    },
    RuleDefinition {
        id: "struct_field_type_changed",
        label: "Struct Field Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing field types breaks layout serialization. Revert the type change or migrate existing data.",
    },
    RuleDefinition {
        id: "event_field_type_changed",
        label: "Event Field Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update event indexers and consumers to handle the new field type.",
    },
    RuleDefinition {
        id: "struct_field_type_widened",
        label: "Struct Field Type Widened",
        severity: Severity::Warning,
        guidance: "This is a widening numeric conversion — every old value fits in the new type without loss, but stored data still uses the old encoding. Migrate existing storage entries to the new field type before relying on it.",
    },
    RuleDefinition {
        id: "struct_field_type_narrowed",
        label: "Struct Field Type Narrowed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Narrowing a stored field's type can truncate every existing value. Revert the narrowing or run a state migration that validates values fit the new type.",
    },
    RuleDefinition {
        id: "struct_field_type_signedness_changed",
        label: "Struct Field Type Signedness Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing a stored field's signedness reinterprets its bit pattern, corrupting existing values. Revert the signedness change or run a state migration that reinterprets and revalidates stored data.",
    },
    RuleDefinition {
        id: "struct_field_documentation_changed",
        label: "Struct Field Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Confirm the updated field documentation is accurate and reflected in client-facing docs.",
    },
    RuleDefinition {
        id: "struct_field_added",
        label: "Struct Field Added",
        severity: Severity::Warning,
        guidance: "Warning: Ensure existing storage entries are migrated or initialized with correct default values for the new field.",
    },
    RuleDefinition {
        id: "event_enum_removed",
        label: "Event Enum Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Downstream event consumers or indexers relying on this enum will fail. Restore the enum.",
    },
    RuleDefinition {
        id: "enum_removed",
        label: "Enum Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Stored data or parameters using this enum will be invalid. Restore the enum.",
    },
    RuleDefinition {
        id: "enum_documentation_changed",
        label: "Enum Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Ensure the updated docs are clear for consumers.",
    },
    RuleDefinition {
        id: "enum_added",
        label: "Enum Added",
        severity: Severity::Info,
        guidance: "No action required. Ensure consumers are aware of the new enum type if needed.",
    },
    RuleDefinition {
        id: "enum_case_removed",
        label: "Enum Case Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. On-chain data or parameters using this case will be invalid. Restore the case.",
    },
    RuleDefinition {
        id: "event_enum_case_removed",
        label: "Event Enum Case Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Downstream event indexers or consumers relying on this case will fail. Restore the case.",
    },
    RuleDefinition {
        id: "enum_case_value_changed",
        label: "Enum Case Value Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Modifying case values breaks serialization/deserialization. Revert the value change.",
    },
    RuleDefinition {
        id: "event_enum_case_value_changed",
        label: "Event Enum Case Value Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Downstream event indexers or consumers relying on these values will fail. Revert the value change.",
    },
    RuleDefinition {
        id: "enum_case_added",
        label: "Enum Case Added",
        severity: Severity::Info,
        guidance: "No action required. Ensure consumers can handle the new case gracefully.",
    },
    RuleDefinition {
        id: "event_enum_case_added",
        label: "Event Enum Case Added",
        severity: Severity::Info,
        guidance: "No action required. Update event indexers and consumers to handle the new event enum case if necessary.",
    },
    RuleDefinition {
        id: "enum_case_documentation_changed",
        label: "Enum Case Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Confirm the updated case documentation is accurate and reflected in client-facing docs.",
    },
    RuleDefinition {
        id: "union_removed",
        label: "Union Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Stored data or parameters using this union will be invalid. Restore the union.",
    },
    RuleDefinition {
        id: "union_added",
        label: "Union Added",
        severity: Severity::Info,
        guidance: "No action required. Ensure consumers are aware of the new union type if needed.",
    },
    RuleDefinition {
        id: "union_documentation_changed",
        label: "Union Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Ensure documentation changes are aligned with the union's intended usage.",
    },
    RuleDefinition {
        id: "union_case_removed",
        label: "Union Case Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. On-chain data using this union case will be invalid. Restore the case.",
    },
    RuleDefinition {
        id: "union_case_reordered",
        label: "Union Case Reordered",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Reordering union cases breaks positional discriminant serialization. Restore the original case order.",
    },
    RuleDefinition {
        id: "union_case_type_changed",
        label: "Union Case Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing union case payload types breaks layout serialization. Revert the type change or migrate existing data.",
    },
    RuleDefinition {
        id: "union_case_type_widened",
        label: "Union Case Type Widened",
        severity: Severity::Warning,
        guidance: "This is a widening numeric conversion — every old value fits in the new type without loss, but stored data still uses the old encoding. Migrate existing storage entries to the new case payload type before relying on it.",
    },
    RuleDefinition {
        id: "union_case_type_narrowed",
        label: "Union Case Type Narrowed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Narrowing a union case's payload type can truncate every existing value. Revert the narrowing or run a state migration that validates values fit the new type.",
    },
    RuleDefinition {
        id: "union_case_type_signedness_changed",
        label: "Union Case Type Signedness Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Changing a union case payload's signedness reinterprets its bit pattern, corrupting existing values. Revert the signedness change or run a state migration.",
    },
    RuleDefinition {
        id: "union_case_added",
        label: "Union Case Added",
        severity: Severity::Info,
        guidance: "No action required. Ensure consumers can handle the new union case gracefully.",
    },
    RuleDefinition {
        id: "error_enum_removed",
        label: "Error Enum Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Clients matching on these error codes will break. Restore the error enum.",
    },
    RuleDefinition {
        id: "error_enum_added",
        label: "Error Enum Added",
        severity: Severity::Info,
        guidance: "No action required. Inform client integrations about the new error enum if needed.",
    },
    RuleDefinition {
        id: "error_enum_documentation_changed",
        label: "Error Enum Documentation Changed",
        severity: Severity::Info,
        guidance: "No code changes required. Ensure documentation changes are aligned with the error enum's intended usage.",
    },
    RuleDefinition {
        id: "error_enum_case_removed",
        label: "Error Enum Case Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Clients matching on this error code will break. Restore the case.",
    },
    RuleDefinition {
        id: "error_enum_case_value_changed",
        label: "Error Enum Case Value Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Modifying error case values breaks error-code compatibility. Revert the value change.",
    },
    RuleDefinition {
        id: "error_enum_case_added",
        label: "Error Enum Case Added",
        severity: Severity::Info,
        guidance: "No action required. Ensure clients can handle the new error case gracefully.",
    },
    RuleDefinition {
        id: "cascading_layout_break",
        label: "Cascading Layout Break",
        severity: Severity::Critical,
        guidance: "This is a breaking change. A nested user-defined type has a breaking layout change. Resolve the break in the referenced type.",
    },
    RuleDefinition {
        id: "export_removed",
        label: "Export Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. The function is no longer exported by the binary. On-chain callers will receive a missing-export error. Restore the export or update all callers before upgrading.",
    },
    RuleDefinition {
        id: "export_added",
        label: "Export Added",
        severity: Severity::Info,
        guidance: "No action required. A new entry-point is now exported by the binary. Ensure the spec is updated to reflect this if the function is intended to be part of the public interface.",
    },
    RuleDefinition {
        id: "export_spec_mismatch",
        label: "Export Spec Mismatch",
        severity: Severity::Critical,
        guidance: "A function appears in the spec but not the binary (or vice versa). The spec and binary must agree on the callable surface. Align the spec and the export list before deploying.",
    },
    RuleDefinition {
        id: "metadata_sdk_version_changed",
        label: "Metadata SDK Version Changed",
        severity: Severity::Warning,
        guidance: "The Soroban SDK version recorded in build metadata changed. Even with an identical exported interface, a new SDK can regenerate the host-interaction code, so rebuild and re-run the test suite, and confirm the new SDK supports the target network's protocol version.",
    },
    RuleDefinition {
        id: "metadata_compiler_version_changed",
        label: "Metadata Compiler Version Changed",
        severity: Severity::Warning,
        guidance: "The Rust compiler version recorded in build metadata changed. This is not a breaking interface change on its own, but it affects code generation; build reproducibly and run the full test suite to confirm behavior is unchanged.",
    },
    RuleDefinition {
        id: "metadata_key_added",
        label: "Metadata Key Added",
        severity: Severity::Info,
        guidance: "A new author-supplied metadata key was added. No action is required for compatibility; confirm the added provenance is intentional.",
    },
    RuleDefinition {
        id: "metadata_key_removed",
        label: "Metadata Key Removed",
        severity: Severity::Info,
        guidance: "An author-supplied metadata key was removed. Confirm no downstream tooling reads this key before deploying.",
    },
    RuleDefinition {
        id: "metadata_key_changed",
        label: "Metadata Key Changed",
        severity: Severity::Info,
        guidance: "An author-supplied metadata value changed. Verify the new value is intended and that any tooling consuming it tolerates the change.",
    },
    RuleDefinition {
        id: "type_renamed",
        label: "Type Renamed",
        severity: Severity::Warning,
        guidance: "A type was renamed but its layout is identical, so stored data stays compatible. Update client code and bindings to use the new type name.",
    },
    RuleDefinition {
        id: "type_renamed_with_changes",
        label: "Type Renamed With Changes",
        severity: Severity::Warning,
        guidance: "A type appears renamed and its layout also changed. Treat the layout change as the breaking part: review the field-level findings and migrate stored data before deploying.",
    },
    RuleDefinition {
        id: "parameter_added",
        label: "Parameter Added",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Adding parameters breaks positional/named RPC invocation. Restore the original parameter structure or update all client integrations.",
    },
    RuleDefinition {
        id: "parameter_removed",
        label: "Parameter Removed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Removing parameters breaks positional/named RPC invocation. Restore the parameter or update all client integrations.",
    },
    RuleDefinition {
        id: "function_renamed",
        label: "Function Renamed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. A function was renamed which breaks existing callers. Update client integrations to use the new function name.",
    },
    RuleDefinition {
        id: "return_type_success_arm_changed",
        label: "Return Type Success Arm Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update caller expectations and client SDKs to match the new success return type.",
    },
    RuleDefinition {
        id: "return_type_error_arm_changed",
        label: "Return Type Error Arm Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update error handling code and client SDKs to handle the new return error type.",
    },
    RuleDefinition {
        id: "spec_entry_duplicate",
        label: "Spec Entry Duplicate",
        severity: Severity::Info,
        guidance: "The same spec entry appears more than once with an identical definition. The WASM is non-canonical but safe to use; regenerate the contract spec to deduplicate.",
    },
    RuleDefinition {
        id: "spec_entry_conflict",
        label: "Spec Entry Conflict",
        severity: Severity::Critical,
        guidance: "This is a breaking change. A spec entry is defined multiple times with conflicting definitions. The contract spec is ambiguous and must be fixed.",
    },
    RuleDefinition {
        id: "unresolved_storage_reference",
        label: "Unresolved Storage Reference",
        severity: Severity::Warning,
        guidance: "The storage schema references a type that could not be resolved, so coverage is incomplete for it. Add the missing type to the schema or correct the reference.",
    },
    RuleDefinition {
        id: "host_import_added",
        label: "Host Import Added",
        severity: Severity::Warning,
        guidance: "A new host function import is required by the WASM. Verify that the target network environment supports this host function before deploying.",
    },
    RuleDefinition {
        id: "host_import_removed",
        label: "Host Import Removed",
        severity: Severity::Info,
        guidance: "No action required. A host function import is no longer required by the WASM.",
    },
];

pub fn all_rules() -> &'static [RuleDefinition] {
    RULES
}

pub fn rule_by_id(rule_id: &str) -> Option<&'static RuleDefinition> {
    RULES.iter().find(|rule| rule.id == rule_id)
}

pub fn rule_by_label(label: &str) -> Option<&'static RuleDefinition> {
    RULES.iter().find(|rule| rule.label == label)
}

pub fn canonical_rule_id(value: &str) -> Option<&'static str> {
    rule_by_id(value)
        .map(|rule| rule.id)
        .or_else(|| rule_by_label(value).map(|rule| rule.id))
}

pub fn display_label_for_rule_id(rule_id: &str) -> Option<&'static str> {
    rule_by_id(rule_id).map(|rule| rule.label)
}

pub fn guidance_for_rule_id(rule_id: &str) -> Option<&'static str> {
    rule_by_id(rule_id).map(|rule| rule.guidance)
}

/// Every registered category, by display label, sorted for stable output.
///
/// This is the enumerable inventory the `explain` subcommand lists and the
/// `[severity]` config validator checks against, so neither has to scrape
/// category names out of source text.
pub fn all_category_labels() -> Vec<&'static str> {
    let mut labels: Vec<&'static str> = RULES.iter().map(|rule| rule.label).collect();
    labels.sort_unstable();
    labels
}

/// Resolve a user-typed category to a rule, accepting either the display label
/// ("Union Case Reordered") or the stable rule id ("union_case_reordered"), in
/// any letter case.
///
/// Exact matching is what the suppression config and the report layer use, so
/// this stays deliberately narrow: it forgives capitalization only. Anything
/// looser belongs in [`suggest_categories`], where the user sees and confirms
/// the correction rather than silently getting a rule they did not name.
pub fn lookup_rule_lenient(input: &str) -> Option<&'static RuleDefinition> {
    let trimmed = input.trim();
    if let Some(rule) = rule_by_id(trimmed).or_else(|| rule_by_label(trimmed)) {
        return Some(rule);
    }
    let needle = trimmed.to_ascii_lowercase();
    RULES.iter().find(|rule| {
        rule.id.eq_ignore_ascii_case(&needle) || rule.label.eq_ignore_ascii_case(&needle)
    })
}

/// Category labels close to `input`, best match first, for "did you mean?".
///
/// Category names are long and matching elsewhere is exact, so an approximate
/// memory of a name would otherwise produce a silent no-op (a suppression rule
/// that never fires, a severity override that never applies). Returning
/// candidates turns that into a correctable mistake.
pub fn suggest_categories(input: &str) -> Vec<&'static str> {
    let needle = input.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }

    let mut scored: Vec<(usize, &'static str)> = RULES
        .iter()
        .map(|rule| {
            let label = rule.label.to_ascii_lowercase();
            // A substring hit ("union case") is a stronger signal than raw edit
            // distance across a long name, so it sorts ahead of everything else.
            let distance = if label.contains(&needle) || needle.contains(&label) {
                0
            } else {
                edit_distance(&needle, &label)
            };
            (distance, rule.label)
        })
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));

    // Scale the tolerance to the input length so a short typo does not drag in
    // every long category name.
    let tolerance = (needle.len() / 2).clamp(3, 8);
    scored
        .into_iter()
        .filter(|(distance, _)| *distance <= tolerance)
        .take(5)
        .map(|(_, label)| label)
        .collect()
}

/// Levenshtein distance over ASCII-lowercased bytes, two rows at a time.
fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];

    for (i, &ac) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &bc) in b.iter().enumerate() {
            let substitution = prev[j] + usize::from(ac != bc);
            curr[j + 1] = substitution.min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}
