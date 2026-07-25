use crate::diff::Severity;

/// A single registered detection rule.
#[derive(Debug, Clone, Copy)]
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
        id: "return_type_changed",
        label: "Return Type Changed",
        severity: Severity::Critical,
        guidance: "This is a breaking change. Update caller expectations and client SDKs to match the new return type.",
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
