use crate::diff::{DiffReport, Finding, Severity};
use crate::interface_hash::InterfaceHash;
use crate::render::{RenderableReport, REPORT_SCHEMA_VERSION};
use crate::suppression::SuppressionConfig;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub use crate::render::SeverityCounts;

/// The status of a compatibility axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AxisStatus {
    Passed,
    Warning,
    Failed,
}

/// A finding as it appears in the report, augmented with suppression state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedFinding {
    #[serde(flatten)]
    #[cfg(feature = "unstable")]
    pub finding: Finding,
    #[serde(flatten)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) finding: Finding,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg(feature = "unstable")]
    pub suppressed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "unstable")]
    pub suppression_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppression_reason: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "unstable")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) remediation: Option<String>,
}

impl ReportedFinding {
    pub fn finding(&self) -> &Finding {
        &self.finding
    }

    pub fn suppressed(&self) -> bool {
        self.suppressed
    }

    pub fn suppression_reason(&self) -> Option<&str> {
        self.suppression_reason.as_deref()
    }

    pub fn remediation(&self) -> Option<&str> {
        self.remediation.as_deref()
    }
}

/// A structured container for aggregated comparison findings.
#[derive(Debug, Default)]
pub struct SafetyReport {
    #[cfg(feature = "unstable")]
    pub critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) critical_count: usize,

    #[cfg(feature = "unstable")]
    pub warning_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) warning_count: usize,

    #[cfg(feature = "unstable")]
    pub info_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) info_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_critical_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_warning_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_warning_count: usize,

    #[cfg(feature = "unstable")]
    pub suppressed_info_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) suppressed_info_count: usize,

    #[cfg(feature = "unstable")]
    pub total_findings: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) total_findings: usize,

    #[cfg(feature = "unstable")]
    pub is_safe: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) is_safe: bool,

    #[cfg(feature = "unstable")]
    pub findings_by_category: HashMap<String, Vec<ReportedFinding>>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) findings_by_category: HashMap<String, Vec<ReportedFinding>>,

    #[cfg(feature = "unstable")]
    pub strict: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) strict: bool,

    #[cfg(feature = "unstable")]
    pub critical_root_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) critical_root_count: usize,

    #[cfg(feature = "unstable")]
    pub cascade_critical_count: usize,
    #[cfg(not(feature = "unstable"))]
    pub(crate) cascade_critical_count: usize,

    #[cfg(feature = "unstable")]
    pub old_interface_hash: Option<InterfaceHash>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) old_interface_hash: Option<InterfaceHash>,

    #[cfg(feature = "unstable")]
    pub new_interface_hash: Option<InterfaceHash>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) new_interface_hash: Option<InterfaceHash>,

    #[cfg(feature = "unstable")]
    pub no_timestamp: bool,
    #[cfg(not(feature = "unstable"))]
    pub(crate) no_timestamp: bool,

    #[cfg(feature = "unstable")]
    pub old_spec_summary: Option<String>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) old_spec_summary: Option<String>,

    #[cfg(feature = "unstable")]
    pub new_spec_summary: Option<String>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) new_spec_summary: Option<String>,

    #[cfg(feature = "unstable")]
    pub scope: AnalysisScope,
    #[cfg(not(feature = "unstable"))]
    pub(crate) scope: AnalysisScope,

    #[cfg(feature = "unstable")]
    pub metrics: Option<BuildMetrics>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) metrics: Option<BuildMetrics>,
}

impl SafetyReport {
    pub fn critical_count(&self) -> usize {
        self.critical_count
    }

    pub fn warning_count(&self) -> usize {
        self.warning_count
    }

    pub fn info_count(&self) -> usize {
        self.info_count
    }

    pub fn suppressed_count(&self) -> usize {
        self.suppressed_count
    }

    pub fn suppressed_critical_count(&self) -> usize {
        self.suppressed_critical_count
    }

    pub fn suppressed_warning_count(&self) -> usize {
        self.suppressed_warning_count
    }

    pub fn suppressed_info_count(&self) -> usize {
        self.suppressed_info_count
    }

    pub fn total_findings(&self) -> usize {
        self.total_findings
    }

    pub fn is_safe(&self) -> bool {
        self.is_safe
    }

    pub fn findings_by_category(&self) -> &HashMap<String, Vec<ReportedFinding>> {
        &self.findings_by_category
    }

    pub fn strict(&self) -> bool {
        self.strict
    }

    pub fn critical_root_count(&self) -> usize {
        self.critical_root_count
    }

    pub fn cascade_critical_count(&self) -> usize {
        self.cascade_critical_count
    }

    pub fn old_interface_hash(&self) -> Option<&InterfaceHash> {
        self.old_interface_hash.as_ref()
    }

    pub fn new_interface_hash(&self) -> Option<&InterfaceHash> {
        self.new_interface_hash.as_ref()
    }

    pub fn no_timestamp(&self) -> bool {
        self.no_timestamp
    }

    pub fn set_no_timestamp(&mut self, val: bool) {
        self.no_timestamp = val;
    }

    pub fn old_spec_summary(&self) -> Option<&str> {
        self.old_spec_summary.as_deref()
    }

    pub fn new_spec_summary(&self) -> Option<&str> {
        self.new_spec_summary.as_deref()
    }

    pub fn scope(&self) -> &AnalysisScope {
        &self.scope
    }

    pub fn metrics(&self) -> Option<&BuildMetrics> {
        self.metrics.as_ref()
    }
}

/// Track what was analyzed in the report.
#[derive(Debug, Clone, Default)]
pub struct AnalysisScope {
    pub exported_interface: bool,
    pub env_metadata: bool,
    pub storage_schema: StorageScopeState,
    pub old_spec_section_count: usize,
    pub new_spec_section_count: usize,
    pub old_duplicate_names: Vec<String>,
    pub new_duplicate_names: Vec<String>,
}

impl AnalysisScope {
    pub fn storage_analyzed(&self) -> bool {
        matches!(self.storage_schema, StorageScopeState::Analyzed { .. })
    }

    pub fn summary_line(&self) -> String {
        let mut parts = Vec::new();
        if self.exported_interface {
            parts.push("exported interface");
        }
        if self.env_metadata {
            parts.push("env metadata");
        }
        if self.storage_analyzed() {
            parts.push("storage schema");
        }
        if parts.is_empty() {
            "nothing".to_string()
        } else {
            parts.join(", ")
        }
    }

    pub fn storage_status_line(&self) -> String {
        match &self.storage_schema {
            StorageScopeState::Analyzed { key_types, value_types } => {
                format!("Storage layout analyzed ({} key types, {} value types)", key_types, value_types)
            }
            StorageScopeState::NotAnalyzed => {
                "Storage layout: NOT analyzed (use a storage schema manifest)".to_string()
            }
        }
    }
}

/// Whether storage schema analysis was performed.
#[derive(Debug, Clone)]
pub enum StorageScopeState {
    NotAnalyzed,
    Analyzed { key_types: usize, value_types: usize },
}

impl Default for StorageScopeState {
    fn default() -> Self {
        StorageScopeState::NotAnalyzed
    }
}

/// Build metrics for the report.
#[derive(Debug, Clone, Serialize)]
pub struct BuildMetrics {
    pub old_wasm_size: usize,
    pub new_wasm_size: usize,
    pub old_functions: usize,
    pub new_functions: usize,
    pub old_structs: usize,
    pub new_structs: usize,
    pub old_enums: usize,
    pub new_enums: usize,
    pub old_unions: usize,
    pub new_unions: usize,
    pub old_error_enums: usize,
    pub new_error_enums: usize,
}

impl BuildMetrics {
    pub fn new(
        old_wasm_size: usize,
        new_wasm_size: usize,
        old_functions: usize,
        new_functions: usize,
        old_structs: usize,
        new_structs: usize,
        old_enums: usize,
        new_enums: usize,
        old_unions: usize,
        new_unions: usize,
        old_error_enums: usize,
        new_error_enums: usize,
    ) -> Self {
        Self {
            old_wasm_size,
            new_wasm_size,
            old_functions,
            new_functions,
            old_structs,
            new_structs,
            old_enums,
            new_enums,
            old_unions,
            new_unions,
            old_error_enums,
            new_error_enums,
        }
    }
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A machine-readable view of a SafetyReport for JSON output.
pub type SafetyReportJson = RenderableReport;

/// Format a contract identity label from optional name and version strings.
fn contract_identity_label(name: Option<&str>, version: Option<&str>) -> String {
    match (name, version) {
        (Some(n), Some(v)) => format!("{} v{}", n, v),
        (Some(n), None) => n.to_string(),
        (None, Some(v)) => format!("v{}", v),
        (None, None) => "<unknown>".to_string(),
    }
}

impl SafetyReport {
    pub fn new(
        diff: &DiffReport,
        old_spec: &crate::spec::ContractSpec,
        new_spec: &crate::spec::ContractSpec,
    ) -> Self {
        Self::with_suppressions(
            diff,
            &SuppressionConfig::default(),
            false,
            false,
            old_spec,
            new_spec,
        )
    }

    pub fn noop(old_wasm_size: usize, new_wasm_size: usize) -> Self {
        let mut axis_verdicts = HashMap::new();
        axis_verdicts.insert(crate::diff::CompatibilityAxis::StorageLayout, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::CallAbi, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::EventIndexer, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::SourceLevel, AxisStatus::Passed);

        let mut gated_axes = HashSet::new();
        gated_axes.insert(crate::diff::CompatibilityAxis::StorageLayout);
        gated_axes.insert(crate::diff::CompatibilityAxis::CallAbi);

        Self {
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            total_findings: 0,
            is_safe: true,
            findings_by_category: HashMap::new(),
            strict: false,
            critical_root_count: 0,
            cascade_critical_count: 0,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            scope: AnalysisScope::default(),
            metrics: Some(BuildMetrics::new(
                old_wasm_size, new_wasm_size,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            )),
            empirical: false,
            empirical_findings: Vec::new(),
        }
    }

    /// Compute a safety report, applying a suppression config.
    pub fn with_suppressions(
        diff: &DiffReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
        old_spec: &crate::spec::ContractSpec,
        new_spec: &crate::spec::ContractSpec,
    ) -> Self {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut suppressed_count = 0;
        let mut suppressed_critical_count = 0;
        let mut suppressed_warning_count = 0;
        let mut suppressed_info_count = 0;
        let mut findings_by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();
        let mut critical_root_count = 0;
        let mut cascade_critical_count = 0;

        let mut axis_verdicts = HashMap::new();
        axis_verdicts.insert(crate::diff::CompatibilityAxis::StorageLayout, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::CallAbi, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::EventIndexer, AxisStatus::Passed);
        axis_verdicts.insert(crate::diff::CompatibilityAxis::SourceLevel, AxisStatus::Passed);

        let mut gated_axes = HashSet::new();
        let axes_list = vec![
            crate::diff::CompatibilityAxis::StorageLayout,
            crate::diff::CompatibilityAxis::CallAbi,
            crate::diff::CompatibilityAxis::EventIndexer,
            crate::diff::CompatibilityAxis::SourceLevel,
        ];
        for axis in axes_list {
            let is_gated = strict || match axis {
                crate::diff::CompatibilityAxis::StorageLayout => suppressions.policy.gate_storage_layout,
                crate::diff::CompatibilityAxis::CallAbi => suppressions.policy.gate_call_abi,
                crate::diff::CompatibilityAxis::EventIndexer => suppressions.policy.gate_event_indexer,
                crate::diff::CompatibilityAxis::SourceLevel => suppressions.policy.gate_source_level,
            };
            if is_gated {
                gated_axes.insert(axis);
            }
        }

        let mut suppressed_root_types: HashSet<String> = HashSet::new();
        for finding in &diff.findings {
            if finding.root_target.is_none() && suppressions.matching_rule(finding).is_some() {
                if let Some(ref tn) = finding.type_name {
                    suppressed_root_types.insert(tn.clone());
                }
            }
        }

        for finding in &diff.findings {
            let is_cascade = finding.root_target.is_some();
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::Warning => warning_count += 1,
                Severity::Info => info_count += 1,
            }

            let rule = suppressions.matching_rule(finding);
            let suppressed = if is_cascade {
                let rt = finding.root_target.as_deref().unwrap();
                rule.is_some() || suppressed_root_types.contains(rt)
            } else {
                rule.is_some()
            };

            if is_cascade && finding.severity == Severity::Critical {
                cascade_critical_count += 1;
            } else if finding.severity == Severity::Critical {
                critical_root_count += 1;
            }

            if suppressed {
                suppressed_count += 1;
                match finding.severity {
                    Severity::Critical => suppressed_critical_count += 1,
                    Severity::Warning => suppressed_warning_count += 1,
                    Severity::Info => suppressed_info_count += 1,
                }
            }

            let remediation = if explain {
                get_remediation_guidance(&finding.category).map(String::from)
            } else {
                None
            };

            // Retrieve or inherit axes
            let axes = if let Some(ref rt) = finding.root_target {
                diff.findings
                    .iter()
                    .find(|f| f.target.as_deref() == Some(rt))
                    .map(|f| crate::diff::classify_finding_axes(&f.category, f.type_name.as_deref(), old_spec, new_spec))
                    .unwrap_or_else(|| {
                        crate::diff::classify_finding_axes(
                            &finding.category,
                            finding.type_name.as_deref(),
                            old_spec,
                            new_spec,
                        )
                    })
            } else {
                crate::diff::classify_finding_axes(
                    &finding.category,
                    finding.type_name.as_deref(),
                    old_spec,
                    new_spec,
                )
            };

            if !suppressed {
                for axis in &axes {
                    let is_gated = strict || match axis {
                        crate::diff::CompatibilityAxis::StorageLayout => suppressions.policy.gate_storage_layout,
                        crate::diff::CompatibilityAxis::CallAbi => suppressions.policy.gate_call_abi,
                        crate::diff::CompatibilityAxis::EventIndexer => suppressions.policy.gate_event_indexer,
                        crate::diff::CompatibilityAxis::SourceLevel => suppressions.policy.gate_source_level,
                    };

                    let new_status = if is_gated {
                        AxisStatus::Failed
                    } else {
                        AxisStatus::Warning
                    };

                    let current = axis_verdicts.entry(*axis).or_insert(AxisStatus::Passed);
                    if *current == AxisStatus::Passed || (*current == AxisStatus::Warning && new_status == AxisStatus::Failed) {
                        *current = new_status;
                    }
                }
            }

            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(ReportedFinding {
                    finding: finding.clone(),
                    axes,
                    suppressed,
                    suppression_reason: rule.and_then(|r| r.reason.clone()),
                    remediation,
                });
        }

        let is_safe = !axis_verdicts.values().any(|&status| status == AxisStatus::Failed);

        Self {
            critical_count,
            warning_count,
            info_count,
            suppressed_count,
            suppressed_critical_count,
            suppressed_warning_count,
            suppressed_info_count,
            total_findings: diff.findings.len(),
            is_safe,
            findings_by_category,
            strict,
            critical_root_count,
            cascade_critical_count,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            scope: AnalysisScope::default(),
            metrics: None,
            empirical: false,
            empirical_findings: Vec::new(),
        }
    }

    pub fn with_interface_hashes(mut self, old: InterfaceHash, new: InterfaceHash) -> Self {
        self.old_interface_hash = Some(old);
        self.new_interface_hash = Some(new);
        self
    }

    pub fn interface_unchanged(&self) -> Option<bool> {
        match (self.old_interface_hash, self.new_interface_hash) {
            (Some(old), Some(new)) => Some(old == new),
            _ => None,
        }
    }

    pub fn recommended_bump(&self) -> &'static str {
        if self.critical_count > 0 {
            "major"
        } else if self.warning_count > 0 {
            "minor"
        } else if self.info_count > 0 {
            if self.has_non_documentation_info_findings() {
                "minor"
            } else {
                "patch"
            }
        } else {
            "patch"
        }
    }

    fn has_non_documentation_info_findings(&self) -> bool {
        const DOC_CATEGORIES: &[&str] = &[
            "Function Documentation Changed",
            "Struct Documentation Changed",
            "Enum Documentation Changed",
        ];

        for findings in self.findings_by_category.values() {
            for reported in findings {
                if reported.finding.severity == Severity::Info
                    && !DOC_CATEGORIES.contains(&reported.finding.category.as_str())
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn to_renderable(&self) -> RenderableReport {
        let timestamp = if self.no_timestamp {
            String::new()
        } else {
            chrono_now_rfc3339()
        };

        let mut findings_by_axis = BTreeMap::new();
        findings_by_axis.insert(crate::diff::CompatibilityAxis::StorageLayout, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::CallAbi, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::EventIndexer, Vec::new());
        findings_by_axis.insert(crate::diff::CompatibilityAxis::SourceLevel, Vec::new());

        for category_findings in self.findings_by_category.values() {
            for reported in category_findings {
                for axis in &reported.axes {
                    if let Some(list) = findings_by_axis.get_mut(axis) {
                        list.push(reported.clone());
                    }
                }
            }
        }

        for list in findings_by_axis.values_mut() {
            list.sort_by(|a, b| {
                a.finding
                    .category
                    .cmp(&b.finding.category)
                    .then_with(|| a.finding.target.cmp(&b.finding.target))
            });
        }

        RenderableReport {
            report_schema_version: REPORT_SCHEMA_VERSION,
            provenance: crate::render::Provenance {
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp,
                inputs: vec![],
            },
            is_safe: self.is_safe,
            strict: self.strict,
            counts: SeverityCounts {
                critical: self.critical_count.saturating_sub(self.suppressed_critical_count),
                warning: self.warning_count.saturating_sub(self.suppressed_warning_count),
                info: self.info_count.saturating_sub(self.suppressed_info_count),
            },
            suppressed_count: self.suppressed_count,
            total_findings: self.total_findings,
            recommended_bump: self.recommended_bump().to_string(),
            old_interface_hash: self.old_interface_hash.map(|h| h.to_hex()),
            new_interface_hash: self.new_interface_hash.map(|h| h.to_hex()),
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            empirical: self.empirical,
            empirical_findings: self.empirical_findings.clone(),
        }
    }

    pub fn to_json(&self) -> RenderableReport {
        self.to_renderable()
    }

    pub fn generate_summary_text(&self, explain: bool) -> String {
        self.to_renderable().to_text(explain)
    }

    pub fn generate_summary_markdown(&self) -> String {
        self.to_renderable().to_markdown()
    }
}

/// Returns remediation/explanation guidance for a given finding category.
pub fn get_remediation_guidance(category: &str) -> Option<&'static str> {
    match category {
        "Environment" => Some("Verify that the target network supports the new protocol version and adjust any SDK/tooling dependencies accordingly."),
        "Function Removed" => Some("This is a breaking change. If the function is no longer needed, deprecate it in client integrations. Otherwise, restore the function signature."),
        "Function Documentation Changed" => Some("No code changes required. Ensure client/consumer integrations are aware of the updated documentation/behavior."),
        "Function Added" => Some("No action required. Inform client integrations about the availability of the new function."),
        "Function Signature Changed" => Some("This is a breaking change. Update call sites, SDKs, and tests to match the new parameter structure."),
        "Parameter Renamed" => Some("This is a breaking change for named-argument RPC systems. Update all client integrations to use the new parameter name."),
        "Parameter Reordered" => Some("This is a breaking change. Reordering parameters breaks positional RPC invocation. Restore the original parameter order."),
        "Parameter Type Changed" => Some("This is a breaking change. Update caller arguments and client SDKs to match the new parameter type."),
        "Return Type Changed" => Some("This is a breaking change. Update caller expectations and client SDKs to match the new return type."),
        "Event Definition Removed" => Some("This is a breaking change. Update or remove downstream event indexing or monitoring systems that consume this event."),
        "Struct Removed" => Some("This is a breaking change. Ensure no stored data or active interfaces reference this struct. If they do, restore the struct."),
        "Struct Documentation Changed" => Some("No code changes required. Ensure documentation changes are aligned with the struct's intended usage."),
        "Struct Added" => Some("No action required. New structs can be safely integrated into storage layouts or interface parameters."),
        "Struct Field Removed" => Some("This is a breaking change. Removing fields breaks serialized storage layouts. Restore the field or perform a state migration."),
        "Event Field Removed" => Some("This is a breaking change. Update event indexers and consumers that expect this field to be present."),
        "Struct Field Reordered" => Some("This is a breaking change. Reordering fields breaks positional serialization layouts. Restore the original field order."),
        "Event Field Reordered" => Some("This is a breaking change. Update event indexers and consumers to handle the new positional field order."),
        "Struct Field Type Changed" => Some("This is a breaking change. Changing field types breaks layout serialization. Revert the type change or migrate existing data."),
        "Event Field Type Changed" => Some("This is a breaking change. Update event indexers and consumers to handle the new field type."),
        "Struct Field Added" => Some("Warning: Ensure existing storage entries are migrated or initialized with correct default values for the new field."),
        "Event Enum Removed" => Some("This is a breaking change. Downstream event consumers or indexers relying on this enum will fail. Restore the enum."),
        "Enum Removed" => Some("This is a breaking change. Stored data or parameters using this enum will be invalid. Restore the enum."),
        "Enum Documentation Changed" => Some("No code changes required. Ensure the updated docs are clear for consumers."),
        "Enum Added" => Some("No action required. Ensure consumers are aware of the new enum type if needed."),
        "Enum Case Removed" => Some("This is a breaking change. On-chain data or parameters using this case will be invalid. Restore the case."),
        "Event Enum Case Removed" => Some("This is a breaking change. Downstream event indexers or consumers relying on this case will fail. Restore the case."),
        "Enum Case Value Changed" => Some("This is a breaking change. Modifying case values breaks serialization/deserialization. Revert the value change."),
        "Event Enum Case Value Changed" => Some("This is a breaking change. Downstream event indexers or consumers relying on these values will fail. Revert the value change."),
        "Enum Case Added" => Some("No action required. Ensure consumers can handle the new case gracefully."),
        "Event Enum Case Added" => Some("No action required. Update event indexers and consumers to handle the new event enum case if necessary."),
        "Union Removed" => Some("This is a breaking change. Stored data or parameters using this union will be invalid. Restore the union."),
        "Union Added" => Some("No action required. Ensure consumers are aware of the new union type if needed."),
        "Union Case Removed" => Some("This is a breaking change. On-chain data using this union case will be invalid. Restore the case."),
        "Union Case Reordered" => Some("This is a breaking change. Reordering union cases breaks positional discriminant serialization. Restore the original case order."),
        "Union Case Type Changed" => Some("This is a breaking change. Changing union case payload types breaks layout serialization. Revert the type change or migrate existing data."),
        "Union Case Added" => Some("No action required. Ensure consumers can handle the new union case gracefully."),
        "Error Enum Removed" => Some("This is a breaking change. Clients matching on these error codes will break. Restore the error enum."),
        "Error Enum Added" => Some("No action required. Inform client integrations about the new error enum if needed."),
        "Error Enum Case Removed" => Some("This is a breaking change. Clients matching on this error code will break. Restore the case."),
        "Error Enum Case Value Changed" => Some("This is a breaking change. Modifying error case values breaks error-code compatibility. Revert the value change."),
        "Error Enum Case Added" => Some("No action required. Ensure clients can handle the new error case gracefully."),
        "Cascading Layout Break" => Some("This is a breaking change. A nested user-defined type has a breaking layout change. Resolve the break in the referenced type."),
        "Type Kind Changed" => Some("This is a breaking change. The type kept its name but is now a different kind of type (struct, enum, union, or error enum), so its serialized layout changed entirely. Stored data written as the old kind cannot be decoded as the new one. Restore the original kind, or migrate the stored data and give the replacement a new name."),
        "BytesN Size Changed" => Some("This is a breaking change. Changing the size of a fixed-size byte array alters its binary encoding. Revert the size or migrate data that depends on the original byte length."),
        _ => None,
    }
}

/// Return the current UTC time as an RFC 3339 / ISO 8601 string.
fn chrono_now_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();

    let mut days = secs / 86400;
    let time_secs = secs % 86400;

    let mut year: u64 = 1970;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    let mut day = days;
    for (i, &md) in month_days.iter().enumerate() {
        if day < md {
            month = i as u64 + 1;
            break;
        }
        day -= md;
    }
    day += 1;

    let hour = time_secs / 3600;
    let minute = (time_secs % 3600) / 60;
    let second = time_secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, nanos / 1_000_000
    )
}

fn is_leap_year(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_emitted_category_has_guidance() {
        let diff_rs_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("diff.rs");
        let content = std::fs::read_to_string(diff_rs_path).expect("Failed to read src/diff.rs");

        let mut checked_categories = std::collections::HashSet::new();

        for line in content.lines() {
            if line.contains("category:") {
                if line.contains("ENVIRONMENT_CATEGORY") {
                    checked_categories.insert("Environment".to_string());
                    continue;
                }

                if line.contains("TYPE_KIND_CHANGED_CATEGORY") {
                    checked_categories.insert(crate::diff::TYPE_KIND_CHANGED_CATEGORY.to_string());
                    continue;
                }

                let mut chars = line.chars().peekable();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        let mut literal = String::new();
                        while let Some(&nc) = chars.peek() {
                            if nc == '"' {
                                chars.next();
                                break;
                            }
                            literal.push(chars.next().unwrap());
                        }
                        if !literal.is_empty() {
                            if literal.contains("{}") {
                                let suffixes = vec![
                                    "Removed", "Reordered", "Type Changed",
                                    "Value Changed", "Added",
                                ];
                                for suffix in suffixes {
                                    if literal == format!("{{}} {}", suffix) {
                                        let prefixes = match suffix {
                                            "Reordered" | "Type Changed" => {
                                                vec!["Struct Field", "Event Field"]
                                            }
                                            "Value Changed" | "Added" => {
                                                vec!["Enum Case", "Event Enum Case"]
                                            }
                                            "Removed" => vec![
                                                "Struct Field", "Event Field",
                                                "Enum Case", "Event Enum Case",
                                            ],
                                            _ => unreachable!(),
                                        };
                                        for prefix in prefixes {
                                            checked_categories
                                                .insert(format!("{} {}", prefix, suffix));
                                        }
                                    }
                                }
                            } else {
                                checked_categories.insert(literal);
                            }
                        }
                    }
                }
            }
        }

        checked_categories.remove("TOTALLY CUSTOM CATEGORY");

        assert!(
            !checked_categories.is_empty(),
            "Sanity check: should have found categories"
        );

        for cat in &checked_categories {
            let guidance = get_remediation_guidance(cat);
            assert!(
                guidance.is_some(),
                "Category '{}' does not have remediation guidance!",
                cat
            );
        }
    }

    #[test]
    fn test_recommended_semver_bump() {
        use crate::diff::Finding;

        fn make_finding(severity: Severity, category: &str) -> ReportedFinding {
            ReportedFinding {
                finding: Finding {
                    severity,
                    axes: Vec::new(),
                    category: category.to_string(),
                    message: String::new(),
                    type_name: None,
                    target: None,
                    root_target: None,
                },
                axes: Vec::new(),
                suppressed: false,
                suppression_reason: None,
                remediation: None,
            }
        }

        let mut report = SafetyReport {
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            total_findings: 0,
            is_safe: true,
            findings_by_category: HashMap::new(),
            strict: false,
            critical_root_count: 0,
            cascade_critical_count: 0,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: false,
            old_spec_summary: None,
            new_spec_summary: None,
            scope: AnalysisScope::default(),
            metrics: None,
        };

        assert_eq!(report.recommended_bump(), "patch");

        report.info_count = 1;
        report.findings_by_category.insert(
            "Function Added".to_string(),
            vec![make_finding(Severity::Info, "Function Added")],
        );
        assert_eq!(report.recommended_bump(), "minor");

        report.info_count = 1;
        report.warning_count = 0;
        report.critical_count = 0;
        report.findings_by_category.clear();
        report.findings_by_category.insert(
            "Function Documentation Changed".to_string(),
            vec![make_finding(Severity::Info, "Function Documentation Changed")],
        );
        assert_eq!(report.recommended_bump(), "patch");

        report.info_count = 0;
        report.warning_count = 1;
        report.findings_by_category.clear();
        assert_eq!(report.recommended_bump(), "minor");

        report.critical_count = 1;
        assert_eq!(report.recommended_bump(), "major");
    }

    #[test]
    fn test_cascade_counts_separated_from_root() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed from i64 to i128".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken because it embeds modified type 'Data'".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            root_target: Some("Data".to_string()),
        });

        let report =
            SafetyReport::with_suppressions(&diff, &SuppressionConfig::default(), false, false, &crate::spec::ContractSpec::default(), &crate::spec::ContractSpec::default());

        assert_eq!(report.critical_root_count, 1);
        assert_eq!(report.cascade_critical_count, 1);
        assert_eq!(report.critical_count, 2);
        assert!(!report.is_safe);
    }

    #[test]
    fn test_cascade_suppressed_when_root_suppressed() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            root_target: Some("Data".to_string()),
        });

        let suppressions = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            reason   = "Acknowledged"
            "#,
        )
        .unwrap();

        let report = SafetyReport::with_suppressions(&diff, &suppressions, false, false, &crate::spec::ContractSpec::default(), &crate::spec::ContractSpec::default());

        let root_finding = report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap();
        assert_eq!(root_finding.len(), 1);
        assert!(root_finding[0].suppressed);

        let cascade_findings = report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap();
        assert_eq!(cascade_findings.len(), 1);
        assert!(cascade_findings[0].suppressed);

        assert!(report.is_safe);
        assert_eq!(report.suppressed_count, 2);
    }

    #[test]
    fn test_cascade_not_suppressed_when_root_not_suppressed() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            axes: Vec::new(),
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            root_target: Some("Data".to_string()),
        });

        let suppressions = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.balance"
            "#,
        )
        .unwrap();

        let report = SafetyReport::with_suppressions(&diff, &suppressions, false, false, &crate::spec::ContractSpec::default(), &crate::spec::ContractSpec::default());

        let root_finding = &report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap()[0];
        assert!(!root_finding.suppressed);

        let cascade_finding = &report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap()[0];
        assert!(!cascade_finding.suppressed);
    }
}
