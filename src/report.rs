use crate::diff::{DiffReport, Finding, Severity};
use crate::suppression::SuppressionConfig;
use colored::Colorize;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

/// A finding as it appears in the report, augmented with suppression state.
///
/// The raw [`Finding`] from the diff layer is left untouched; suppression is a
/// report-time concern layered on top. A suppressed finding is still listed in
/// full — it simply does not count toward the failing set.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedFinding {
    /// The underlying finding, flattened so JSON keeps its original shape
    /// (`severity`, `category`, `message`, `type_name`, `target`).
    #[serde(flatten)]
    pub finding: Finding,
    /// Whether a suppression rule acknowledged this finding.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub suppressed: bool,
    /// The justification copied from the matching rule, if it provided one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    /// Optional remediation/explanation advice for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

/// A structured container for aggregated comparison findings.
pub struct SafetyReport {
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    /// Number of findings (of any severity) acknowledged by a suppression rule.
    pub suppressed_count: usize,
    pub total_findings: usize,
    pub is_safe: bool,
    pub findings_by_category: HashMap<String, Vec<ReportedFinding>>,
    pub strict: bool,
    pub settings: ReportSettings,
    /// What this run actually inspected. Drives the scope reporting so a verdict
    /// is never read as broader than the analysis that produced it.
    pub scope: AnalysisScope,
    /// Where the baseline (old) contract was sourced from (e.g. "RPC", "Local File").
    pub baseline_source: Option<String>,
    /// Verified SHA-256 hash of the baseline WASM bytecode (hex), if verified.
    pub verified_code_hash: Option<String>,
    /// Active category filter, if any.
    pub category_filter: CategoryFilter,
    /// Human-readable summary of the old contract spec (e.g. "3 fns, 2 types").
    /// Populated by the canonical pipeline so callers don't need to re-extract metadata.
    pub old_spec_summary: Option<String>,
    /// Human-readable summary of the new contract spec.
    /// Populated by the canonical pipeline so callers don't need to re-extract metadata.
    pub new_spec_summary: Option<String>,
    /// Contract name extracted from the old build's `contractmetav0` metadata,
    /// when present. `None` when the metadata is absent or contains no
    /// recognizable name key.
    pub old_contract_name: Option<String>,
    /// Contract version extracted from the old build's `contractmetav0` metadata.
    pub old_contract_version: Option<String>,
    /// Contract name extracted from the new build's `contractmetav0` metadata.
    pub new_contract_name: Option<String>,
    /// Contract version extracted from the new build's `contractmetav0` metadata.
    pub new_contract_version: Option<String>,
    /// Build size and interface-count metrics. `None` when the pipeline did not
    /// supply byte sizes (e.g. in some library callers that use `compare_wasm_bytes`
    /// without access to the original slices' lengths — though in practice the
    /// canonical pipeline always populates this).
    pub metrics: Option<BuildMetrics>,
    /// Suppression rules from the config that matched no finding during this run.
    /// Non-empty indicates a potential typo or a stale rule, surfaced to stderr.
    pub unmatched_suppressions: Vec<crate::suppression::SuppressionRule>,
    /// Set by [`crate::baseline::apply`] when a `--baseline` report was
    /// supplied. `None` means no baseline comparison was requested.
    pub baseline_diff: Option<crate::baseline::BaselineDiff>,
    /// When `true`, [`Self::generate_summary_text`] appends a highlighted
    /// two-line type diff after each type-change finding.  Set from the
    /// `--diff-types` CLI flag.  Has no effect on JSON or Markdown output.
    pub diff_types: bool,
    /// Whether color is enabled for this report's text rendering.
    ///
    /// Mirrors the process-wide color decision made by `main` and stored here
    /// so [`Self::generate_summary_text`] can pass the right value to
    /// [`crate::type_diff::render_type_diff`] without accessing global state.
    pub use_color: bool,
    /// Whether the old and new WASM binaries were byte-identical.
    ///
    /// When `true`, the full analysis pipeline was skipped because there is
    /// literally nothing to compare. Reported as an explicit "no-op upgrade"
    /// in every output format so a reader cannot mistake an empty finding
    /// set for a clean diff of different builds.
    pub is_noop: bool,
}

/// Severity counts, serialized as a nested `counts` object.
#[derive(Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}

/// A machine-readable view of a [`SafetyReport`] for `--format json`.
///
/// Borrows from the owning report. Categories are stored in a [`BTreeMap`]
/// so the emitted JSON has a stable, diffable key order.
#[derive(Serialize)]
pub struct SafetyReportJson<'a> {
    pub is_safe: bool,
    pub strict: bool,
    pub counts: SeverityCounts,
    /// Findings (of any severity) acknowledged by the suppression config.
    pub suppressed_count: usize,
    pub total_findings: usize,
    pub recommended_bump: &'static str,
    pub findings_by_category: BTreeMap<&'a str, &'a Vec<ReportedFinding>>,
    /// Build size and interface-count metrics (always present in CLI output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<&'a BuildMetrics>,
    /// Suppression rules from the config that matched no finding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unmatched_suppressions: Vec<UnmatchedSuppressionJson>,
    /// This tool's version, so a later run can detect an incompatible
    /// baseline before comparing against this report via `--baseline`.
    pub tool_version: &'static str,
    /// Present when `--baseline` was supplied: classifies this run's
    /// findings as new/persisting relative to it, and lists resolved ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_diff: Option<&'a crate::baseline::BaselineDiff>,
    /// Contract name from the old build's metadata (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_contract_name: Option<&'a str>,
    /// Contract version from the old build's metadata (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_contract_version: Option<&'a str>,
    /// Contract name from the new build's metadata (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_contract_name: Option<&'a str>,
    /// Contract version from the new build's metadata (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_contract_version: Option<&'a str>,
    /// Whether the old and new WASM binaries were byte-identical (no-op).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_noop: bool,
}

/// JSON representation of a suppression rule that matched no finding.
#[derive(Serialize, JsonSchema)]
pub struct UnmatchedSuppressionJson {
    pub category: String,
    pub target: Option<String>,
}

/// Format a contract identity label from optional name and version strings.
///
/// Used in both text and Markdown report headers to display which contract
/// is being compared. Falls back to `<unknown>` when both are absent.
fn contract_identity_label(name: Option<&str>, version: Option<&str>) -> String {
    match (name, version) {
        (Some(n), Some(v)) => format!("{} v{}", n, v),
        (Some(n), None) => n.to_string(),
        (None, Some(v)) => format!("v{}", v),
        (None, None) => "<unknown>".to_string(),
    }
}

impl SafetyReport {
    /// Compute a safety report from a raw DiffReport, with no suppressions.
    ///
    /// Equivalent to [`SafetyReport::with_suppressions`] using an empty config,
    /// so behavior is identical to before suppression support existed.
    pub fn new(diff: &DiffReport) -> Self {
        Self::with_suppressions(diff, &SuppressionConfig::default(), false, false)
    }

    /// Build a no-op report: the old and new WASM binaries were byte-identical
    /// so the full analysis pipeline was skipped.
    pub fn noop(old_wasm_size: usize, new_wasm_size: usize) -> Self {
        use crate::suppression::SuppressionConfig;

        Self {
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            filtered_count: 0,
            severity_overridden_count: 0,
            verdict_changed_by_override: false,
            suppressed_critical_count: 0,
            total_findings: 0,
            is_safe: true,
            findings_by_category: HashMap::new(),
            strict: false,
            settings: ReportSettings {
                strict: false,
                explain: false,
                max_suppressions: None,
                allow_targetless: None,
                max_xdr_depth: ResourcePolicy::default().max_xdr_depth,
                max_xdr_len: ResourcePolicy::default().max_xdr_len,
                max_entries: ResourcePolicy::default().max_entries,
                max_walk_depth: ResourcePolicy::default().max_walk_depth,
            },
            scope: AnalysisScope::default(),
            baseline_source: None,
            verified_code_hash: None,
            category_filter: CategoryFilter::default(),
            old_spec_summary: None,
            new_spec_summary: None,
            metrics: Some(BuildMetrics::new(
                old_wasm_size,
                new_wasm_size,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            )),
            unmatched_suppressions: Vec::new(),
            baseline_diff: None,
            diff_types: false,
            use_color: false,
            is_noop: true,
        }
    }

    /// Compute a safety report, applying a suppression config.
    ///
    /// Every finding is still listed; those matched by a rule are flagged as
    /// suppressed and excluded from the failing set. `is_safe` is therefore
    /// true when no *unsuppressed* Critical finding remains — a deliberately
    /// acknowledged breaking change no longer fails the run.
    pub fn with_suppressions(
        diff: &DiffReport,
        suppressions: &SuppressionConfig,
        explain: bool,
        strict: bool,
    ) -> Self {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut suppressed_count = 0;
        let mut failing_critical_count = 0;
        let mut failing_warning_count = 0;
        let mut findings_by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();

        for finding in &diff.findings {
            match finding.severity {
                Severity::Critical => critical_count += 1,
                Severity::Warning => warning_count += 1,
                Severity::Info => info_count += 1,
            }

            let rule = suppressions.matching_rule(finding);
            let suppressed = rule.is_some();
            if suppressed {
                suppressed_count += 1;
            } else {
                match finding.severity {
                    Severity::Critical => failing_critical_count += 1,
                    Severity::Warning => failing_warning_count += 1,
                    _ => {}
                }
            }

            let remediation = if explain {
                get_remediation_guidance(&finding.category).map(String::from)
            } else {
                None
            };

            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(ReportedFinding {
                    finding: finding.clone(),
                    suppressed,
                    suppression_reason: rule.and_then(|r| r.reason.clone()),
                    remediation,
                });
        }

        let is_safe = if strict {
            failing_critical_count == 0 && failing_warning_count == 0
        } else {
            failing_critical_count == 0
        };

        Self {
            critical_count,
            warning_count,
            info_count,
            suppressed_count,
            total_findings: diff.findings.len(),
            is_safe,
            findings_by_category,
            strict,
            settings,
            scope: AnalysisScope::default(),
            baseline_source: None,
            verified_code_hash: None,
            category_filter: CategoryFilter::default(),
            old_spec_summary: None,
            new_spec_summary: None,
            old_contract_name: None,
            old_contract_version: None,
            new_contract_name: None,
            new_contract_version: None,
            metrics: None,
            unmatched_suppressions,
            baseline_diff: None,
            diff_types: false,
            use_color: false,
            is_noop: false,
        }
    }

/// The passing status label, widened only as far as the analysis actually
    /// went. Without a storage schema the claim stays bounded to the exported
    /// interface; with one it may also speak to the declared storage types.
    pub fn passed_status_label(&self) -> &'static str {
        if self.scope.storage_analyzed() {
            "✅ PASSED (No exported-interface or declared-storage breaks)"
        } else {
            "✅ PASSED (No exported-interface breaking changes)"
        }
    }

    /// The failing status label, naming the scopes a break could have come from.
    pub fn failed_status_label(&self) -> &'static str {
        if self.scope.storage_analyzed() {
            "❌ FAILED (Breaking changes detected in the exported interface or declared storage)"
        } else {
            "❌ FAILED (Exported-interface breaking changes detected)"
        }
    }

    /// The sentence stating that a `[severity]` override changed the verdict,
    /// or `None` when it did not.
    ///
    /// A tool that can be quietly reconfigured into always passing is worse than
    /// no tool, so this is the one line that must appear, unhedged, in every
    /// format whenever configuration — not analysis — decided the outcome.
    pub fn override_verdict_notice(&self) -> Option<String> {
        if !self.verdict_changed_by_override {
            return None;
        }
        Some(if self.is_safe {
            "VERDICT CHANGED BY CONFIG: this run passes only because the [severity] table \
             lowered one or more findings. Without those overrides it would have FAILED."
                .to_string()
        } else {
            "VERDICT CHANGED BY CONFIG: this run fails only because the [severity] table \
             raised one or more findings. Without those overrides it would have PASSED."
                .to_string()
        })
    }

    /// The override notice rendered for text output, empty when not applicable.
    fn override_verdict_notice_text(&self) -> String {
        match self.override_verdict_notice() {
            // Red rather than dimmed: a demotion that greens a failing gate is
            // the case this line exists to make impossible to skim past.
            Some(notice) => format!("{}\n", format!("⚠️  {notice}").red().bold()),
            None => String::new(),
        }
    }

    /// The `[SEVERITY: critical → warning]` tag for a finding whose severity an
    /// override changed, or an empty string when it was left alone.
    fn override_tag(reported: &ReportedFinding) -> String {
        match &reported.original_severity {
            Some(original) => format!(
                "[SEVERITY {} → {}] ",
                original.label(),
                reported.finding.severity.label()
            ),
            None => String::new(),
        }
    }

    /// Derive the recommended SemVer bump from safety report findings:
    /// - `Critical` findings present -> `major` (breaking interface or storage changes).
    /// - `Warning` findings present -> `minor` (we map warnings like `Parameter Renamed`
    ///   or `Struct Field Added` explicitly to `minor` because they represent changes
    ///   that are not strictly breaking for all contexts, but require caller adjustments
    ///   or data migrations).
    /// - `Info` findings present -> `minor` (additive, non-breaking changes).
    /// - No findings -> `patch` (identical interface).
    pub fn recommended_bump(&self) -> &'static str {
        if self.critical_count > 0 {
            "major"
        } else if self.warning_count > 0 || self.info_count > 0 {
            "minor"
        } else {
            "patch"
        }
    }

    /// Build a serializable, machine-readable view of this report.
    pub fn to_json(&self) -> SafetyReportJson<'_> {
        SafetyReportJson {
            is_safe: self.is_safe,
            strict: self.strict,
            counts: SeverityCounts {
                critical: self.critical_count,
                warning: self.warning_count,
                info: self.info_count,
            },
            suppressed_count: self.suppressed_count,
            total_findings: self.total_findings,
            recommended_bump: self.recommended_bump(),
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
            metrics: self.metrics.as_ref(),
            unmatched_suppressions,
            tool_version: env!("CARGO_PKG_VERSION"),
            baseline_diff: self.baseline_diff.as_ref(),
            old_contract_name: self.old_contract_name.as_deref(),
            old_contract_version: self.old_contract_version.as_deref(),
            new_contract_name: self.new_contract_name.as_deref(),
            new_contract_version: self.new_contract_version.as_deref(),
            is_noop: self.is_noop,
        }
    }

    /// Generate a structured, human-readable text output for the CLI.
    pub fn generate_summary_text(&self, explain: bool) -> String {
        let mut output = String::new();
        output.push_str(
            &"\n========================================\n"
                .bold()
                .to_string(),
        );
        output.push_str(
            &"    SOROBAN UPGRADE SAFETY REPORT\n"
                .bold()
                .cyan()
                .to_string(),
        );
        if self.strict {
            output.push_str(&"    [STRICT MODE ACTIVE]\n".bold().yellow().to_string());
        }
        output.push_str(
            &"========================================\n"
                .bold()
                .to_string(),
        );

        let status = if self.is_safe {
            "✅ PASSED (No breaking changes detected)".green().bold()
        } else if self.strict && self.critical_count == 0 {
            "❌ FAILED (Warnings detected in strict mode)".red().bold()
        } else {
            "❌ FAILED (Critical breaking changes detected)"
            self.failed_status_label().red().bold()
        };
        output.push_str(&format!("Status: {}\n", status));
        // Show contract identity when available.
        if self.old_contract_name.is_some()
            || self.new_contract_name.is_some()
            || self.old_contract_version.is_some()
            || self.new_contract_version.is_some()
        {
            let old_label = contract_identity_label(
                self.old_contract_name.as_deref(),
                self.old_contract_version.as_deref(),
            );
            let new_label = contract_identity_label(
                self.new_contract_name.as_deref(),
                self.new_contract_version.as_deref(),
            );
            output.push_str(&format!("Contract: {} → {}\n", old_label, new_label));
        }
        output.push_str(&format!("Scope:  {}\n", self.scope.summary_line().dimmed()));
        let storage_status = self.scope.storage_status_line();
        let storage_status = if self.scope.storage_analyzed() {
            storage_status.dimmed()
        } else {
            // No schema: make the "not analyzed" gap visible rather than dim.
            storage_status.yellow()
        };
        output.push_str(&format!("        {}\n", storage_status));

        // Spec-section integrity summary (non-zero section count or duplicates).
        if self.scope.old_spec_section_count > 1 || self.scope.new_spec_section_count > 1 {
            output.push_str(
                &format!(
                    "        Spec sections: old={}, new={} (multi-section WASMs detected)\n",
                    self.scope.old_spec_section_count, self.scope.new_spec_section_count,
                )
                .yellow()
                .to_string(),
            );
        }
        let all_dups: Vec<String> = self
            .scope
            .old_duplicate_names
            .iter()
            .map(|n| format!("old:{n}"))
            .chain(
                self.scope
                    .new_duplicate_names
                    .iter()
                    .map(|n| format!("new:{n}")),
            )
            .collect();
        if !all_dups.is_empty() {
            output.push_str(
                &format!(
                    "        Duplicate entries detected: {}\n",
                    all_dups.join(", ")
                )
                .red()
                .bold()
        };
        output.push_str(&format!("Status: {}\n", status));

        let crit_str = if self.critical_count > 0 {
            self.critical_count.to_string().red().bold()
        } else {
            self.critical_count.to_string().green()
        };
        let warn_str = if self.warning_count > 0 {
            self.warning_count.to_string().yellow().bold()
        } else {
            self.warning_count.to_string().normal()
        };
        let info_str = self.info_count.to_string().blue();

        output.push_str(&format!("Critical: {}\n", crit_str));
        output.push_str(&format!("Warnings: {}\n", warn_str));
        output.push_str(&format!("Info:     {}\n", info_str));
        if self.suppressed_count > 0 {
            output.push_str(&format!(
                "Suppressed: {}\n",
                self.suppressed_count.to_string().magenta().bold()
            ));
        }
        let bump = self.recommended_bump();
        let bump_str = match bump {
            "major" => "major".red().bold(),
            "minor" => "minor".yellow().bold(),
            "patch" => "patch".green().bold(),
            _ => bump.normal(),
        };
        output.push_str(&format!("Recommended Bump: {}\n", bump_str));
        output.push_str(
            &"----------------------------------------\n\n"
                .dimmed()
                .to_string(),
        );

        if self.total_findings == 0 {
            if self.is_noop {
                output.push_str(&"No-op upgrade detected: the old and new WASM binaries are byte-identical.\n".green().bold().to_string());
                output.push_str(&"The full analysis pipeline was skipped because there are no differences to report.\n".green().to_string());
            } else {
                output.push_str(&"No relevant changes detected. The exported interface is identical in its exports and types.\n".green().to_string());
            }
            output.push_str(&format!("\n{}\n", STORAGE_NOT_VERIFIED_NOTE.dimmed()));
            self.append_metrics_text(&mut output);
            output.push_str(&"No relevant changes detected. The upgrade is identical in its exports and types.\n".green().to_string());
            return output;
        }

        // Sort categories to have consistent output; surface Environment first.
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort_by(|a, b| {
            let rank = |name: &str| if name == "Environment" { 0 } else { 1 };
            rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
        });

        for category in categories {
            output.push_str(
                &format!("--- [{}] ---\n", category.to_ascii_uppercase())
                    .magenta()
                    .bold()
                    .to_string(),
            );
            let group = self.findings_by_category.get(category).unwrap();
            for reported in group {
                let finding = &reported.finding;

                if reported.suppressed {
                    // Suppressed findings are still listed, but clearly marked
                    // and dimmed so they read as acknowledged, not active.
                    let label = format!("🔕 [SUPPRESSED] {}", finding.message)
                        .dimmed()
                        .to_string();
                    output.push_str(&format!("{}\n", label));
                    if let Some(reason) = &reported.suppression_reason {
                        output
                            .push_str(&format!("    ↳ reason: {}\n", reason).dimmed().to_string());
                    }
                    if explain {
                        if let Some(remediation) = &reported.remediation {
                            output.push_str(
                                &format!("    ↳ guidance: {}\n", remediation)
                                    .dimmed()
                                    .to_string(),
                            );
                        }
                    }
                    continue;
                }

                let formatted = match finding.severity {
                    Severity::Critical => format!("🔴 {}", finding.message).red(),
                    Severity::Warning => format!("🟡 {}", finding.message).yellow(),
                    Severity::Info => format!("🔵 {}", finding.message).cyan(),
                };
                output.push_str(&format!("{}\n", formatted));
                if explain {
                    if let Some(remediation) = &reported.remediation {
                        output.push_str(
                            &format!("    ↳ guidance: {}\n", remediation)
                                .green()
                                .to_string(),
                        );
                    }
                }
            }
            output.push('\n');
        }

        if !self.is_safe {
            if self.strict && self.critical_count == 0 {
                output.push_str(
                    &"⚠️  ACTION REQUIRED: Strict mode is active and warnings were detected.\n"
                        .yellow()
                        .bold()
                        .to_string(),
                );
                output.push_str(
                    &"These warnings must be resolved or strict mode disabled to proceed.\n"
                        .yellow()
                        .to_string(),
                );
            } else {
                output.push_str(&"⚠️  ACTION REQUIRED: The new contract version modifies existing storage layouts or function interfaces.\n".red().bold().to_string());
                output.push_str(&"Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n".red().to_string());
            }
        }

        output
    }

    /// Generate a structured Markdown output.
    pub fn generate_summary_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str("# Soroban Upgrade Safety Report\n\n");

        let status = if self.is_safe {
            "✅ PASSED (No breaking changes detected)"
        } else {
            "❌ FAILED (Critical breaking changes detected)"
        };
        output.push_str(&format!("## Status: {}\n\n", status));

        if self.old_contract_name.is_some()
            || self.new_contract_name.is_some()
            || self.old_contract_version.is_some()
            || self.new_contract_version.is_some()
        {
            let old_label = contract_identity_label(
                self.old_contract_name.as_deref(),
                self.old_contract_version.as_deref(),
            );
            let new_label = contract_identity_label(
                self.new_contract_name.as_deref(),
                self.new_contract_version.as_deref(),
            );
            output.push_str(&format!("**Contract**: {} → {}\n\n", old_label, new_label));
        }

        output.push_str("### Summary Table\n\n");
        output.push_str("| Finding Severity | Count |\n");
        output.push_str("| :--- | :--- |\n");
        output.push_str(&format!("| **Critical** | {} |\n", self.critical_count));
        output.push_str(&format!("| **Warning** | {} |\n", self.warning_count));
        output.push_str(&format!("| **Info** | {} |\n", self.info_count));
        if self.suppressed_count > 0 {
            output.push_str(&format!("| **Suppressed** | {} |\n", self.suppressed_count));
        }
        output.push_str(&format!(
            "\n**Recommended SemVer Bump**: `{}`\n\n",
            self.recommended_bump()
        ));
        output.push_str("---\n\n");

        if self.total_findings == 0 {
            if self.is_noop {
                output.push_str("**No-op upgrade detected**: the old and new WASM binaries are byte-identical.\n\n");
                output.push_str("The full analysis pipeline was skipped because there are no differences to report.\n");
            } else {
                output.push_str("No relevant changes detected. The exported interface is identical in its exports and types.\n");
            }

        if let Some(source) = &self.baseline_source {
            output.push_str(&format!("**Baseline Source**: `{}`\n\n", source));
        }
        if let Some(hash) = &self.verified_code_hash {
            output.push_str(&format!("**Verified Code Hash**: `{}`\n\n", hash));
        }
        if let Some(bd) = &self.baseline_diff {
            output.push_str(&format!(
                "**Baseline**: {} new, {} persisting, {} resolved (vs. tool v{}){}\n\n",
                bd.new_count,
                bd.persisting_count,
                bd.resolved.len(),
                bd.baseline_tool_version,
                if bd.fail_on_new_only {
                    " — verdict reflects new findings only"
                } else {
                    ""
                },
            ));
        }

        output.push_str("---\n\n");

        if self.total_findings == 0 {
            output.push_str("No relevant changes detected. The exported interface is identical in its exports and types.\n\n");
            output.push_str(&format!("> {}\n", STORAGE_NOT_VERIFIED_NOTE));
            self.append_metrics_markdown(&mut output);
            output.push_str("No relevant changes detected. The upgrade is identical in its exports and types.\n");
            return output;
        }

        // Sort categories to have consistent output; surface Environment first.
        let mut categories: Vec<&String> = self.findings_by_category.keys().collect();
        categories.sort_by(|a, b| {
            let rank = |name: &str| if name == "Environment" { 0 } else { 1 };
            rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
        });

        for category in categories {
            output.push_str(&format!("### {}\n\n", category));
            let group = self.findings_by_category.get(category).unwrap();
            for reported in group {
                let finding = &reported.finding;

                if reported.suppressed {
                    output.push_str(&format!("- 🔕 **[SUPPRESSED]** {}\n", finding.message));
                    if let Some(reason) = &reported.suppression_reason {
                        output.push_str(&format!("  - ↳ reason: {}\n", reason));
                    }
                    continue;
                }

                let emoji = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::Warning => "🟡",
                    Severity::Info => "🔵",
                };
                output.push_str(&format!("- {} {}\n", emoji, finding.message));
            }
            output.push('\n');
        }

        if !self.is_safe {
            output.push_str("### ⚠️ Action Required\n\n");
            output.push_str("- The new contract version modifies existing storage layouts or function interfaces.\n");
            output.push_str("- Deploying this upgrade will result in orphaned data, serialization panics, or broken integrations.\n");
        }

        output
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
        _ => None,
    }
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
                // If it is ENVIRONMENT_CATEGORY
                if line.contains("ENVIRONMENT_CATEGORY") {
                    checked_categories.insert("Environment".to_string());
                    continue;
                }

                // Find all string literals in the line
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
                            // If it's a format string like "{} Removed"
                            if literal.contains("{}") {
                                let suffixes = vec![
                                    "Removed",
                                    "Reordered",
                                    "Type Changed",
                                    "Value Changed",
                                    "Added",
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
                                                "Struct Field",
                                                "Event Field",
                                                "Enum Case",
                                                "Event Enum Case",
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

        // Remove test custom categories
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
        let mut report = SafetyReport {
            critical_count: 0,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            total_findings: 0,
            is_safe: true,
            findings_by_category: std::collections::HashMap::new(),
            strict: false,
        };

        // Identical upgrade -> patch
        assert_eq!(report.recommended_bump(), "patch");

        // Info findings -> minor
        report.info_count = 1;
        assert_eq!(report.recommended_bump(), "minor");

        // Warning findings -> minor
        report.info_count = 0;
        report.warning_count = 1;
        assert_eq!(report.recommended_bump(), "minor");

        // Critical findings -> major (even if other findings are present)
        report.critical_count = 1;
        assert_eq!(report.recommended_bump(), "major");
    }
}
