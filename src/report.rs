use crate::diff::{DiffReport, Finding, Severity};
use crate::suppression::SuppressionConfig;
use colored::Colorize;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// Number of suppressed Critical findings.
    pub suppressed_critical_count: usize,
    /// Number of suppressed Warning findings.
    pub suppressed_warning_count: usize,
    /// Number of suppressed Info findings.
    pub suppressed_info_count: usize,
    pub total_findings: usize,
    pub is_safe: bool,
    pub findings_by_category: HashMap<String, Vec<ReportedFinding>>,
    pub strict: bool,
    /// Number of critical root-cause findings (non-cascade).
    pub critical_root_count: usize,
    /// Number of critical cascade consequences.
    pub cascade_critical_count: usize,
}

/// Severity counts, serialized as a nested `counts` object.
#[derive(Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    /// Suppressed Critical findings (0 when none).
    #[serde(skip_serializing_if = "is_zero")]
    pub suppressed_critical: usize,
    /// Suppressed Warning findings (0 when none).
    #[serde(skip_serializing_if = "is_zero")]
    pub suppressed_warning: usize,
    /// Suppressed Info findings (0 when none).
    #[serde(skip_serializing_if = "is_zero")]
    pub suppressed_info: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
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
    /// Number of unsuppressed critical root-cause findings.
    pub critical_root_count: usize,
    /// Number of unsuppressed critical cascade consequences.
    pub cascade_critical_count: usize,
    /// Findings (of any severity) acknowledged by the suppression config.
    pub suppressed_count: usize,
    pub total_findings: usize,
    pub recommended_bump: &'static str,
    pub findings_by_category: BTreeMap<&'a str, &'a Vec<ReportedFinding>>,
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
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
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
    ///
    /// Cascade findings whose root cause finding is suppressed are also
    /// suppressed (cascade-by-root suppression). Severity counts distinguish
    /// root-cause findings from cascade-consequence findings.
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
        let mut suppressed_critical_count = 0;
        let mut suppressed_warning_count = 0;
        let mut suppressed_info_count = 0;
        let mut failing_critical_count = 0;
        let mut failing_warning_count = 0;
        let mut findings_by_category: HashMap<String, Vec<ReportedFinding>> = HashMap::new();
        let mut critical_root_count = 0;
        let mut cascade_critical_count = 0;

        // First pass: identify root-cause types whose direct finding is suppressed.
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

            // A cascade finding is suppressed if its root cause finding is suppressed.
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
            suppressed_critical_count,
            suppressed_warning_count,
            suppressed_info_count,
            total_findings: diff.findings.len(),
            is_safe,
            findings_by_category,
            strict,
            critical_root_count,
            cascade_critical_count,
        }
    }

    /// Derive the recommended SemVer bump from safety report findings:
    /// - `Critical` findings present -> `major` (breaking interface or storage changes).
    /// - `Warning` findings present -> `minor` (we map warnings like `Parameter Renamed`
    ///   or `Struct Field Added` explicitly to `minor` because they represent changes
    ///   that are not strictly breaking for all contexts, but require caller adjustments
    ///   or data migrations).
    /// - `Info` findings present that are additive (e.g. new functions, new types) -> `minor`.
    /// - `Info` findings present that are only documentation changes -> `patch`.
    /// - No findings -> `patch` (identical interface).
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

    /// Returns `true` when at least one Info-severity finding is not a
    /// non-functional documentation change (e.g. reworded doc comments).
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

    /// Build a serializable, machine-readable view of this report.
    pub fn to_json(&self) -> SafetyReportJson<'_> {
        SafetyReportJson {
            is_safe: self.is_safe,
            strict: self.strict,
            counts: SeverityCounts {
                critical: self.critical_count - self.suppressed_critical_count,
                warning: self.warning_count - self.suppressed_warning_count,
                info: self.info_count - self.suppressed_info_count,
                suppressed_critical: self.suppressed_critical_count,
                suppressed_warning: self.suppressed_warning_count,
                suppressed_info: self.suppressed_info_count,
            },
            critical_root_count: self.critical_root_count,
            cascade_critical_count: self.cascade_critical_count,
            suppressed_count: self.suppressed_count,
            total_findings: self.total_findings,
            recommended_bump: self.recommended_bump(),
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
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
                .red()
                .bold()
            );
        }
        output.push_str(&format!("Status: {}\n", status));

        let root_crit = self.critical_root_count;
        let cascade_crit = self.cascade_critical_count;

        let crit_label = if cascade_crit > 0 {
            format!(
                "Critical (root): {} | Critical (cascade): {}",
                root_crit.to_string().red().bold(),
                cascade_crit.to_string().red().bold(),
            )
        } else {
            format!("Critical: {}", root_crit.to_string().red().bold())
        };
        let warn_str = if active_warning > 0 {
            fmt_count(active_warning, self.suppressed_warning_count).yellow().bold()
        } else {
            fmt_count(active_warning, self.suppressed_warning_count).normal()
        };
        let info_str = fmt_count(active_info, self.suppressed_info_count).blue();

        output.push_str(&format!("{}\n", crit_label));
        output.push_str(&format!("Warnings: {}\n", warn_str));
        output.push_str(&format!("Info:     {}\n", info_str));
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

            // Cascade findings are grouped by root_target in the rolled-up view.
            if category == "Cascading Layout Break" {
                let mut by_root: BTreeMap<&str, Vec<&ReportedFinding>> = BTreeMap::new();
                for reported in group {
                    let key = reported
                        .finding
                        .root_target
                        .as_deref()
                        .unwrap_or("(unknown)");
                    by_root.entry(key).or_default().push(reported);
                }
                for (root_target, cascades) in &by_root {
                    let any_suppressed = cascades.iter().any(|r| r.suppressed);
                    if any_suppressed {
                        let label =
                            format!("🔕 [SUPPRESSED] Cascading break from root: {}", root_target)
                                .dimmed()
                                .to_string();
                        output.push_str(&format!("{}\n", label));
                        for reported in cascades {
                            if let Some(reason) = &reported.suppression_reason {
                                output.push_str(
                                    &format!("    ↳ reason: {}\n", reason).dimmed().to_string(),
                                );
                            }
                        }
                    } else {
                        let first = &cascades[0];
                        let emoji = match first.finding.severity {
                            Severity::Critical => "🔴",
                            Severity::Warning => "🟡",
                            Severity::Info => "🔵",
                        };
                        let root_label =
                            format!("{} Cascading break via root type: {}", emoji, root_target);
                        let formatted = match first.finding.severity {
                            Severity::Critical => root_label.red(),
                            Severity::Warning => root_label.yellow(),
                            Severity::Info => root_label.cyan(),
                        };
                        output.push_str(&format!("{}\n", formatted));
                        for reported in cascades {
                            output.push_str(&format!(
                                "    ↳ {} (type: {})\n",
                                reported.finding.target.as_deref().unwrap_or("?"),
                                reported.finding.type_name.as_deref().unwrap_or("?"),
                            ));
                        }
                    }
                }
            } else {
                for reported in group {
                    let finding = &reported.finding;

                    if reported.suppressed {
                        let label = format!("🔕 [SUPPRESSED] {}", finding.message)
                            .dimmed()
                            .to_string();
                        output.push_str(&format!("{}\n", label));
                        if let Some(reason) = &reported.suppression_reason {
                            output.push_str(
                                &format!("    ↳ reason: {}\n", reason).dimmed().to_string(),
                            );
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

        output.push_str("### Summary Table\n\n");
        let active_critical = self.critical_count - self.suppressed_critical_count;
        let active_warning = self.warning_count - self.suppressed_warning_count;
        let active_info = self.info_count - self.suppressed_info_count;

        let fmt_count = |active: usize, suppressed: usize| -> String {
            if suppressed > 0 {
                format!("{} ({} suppressed)", active, suppressed)
            } else {
                active.to_string()
            }
        };

        output.push_str("| Finding Severity | Count |\n");
        output.push_str("| :--- | :--- |\n");
        if self.cascade_critical_count > 0 {
            output.push_str(&format!(
                "| **Critical (root)** | {} |\n",
                self.critical_root_count
            ));
            output.push_str(&format!(
                "| **Critical (cascade)** | {} |\n",
                self.cascade_critical_count
            ));
        } else {
            output.push_str(&format!("| **Critical** | {} |\n", self.critical_count));
        }
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

            if category == "Cascading Layout Break" {
                let mut by_root: BTreeMap<&str, Vec<&ReportedFinding>> = BTreeMap::new();
                for reported in group {
                    let key = reported
                        .finding
                        .root_target
                        .as_deref()
                        .unwrap_or("(unknown)");
                    by_root.entry(key).or_default().push(reported);
                }
                for (root_target, cascades) in &by_root {
                    let any_suppressed = cascades.iter().any(|r| r.suppressed);
                    if any_suppressed {
                        output.push_str(&format!(
                            "- 🔕 **[SUPPRESSED]** Cascading break from root: {}\n",
                            root_target
                        ));
                        for reported in cascades {
                            if let Some(reason) = &reported.suppression_reason {
                                output.push_str(&format!("  - ↳ reason: {}\n", reason));
                            }
                        }
                    } else {
                        let first = &cascades[0];
                        let emoji = match first.finding.severity {
                            Severity::Critical => "🔴",
                            Severity::Warning => "🟡",
                            Severity::Info => "🔵",
                        };
                        output.push_str(&format!(
                            "- {} Cascading break via root type: {}\n",
                            emoji, root_target
                        ));
                        for reported in cascades {
                            output.push_str(&format!(
                                "    - type: {}, target: {}\n",
                                reported.finding.type_name.as_deref().unwrap_or("?"),
                                reported.finding.target.as_deref().unwrap_or("?"),
                            ));
                        }
                    }
                }
            } else {
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
        "BytesN Size Changed" => Some("This is a breaking change. Changing the size of a fixed-size byte array alters its binary encoding. Revert the size or migrate data that depends on the original byte length."),
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
        use crate::diff::Finding;

        fn make_finding(severity: Severity, category: &str) -> ReportedFinding {
            ReportedFinding {
                finding: Finding {
                    severity,
                    category: category.to_string(),
                    message: String::new(),
                    type_name: None,
                    target: None,
                },
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
            findings_by_category: std::collections::HashMap::new(),
            strict: false,
            critical_root_count: 0,
            cascade_critical_count: 0,
        };

        // Identical upgrade -> patch
        assert_eq!(report.recommended_bump(), "patch");

        // Additive Info findings -> minor
        report.info_count = 1;
        report.findings_by_category.insert(
            "Function Added".to_string(),
            vec![make_finding(Severity::Info, "Function Added")],
        );
        assert_eq!(report.recommended_bump(), "minor");

        // Documentation-only Info findings -> patch
        report.info_count = 1;
        report.warning_count = 0;
        report.critical_count = 0;
        report.findings_by_category.clear();
        report.findings_by_category.insert(
            "Function Documentation Changed".to_string(),
            vec![make_finding(
                Severity::Info,
                "Function Documentation Changed",
            )],
        );
        assert_eq!(report.recommended_bump(), "patch");

        // Warning findings -> minor
        report.info_count = 0;
        report.warning_count = 1;
        report.findings_by_category.clear();
        assert_eq!(report.recommended_bump(), "minor");

        // Critical findings -> major (even if other findings are present)
        report.critical_count = 1;
        assert_eq!(report.recommended_bump(), "major");
    }

    #[test]
    fn test_cascade_counts_separated_from_root() {
        let mut diff = DiffReport::default();
        // Root cause: Struct Field Type Changed on Data
        diff.findings.push(Finding {
            severity: Severity::Critical,
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed from i64 to i128".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        // Cascade consequence: Cascading Layout Break on Outer due to Data
        diff.findings.push(Finding {
            severity: Severity::Critical,
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken because it embeds modified type 'Data'"
                .to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            root_target: Some("Data".to_string()),
        });

        let report =
            SafetyReport::with_suppressions(&diff, &SuppressionConfig::default(), false, false);

        assert_eq!(
            report.critical_root_count, 1,
            "root count must include only the direct critical"
        );
        assert_eq!(
            report.cascade_critical_count, 1,
            "cascade count must include the cascade finding"
        );
        assert_eq!(
            report.critical_count, 2,
            "total critical must be sum of root + cascade"
        );
        assert_eq!(report.is_safe, false, "unsuppressed criticals -> unsafe");
    }

    #[test]
    fn test_cascade_suppressed_when_root_suppressed() {
        let mut diff = DiffReport::default();
        // Root cause
        diff.findings.push(Finding {
            severity: Severity::Critical,
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        // Cascade
        diff.findings.push(Finding {
            severity: Severity::Critical,
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

        let report = SafetyReport::with_suppressions(&diff, &suppressions, false, false);

        // Both root and cascade should be suppressed
        let root_finding = report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap();
        assert_eq!(root_finding.len(), 1);
        assert!(
            root_finding[0].suppressed,
            "root cause finding should be suppressed"
        );

        let cascade_findings = report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap();
        assert_eq!(cascade_findings.len(), 1);
        assert!(
            cascade_findings[0].suppressed,
            "cascade finding should be suppressed via root cause"
        );

        assert!(report.is_safe, "all criticals suppressed -> safe");
        assert_eq!(report.suppressed_count, 2);
    }

    #[test]
    fn test_cascade_not_suppressed_when_root_not_suppressed() {
        let mut diff = DiffReport::default();
        diff.findings.push(Finding {
            severity: Severity::Critical,
            category: "Struct Field Type Changed".to_string(),
            message: "Type 'Data' field 'amount' changed".to_string(),
            type_name: Some("Data".to_string()),
            target: Some("Data.amount".to_string()),
            root_target: None,
        });
        diff.findings.push(Finding {
            severity: Severity::Critical,
            category: "Cascading Layout Break".to_string(),
            message: "Type 'Outer' layout is broken".to_string(),
            type_name: Some("Outer".to_string()),
            target: Some("Outer".to_string()),
            root_target: Some("Data".to_string()),
        });

        // Suppress a different target -- cascade should NOT carry across
        let suppressions = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.balance"
            "#,
        )
        .unwrap();

        let report = SafetyReport::with_suppressions(&diff, &suppressions, false, false);

        let root_finding = &report
            .findings_by_category
            .get("Struct Field Type Changed")
            .unwrap()[0];
        assert!(
            !root_finding.suppressed,
            "different target should not match"
        );

        let cascade_finding = &report
            .findings_by_category
            .get("Cascading Layout Break")
            .unwrap()[0];
        assert!(
            !cascade_finding.suppressed,
            "cascade should not be suppressed when root is not"
        );
    }
}
