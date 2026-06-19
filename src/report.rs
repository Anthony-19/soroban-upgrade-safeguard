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
    pub findings_by_category: BTreeMap<&'a str, &'a Vec<ReportedFinding>>,
}

impl SafetyReport {
    /// Compute a safety report from a raw DiffReport, with no suppressions.
    ///
    /// Equivalent to [`SafetyReport::with_suppressions`] using an empty config,
    /// so behavior is identical to before suppression support existed.
    pub fn new(diff: &DiffReport) -> Self {
        Self::with_suppressions(diff, &SuppressionConfig::default())
    }

    /// Compute a safety report, applying a suppression config.
    ///
    /// Every finding is still listed; those matched by a rule are flagged as
    /// suppressed and excluded from the failing set. `is_safe` is therefore
    /// true when no *unsuppressed* Critical finding remains — a deliberately
    /// acknowledged breaking change no longer fails the run.
    pub fn with_suppressions(diff: &DiffReport, suppressions: &SuppressionConfig) -> Self {
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut suppressed_count = 0;
        let mut failing_critical_count = 0;
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
            } else if finding.severity == Severity::Critical {
                failing_critical_count += 1;
            }

            findings_by_category
                .entry(finding.category.clone())
                .or_default()
                .push(ReportedFinding {
                    finding: finding.clone(),
                    suppressed,
                    suppression_reason: rule.and_then(|r| r.reason.clone()),
                });
        }

        let is_safe = if strict {
            critical_count == 0 && warning_count == 0
        } else {
            critical_count == 0
        };

        Self {
            critical_count,
            warning_count,
            info_count,
            suppressed_count,
            total_findings: diff.findings.len(),
            is_safe: failing_critical_count == 0,
            findings_by_category,
            strict,
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
            findings_by_category: self
                .findings_by_category
                .iter()
                .map(|(k, v)| (k.as_str(), v))
                .collect(),
        }
    }

    /// Generate a structured, human-readable text output for the CLI.
    pub fn generate_summary_text(&self) -> String {
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
            output.push_str(
                &"    [STRICT MODE ACTIVE]\n"
                    .bold()
                    .yellow()
                    .to_string(),
            );
        }
        output.push_str(
            &"========================================\n"
                .bold()
                .to_string(),
        );

        let status = if self.is_safe {
            "✅ PASSED (No breaking changes detected)".green().bold()
        } else if self.strict && self.critical_count == 0 {
            "❌ FAILED (Warnings detected in strict mode)"
                .red()
                .bold()
        } else {
            "❌ FAILED (Critical breaking changes detected)"
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
                        output.push_str(
                            &format!("    ↳ reason: {}\n", reason).dimmed().to_string(),
                        );
                    }
                    continue;
                }

                let formatted = match finding.severity {
                    Severity::Critical => format!("🔴 {}", finding.message).red(),
                    Severity::Warning => format!("🟡 {}", finding.message).yellow(),
                    Severity::Info => format!("🔵 {}", finding.message).cyan(),
                };
                output.push_str(&format!("{}\n", formatted));
            }
            output.push('\n');
        }

        if !self.is_safe {
            if self.strict && self.critical_count == 0 {
                output.push_str(&"⚠️  ACTION REQUIRED: Strict mode is active and warnings were detected.\n".yellow().bold().to_string());
                output.push_str(&"These warnings must be resolved or strict mode disabled to proceed.\n".yellow().to_string());
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
        output.push_str("| Finding Severity | Count |\n");
        output.push_str("| :--- | :--- |\n");
        output.push_str(&format!("| **Critical** | {} |\n", self.critical_count));
        output.push_str(&format!("| **Warning** | {} |\n", self.warning_count));
        output.push_str(&format!("| **Info** | {} |\n", self.info_count));
        if self.suppressed_count > 0 {
            output.push_str(&format!("| **Suppressed** | {} |\n", self.suppressed_count));
        }
        output.push_str("\n---\n\n");

        if self.total_findings == 0 {
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
