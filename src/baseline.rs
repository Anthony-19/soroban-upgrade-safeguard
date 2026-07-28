//! Compare a run's findings against a previously emitted JSON report.
//!
//! Every run of this tool reports every finding from scratch, which makes it
//! hard to tell a genuinely new problem apart from one that was already known
//! and accepted. A baseline addresses that without requiring a suppression
//! rule per finding: point `--baseline` at a JSON report from a previous run
//! and each current finding is classified as `new` (not present in the
//! baseline) or `persisting` (present in both). Findings present in the
//! baseline but absent now are recorded separately as `resolved`.
//!
//! Findings are matched on `(category, target)` — the same stable identifiers
//! the suppression config relies on — so message-wording changes don't create
//! spurious "new" findings.
//!
//! # Effect on the verdict
//!
//! By default, supplying a baseline only *labels* findings; it does not change
//! `is_safe` or the exit code — a persisting Critical finding still fails the
//! run exactly as it would without a baseline. Pass `fail_on_new_only: true`
//! (the CLI's `--baseline-fail-on-new` flag) to instead gate the verdict on
//! new findings only, ignoring the severity of findings that already existed
//! in the baseline. This must be opted into explicitly; there is no silent
//! default that changes pass/fail behavior.

use crate::diff::Severity;
use crate::report::{ReportedFinding, SafetyReport};
use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Whether a finding in the current run was already present in the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BaselineStatus {
    /// Not present in the baseline report.
    New,
    /// Present in both the baseline and the current run.
    Persisting,
}

/// A finding that was present in the baseline but is absent from the current
/// run — i.e. it appears to have been fixed.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ResolvedFinding {
    pub category: String,
    pub target: Option<String>,
    pub message: String,
}

/// Summary of a run compared against a baseline report, attached to
/// [`SafetyReport::baseline_diff`] and rendered in every output format.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct BaselineDiff {
    /// The `tool_version` recorded in the baseline JSON.
    pub baseline_tool_version: String,
    /// Count of current findings not present in the baseline.
    pub new_count: usize,
    /// Count of current findings also present in the baseline.
    pub persisting_count: usize,
    /// Findings present in the baseline but absent from the current run.
    pub resolved: Vec<ResolvedFinding>,
    /// Whether the verdict was recomputed to consider only new findings.
    pub fail_on_new_only: bool,
}

/// The subset of a baseline JSON report's shape this module needs to parse.
/// Deliberately narrow: it only reads `tool_version` and the
/// `(category, target, message)` of each finding, so it tolerates fields the
/// current version's `SafetyReportJson` adds or removes elsewhere.
#[derive(Debug, Deserialize)]
struct BaselineFindingDoc {
    category: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct BaselineReportDoc {
    #[serde(default)]
    tool_version: Option<String>,
    #[serde(default)]
    findings_by_category: BTreeMap<String, Vec<BaselineFindingDoc>>,
}

/// The major-version component of a SemVer-ish string (`"1.2.3"` -> `"1"`).
fn major_version(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// Load `baseline_path` as a JSON report produced by this tool, and classify
/// every finding in `report` as new or persisting relative to it. Findings in
/// the baseline that no longer appear are recorded as resolved.
///
/// When `fail_on_new_only` is set, `report.is_safe` (and the counts derived
/// from it) are recomputed considering only findings classified as `New` —
/// see the module docs for why this is opt-in rather than the default.
///
/// # Errors
///
/// Returns an error if the file cannot be read, is not valid JSON in the
/// expected shape, or was produced by an incompatible major version of this
/// tool (detected via the `tool_version` field recorded in the JSON).
pub fn apply(
    report: &mut SafetyReport,
    baseline_path: &Path,
    fail_on_new_only: bool,
) -> Result<()> {
    let contents = std::fs::read_to_string(baseline_path).with_context(|| {
        format!(
            "Failed to read baseline report '{}'",
            baseline_path.display()
        )
    })?;
    let baseline: BaselineReportDoc = serde_json::from_str(&contents).with_context(|| {
        format!(
            "Baseline report '{}' is not a valid JSON report produced by this tool",
            baseline_path.display()
        )
    })?;

    let baseline_tool_version = baseline.tool_version.ok_or_else(|| {
        anyhow::anyhow!(
            "Baseline report '{}' has no 'tool_version' field, so compatibility can't be \
             verified. It may predate baseline support, or not be a report from this tool.",
            baseline_path.display()
        )
    })?;

    let current_version = env!("CARGO_PKG_VERSION");
    if major_version(&baseline_tool_version) != major_version(current_version) {
        anyhow::bail!(
            "Baseline report '{}' was produced by an incompatible version of this tool \
             (baseline: {baseline_tool_version}, current: {current_version}). Regenerate the \
             baseline with the current version.",
            baseline_path.display()
        );
    }

    // Keyed on `(category, target)` and deduped, so a baseline that lists the
    // same key twice yields one entry. `BTreeMap` also fixes the order of
    // `resolved`, keeping the rendered report reproducible run-to-run.
    let baseline_by_key: BTreeMap<(String, Option<String>), &BaselineFindingDoc> = baseline
        .findings_by_category
        .values()
        .flatten()
        .map(|f| ((f.category.clone(), f.target.clone()), f))
        .collect();

    let mut current_keys: HashSet<(String, Option<String>)> = HashSet::new();
    let mut new_count = 0;
    let mut persisting_count = 0;

    for group in report.findings_by_category.values_mut() {
        for reported in group.iter_mut() {
            let key = (
                reported.finding.category.clone(),
                reported.finding.target.clone(),
            );
            let status = if baseline_by_key.contains_key(&key) {
                persisting_count += 1;
                BaselineStatus::Persisting
            } else {
                new_count += 1;
                BaselineStatus::New
            };
            current_keys.insert(key);
            reported.baseline_status = Some(status);
        }
    }

    let resolved: Vec<ResolvedFinding> = baseline_by_key
        .into_iter()
        .filter(|(key, _)| !current_keys.contains(key))
        .map(|(_, f)| ResolvedFinding {
            category: f.category.clone(),
            target: f.target.clone(),
            message: f.message.clone(),
        })
        .collect();

    if fail_on_new_only {
        recompute_verdict_for_new_only(report);
    }

    report.baseline_diff = Some(BaselineDiff {
        baseline_tool_version,
        new_count,
        persisting_count,
        resolved,
        fail_on_new_only,
    });

    Ok(())
}

/// Recompute `report.is_safe` considering only findings classified as `New`,
/// mirroring the same strict/non-strict rule [`SafetyReport::with_suppressions`]
/// uses, but scoped to the new subset instead of every unsuppressed finding.
fn recompute_verdict_for_new_only(report: &mut SafetyReport) {
    let is_new_and_failing = |finding: &ReportedFinding, severity: Severity| {
        !finding.suppressed
            && finding.finding.severity == severity
            && finding.baseline_status == Some(BaselineStatus::New)
    };

    let failing_critical = report
        .findings_by_category
        .values()
        .flatten()
        .filter(|f| is_new_and_failing(f, Severity::Critical))
        .count();
    let failing_warning = report
        .findings_by_category
        .values()
        .flatten()
        .filter(|f| is_new_and_failing(f, Severity::Warning))
        .count();

    report.is_safe = if report.strict {
        failing_critical == 0 && failing_warning == 0
    } else {
        failing_critical == 0
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{DiffReport, Finding};

    fn finding(category: &str, target: &str, severity: Severity) -> Finding {
        Finding {
            severity,
            category: category.to_string(),
            message: format!("{category} on {target}"),
            type_name: None,
            target: Some(target.to_string()),
            classification: None,
        }
    }

    fn report_with(findings: Vec<Finding>) -> SafetyReport {
        SafetyReport::new(&DiffReport { findings })
    }

    /// Write `contents` to a uniquely named temp file and return its path.
    fn temp_json(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("safeguard-baseline-test-{name}.json"));
        std::fs::write(&path, contents).expect("write temp baseline");
        path
    }

    /// A baseline document listing the given `(category, target)` pairs, stamped
    /// with the current tool version so it is always considered compatible.
    ///
    /// Built with `serde_json` rather than string formatting so the fixture is
    /// always valid JSON regardless of the values used.
    fn baseline_json(entries: &[(&str, &str)]) -> String {
        let mut by_category: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
        for (category, target) in entries {
            by_category
                .entry((*category).to_string())
                .or_default()
                .push(serde_json::json!({
                    "category": category,
                    "target": target,
                    "message": format!("{category} on {target}"),
                    "severity": "critical",
                    "rule_id": "x",
                    "fingerprint": "y",
                }));
        }
        serde_json::json!({
            "tool_version": env!("CARGO_PKG_VERSION"),
            "findings_by_category": by_category,
        })
        .to_string()
    }

    /// The status recorded for the finding with the given target.
    fn status_of(report: &SafetyReport, target: &str) -> Option<BaselineStatus> {
        report
            .findings_by_category
            .values()
            .flatten()
            .find(|f| f.finding.target.as_deref() == Some(target))
            .expect("finding present")
            .baseline_status
    }

    #[test]
    fn classifies_new_persisting_and_resolved() {
        let mut report = report_with(vec![
            finding("Struct Field Removed", "Data.old", Severity::Critical),
            finding("Function Removed", "brand_new", Severity::Critical),
        ]);
        let path = temp_json(
            "mixed",
            &baseline_json(&[
                ("Struct Field Removed", "Data.old"),
                ("Enum Case Removed", "Status.Gone"),
            ]),
        );

        apply(&mut report, &path, false).expect("baseline applies");

        assert_eq!(
            status_of(&report, "Data.old"),
            Some(BaselineStatus::Persisting)
        );
        assert_eq!(status_of(&report, "brand_new"), Some(BaselineStatus::New));

        let diff = report.baseline_diff.expect("baseline diff recorded");
        assert_eq!(diff.new_count, 1);
        assert_eq!(diff.persisting_count, 1);
        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.resolved[0].category, "Enum Case Removed");
        assert_eq!(diff.resolved[0].target.as_deref(), Some("Status.Gone"));
        assert!(!diff.fail_on_new_only);
    }

    #[test]
    fn matching_ignores_message_wording() {
        // Same (category, target) as the baseline but a reworded message: still
        // persisting, not new.
        let mut report = report_with(vec![Finding {
            message: "completely different wording".to_string(),
            ..finding("Struct Field Removed", "Data.old", Severity::Critical)
        }]);
        let path = temp_json(
            "wording",
            &baseline_json(&[("Struct Field Removed", "Data.old")]),
        );

        apply(&mut report, &path, false).expect("baseline applies");

        assert_eq!(
            status_of(&report, "Data.old"),
            Some(BaselineStatus::Persisting)
        );
        assert_eq!(report.baseline_diff.unwrap().new_count, 0);
    }

    #[test]
    fn baseline_alone_does_not_change_the_verdict() {
        let mut report = report_with(vec![finding(
            "Struct Field Removed",
            "Data.old",
            Severity::Critical,
        )]);
        assert!(!report.is_safe, "a Critical finding fails the run");

        let path = temp_json(
            "verdict-default",
            &baseline_json(&[("Struct Field Removed", "Data.old")]),
        );
        apply(&mut report, &path, false).expect("baseline applies");

        assert!(
            !report.is_safe,
            "without --baseline-fail-on-new a persisting Critical must still fail"
        );
    }

    #[test]
    fn fail_on_new_only_ignores_persisting_criticals() {
        let mut report = report_with(vec![finding(
            "Struct Field Removed",
            "Data.old",
            Severity::Critical,
        )]);
        let path = temp_json(
            "verdict-new-only",
            &baseline_json(&[("Struct Field Removed", "Data.old")]),
        );

        apply(&mut report, &path, true).expect("baseline applies");

        assert!(
            report.is_safe,
            "a Critical finding already in the baseline must not fail under fail-on-new-only"
        );
        assert!(report.baseline_diff.unwrap().fail_on_new_only);
    }

    #[test]
    fn fail_on_new_only_still_fails_a_new_critical() {
        let mut report = report_with(vec![
            finding("Struct Field Removed", "Data.old", Severity::Critical),
            finding("Function Removed", "brand_new", Severity::Critical),
        ]);
        let path = temp_json(
            "verdict-new-critical",
            &baseline_json(&[("Struct Field Removed", "Data.old")]),
        );

        apply(&mut report, &path, true).expect("baseline applies");

        assert!(!report.is_safe, "a new Critical finding must fail the run");
    }

    #[test]
    fn incompatible_major_version_is_rejected() {
        let mut report = report_with(vec![]);
        let path = temp_json(
            "incompatible",
            r#"{"tool_version":"9999.0.0","findings_by_category":{}}"#,
        );

        let err = apply(&mut report, &path, false).expect_err("must reject the baseline");
        let message = format!("{err:#}");
        assert!(
            message.contains("incompatible version"),
            "unexpected error: {message}"
        );
        assert!(report.baseline_diff.is_none());
    }

    #[test]
    fn baseline_without_tool_version_is_rejected() {
        let mut report = report_with(vec![]);
        let path = temp_json("no-version", r#"{"findings_by_category":{}}"#);

        let err = apply(&mut report, &path, false).expect_err("must reject the baseline");
        assert!(
            format!("{err:#}").contains("tool_version"),
            "the error must name the missing field"
        );
    }

    #[test]
    fn malformed_baseline_is_rejected() {
        let mut report = report_with(vec![]);
        let path = temp_json("malformed", "{not json at all");

        let err = apply(&mut report, &path, false).expect_err("must reject the baseline");
        assert!(format!("{err:#}").contains("not a valid JSON report"));
    }

    #[test]
    fn missing_baseline_file_is_rejected() {
        let mut report = report_with(vec![]);
        let path = std::env::temp_dir().join("safeguard-baseline-does-not-exist.json");
        let _ = std::fs::remove_file(&path);

        let err = apply(&mut report, &path, false).expect_err("must reject the baseline");
        assert!(format!("{err:#}").contains("Failed to read baseline report"));
    }
}
