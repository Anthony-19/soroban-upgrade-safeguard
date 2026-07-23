//! Suppression configuration for known, intentional breaking changes.
//!
//! Some breaking changes are deliberate and already accounted for (for example
//! a planned storage migration). A suppression config lets a team whitelist
//! specific, reviewed findings so they no longer fail the run — while keeping
//! them visible in the report as explicitly acknowledged.
//!
//! ## File format (`.safeguard.toml`)
//!
//! ```toml
//! # Each [[suppress]] entry acknowledges exactly one reviewed finding.
//! [[suppress]]
//! category = "Struct Field Type Changed"
//! target   = "Data.amount"          # `Type.field` for fields
//! reason   = "Planned migration in v3 widens the balance to i128."
//!
//! [[suppress]]
//! category = "Function Removed"
//! target   = "legacy_init"          # bare name for functions
//! reason   = "Deprecated initializer dropped after the v2 cutover."
//! ```
//!
//! Matching is **exact**: a rule applies only when both its `category` and its
//! `target` equal the finding's own [`Finding::category`] and [`Finding::target`].
//! A rule that omits `target` matches only findings that themselves have no
//! target (e.g. environment-metadata changes). This deliberate strictness keeps
//! a suppression from over-applying to sibling fields, cases, or parameters.
//!
//! The `target` convention mirrors [`Finding::target`]:
//!
//! - functions: the function name (e.g. `transfer`)
//! - function parameters: `function.param` (e.g. `transfer.to`)
//! - types: the type name (e.g. `Data`)
//! - struct fields: `Type.field` (e.g. `Data.amount`)
//! - enum cases: `Enum.case` (e.g. `Status.Active`)
//!
//! ## Stable category keys
//!
//! Categories describe **structure only** — `"Enum Case Value Changed"`, never
//! `"Event Enum Case Value Changed"`. Whether a type is an event is reported
//! separately in the finding's `classification` field and affects only wording
//! and remediation. That separation is deliberate: a suppression key can never
//! shift because the event classification changed, so a reclassification cannot
//! silently un-suppress (or newly suppress) a real breaking change.
//!
//! Configs written against the older event-flavored names keep working —
//! [`stable_category`] maps each one onto its structural replacement — but new
//! rules should use the structural keys.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::diff::Finding;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// A parsed suppression config: a flat list of reviewed acknowledgements plus
/// the optional type-classification settings that drive event vs. storage
/// wording. Both live in the same `.safeguard.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuppressionConfig {
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    pub rules: Vec<SuppressionRule>,
    /// Explicit event/storage classification (the `[classification]` table).
    ///
    /// Classification only affects a finding's wording, remediation, and
    /// `classification` metadata — never the structural `category` used for
    /// suppression matching — so changing it can never silently move a finding
    /// out from under an existing suppression rule.
    #[serde(default)]
    pub classification: crate::classification::ClassificationConfig,
}

/// A single whitelisted finding, keyed by category and (optionally) target.
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressionRule {
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    pub category: String,
    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    pub target: Option<String>,
    /// An optional human-readable justification, surfaced in the report.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Map a pre-1.0 event-flavored category onto the structural category that
/// replaced it.
///
/// Categories used to encode the event/storage guess in the string itself
/// (`"Event Enum Case Value Changed"`), which meant a change to the
/// classification heuristic silently moved a finding out from under an
/// existing suppression. Categories are now purely structural and event-ness
/// lives in the separate `classification` field, so these names are no longer
/// emitted — but configs in the wild still reference them. Translating them
/// here keeps those configs working; the docs list the mapping so teams can
/// migrate to the stable keys at their own pace.
pub fn stable_category(category: &str) -> &str {
    match category {
        "Event Definition Removed" => "Struct Removed",
        "Event Field Removed" => "Struct Field Removed",
        "Event Field Reordered" => "Struct Field Reordered",
        "Event Field Type Changed" => "Struct Field Type Changed",
        "Event Enum Removed" => "Enum Removed",
        "Event Enum Case Removed" => "Enum Case Removed",
        "Event Enum Case Value Changed" => "Enum Case Value Changed",
        "Event Enum Case Added" => "Enum Case Added",
        other => other,
    }
}

impl SuppressionRule {
    /// Whether this rule matches `finding` exactly on both category and target.
    ///
    /// The rule's category is normalized through [`stable_category`] first so a
    /// legacy event-flavored key still matches the structural category that
    /// replaced it. Findings always carry structural categories, so this only
    /// ever widens what an old config matches — never what a current one does.
    fn matches(&self, finding: &Finding) -> bool {
        stable_category(&self.category) == finding.category
            && self.target.as_deref() == finding.target.as_deref()
    }
}

impl SuppressionConfig {
    /// Parse a config from a TOML string.
    pub fn from_toml_str(contents: &str) -> Result<Self> {
        toml::from_str(contents).context("Failed to parse suppression config as TOML")
    }

    /// Load a config from an explicit path. Errors if the file is missing or
    /// malformed — callers that pass a path are asserting it should exist.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read suppression config '{}'", path.display()))?;
        Self::from_toml_str(&contents)
            .with_context(|| format!("Invalid suppression config '{}'", path.display()))
    }

    /// Load the default config file if it exists, returning `None` when it is
    /// absent. A present-but-malformed file is still an error, so typos are not
    /// silently ignored. This preserves today's behavior when no config is set.
    pub fn load_optional(path: &Path) -> Result<Option<Self>> {
        if path.exists() {
            Ok(Some(Self::load_from_path(path)?))
        } else {
            Ok(None)
        }
    }

    /// Return the first rule that matches `finding`, if any.
    pub fn matching_rule(&self, finding: &Finding) -> Option<&SuppressionRule> {
        self.rules.iter().find(|rule| rule.matches(finding))
    }

    /// Whether any rule matches `finding`.
    pub fn is_suppressed(&self, finding: &Finding) -> bool {
        self.matching_rule(finding).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Severity;

    /// Build a finding with the given category and target for matching tests.
    fn finding(category: &str, target: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Critical,
            category: category.to_string(),
            message: "irrelevant to matching".to_string(),
            type_name: target.map(|t| t.split('.').next().unwrap().to_string()),
            target: target.map(|t| t.to_string()),
            classification: None,
        }
    }

    #[test]
    fn empty_config_suppresses_nothing() {
        let config = SuppressionConfig::default();
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.amount"))));
    }

    #[test]
    fn exact_match_on_category_and_target_suppresses() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            reason   = "Planned migration"
            "#,
        )
        .unwrap();

        let f = finding("Struct Field Type Changed", Some("Data.amount"));
        let rule = config.matching_rule(&f).expect("should match exactly");
        assert_eq!(rule.reason.as_deref(), Some("Planned migration"));
    }

    #[test]
    fn different_target_in_same_category_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same category, sibling field -> must NOT over-apply.
        assert!(!config.is_suppressed(&finding("Struct Field Type Changed", Some("Data.balance"))));
    }

    #[test]
    fn different_category_same_target_is_not_suppressed() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Type Changed"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        // Same target, different category -> must NOT match.
        assert!(!config.is_suppressed(&finding("Struct Field Removed", Some("Data.amount"))));
    }

    #[test]
    fn rule_without_target_matches_only_targetless_findings() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Environment"
            "#,
        )
        .unwrap();

        // A targetless finding in that category matches.
        assert!(config.is_suppressed(&finding("Environment", None)));
        // A finding that *has* a target in the same category does not.
        assert!(!config.is_suppressed(&finding("Environment", Some("Whatever"))));
    }

    #[test]
    fn legacy_event_category_still_matches_its_structural_replacement() {
        // A config written before categories became purely structural must keep
        // suppressing the same finding, not silently stop applying.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Event Enum Case Value Changed"
            target   = "StatusEvent.Paused"
            "#,
        )
        .unwrap();

        assert!(config.is_suppressed(&finding(
            "Enum Case Value Changed",
            Some("StatusEvent.Paused")
        )));
        // Aliasing must not widen the target match.
        assert!(!config.is_suppressed(&finding(
            "Enum Case Value Changed",
            Some("StatusEvent.Active")
        )));
    }

    #[test]
    fn stable_categories_are_passed_through_unchanged() {
        for cat in [
            "Struct Field Removed",
            "Enum Case Value Changed",
            "Function Signature Changed",
            "Type Renamed",
            "Environment",
        ] {
            assert_eq!(stable_category(cat), cat);
        }
    }

    #[test]
    fn function_target_matches_bare_name() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            reason   = "Dropped after v2 cutover"
            "#,
        )
        .unwrap();

        assert!(config.is_suppressed(&finding("Function Removed", Some("legacy_init"))));
        assert!(!config.is_suppressed(&finding("Function Removed", Some("transfer"))));
    }
}
