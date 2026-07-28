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

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::diff::Finding;
use crate::error::Error;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// A parsed suppression config: a flat list of reviewed acknowledgements.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuppressionConfig {
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    pub rules: Vec<SuppressionRule>,
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

impl SuppressionRule {
    /// Whether this rule matches `finding` exactly on both category and target.
    fn matches(&self, finding: &Finding) -> bool {
        self.category == finding.category && self.target.as_deref() == finding.target.as_deref()
    }
}

impl SuppressionConfig {
    /// Parse a config from a TOML string.
    pub fn from_toml_str(contents: &str) -> Result<Self, Error> {
        toml::from_str(contents).map_err(|e| Error::SuppressionConfig {
            path: None,
            details: "Failed to parse suppression config as TOML".to_string(),
            source: Some(Box::new(e)),
        })
    }

    /// Load a config from an explicit path. Errors if the file is missing or
    /// malformed — callers that pass a path are asserting it should exist.
    pub fn load_from_path(path: &Path) -> Result<Self, Error> {
        let contents = fs::read_to_string(path).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Failed to read suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })?;
        Self::from_toml_str(&contents).map_err(|e| Error::SuppressionConfig {
            path: Some(path.to_path_buf()),
            details: format!("Invalid suppression config '{}'", path.display()),
            source: Some(Box::new(e)),
        })
    }

    /// Load the default config file if it exists, returning `None` when it is
    /// absent. A present-but-malformed file is still an error, so typos are not
    /// silently ignored. This preserves today's behavior when no config is set.
    pub fn load_optional(path: &Path) -> Result<Option<Self>, Error> {
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

    /// Validate the config on its own, without running a comparison.
    ///
    /// Parsing problems already surface at load time (see
    /// [`Self::load_from_path`]); this second pass catches rules that parse but
    /// can never match anything — most usefully a rule naming a `category` the
    /// tool never emits, which would otherwise silently never fire. It needs no
    /// WASM inputs, so a team can check a `.safeguard.toml` in isolation.
    pub fn validate(&self) -> ConfigValidation {
        let unknown_categories = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| !is_known_category(&rule.category))
            .map(|(i, rule)| (i + 1, rule.category.clone()))
            .collect();
        ConfigValidation { unknown_categories }
    }
}

/// Whether `category` is one the tool can actually emit as a finding category.
///
/// The valid set is shared with the report layer rather than duplicated: a
/// category is recognized exactly when the report has remediation guidance for
/// it, which by construction covers every category the diff stage emits. A rule
/// naming anything outside this set can never match a real finding.
pub fn is_known_category(category: &str) -> bool {
    crate::report::get_remediation_guidance(category).is_some()
}

/// The outcome of [`SuppressionConfig::validate`].
///
/// A config is valid when this carries no problems. Today the only class of
/// problem detected is a rule naming an unknown category, but the type leaves
/// room to grow (e.g. rules that match nothing during a run).
#[derive(Debug, Default)]
pub struct ConfigValidation {
    /// `(1-based rule number, category)` for every rule whose `category` the
    /// tool never emits.
    pub unknown_categories: Vec<(usize, String)>,
}

impl ConfigValidation {
    /// Whether the config is free of detected problems.
    pub fn is_valid(&self) -> bool {
        self.unknown_categories.is_empty()
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

    #[test]
    fn validate_accepts_a_config_of_known_categories() {
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target   = "Data.amount"

            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(validation.is_valid());
        assert!(validation.unknown_categories.is_empty());
    }

    #[test]
    fn validate_flags_a_rule_with_an_unknown_category() {
        // "Struct Field Reordded" is a misspelling of "Struct Field Reordered";
        // the tool never emits it, so the rule could never match.
        let config = SuppressionConfig::from_toml_str(
            r#"
            [[suppress]]
            category = "Function Removed"
            target   = "legacy_init"

            [[suppress]]
            category = "Struct Field Reordded"
            target   = "Data.amount"
            "#,
        )
        .unwrap();

        let validation = config.validate();
        assert!(!validation.is_valid());
        assert_eq!(validation.unknown_categories.len(), 1);
        // Reported as the 2nd rule, with the offending category.
        assert_eq!(validation.unknown_categories[0].0, 2);
        assert_eq!(validation.unknown_categories[0].1, "Struct Field Reordded");
    }

    #[test]
    fn is_known_category_matches_the_emitted_set() {
        assert!(is_known_category("Struct Field Removed"));
        assert!(is_known_category("Environment"));
        assert!(!is_known_category("Totally Made Up Category"));
    }

    #[test]
    fn malformed_config_is_a_clear_specific_error() {
        // A key with spaces is not valid TOML.
        let err = SuppressionConfig::from_toml_str("this is not = valid").unwrap_err();
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("suppression config"),
            "error should name the suppression config, got: {message}"
        );
    }
}
