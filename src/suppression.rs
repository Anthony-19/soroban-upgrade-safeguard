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
#[non_exhaustive]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SuppressionConfig {
    /// Configurable maximum number of suppressions. Enforced globally.
    #[cfg(feature = "unstable")]
    pub max_suppressions: Option<usize>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) max_suppressions: Option<usize>,

    /// Explicit opt-in for targetless (wildcard) rules.
    #[cfg(feature = "unstable")]
    pub allow_targetless: Option<bool>,
    #[cfg(not(feature = "unstable"))]
    pub(crate) allow_targetless: Option<bool>,

    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    #[cfg(feature = "unstable")]
    pub rules: Vec<SuppressionRule>,
    #[serde(default, rename = "suppress")]
    #[cfg(not(feature = "unstable"))]
    pub(crate) rules: Vec<SuppressionRule>,
}

impl SuppressionConfig {
    /// Get the maximum permitted suppressions limit.
    pub fn max_suppressions(&self) -> Option<usize> {
        self.max_suppressions
    }

    /// Get whether targetless (wildcard) suppressions are allowed.
    pub fn allow_targetless(&self) -> Option<bool> {
        self.allow_targetless
    }

    /// Get the raw slice of suppression rules.
    pub fn rules(&self) -> &[SuppressionRule] {
        &self.rules
    }
}

/// A single whitelisted finding, keyed by category and (optionally) target.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressionRule {
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    #[cfg(feature = "unstable")]
    pub category: String,
    #[cfg(not(feature = "unstable"))]
    pub(crate) category: String,

    /// The exact [`Finding::target`] to match. When omitted, the rule matches
    /// only findings whose target is `None`.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub target: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) target: Option<String>,

    /// The author of the rule, required for security accountability in the new format.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub author: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) author: Option<String>,

    /// The human-readable justification, surfaced in the report.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub reason: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) reason: Option<String>,

    /// Expiry date for the suppression rule in YYYY-MM-DD format.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub expiry: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) expiry: Option<String>,

    /// Content fingerprint of the finding (SHA-256 hex).
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) fingerprint: Option<String>,
}

impl SuppressionRule {
    /// Get the category to match.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Get the target entity name if specified.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Get the author of the rule.
    pub fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }

    /// Get the human-readable reason/justification.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Get the expiry date in YYYY-MM-DD format.
    pub fn expiry(&self) -> Option<&str> {
        self.expiry.as_deref()
    }

    /// Get the content fingerprint of the finding.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
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
            root_target: None,
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
}
