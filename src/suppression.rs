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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::diff::Finding;

/// The default config file name looked up in the current working directory.
pub const DEFAULT_CONFIG_FILE: &str = ".safeguard.toml";

/// A parsed suppression config: a flat list of reviewed acknowledgements.
#[derive(Debug, Clone, Default, Deserialize)]
///
/// `deny_unknown_fields` is deliberate: this is the one config file that can
/// turn the safety gate off, so a mistyped key (`targets`, `[[suppression]]`)
/// must be a loud parse error rather than a silently dropped rule.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionConfig {
    /// The acknowledged findings, one `[[suppress]]` table per entry.
    #[serde(default, rename = "suppress")]
    pub rules: Vec<SuppressionRule>,
}

/// A single whitelisted finding, keyed by category and (optionally) target.
#[derive(Debug, Clone, Deserialize)]
    /// Explicit event/storage classification (the `[classification]` table).
    ///
    /// Classification only affects a finding's wording, remediation, and
    /// `classification` metadata — never the structural `category` used for
    /// suppression matching — so changing it can never silently move a finding
    /// out from under an existing suppression rule.
    #[serde(default)]
    pub classification: crate::classification::ClassificationConfig,
    /// The `[severity]` table: per-category severity overrides.
    ///
    /// Carried alongside the suppression rules because it is the same file and
    /// the same layer of policy — both decide how a described change is
    /// *treated*, neither changes what the diff actually found. Threading it
    /// here means every existing caller of
    /// [`crate::report::SafetyReport::with_suppressions`] picks the overrides
    /// up without a signature change.
    #[serde(default, rename = "severity")]
    pub severity_overrides: crate::severity_override::SeverityOverrides,
    /// The `[limits]` table is parsed independently by [`crate::limits`]. We
    /// still declare it here so `deny_unknown_fields` accepts a combined config
    /// carrying both `[[suppress]]` rules and `[limits]`; its contents are
    /// ignored by this parser.
    #[serde(default)]
    #[allow(dead_code)] // Present only so deny_unknown_fields accepts `[limits]`.
    limits: Option<toml::Value>,
}

/// A single whitelisted finding, keyed by category and (optionally) target.
///
/// `deny_unknown_fields` guards against a typo (e.g. `targets` for `target`)
/// silently changing what the rule matches.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
        self.canonical_rule_id().is_some_and(|rule_id| {
            canonical_rule_id(stable_category(&finding.category))
                .is_some_and(|finding_rule_id| rule_id == finding_rule_id)
                && self.target.as_deref() == finding.target.as_deref()
                && self.fingerprint.as_ref().map_or(true, |fp| {
                    fp.eq_ignore_ascii_case(&compute_fingerprint(finding))
                })
        })
    }

    fn canonical_rule_id(&self) -> Option<&'static str> {
        canonical_rule_id(stable_category(&self.rule_id))
    }
}

impl SuppressionConfig {
    /// Validate the configuration for security limits, format correctness, and expiration.
    pub fn validate(&self) -> Result<()> {
        // Category names in [severity] are checked first: a typo there silently
        // disables a policy the user believes is active, so it must never be
        // reachable past load time.
        self.severity_overrides.validate()?;

        let max_allowed = self.max_suppressions.unwrap_or(10);
        if self.rules.len() > max_allowed {
            anyhow::bail!(
                "Configured suppressions ({}) exceed the maximum limit of {}.",
                self.rules.len(),
                max_allowed
            );
        }

        let mut targetless_count = 0;
        for rule in &self.rules {
            if rule.target.is_none() {
                targetless_count += 1;
            }
        }

        if targetless_count > 0 {
            if !self.allow_targetless.unwrap_or(false) {
                anyhow::bail!(
                    "Targetless wildcard suppressions are disabled. Set 'allow_targetless = true' in config to enable."
                );
            }
            if targetless_count > 3 {
                anyhow::bail!(
                    "Number of targetless wildcard suppressions ({}) exceeds the ceiling of 3.",
                    targetless_count
                );
            }
        }

        for rule in &self.rules {
            if let Some(expiry_str) = &rule.expiry {
                if is_expired(expiry_str)? {
                    anyhow::bail!(
                        "Suppression rule for category '{}' has expired on {}.",
                        rule.rule_id,
                        expiry_str
                    );
                }
            }

            let is_new_format =
                rule.fingerprint.is_some() || rule.author.is_some() || rule.expiry.is_some();
            if is_new_format {
                if rule.author.is_none() {
                    anyhow::bail!(
                        "Missing 'author' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
                if rule.expiry.is_none() {
                    anyhow::bail!(
                        "Missing 'expiry' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
                if rule.fingerprint.is_none() {
                    anyhow::bail!(
                        "Missing 'fingerprint' for suppression rule under category '{}' (target: '{:?}').",
                        rule.rule_id,
                        rule.target
                    );
                }
            }
        }
        Ok(())
    }

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

    /// Return the first rule that matches `finding` together with its index, if any.
    /// The index is used by the report layer to track which rules were used.
    pub fn matching_rule_with_index(&self, finding: &Finding) -> Option<(usize, &SuppressionRule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches(finding))
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
    fn test_compute_fingerprint() {
        let f = Finding {
            severity: Severity::Critical,
            category: "Struct Field Removed".to_string(),
            message: "Struct field threshold of type ConfigData was removed".to_string(),
            type_name: Some("ConfigData".to_string()),
            target: Some("ConfigData.threshold".to_string()),
            classification: None,
        };
        let fp = compute_fingerprint(&f);
        let expected_input = "category:Struct Field Removed\ntarget:ConfigData.threshold\nmessage:Struct field threshold of type ConfigData was removed";
        let expected_hash = sha256(expected_input.as_bytes());
        let expected_fp = hex::encode(expected_hash);
        assert_eq!(fp, expected_fp);
    }

    #[test]
    fn test_seconds_to_ymd_and_is_expired() {
        assert_eq!(seconds_to_ymd(0), (1970, 1, 1));
        assert_eq!(seconds_to_ymd(1709164800), (2024, 2, 29));

        assert!(is_expired("1970-01-01").unwrap());
        assert!(!is_expired("2099-12-31").unwrap());

        // Exact today must not be expired
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (y, m, d) = seconds_to_ymd(now_secs);
        let today_str = format!("{:04}-{:02}-{:02}", y, m, d);
        assert!(!is_expired(&today_str).unwrap());

        assert!(is_expired("invalid-date").is_err());
    }

    #[test]
    fn test_config_validation_limits() {
        let toml_exceed = r#"
            max_suppressions = 1
            [[suppress]]
            category = "CatA"
            [[suppress]]
            category = "CatB"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_exceed).is_err());

        let toml_wildcard_disabled = r#"
            [[suppress]]
            category = "Environment"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_wildcard_disabled).is_err());

        let toml_wildcard_exceed = r#"
            allow_targetless = true
            [[suppress]]
            category = "Env1"
            [[suppress]]
            category = "Env2"
            [[suppress]]
            category = "Env3"
            [[suppress]]
            category = "Env4"
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_wildcard_exceed).is_err());

        let toml_missing_new_format = r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            fingerprint = "8a3f..."
        "#;
        assert!(SuppressionConfig::from_toml_str(toml_missing_new_format).is_err());
    }

    #[test]
    fn test_fingerprint_matching() {
        let f = Finding {
            severity: Severity::Critical,
            category: "Struct Field Removed".to_string(),
            message: "Struct field threshold of type ConfigData was removed".to_string(),
            type_name: Some("ConfigData".to_string()),
            target: Some("ConfigData.threshold".to_string()),
            classification: None,
        };
        let fp = compute_fingerprint(&f);

        let toml_str = format!(
            r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            author = "Alice"
            expiry = "2099-12-31"
            fingerprint = "{}"
            "#,
            fp.to_uppercase()
        );
        let config = SuppressionConfig::from_toml_str(&toml_str).unwrap();
        assert!(config.is_suppressed(&f));

        let toml_mismatch = r#"
            [[suppress]]
            category = "Struct Field Removed"
            target = "ConfigData.threshold"
            author = "Alice"
            expiry = "2099-12-31"
            fingerprint = "incorrectfingerprint"
        "#;
        let config_mismatch = SuppressionConfig::from_toml_str(toml_mismatch).unwrap();
        assert!(!config_mismatch.is_suppressed(&f));
    }
}
