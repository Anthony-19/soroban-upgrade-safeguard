//! Declared storage schemas and evidence-based reconciliation.

use serde::{Deserialize, Serialize};

use crate::storage_inference::{CoverageGap, Durability, StorageInference, StorageOperation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageDeclaration {
    pub name: String,
    #[serde(default)]
    pub function: Option<String>,
    pub operation: StorageOperation,
    #[serde(default)]
    pub durability: Option<Durability>,
    #[serde(default)]
    pub key_type: Option<String>,
    #[serde(default)]
    pub value_type: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSchema {
    #[serde(default)]
    pub declarations: Vec<StorageDeclaration>,
}

impl StorageSchema {
    pub fn from_json(input: &str) -> Result<Self, String> {
        serde_json::from_str(input).map_err(|e| format!("invalid storage schema JSON: {e}"))
    }

    pub fn from_toml(input: &str) -> Result<Self, String> {
        toml::from_str(input).map_err(|e| format!("invalid storage schema TOML: {e}"))
    }

    pub fn from_str(input: &str, format: SchemaFormat) -> Result<Self, String> {
        let schema = match format {
            SchemaFormat::Json => Self::from_json(input)?,
            SchemaFormat::Toml => Self::from_toml(input)?,
        };
        schema.validate()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.declarations.iter().any(|d| d.name.trim().is_empty()) {
            return Err("storage schema declaration names must not be empty".into());
        }
        for (index, declaration) in self.declarations.iter().enumerate() {
            if declaration.operation == StorageOperation::Unknown {
                return Err(format!(
                    "declaration {index} uses unknown storage operation"
                ));
            }
        }
        Ok(())
    }

    pub fn reconcile(&self, inferred: &StorageInference) -> StorageReconciliation {
        let mut findings = Vec::new();
        let mut used = vec![false; self.declarations.len()];

        for observation in &inferred.observations {
            let candidate = self
                .declarations
                .iter()
                .enumerate()
                .find(|(_, declaration)| declaration_matches(declaration, observation));
            let Some((index, declaration)) = candidate else {
                findings.push(SchemaMismatch::MissingDeclaration {
                    function: observation.function.clone(),
                    operation: observation.operation,
                    durability: observation.durability,
                    evidence: observation.evidence.clone(),
                });
                continue;
            };
            used[index] = true;
            if let (Some(inferred), Some(declared)) = (
                observation.key_type.as_deref(),
                declaration.key_type.as_deref(),
            ) {
                if inferred != declared {
                    findings.push(SchemaMismatch::TypeContradiction {
                        declaration: declaration.name.clone(),
                        role: "key".into(),
                        declared: declared.into(),
                        inferred: inferred.into(),
                    });
                }
            }
            if let (Some(inferred), Some(declared)) = (
                observation.value_type.as_deref(),
                declaration.value_type.as_deref(),
            ) {
                if inferred != declared {
                    findings.push(SchemaMismatch::TypeContradiction {
                        declaration: declaration.name.clone(),
                        role: "value".into(),
                        declared: declared.into(),
                        inferred: inferred.into(),
                    });
                }
            }
            if declaration.durability.is_some()
                && observation.durability.is_some()
                && declaration.durability != observation.durability
            {
                findings.push(SchemaMismatch::DurabilityContradiction {
                    declaration: declaration.name.clone(),
                    declared: declaration.durability,
                    inferred: observation.durability,
                });
            }
        }

        for (index, declaration) in self.declarations.iter().enumerate() {
            if !used[index] {
                findings.push(SchemaMismatch::UnobservedDeclaration {
                    declaration: declaration.name.clone(),
                });
            }
        }

        StorageReconciliation {
            findings,
            coverage_gaps: inferred.gaps.clone(),
            complete: inferred.gaps.is_empty(),
        }
    }
}

fn declaration_matches(
    declaration: &StorageDeclaration,
    observation: &crate::storage_inference::StorageObservation,
) -> bool {
    declaration.operation == observation.operation
        && declaration
            .function
            .as_deref()
            .map(|name| name == observation.function)
            .unwrap_or(true)
        && declaration
            .durability
            .map(|durability| Some(durability) == observation.durability)
            .unwrap_or(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFormat {
    Json,
    Toml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaMismatch {
    MissingDeclaration {
        function: String,
        operation: StorageOperation,
        durability: Option<Durability>,
        evidence: Vec<String>,
    },
    TypeContradiction {
        declaration: String,
        role: String,
        declared: String,
        inferred: String,
    },
    DurabilityContradiction {
        declaration: String,
        declared: Option<Durability>,
        inferred: Option<Durability>,
    },
    UnobservedDeclaration {
        declaration: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReconciliation {
    pub findings: Vec<SchemaMismatch>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub complete: bool,
}

impl StorageReconciliation {
    pub fn is_compatible(&self) -> bool {
        self.findings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_inference::{StorageObservation, StorageOperation};

    #[test]
    fn reports_missing_declaration_and_preserves_gap() {
        let inferred = StorageInference {
            observations: vec![StorageObservation {
                function: "save".into(),
                operation: StorageOperation::Set,
                durability: Some(Durability::Persistent),
                key_type: None,
                value_type: None,
                confidence: "host_call_only".into(),
                evidence: vec!["call env::storage_set".into()],
            }],
            gaps: vec![CoverageGap {
                function: Some("save".into()),
                reason: "indirect call".into(),
                evidence: vec![],
            }],
            ..Default::default()
        };
        let result = StorageSchema::default().reconcile(&inferred);
        assert!(!result.is_compatible());
        assert_eq!(result.coverage_gaps.len(), 1);
        assert!(matches!(
            result.findings[0],
            SchemaMismatch::MissingDeclaration { .. }
        ));
    }

    #[test]
    fn rejects_unknown_operations() {
        let schema = StorageSchema {
            declarations: vec![StorageDeclaration {
                name: "x".into(),
                function: None,
                operation: StorageOperation::Unknown,
                durability: None,
                key_type: None,
                value_type: None,
            }],
        };
        assert!(schema.validate().is_err());
    }
}
