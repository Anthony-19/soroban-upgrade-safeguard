//! Structural fingerprints and rename detection for user-defined types.
//!
//! ## The problem
//!
//! The comparison keys every type on its *name*. A rename (`Balance` ->
//! `Account`) with an identical layout is therefore modeled as a delete plus an
//! add — a false Critical that buries the fact that the layout never changed.
//! Worse, a delete of one type and an unrelated add that happens to reuse the
//! old name is silently treated as "the same type".
//!
//! This module separates *human name* from *structural identity*. A
//! [`Fingerprint`] is a deterministic, order-sensitive digest of a type's
//! layout (field names, field types, case discriminants) that ignores the
//! type's own name and doc-strings. Two types with the same fingerprint have an
//! identical on-chain layout.
//!
//! ## Rename detection
//!
//! Given the set of removed and added names within one kind (structs, enums,
//! …), [`match_renames`] pairs a removed type with an added type when they are
//! the best structural match. It is:
//!
//! - **Deterministic**: candidates are considered in sorted-name order and ties
//!   break on name, so the result never depends on `HashMap` iteration order.
//! - **Bounded**: at most `removed * added` fingerprint comparisons, and each
//!   fingerprint is computed once. No backtracking.
//! - **Conservative**: a removed type is only ever paired with an added type
//!   whose *field/case structure aligns* (same field names, or an identical
//!   fingerprint). Two types that share no structure are never matched, so a
//!   coincidental delete+add is reported as delete+add, not a rename.

use std::collections::{BTreeMap, BTreeSet};

use stellar_xdr::curr::{
    ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionV0,
};

use crate::mapper::type_to_string;

/// A deterministic, name-independent digest of a type's layout.
///
/// Equality of fingerprints means the two types serialize identically. The
/// string form is stable across runs (it is built from sorted-free, positional
/// data) so it can be compared directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    fn from_parts(kind: &str, parts: &[String]) -> Self {
        Fingerprint(format!("{kind}[{}]", parts.join(";")))
    }

    /// Fingerprint of a struct: positional `(name:type)` pairs.
    pub fn of_struct(s: &ScSpecUdtStructV0) -> Self {
        let parts: Vec<String> = s
            .fields
            .iter()
            .map(|f| format!("{}:{}", f.name, type_to_string(&f.type_)))
            .collect();
        Fingerprint::from_parts("struct", &parts)
    }

    /// Fingerprint of a unit enum: positional `(name=value)` pairs.
    pub fn of_enum(e: &ScSpecUdtEnumV0) -> Self {
        let parts: Vec<String> = e
            .cases
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Fingerprint::from_parts("enum", &parts)
    }

    /// Fingerprint of an error enum: positional `(name=value)` pairs.
    pub fn of_error_enum(e: &ScSpecUdtErrorEnumV0) -> Self {
        let parts: Vec<String> = e
            .cases
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Fingerprint::from_parts("error_enum", &parts)
    }

    /// Fingerprint of a union: positional `(name:signature)` pairs.
    pub fn of_union(u: &ScSpecUdtUnionV0) -> Self {
        let parts: Vec<String> = u.cases.iter().map(union_case_fingerprint_part).collect();
        Fingerprint::from_parts("union", &parts)
    }
}

fn union_case_fingerprint_part(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(v) => format!("{}:void", v.name),
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: Vec<String> = t.type_.iter().map(type_to_string).collect();
            format!("{}:({})", t.name, types.join(","))
        }
    }
}

/// A detected rename: the old name, the new name, and whether the layout is
/// byte-for-byte identical (an exact fingerprint match) or merely structurally
/// related (matched on field names, but with field-level changes to diff).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    pub old_name: String,
    pub new_name: String,
    /// `true` when old and new fingerprints are identical (pure rename, no
    /// layout change). `false` when they were matched on structural similarity
    /// but still differ in some field/case.
    pub identical: bool,
}

/// Something that can be fingerprinted and expose its set of member keys
/// (field or case names) so structural similarity can be scored.
pub trait Fingerprintable {
    fn fingerprint(&self) -> Fingerprint;
    /// The set of member names (struct fields, enum/union cases). Used to score
    /// similarity when fingerprints are not identical.
    fn member_keys(&self) -> BTreeSet<String>;
}

impl Fingerprintable for ScSpecUdtStructV0 {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_struct(self)
    }
    fn member_keys(&self) -> BTreeSet<String> {
        self.fields.iter().map(|f| f.name.to_string()).collect()
    }
}

impl Fingerprintable for ScSpecUdtEnumV0 {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_enum(self)
    }
    fn member_keys(&self) -> BTreeSet<String> {
        self.cases.iter().map(|c| c.name.to_string()).collect()
    }
}

impl Fingerprintable for ScSpecUdtErrorEnumV0 {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_error_enum(self)
    }
    fn member_keys(&self) -> BTreeSet<String> {
        self.cases.iter().map(|c| c.name.to_string()).collect()
    }
}

impl Fingerprintable for ScSpecUdtUnionV0 {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of_union(self)
    }
    fn member_keys(&self) -> BTreeSet<String> {
        self.cases
            .iter()
            .map(|c| match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string(),
                ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string(),
            })
            .collect()
    }
}

/// The minimum Jaccard similarity of member-name sets required to treat a
/// non-identical pair as a rename. Anchored to structure, not names: two types
/// sharing no members can never be matched. `0.5` means a majority of the
/// members must align.
const MIN_SIMILARITY: f64 = 0.5;

/// Similarity of two member-name sets in `[0, 1]` (Jaccard index).
fn similarity(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        // Two empty (field-less) types share no structure to anchor a rename to.
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    inter / union
}

/// Detect renames between removed and added types of a single kind.
///
/// `removed` and `added` map name -> item for the types present in only the old
/// or only the new spec, respectively. Returns the matched renames; callers
/// remove the paired names from their delete/add sets and emit a field-level
/// diff for non-identical pairs.
///
/// Guarantees (see module docs): deterministic ordering, bounded cost, and no
/// match between structurally unrelated types.
pub fn match_renames<T: Fingerprintable>(
    removed: &BTreeMap<String, &T>,
    added: &BTreeMap<String, &T>,
) -> Vec<Rename> {
    // Precompute fingerprints and member keys once each.
    let old_prints: BTreeMap<&str, (Fingerprint, BTreeSet<String>)> = removed
        .iter()
        .map(|(n, t)| (n.as_str(), (t.fingerprint(), t.member_keys())))
        .collect();
    let new_prints: BTreeMap<&str, (Fingerprint, BTreeSet<String>)> = added
        .iter()
        .map(|(n, t)| (n.as_str(), (t.fingerprint(), t.member_keys())))
        .collect();

    let mut renames = Vec::new();
    let mut used_new: BTreeSet<&str> = BTreeSet::new();

    // Deterministic: BTreeMap iterates in sorted key order.
    for (old_name, (old_fp, old_keys)) in &old_prints {
        // Find the best available new candidate. Prefer an exact fingerprint
        // match; otherwise the highest member-key similarity above threshold.
        let mut best: Option<(&str, bool, f64)> = None; // (new_name, identical, score)

        for (new_name, (new_fp, new_keys)) in &new_prints {
            if used_new.contains(new_name) {
                continue;
            }

            let identical = old_fp == new_fp;
            let score = if identical {
                // Exact layout match ranks above everything.
                f64::INFINITY
            } else {
                similarity(old_keys, new_keys)
            };

            if !identical && score < MIN_SIMILARITY {
                continue;
            }

            let better = match best {
                None => true,
                // Higher score wins; tie breaks on the lexicographically
                // smaller new name for determinism.
                Some((best_name, _, best_score)) => {
                    score > best_score || (score == best_score && *new_name < best_name)
                }
            };
            if better {
                best = Some((new_name, identical, score));
            }
        }

        if let Some((new_name, identical, _)) = best {
            used_new.insert(new_name);
            renames.push(Rename {
                old_name: old_name.to_string(),
                new_name: new_name.to_string(),
                identical,
            });
        }
    }

    renames
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ScSpecTypeDef, ScSpecUdtStructFieldV0, StringM, VecM};

    fn struct_with(name: &str, fields: &[(&str, ScSpecTypeDef)]) -> ScSpecUdtStructV0 {
        let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
            .iter()
            .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: (*fname).try_into().unwrap(),
                type_: ftype.clone(),
            })
            .collect();
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: VecM::try_from(xdr_fields).unwrap(),
        }
    }

    #[test]
    fn identical_layout_is_detected_as_pure_rename() {
        let old = struct_with("Balance", &[("amount", ScSpecTypeDef::I128)]);
        let new = struct_with("Account", &[("amount", ScSpecTypeDef::I128)]);

        let removed = BTreeMap::from([("Balance".to_string(), &old)]);
        let added = BTreeMap::from([("Account".to_string(), &new)]);

        let renames = match_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].old_name, "Balance");
        assert_eq!(renames[0].new_name, "Account");
        assert!(renames[0].identical, "same fields -> identical layout");
    }

    #[test]
    fn rename_with_field_change_is_detected_but_not_identical() {
        let old = struct_with("Balance", &[("amount", ScSpecTypeDef::I128)]);
        // Same field name, different type -> structurally related, not identical.
        let new = struct_with("Account", &[("amount", ScSpecTypeDef::U64)]);

        let removed = BTreeMap::from([("Balance".to_string(), &old)]);
        let added = BTreeMap::from([("Account".to_string(), &new)]);

        let renames = match_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert!(!renames[0].identical, "field type changed -> not identical");
    }

    #[test]
    fn unrelated_types_are_not_matched() {
        let old = struct_with("Balance", &[("amount", ScSpecTypeDef::I128)]);
        let new = struct_with(
            "Widget",
            &[
                ("color", ScSpecTypeDef::Bytes),
                ("size", ScSpecTypeDef::U32),
            ],
        );

        let removed = BTreeMap::from([("Balance".to_string(), &old)]);
        let added = BTreeMap::from([("Widget".to_string(), &new)]);

        let renames = match_renames(&removed, &added);
        assert!(renames.is_empty(), "no shared structure -> no rename");
    }

    #[test]
    fn coincidental_identical_fingerprint_across_kinds_is_still_a_rename() {
        // Two structs with the same single i128 field but different names: this
        // IS an identical layout, so it is legitimately reported as a rename.
        let old = struct_with("Foo", &[("v", ScSpecTypeDef::I128)]);
        let new = struct_with("Bar", &[("v", ScSpecTypeDef::I128)]);
        let removed = BTreeMap::from([("Foo".to_string(), &old)]);
        let added = BTreeMap::from([("Bar".to_string(), &new)]);
        let renames = match_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert!(renames[0].identical);
    }

    #[test]
    fn swap_pairs_deterministically() {
        // A and B swap names. Both are identical-layout matches; the pairing
        // must be deterministic regardless of map order.
        let old_a = struct_with("A", &[("x", ScSpecTypeDef::U32)]);
        let old_b = struct_with("B", &[("y", ScSpecTypeDef::U64)]);
        let new_a = struct_with("A", &[("y", ScSpecTypeDef::U64)]); // now holds B's layout
        let new_b = struct_with("B", &[("x", ScSpecTypeDef::U32)]); // now holds A's layout

        let removed = BTreeMap::from([("A".to_string(), &old_a), ("B".to_string(), &old_b)]);
        let added = BTreeMap::from([("A".to_string(), &new_a), ("B".to_string(), &new_b)]);

        let r1 = match_renames(&removed, &added);
        let r2 = match_renames(&removed, &added);
        assert_eq!(r1, r2, "rename detection must be deterministic");
    }

    #[test]
    fn multiple_candidates_pick_best_and_do_not_double_assign() {
        let old = struct_with(
            "Src",
            &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        );
        // exact match
        let exact = struct_with(
            "Exact",
            &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        );
        // partial match
        let partial = struct_with(
            "Partial",
            &[("a", ScSpecTypeDef::U32), ("c", ScSpecTypeDef::U32)],
        );

        let removed = BTreeMap::from([("Src".to_string(), &old)]);
        let added = BTreeMap::from([
            ("Exact".to_string(), &exact),
            ("Partial".to_string(), &partial),
        ]);

        let renames = match_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].new_name, "Exact", "exact layout match preferred");
        assert!(renames[0].identical);
    }
}
