//! Property tests for structural rename detection.
//!
//! The unit tests in `src/rename.rs` pin down specific scenarios. These check
//! the invariants that must hold across *arbitrary* type layouts, which is
//! where a similarity-based matcher is most likely to misbehave:
//!
//! - a pure rename is always recognized, and always as identical
//! - a name swap never produces a bogus "same type" match
//! - types sharing no members are never matched (no false collisions)
//! - the output is a partial matching: no type is paired twice
//! - the result never depends on how the inputs were built

use std::collections::BTreeMap;

use proptest::prelude::*;
use stellar_xdr::curr::{ScSpecTypeDef, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM};

use soroban_upgrade_safeguard::rename::match_renames;

/// Build a struct from `(field_name, field_type)` pairs.
fn struct_with(name: &str, fields: &[(String, ScSpecTypeDef)]) -> ScSpecUdtStructV0 {
    let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
        .iter()
        .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: fname.as_str().try_into().unwrap(),
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

/// A small alphabet of spec types, enough to vary layouts meaningfully.
fn any_type() -> impl Strategy<Value = ScSpecTypeDef> {
    prop_oneof![
        Just(ScSpecTypeDef::U32),
        Just(ScSpecTypeDef::U64),
        Just(ScSpecTypeDef::I128),
        Just(ScSpecTypeDef::Bool),
        Just(ScSpecTypeDef::Bytes),
        Just(ScSpecTypeDef::String),
    ]
}

/// Field names drawn from a fixed pool, so generated types have a realistic
/// chance of overlapping rather than being almost surely disjoint.
fn field_name(pool: &'static [&'static str]) -> impl Strategy<Value = String> {
    (0..pool.len()).prop_map(move |i| pool[i].to_string())
}

const POOL_A: &[&str] = &["amount", "owner", "expiry", "nonce", "flags", "scale"];
const POOL_B: &[&str] = &["color", "shape", "weight", "label", "origin", "depth"];

/// A non-empty field list with unique names drawn from `pool`.
fn fields(pool: &'static [&'static str]) -> impl Strategy<Value = Vec<(String, ScSpecTypeDef)>> {
    prop::collection::vec((field_name(pool), any_type()), 1..=5).prop_map(|mut v| {
        // A spec cannot have duplicate field names; keep the first of each.
        let mut seen = std::collections::BTreeSet::new();
        v.retain(|(n, _)| seen.insert(n.clone()));
        v
    })
}

proptest! {
    /// A type renamed with its layout untouched is always reported as exactly
    /// one rename, flagged identical — never as a delete plus an add.
    #[test]
    fn pure_rename_is_always_detected_as_identical(f in fields(POOL_A)) {
        let old = struct_with("OldName", &f);
        let new = struct_with("NewName", &f);

        let removed = BTreeMap::from([("OldName".to_string(), &old)]);
        let added = BTreeMap::from([("NewName".to_string(), &new)]);

        let renames = match_renames(&removed, &added);
        prop_assert_eq!(renames.len(), 1);
        prop_assert_eq!(&renames[0].old_name, "OldName");
        prop_assert_eq!(&renames[0].new_name, "NewName");
        prop_assert!(renames[0].identical, "layout is unchanged, so the rename is pure");
    }

    /// Types whose member names are entirely disjoint must never be matched.
    /// This is the false-collision guard: a delete and an unrelated add stay a
    /// delete and an unrelated add, however the two layouts happen to look.
    #[test]
    fn disjoint_members_are_never_matched(
        a in fields(POOL_A),
        b in fields(POOL_B),
    ) {
        let old = struct_with("Gone", &a);
        let new = struct_with("Fresh", &b);

        let removed = BTreeMap::from([("Gone".to_string(), &old)]);
        let added = BTreeMap::from([("Fresh".to_string(), &new)]);

        // POOL_A and POOL_B share no names, so similarity is 0 unless the two
        // layouts are byte-identical — impossible with disjoint field names.
        prop_assert!(
            match_renames(&removed, &added).is_empty(),
            "types sharing no members must not be matched"
        );
    }

    /// Two types that swap names: each new name carries the *other* type's
    /// layout. The matcher must pair by structure (A's layout -> B, B's -> A)
    /// and must never leave a type paired with itself.
    #[test]
    fn name_swap_pairs_by_structure_not_by_name(
        a in fields(POOL_A),
        b in fields(POOL_B),
    ) {
        let old_a = struct_with("A", &a);
        let old_b = struct_with("B", &b);
        // Names swap: "A" now holds what used to be B, and vice versa.
        let new_a = struct_with("A", &b);
        let new_b = struct_with("B", &a);

        let removed = BTreeMap::from([("A".to_string(), &old_a), ("B".to_string(), &old_b)]);
        let added = BTreeMap::from([("A".to_string(), &new_a), ("B".to_string(), &new_b)]);

        for r in match_renames(&removed, &added) {
            // Field pools are disjoint, so a same-name pairing would mean the
            // matcher followed the name instead of the structure.
            prop_assert_ne!(
                &r.old_name, &r.new_name,
                "a swapped name must not be matched to itself"
            );
        }
    }

    /// Whatever the inputs, the result is a valid partial matching: every old
    /// name and every new name appears at most once. No type is renamed twice.
    #[test]
    fn output_is_a_partial_matching(
        a in fields(POOL_A),
        b in fields(POOL_A),
        c in fields(POOL_A),
    ) {
        let o1 = struct_with("O1", &a);
        let o2 = struct_with("O2", &b);
        let n1 = struct_with("N1", &b);
        let n2 = struct_with("N2", &c);

        let removed = BTreeMap::from([("O1".to_string(), &o1), ("O2".to_string(), &o2)]);
        let added = BTreeMap::from([("N1".to_string(), &n1), ("N2".to_string(), &n2)]);

        let renames = match_renames(&removed, &added);

        let mut old_seen = std::collections::BTreeSet::new();
        let mut new_seen = std::collections::BTreeSet::new();
        for r in &renames {
            prop_assert!(old_seen.insert(r.old_name.clone()), "old name paired twice");
            prop_assert!(new_seen.insert(r.new_name.clone()), "new name paired twice");
        }
        prop_assert!(renames.len() <= 2, "cannot exceed the smaller side");
    }

    /// The same inputs always produce the same output, in the same order.
    /// Rename detection must not depend on hash iteration order.
    #[test]
    fn matching_is_deterministic(
        a in fields(POOL_A),
        b in fields(POOL_A),
        c in fields(POOL_A),
    ) {
        let o1 = struct_with("O1", &a);
        let o2 = struct_with("O2", &b);
        let n1 = struct_with("N1", &b);
        let n2 = struct_with("N2", &c);

        // Insert in opposite orders; BTreeMap normalizes, so any difference in
        // the result would have to come from the matcher itself.
        let removed_fwd = BTreeMap::from([("O1".to_string(), &o1), ("O2".to_string(), &o2)]);
        let removed_rev = BTreeMap::from([("O2".to_string(), &o2), ("O1".to_string(), &o1)]);
        let added_fwd = BTreeMap::from([("N1".to_string(), &n1), ("N2".to_string(), &n2)]);
        let added_rev = BTreeMap::from([("N2".to_string(), &n2), ("N1".to_string(), &n1)]);

        prop_assert_eq!(
            match_renames(&removed_fwd, &added_fwd),
            match_renames(&removed_rev, &added_rev)
        );
    }

    /// A rename that also changes the layout is still detected as a rename, but
    /// must never claim the layout is identical — otherwise a real breaking
    /// change would be reported as an informational rename.
    #[test]
    fn changed_layout_is_never_reported_as_identical(
        f in fields(POOL_A),
        extra_type in any_type(),
    ) {
        let old = struct_with("OldName", &f);

        // Add a field that is guaranteed not to be in the pool the old type
        // drew from, so the layout genuinely differs.
        let mut changed = f.clone();
        changed.push(("added_field".to_string(), extra_type));
        let new = struct_with("NewName", &changed);

        let removed = BTreeMap::from([("OldName".to_string(), &old)]);
        let added = BTreeMap::from([("NewName".to_string(), &new)]);

        for r in match_renames(&removed, &added) {
            prop_assert!(
                !r.identical,
                "layout changed, so the rename must not be flagged identical"
            );
        }
    }
}
