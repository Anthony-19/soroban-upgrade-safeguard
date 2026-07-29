use std::collections::hash_map::Entry;
use std::collections::HashMap;

use stellar_xdr::curr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0,
    ScSpecUdtUnionV0,
};

/// A structured representation of a Soroban contract's public interface,
/// organized by type for easy comparison between contract versions.
#[derive(Debug, Default)]
pub struct ContractSpec {
    /// Contract functions, keyed by name.
    pub functions: HashMap<String, ScSpecFunctionV0>,
    /// User-defined structs, keyed by name.
    pub structs: HashMap<String, ScSpecUdtStructV0>,
    /// User-defined enums, keyed by name.
    pub enums: HashMap<String, ScSpecUdtEnumV0>,
    /// User-defined unions (tagged enums with data), keyed by name.
    pub unions: HashMap<String, ScSpecUdtUnionV0>,
    /// Error enums, keyed by name.
    pub error_enums: HashMap<String, ScSpecUdtErrorEnumV0>,
}

impl ContractSpec {
    /// Build a `ContractSpec` from a list of decoded `ScSpecEntry` objects.
    ///
    /// If multiple entries with the same name for a given kind (e.g., two functions
    /// with the same name) are encountered, a warning is printed to stderr. Under the
    /// first-wins tie-break strategy, the first entry encountered in the `entries`
    /// slice is retained, and subsequent duplicates are ignored.
    pub fn from_entries(entries: &[ScSpecEntry]) -> Self {
        let mut spec = ContractSpec::default();

        for entry in entries {
            match entry {
                ScSpecEntry::FunctionV0(f) => {
                    let name = f.name.to_string();
<<<<<<< HEAD
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut fn_seen,
                        &mut duplicates,
                        SpecEntryKind::Function,
                        || {
                            spec.functions
                                .entry(name.clone())
                                .or_insert_with(|| f.clone());
                        },
                    );
                }
                ScSpecEntry::UdtStructV0(s) => {
                    let name = s.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut struct_seen,
                        &mut duplicates,
                        SpecEntryKind::Struct,
                        || {
                            spec.structs
                                .entry(name.clone())
                                .or_insert_with(|| s.clone());
                        },
                    );
                }
                ScSpecEntry::UdtEnumV0(e) => {
                    let name = e.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut enum_seen,
                        &mut duplicates,
                        SpecEntryKind::Enum,
                        || {
                            spec.enums.entry(name.clone()).or_insert_with(|| e.clone());
                        },
                    );
                }
                ScSpecEntry::UdtUnionV0(u) => {
                    let name = u.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut union_seen,
                        &mut duplicates,
                        SpecEntryKind::Union,
                        || {
                            spec.unions.entry(name.clone()).or_insert_with(|| u.clone());
                        },
                    );
                }
                ScSpecEntry::UdtErrorEnumV0(e) => {
                    let name = e.name.to_string();
                    let xdr = entry_to_xdr(&tagged.entry);
                    check_and_insert(
                        &name,
                        section,
                        xdr,
                        &mut err_seen,
                        &mut duplicates,
                        SpecEntryKind::ErrorEnum,
                        || {
                            spec.error_enums
                                .entry(name.clone())
                                .or_insert_with(|| e.clone());
                        },
                    );
=======
                    match spec.functions.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate function '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(f.clone());
                        }
                    }
                }
                ScSpecEntry::UdtStructV0(s) => {
                    let name = s.name.to_string();
                    match spec.structs.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate struct '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(s.clone());
                        }
                    }
                }
                ScSpecEntry::UdtEnumV0(e) => {
                    let name = e.name.to_string();
                    match spec.enums.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate enum '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(e.clone());
                        }
                    }
                }
                ScSpecEntry::UdtUnionV0(u) => {
                    let name = u.name.to_string();
                    match spec.unions.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate union '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(u.clone());
                        }
                    }
                }
                ScSpecEntry::UdtErrorEnumV0(e) => {
                    let name = e.name.to_string();
                    match spec.error_enums.entry(name) {
                        Entry::Occupied(entry) => {
                            eprintln!(
                                "WARNING: Duplicate error enum '{}' detected. Keeping the first entry.",
                                entry.key()
                            );
                        }
                        Entry::Vacant(slot) => {
                            slot.insert(e.clone());
                        }
                    }
>>>>>>> c63f1bddec211d5f042ed4554ca9b55e041ccb00
                }
            }
        }

        spec
    }

    /// Returns a summary string of the spec contents.
    pub fn summary(&self) -> String {
        format!(
            "Functions: {}, Structs: {}, Enums: {}, Unions: {}, Errors: {}",
            self.functions.len(),
            self.structs.len(),
            self.enums.len(),
            self.unions.len(),
            self.error_enums.len(),
        )
    }
}

<<<<<<< HEAD
/// Serialize a `ScSpecEntry` to raw XDR bytes for structural identity comparison.
///
/// This is the canonical way to check whether two entries with the same name
/// are truly identical without implementing a custom `PartialEq` for every
/// variant. An XDR round-trip is deterministic so byte equality implies
/// structural equality.
fn entry_to_xdr(entry: &ScSpecEntry) -> Vec<u8> {
    use stellar_xdr::curr::{Limited, Limits, WriteXdr};
    // Unlimited budget — we only need byte equality, not security bounding.
    // If encoding fails we return an empty Vec, which will never equal any
    // other entry's bytes, steering us to the more conservative conflicting-
    // duplicate path.
    let unlimited = Limits {
        depth: u32::MAX,
        len: usize::MAX,
    };
    let mut buf = Limited::new(Vec::new(), unlimited);
    let _ = entry.write_xdr(&mut buf);
    buf.inner
}

/// Core per-entry deduplication helper.
///
/// `seen` maps `name → (first_section_index, first_xdr_bytes)`.
/// `insert_fn` is called exactly once — when inserting the first occurrence.
/// `duplicates` is appended to when a second occurrence is found.
fn check_and_insert(
    name: &str,
    section: usize,
    xdr: Vec<u8>,
    seen: &mut BTreeMap<String, (usize, Vec<u8>)>,
    duplicates: &mut Vec<DuplicateEntry>,
    kind: SpecEntryKind,
    insert_fn: impl FnOnce(),
) {
    match seen.get(name) {
        None => {
            seen.insert(name.to_string(), (section, xdr));
            insert_fn();
        }
        Some((first_section, first_xdr)) => {
            let is_identical = *first_xdr == xdr;
            if let Some(dup) = duplicates
                .iter_mut()
                .find(|d| d.kind == kind && d.name == name)
            {
                dup.sections.push(section);
                if !is_identical {
                    dup.is_identical = false;
                }
            } else {
                duplicates.push(DuplicateEntry {
                    kind,
                    name: name.to_string(),
                    sections: vec![*first_section, section],
                    is_identical,
                });
            }
        }
    }
}

=======
>>>>>>> c63f1bddec211d5f042ed4554ca9b55e041ccb00
#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{StringM, VecM};

<<<<<<< HEAD
    // ---------------------------------------------------------------
    // Helper builders
    // ---------------------------------------------------------------
    fn make_fn(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: doc.try_into().unwrap(),
            name: name.try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        })
    }

    fn make_struct(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtStructV0(ScSpecUdtStructV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: VecM::default(),
        })
    }

    fn make_enum(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtEnumV0(ScSpecUdtEnumV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn make_union(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtUnionV0(ScSpecUdtUnionV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn make_err(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::default(),
        })
    }

    fn tagged(entry: ScSpecEntry, section: usize) -> TaggedSpecEntry {
        TaggedSpecEntry::new(entry, section)
    }

    // ---------------------------------------------------------------
    // Identical duplicates — informational, first definition wins
    // ---------------------------------------------------------------
    #[test]
    fn identical_duplicate_function_is_informational() {
        let e1 = make_fn("my_func", "same doc");
        let e2 = make_fn("my_func", "same doc"); // byte-identical
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1, "only one entry inserted");
        assert_eq!(dups.len(), 1);
        assert!(
            dups[0].is_identical,
            "identical duplicate must be flagged as identical"
        );
        assert_eq!(dups[0].kind, SpecEntryKind::Function);
        assert_eq!(dups[0].sections, vec![0, 1]);
    }

    #[test]
    fn identical_duplicate_struct_is_informational() {
        let e1 = make_struct("MyStruct", "same doc");
        let e2 = make_struct("MyStruct", "same doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 0)]; // same section

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.structs.len(), 1);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Struct);
        assert_eq!(dups[0].sections, vec![0, 0]);
    }

    #[test]
    fn identical_duplicate_enum_is_informational() {
        let e1 = make_enum("MyEnum", "doc");
        let e2 = make_enum("MyEnum", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Enum);
    }

    #[test]
    fn identical_duplicate_union_is_informational() {
        let e1 = make_union("MyUnion", "doc");
        let e2 = make_union("MyUnion", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Union);
    }

    #[test]
    fn identical_duplicate_error_enum_is_informational() {
        let e1 = make_err("MyErr", "doc");
        let e2 = make_err("MyErr", "doc");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::ErrorEnum);
    }

    // ---------------------------------------------------------------
    // Conflicting duplicates — critical, different definitions
    // ---------------------------------------------------------------
    #[test]
    fn conflicting_duplicate_function_is_not_identical() {
        let e1 = make_fn("transfer", "v1 doc");
        let e2 = make_fn("transfer", "v2 doc different"); // differs in doc → different XDR
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        // First definition wins
        assert_eq!(
            spec.functions["transfer"].doc.to_string(),
            "v1 doc",
            "first definition must be retained"
        );
        assert_eq!(dups.len(), 1);
        assert!(
            !dups[0].is_identical,
            "conflicting duplicate must not be identical"
        );
        assert_eq!(dups[0].kind, SpecEntryKind::Function);
        assert_eq!(dups[0].name, "transfer");
        assert_eq!(dups[0].sections, vec![0, 1]);
    }

    #[test]
    fn conflicting_duplicate_struct_is_not_identical() {
        let e1 = make_struct("Ledger", "v1");
        let e2 = make_struct("Ledger", "v2"); // doc differs
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.structs["Ledger"].doc.to_string(), "v1");
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Struct);
    }

    #[test]
    fn conflicting_duplicate_enum_is_not_identical() {
        let e1 = make_enum("Status", "a");
        let e2 = make_enum("Status", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Enum);
    }

    #[test]
    fn conflicting_duplicate_union_is_not_identical() {
        let e1 = make_union("Action", "a");
        let e2 = make_union("Action", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::Union);
    }

    #[test]
    fn conflicting_duplicate_error_enum_is_not_identical() {
        let e1 = make_err("ContractError", "a");
        let e2 = make_err("ContractError", "b");
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert!(!dups[0].is_identical);
        assert_eq!(dups[0].kind, SpecEntryKind::ErrorEnum);
    }

    // ---------------------------------------------------------------
    // Three occurrences accumulate into a single DuplicateEntry
    // ---------------------------------------------------------------
    #[test]
    fn three_occurrences_accumulate_into_one_duplicate_entry() {
        let e1 = make_fn("foo", "v1");
        let e2 = make_fn("foo", "v1"); // identical to e1
        let e3 = make_fn("foo", "v3"); // conflicts
        let entries = vec![tagged(e1, 0), tagged(e2, 1), tagged(e3, 2)];

        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions["foo"].doc.to_string(), "v1", "first wins");
        assert_eq!(dups.len(), 1, "all three collapsed into one DuplicateEntry");
        assert_eq!(dups[0].sections, vec![0, 1, 2]);
        assert!(
            !dups[0].is_identical,
            "conflicting third makes the whole group conflicting"
        );
    }

    // ---------------------------------------------------------------
    // Multiple different names do not produce spurious duplicates
    // ---------------------------------------------------------------
    #[test]
    fn unique_names_produce_no_duplicates() {
        let entries = vec![
            tagged(make_fn("a", ""), 0),
            tagged(make_fn("b", ""), 0),
            tagged(make_struct("S", ""), 0),
        ];
        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 2);
        assert_eq!(spec.structs.len(), 1);
        assert!(dups.is_empty(), "no duplicates expected for unique names");
    }

    // ---------------------------------------------------------------
    // Same name, different kinds — NOT a duplicate
    // ---------------------------------------------------------------
    #[test]
    fn same_name_different_kinds_is_not_a_duplicate() {
        // A function named "Token" and a struct named "Token" are distinct namespaces.
        let entries = vec![
            tagged(make_fn("Token", ""), 0),
            tagged(make_struct("Token", ""), 0),
        ];
        let (spec, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.structs.len(), 1);
        assert!(dups.is_empty(), "different kinds share no namespace");
    }

    // ---------------------------------------------------------------
    // from_entries backward-compat wrapper — still works, no duplicates surfaced
    // ---------------------------------------------------------------
    #[test]
    fn from_entries_backward_compat_accepts_duplicate_silently() {
        let entries = vec![make_fn("my_func", "doc1"), make_fn("my_func", "doc2")];
        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions["my_func"].doc.to_string(), "doc1");
    }

    // ---------------------------------------------------------------
    // Provenance: section indices are correctly threaded through
    // ---------------------------------------------------------------
    #[test]
    fn provenance_section_indices_are_tracked() {
        let e1 = make_struct("Foo", "a");
        let e2 = make_struct("Foo", "b");
        let entries = vec![tagged(e1, 3), tagged(e2, 7)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups[0].sections, vec![3, 7]);
    }

    // ---------------------------------------------------------------
    // Duplicate only-differs-in-doc: still conflicting (structural
    // equality uses XDR bytes, doc is part of the XDR encoding)
    // ---------------------------------------------------------------
    #[test]
    fn doc_only_difference_is_conflicting() {
        // Two structs with same name/fields but different doc strings.
        // The issue acceptance criterion says doc-only differences should
        // still be detected (the second definition DIFFERS from the first).
        let e1 = make_struct("Data", "documented");
        let e2 = make_struct("Data", ""); // empty doc
        let entries = vec![tagged(e1, 0), tagged(e2, 1)];

        let (_, dups) = ContractSpec::from_entries_checked(&entries);
        assert_eq!(dups.len(), 1);
        assert!(
            !dups[0].is_identical,
            "doc-only difference is still a conflict"
        );
    }

    // ---------------------------------------------------------------
    // Old test parity: from_entries_checked equivalent of the original tests
    // ---------------------------------------------------------------
=======
>>>>>>> c63f1bddec211d5f042ed4554ca9b55e041ccb00
    #[test]
    fn test_from_entries_duplicate_function_first_wins() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
<<<<<<< HEAD
        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];
=======

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

>>>>>>> c63f1bddec211d5f042ed4554ca9b55e041ccb00
        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.functions.len(), 1);
        let resolved = spec.functions.get("my_func").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_struct_first_wins() {
        let s1 = ScSpecUdtStructV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_struct".try_into().unwrap(),
            fields: VecM::default(),
        };
        let s2 = ScSpecUdtStructV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_struct".try_into().unwrap(),
            fields: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtStructV0(s1), ScSpecEntry::UdtStructV0(s2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.structs.len(), 1);
        let resolved = spec.structs.get("my_struct").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_enum_first_wins() {
        let e1 = ScSpecUdtEnumV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_enum".try_into().unwrap(),
            cases: VecM::default(),
        };
        let e2 = ScSpecUdtEnumV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_enum".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtEnumV0(e1), ScSpecEntry::UdtEnumV0(e2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.enums.len(), 1);
        let resolved = spec.enums.get("my_enum").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_union_first_wins() {
        let u1 = ScSpecUdtUnionV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_union".try_into().unwrap(),
            cases: VecM::default(),
        };
        let u2 = ScSpecUdtUnionV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_union".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![ScSpecEntry::UdtUnionV0(u1), ScSpecEntry::UdtUnionV0(u2)];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.unions.len(), 1);
        let resolved = spec.unions.get("my_union").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_duplicate_error_enum_first_wins() {
        let e1 = ScSpecUdtErrorEnumV0 {
            doc: "doc1".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_err".try_into().unwrap(),
            cases: VecM::default(),
        };
        let e2 = ScSpecUdtErrorEnumV0 {
            doc: "doc2".try_into().unwrap(),
            lib: StringM::default(),
            name: "my_err".try_into().unwrap(),
            cases: VecM::default(),
        };

        let entries = vec![
            ScSpecEntry::UdtErrorEnumV0(e1),
            ScSpecEntry::UdtErrorEnumV0(e2),
        ];

        let spec = ContractSpec::from_entries(&entries);

        assert_eq!(spec.error_enums.len(), 1);
        let resolved = spec.error_enums.get("my_err").unwrap();
        assert_eq!(resolved.doc.to_string(), "doc1");
    }

    #[test]
    fn test_from_entries_unique_names_no_warning() {
        let f1 = ScSpecFunctionV0 {
            doc: "doc1".try_into().unwrap(),
            name: "my_func1".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let f2 = ScSpecFunctionV0 {
            doc: "doc2".try_into().unwrap(),
            name: "my_func2".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
<<<<<<< HEAD
        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];
=======

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

>>>>>>> c63f1bddec211d5f042ed4554ca9b55e041ccb00
        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 2);
    }
}
