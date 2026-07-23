use std::collections::hash_map::Entry;
use std::collections::HashMap;

use stellar_xdr::curr::{
    ScSpecEntry, ScSpecFunctionV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0,
    ScSpecUdtUnionV0,
};

/// A structured representation of a Soroban contract's public interface,
/// organized by type for easy comparison between contract versions.
#[derive(Debug, Default, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{StringM, VecM};

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

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

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

        let entries = vec![ScSpecEntry::FunctionV0(f1), ScSpecEntry::FunctionV0(f2)];

        let spec = ContractSpec::from_entries(&entries);
        assert_eq!(spec.functions.len(), 2);
    }
}
