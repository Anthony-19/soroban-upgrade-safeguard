//! Property tests: the decode and type-walk paths must never abort (issue #52,
//! acceptance criterion 16).
//!
//! proptest catches panics as test failures. A stack overflow (`SIGABRT`) cannot
//! be caught, so the guarantee rests entirely on the depth/length guards tripping
//! *before* the recursive step — these properties exercise that across thousands
//! of random and adversarially deep inputs. If a guard were ever placed
//! after-the-recursion, a deep case here would crash the whole test binary rather
//! than fail gracefully.

use proptest::prelude::*;

use soroban_upgrade_safeguard::limits::ResourcePolicy;
use soroban_upgrade_safeguard::mapper::{try_type_to_string, LayoutMapper};
use soroban_upgrade_safeguard::parser::extract_metadata_with_policy;
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{ScSpecTypeDef, ScSpecTypeMap, ScSpecTypeOption, ScSpecTypeVec};

/// A primitive leaf selected by a random byte.
fn leaf(sel: u8) -> ScSpecTypeDef {
    match sel % 6 {
        0 => ScSpecTypeDef::U32,
        1 => ScSpecTypeDef::I32,
        2 => ScSpecTypeDef::Bool,
        3 => ScSpecTypeDef::Bytes,
        4 => ScSpecTypeDef::String,
        _ => ScSpecTypeDef::Void,
    }
}

/// Build a container chain `depth` levels deep, choosing Vec/Option/Map at each
/// level from `shape`, wrapping the `leaf`. Deliberately allows depths far beyond
/// any limit so the guards are actually exercised.
fn build_nested(depth: usize, shape: &[u8], leaf_sel: u8) -> ScSpecTypeDef {
    let mut t = leaf(leaf_sel);
    for i in 0..depth {
        let s = shape[i % shape.len()];
        t = match s % 3 {
            0 => ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                element_type: Box::new(t),
            })),
            1 => ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                value_type: Box::new(t),
            })),
            _ => ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
                key_type: Box::new(ScSpecTypeDef::U32),
                value_type: Box::new(t),
            })),
        };
    }
    t
}

/// Tear a nested type down iteratively.
///
/// `ScSpecTypeDef`'s derived `Drop` is recursive, so letting an absurdly deep
/// value fall out of scope would overflow the stack in the destructor — a Rust
/// language artifact, unrelated to the walkers under test (and impossible in
/// production, where the depth-bounded decoder never builds such a value). We
/// dismantle the chain in a loop so the test can push depth arbitrarily high.
fn dismantle(mut t: ScSpecTypeDef) {
    loop {
        t = match t {
            ScSpecTypeDef::Vec(b) => {
                let v = *b;
                *v.element_type
            }
            ScSpecTypeDef::Option(b) => {
                let o = *b;
                *o.value_type
            }
            ScSpecTypeDef::Map(b) => {
                let m = *b;
                dismantle(*m.key_type);
                *m.value_type
            }
            other => {
                drop(other);
                return;
            }
        };
    }
}

/// Minimal LEB128 encoder for WASM section sizes.
fn leb128(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// Wrap arbitrary bytes as a `contractspecv0` custom section in a valid module.
fn wrap_spec_section(data: &[u8]) -> Vec<u8> {
    let name = "contractspecv0";
    let mut payload = leb128(name.len());
    payload.extend(name.as_bytes());
    payload.extend_from_slice(data);

    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm.push(0x00);
    wasm.extend(leb128(payload.len()));
    wasm.extend(payload);
    wasm
}

proptest! {
    // Decode path: any random byte string returns Ok or Err, never panics/aborts.
    #[test]
    fn decode_random_bytes_never_aborts(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = extract_metadata_with_policy(&bytes, &ResourcePolicy::default());
    }

    // Decode path: random bytes framed as a real spec section (exercises the
    // concatenated-entry loop and the entry-count/length guards together).
    #[test]
    fn decode_random_spec_section_never_aborts(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let wasm = wrap_spec_section(&data);
        let _ = extract_metadata_with_policy(&wasm, &ResourcePolicy::default());
    }

    // Walk path: arbitrarily deep constructed types must return from every walker,
    // never overflow the stack. Depths reach 20_000 — ~150x the default budget.
    #[test]
    fn type_walk_never_aborts(
        depth in 0usize..20_000,
        shape in prop::collection::vec(any::<u8>(), 1..8),
        leaf_sel in any::<u8>(),
    ) {
        let t = build_nested(depth, &shape, leaf_sel);
        let policy = ResourcePolicy::default();

        // Rendering (bounded, fallible) and the infallible sentinel wrapper.
        let _ = try_type_to_string(&t, 0, policy.max_walk_depth);
        let _ = soroban_upgrade_safeguard::mapper::type_to_string(&t);

        // UDT-dependency extraction walks the same container nesting.
        let spec = ContractSpec::default();
        let mapper = LayoutMapper::new_with_policy(&spec, &policy);
        let _ = mapper.try_get_udt_dependencies(&t);

        // Iterative teardown (the value is too deep for recursive Drop).
        dismantle(t);
    }
}
