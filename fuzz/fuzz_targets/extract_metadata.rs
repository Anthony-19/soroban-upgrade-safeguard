#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_upgrade_safeguard::parser::extract_metadata;

// Property: `extract_metadata` must return `Ok` or `Err` on ANY input — never
// panic, never hang, never blow up memory.
//
// It runs a full WASM parse followed by the concatenated-XDR decode loop on
// input the tool does not control (in RPC mode the bytes are fetched from a
// remote endpoint), so robustness here is a security property. The default
// `ResourcePolicy` bounds allocation, and libFuzzer's timeout enforces the
// no-hang half of the property.
fuzz_target!(|data: &[u8]| {
    let _ = extract_metadata(data);
});
