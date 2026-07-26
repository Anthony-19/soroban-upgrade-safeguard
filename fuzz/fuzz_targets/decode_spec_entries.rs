#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_upgrade_safeguard::parser::decode_spec_entries;

// Property: the hand-written XDR cursor-advance loop must terminate and never
// panic on arbitrary bytes.
//
// Feeding `decode_spec_entries` directly bypasses the WASM wrapper, so the loop
// is exercised without first constructing a valid module — the point of issue
// #129. Loop termination relies on the cursor position strictly advancing each
// iteration; a decode that consumed zero bytes would spin forever, so libFuzzer's
// timeout is what guards that invariant, while this harness guards "never panic".
fuzz_target!(|data: &[u8]| {
    let _ = decode_spec_entries(data);
});
