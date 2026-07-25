# Soroban Upgrade Safeguard Documentation

This document explains what Soroban Upgrade Safeguard does, how it works internally, and how to read its output. It is meant for contract authors who want to understand exactly why a given upgrade is flagged as safe or unsafe.

## Table of Contents

1. [Overview](#overview)
2. [Why Upgrade Safety Matters](#why-upgrade-safety-matters)
3. [What a Passing Verdict Guarantees](#what-a-passing-verdict-guarantees)
4. [Installation](#installation)
5. [Docker](#docker)
6. [Command Line Usage](#command-line-usage)
7. [How the Analysis Works](#how-the-analysis-works)
8. [Storage Schema Analysis](#storage-schema-analysis)
9. [Detection Categories](#detection-categories)
10. [Severity Levels](#severity-levels)
11. [Cascading Layout Breaks](#cascading-layout-breaks)
12. [Spec Entry Integrity and Duplicate Detection](#spec-entry-integrity-and-duplicate-detection)
13. [Reading the Report](#reading-the-report)
14. [Suppressing Known Breaking Changes](#suppressing-known-breaking-changes)
15. [Resource Limits and Hardening Against Malicious Input](#resource-limits-and-hardening-against-malicious-input)
16. [Exit Codes and CI Integration](#exit-codes-and-ci-integration)
17. [Limitations](#limitations)
18. [Migration Note](#migration-note)
19. [Frequently Asked Questions](#frequently-asked-questions)

## Overview

Soroban Upgrade Safeguard is a command line tool that compares two compiled Soroban contract builds (WASM files) and reports whether upgrading from the old build to the new build would introduce breaking changes. It focuses on three areas that commonly cause silent failures after a deployment:

- Storage layout of structs, enums, and unions
- Public function signatures
- Event schemas used by off-chain indexers

The tool reads the contract interface that the Soroban SDK embeds inside the compiled WASM, decodes it, and performs a deep structural comparison. It does not need source code, a running network, or any external service.

## Why Upgrade Safety Matters

On Stellar, a Soroban contract can be upgraded in place by swapping the WASM behind the same contract address. The contract keeps its existing on-chain storage entries across the upgrade. This is powerful, but it carries a risk: the new code must still be able to read data that the old code wrote.

Soroban serializes most user-defined types by field position rather than by field name. If the new version of a struct removes a field, reorders fields, or changes a field type, the bytes already stored on chain no longer match what the new code expects. The result is orphaned data, deserialization panics, or integrations that quietly read the wrong values.

These problems usually do not appear at compile time. They appear in production, after the upgrade is live and real data is involved. The goal of this tool is to surface those problems before you deploy.

## What a Passing Verdict Guarantees

This section is the most important one in this document. Read it before you treat a green run as permission to deploy.

By default, the tool reads only the `contractspecv0` custom section, which describes a contract's **callable surface**: its exported functions and the user-defined types those functions mention. Everything the tool says by default is a statement about that surface and nothing else.

**A passing run certifies:**

- No exported function was removed, and none changed its parameters or return types.
- No exported user-defined type changed in a way that breaks its layout.
- The environment metadata (`contractenvmetav0`) was compared.

**A passing run does NOT certify:**

- That the upgrade is **storage compatible**.
- That internal types serialized into persistent, instance, or temporary storage kept their layout.
- That storage-key types kept their discriminants, so existing entries still resolve.
- That function bodies behave the same way.

The reason for that gap is structural. Soroban storage compatibility is decided by the bytes a contract writes: the layout of the values it serializes into storage, and the discriminants of the types it builds storage keys from. Neither has to appear in `contractspecv0`. A type used only as a storage payload is invisible to the exported spec, so a contract can keep its public interface byte-identical while reordering the fields of an internal struct or shifting a storage-key discriminant. That is guaranteed data corruption on upgrade, and by default the tool cannot see it.

This is why the verdict vocabulary is deliberately bounded. A pass reads:

```
Status: ✅ PASSED (No exported-interface breaking changes)
Scope:  Exported interface + environment metadata only — storage layout is NOT verified by this result.
        Storage layout: NOT analyzed — no storage schema supplied.
```

"No exported-interface breaks" and "storage compatible" are different claims, and the tool only makes the first one unless you give it more to work with. To close the gap, supply a [storage schema](#storage-schema-analysis).

## Installation

Build and install the binary from the repository root:

```bash
cargo install --path .
```

This places a `soroban-upgrade-safeguard` binary on your Cargo bin path. You can also run it directly during development without installing:

```bash
cargo run -- <OLD_WASM> <NEW_WASM>
```

## Docker

Build the image from the repository root:

```bash
docker build -t soroban-upgrade-safeguard .
```

The build uses two stages: the first compiles a release binary using `rust:slim-bookworm`; the second copies only that binary into `debian:bookworm-slim`. The final image does not contain `cargo`, `rustc`, or `rustup`.

### Local mode

Mount a directory that contains your WASM files and pass the in-container paths as arguments:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm
```

All paths you pass must be paths inside the container. Use `--format` to choose a different output format:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm --format json
```

### RPC mode

```bash
docker run --rm \
  -v $(pwd)/path/to/new:/wasms \
  soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  /wasms/new.wasm
```

For local development against a local RPC node:

```bash
soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url http://localhost:8000 \
  --allow-http-local \
  new.wasm
```

To pin the expected on-chain WASM hash (CI/CD safety):

```bash
soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  --expected-wasm-hash a1b2c3d4e5f6... \
  new.wasm
```

### Suppression config

Mount the directory that contains `.safeguard.toml` and point to it with `--config`:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  -v $(pwd):/config \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm --config /config/.safeguard.toml
```

### CI example

The image preserves exit code semantics (0 = safe, 1 = critical findings). Use it directly as a pipeline step:

```yaml
- name: Check upgrade safety
  run: |
    docker run --rm \
      -v ${{ github.workspace }}/wasm:/wasms \
      soroban-upgrade-safeguard /wasms/on-chain.wasm /wasms/candidate.wasm
```

## Command Line Usage

The tool takes exactly two positional arguments: the path to the previous (on-chain) WASM and the path to the new (candidate) WASM.

```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
```

Example:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

The first argument should be the build that is currently deployed on chain. The second argument should be the build you intend to deploy. Order matters: the comparison is directional, because removing a field from the old version is treated differently from adding a field in the new version.

Common flags: `--format <text|json|markdown>`, `--explain`, `--strict`, `--config <PATH>`, and the resource-limit overrides `--max-xdr-depth`, `--max-xdr-len`, `--max-entries`, and `--max-walk-depth` (see [Resource Limits](#resource-limits-and-hardening-against-malicious-input)).

## How the Analysis Works

The analysis runs as a short pipeline. Each stage lives in its own module under `src/`.

1. **Load and validate (`loader.rs`).** Each file is read from disk and checked for the WASM magic header. The tool then walks every WASM payload to confirm the binary is structurally well formed before any deeper work happens. A corrupt or non-WASM file fails fast with a clear message.

   When the baseline is fetched from an RPC endpoint (`--contract-id` / `--rpc-url`), the loader applies a **zero-trust pipeline**: the URL is validated for transport security (HTTPS required unless `--allow-http-local` is set), the RPC response entries are checked for matching ledger keys, and the SHA-256 hash of the fetched bytecode is verified against the on-chain contract instance hash. An optional `--expected-wasm-hash` flag provides additional hash pinning.

2. **Extract metadata (`parser.rs`).** The Soroban SDK stores the contract interface in custom WASM sections. The parser scans for the `contractspecv0` section and decodes the concatenated XDR `ScSpecEntry` objects it contains. The `contractenvmetav0` section is captured as well for completeness.

3. **Build the spec model (`spec.rs`).** Decoded entries are sorted into a `ContractSpec`, which groups functions, structs, enums, unions, and error enums into separate maps keyed by name. This gives the comparison stage fast lookups by type name.

4. **Compare (`diff.rs`).** The old and new specs are compared item by item. Functions, structs, and enums are matched by name and then examined for the specific breaking changes described below. Every difference becomes a `Finding` with a severity and a category.

5. **Map dependencies (`mapper.rs`).** A `LayoutMapper` builds a reverse dependency graph over user-defined types. This is what lets the tool understand that a change to a small shared type can break every larger type that embeds it.

6. **Report (`report.rs`).** All findings are aggregated into a `SafetyReport`, grouped by category, counted by severity, and rendered as a colored summary. The overall run is considered safe only when there are zero critical findings.

Every report also carries an **analysis scope**, which records which of these dimensions actually ran. It is printed under the status line and exposed as a `scope` object in JSON, so neither a human nor a CI job has to guess how much a verdict covers.

## Storage Schema Analysis

A storage schema is an opt-in manifest in which you declare the types that actually govern your storage layout. It is the bridge between what the exported spec exposes and what determines on-chain compatibility.

### Why it is needed

Consider a lending contract that stores positions under a key enum `DataKey::Position(Address)` and serializes an internal struct `PositionState { collateral: i128, debt: i128 }`. Neither type is exported. An upgrade that swaps those two fields, or renames the key variant, leaves the public interface byte-identical. Without a schema the tool reports PASSED, and on deploy every stored position decodes with collateral and debt reversed while existing keys stop resolving.

Declaring those two types lets the tool diff them with the same engine and the same severities it already applies to exported types.

### Supplying a schema

A manifest describes the storage layout of **one build**. Detecting a reorder requires two snapshots, so you supply one manifest per side:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm \
  --old-storage-schema ./schemas/v1.storage-schema.toml \
  --new-storage-schema ./schemas/v2.storage-schema.toml
```

Both flags are required together. Supplying only one is an error, because a single snapshot cannot show a change. Keep the manifest versioned next to your contract and update it in the same commit that changes a storage type.

### Manifest format

TOML and JSON are both accepted with the same shape. A ready-to-copy template lives at [`.storage-schema.example.toml`](../.storage-schema.example.toml).

```toml
# Storage-key types: what addresses your entries.
[[storage_key]]
name = "DataKey"
kind = "union"             # "union" for data-carrying, "enum" for unit variants
durability = "persistent"  # persistent | instance | temporary (optional)

  [[storage_key.variant]]
  name = "Admin"           # void variant, no payload

  [[storage_key.variant]]
  name = "Position"
  type = ["Address"]       # tuple payload types, in order

# Internal value types: what you serialize into those entries.
[[value_type]]
name = "PositionState"
kind = "struct"
durability = "persistent"

  [[value_type.field]]
  name = "collateral"
  type = "i128"

  [[value_type.field]]
  name = "debt"
  type = "i128"
```

A unit enum declares explicit discriminants instead of variants:

```toml
[[value_type]]
name = "Status"
kind = "enum"

  [[value_type.case]]
  name = "Active"
  value = 0

  [[value_type.case]]
  name = "Paused"
  value = 1
```

**Declaration order is layout order.** Soroban serializes struct fields and union variants positionally, so the order you write them in is the order stored on chain. Write them in the order your Rust type declares them. For a unit enum the `value` is the discriminant that is actually written, so order in the file does not matter but the numbers do.

### Type spelling

Type strings use the same Rust-like spelling the report prints, so a type named in a finding can be pasted straight back into a manifest.

| Spelling | Meaning |
| :--- | :--- |
| `bool`, `u32`, `i32`, `u64`, `i64`, `u128`, `i128`, `u256`, `i256` | scalars |
| `Bytes`, `String`, `Symbol`, `Address`, `Timepoint`, `Duration` | built-ins |
| `Val`, `Error`, `()` | raw value, error, void |
| `Option<T>`, `Vec<T>`, `Map<K, V>`, `Result<T, E>` | containers |
| `BytesN<32>` | fixed-length bytes |
| `(Address, u32)` | tuple |
| `PositionState` | a user-defined type, exported or declared in the manifest |

### Validation and reconciliation

A manifest is a safety input, so it is validated strictly rather than interpreted loosely. Unknown keys, a `kind` that does not match the member table supplied, duplicate fields, two enum cases sharing a discriminant, and unparseable type strings are all hard errors. A typo fails loudly instead of silently narrowing coverage.

Each manifest is also reconciled against its own build's exported spec. A declared type that the spec has never heard of is fine, since that is precisely the internal-type case the manifest exists for. But when a declared name **is** exported, the two must agree on field order, field types, variant order, payloads, and discriminants. Disagreement stops the run:

```
Error: Storage schema for the old build disagrees with that build's exported contract spec

Caused by:
    struct 'ConfigData': field at position 0 is declared as 'threshold' but the old build
    exports 'admin' there. Field order is layout, so this disagreement cannot be reconciled
    automatically.
```

This is deliberate. A manifest that contradicts the contract is more dangerous than no manifest, because it would certify a layout the contract does not use.

### How storage findings are reported

Storage findings reuse the exported-interface categories behind a `Storage ` prefix, and each message is qualified with the declared role and durability:

```
--- [STORAGE STRUCT FIELD REORDERED] ---
🔴 [declared storage value (persistent)] Struct 'PositionState': field at position 0 changed
   from 'collateral' to 'debt'. Positional serialization breaks layout compatibility.
```

Severities match the exported rules with one deliberate exception. Appending a field is a **Warning** for a storage value, because existing entries still decode for the fields that were already there and only need a migration or default. The same append to a storage **key** is **Critical**, because a key's bytes are the address of every entry written under it, so changing its shape orphans all existing data.

When a schema is analyzed, the verdict widens but stays bounded:

```
Status: ✅ PASSED (No exported-interface or declared-storage breaks)
Scope:  Exported interface + environment metadata, plus a declared storage schema
        (1 key type(s), 1 value type(s)). Storage coverage is limited to the declared types.
```

Storage findings count toward `is_safe` and therefore toward the exit code, so a declared-layout break blocks a deployment exactly as an exported break does.

### Coverage limits

Coverage is bounded by what you declare. A storage type you forget to declare is not analyzed, and the report does not pretend otherwise. If a declaration references a type that is neither declared in the manifest nor exported by the contract, that dangling reference is reported as an informational finding rather than quietly skipped.

Storage schemas apply to a single contract pair and are refused in batch mode, since one manifest cannot describe several different contracts.

## Detection Categories

The comparison stage looks for the following classes of change.

### Functions

- **Function Removed.** A function that existed in the old build is gone in the new build. Existing callers and dependent contracts will break. Critical.
- **Function Signature Changed.** The number of parameters changed. Critical.
- **Parameter Type Changed.** A parameter kept its position but changed type. Critical.
- **Parameter Renamed.** A parameter changed name but kept its type. This is a warning, since positional encoding still matches but client code referring to the name may need updates.
- **Return Type Changed.** The count or type of return values changed. Critical.
- **Function Added.** A new function appears in the new build. Informational.

### Structs

- **Struct Removed.** A struct present in the old build is missing. Any storage entry of that type becomes unreadable. Critical.
- **Struct Field Removed.** A named field disappeared. Critical.
- **Struct Field Reordered.** The field at a given position now has a different name, which means the positional layout shifted. Critical.
- **Struct Field Type Changed.** A field kept its name and position but changed type. Critical.
- **Struct Field Added.** A new field was appended after the existing fields. This is a warning rather than a critical issue, because appended fields do not move existing fields, but old storage entries will lack the value, so a migration or default must be in place.
- **Struct Added.** A brand new struct. Informational.

### Enums

- **Enum Removed.** An enum is gone. Critical.
- **Enum Case Removed.** A variant disappeared, so stored values using it become invalid. Critical.
- **Enum Case Value Changed.** A variant kept its name but its integer value changed, which breaks serialization. Critical.
- **Enum Case Added.** A new variant. Informational.

### Events

Soroban does not mark event types explicitly in the spec, so the tool uses a naming heuristic: any user-defined type whose name contains the word `event` (case insensitive) is treated as an event type. When such a type changes, the same struct and enum checks apply but the findings are labeled with event-specific categories such as **Event Schema Removed** or **Event Enum Case Value Changed**. This matters because off-chain indexers and subscribers depend on a stable event shape, and a change that is merely awkward for storage can be fully breaking for an indexer.

## Severity Levels

Every finding carries one of three severity levels.

- **Critical.** A change that will cause data corruption, serialization panics, or broken integrations. The presence of any critical finding marks the whole run as unsafe. Do not deploy.
- **Warning.** A change that may affect external systems or requires a migration step, but does not by itself corrupt local storage. Appended struct fields and parameter renames fall here.
- **Info.** A non-breaking, additive change recorded for visibility, such as a new function or a new enum case.

## Cascading Layout Breaks

The most subtle failures come from shared types. Suppose a small struct named `Money` is used as a field inside `Account`, and `Account` is used inside `Ledger`. If you change `Money`, the stored bytes for every `Account` and every `Ledger` are now wrong, even though you never touched those larger types directly.

To catch this, `mapper.rs` builds a reverse dependency graph: for each user-defined type, it records which other types embed it. After the direct comparison finds the set of types with critical changes, `diff.rs` walks that graph outward and marks every dependent type as broken too, transitively. These appear in the report under the **Cascading Layout Break** category, naming both the affected parent type and the underlying modified type that caused the break. Cyclic type references are handled safely so the walk always terminates.

## Spec Entry Integrity and Duplicate Detection

WASM binaries are permitted to carry more than one custom section with the same name. The Soroban toolchain typically emits a single `contractspecv0` section, but a crafted or malformed build can contain multiple. The parser concatenates entries from all `contractspecv0` sections in order, and then `spec.rs` checks for duplicate names within each kind (function, struct, enum, union, error enum).

### Why duplicates are a soundness problem

If two sections define the same type name differently, the analysis model contains the first definition it encountered. Any subsequent conflicting definition is discarded from the model. This creates a gap: the definition the tool analyzes may not be the one the contract actually uses. An attacker who controls section ordering can steer the tool to analyze a benign definition while the real, breaking one is ignored. The upgrade appears safe; in production it corrupts data.

### Detection policy

The tool compares every pair of definitions that share a name and kind using their serialized XDR bytes:

- **Conflicting duplicates** (same name, different bytes) produce a **`Spec Entry Conflict`** finding at `Critical` severity. The run is marked `is_safe: false` and exits with code 1. This is true regardless of which side carries the duplicate (old or new) and regardless of whether `--compat-duplicates` is set.

- **Identical duplicates** (same name, byte-identical bytes) produce a **`Spec Entry Duplicate`** finding. The severity depends on the mode:
  - **Default mode**: `Warning`. The WASM is non-canonical and the condition is suspicious.
  - **Compat mode** (`--compat-duplicates`): `Info`. Legitimate toolchains that historically emit split sections with identical entries can set this flag to suppress the warning without hiding genuine conflicts.

The first encountered definition is always the one used for comparison. The policy is deterministic and independent of `HashMap` iteration order.

### JSON fields

The `scope` object in JSON output always reflects the duplicate status:

```json
{
  "scope": {
    "old_spec_section_count": 2,
    "new_spec_section_count": 1,
    "old_duplicate_names": ["Ledger"],
    "new_duplicate_names": []
  }
}
```

`old_spec_section_count` and `new_spec_section_count` give the raw number of `contractspecv0` sections found in each binary. `old_duplicate_names` and `new_duplicate_names` list every entry name that appeared more than once (across all kinds), sorted for stable output. These fields are always present; the name lists are omitted from JSON when empty.

### Compat mode

Some older SDK versions emit two `contractspecv0` sections with identical entries. To handle those WASMs without failing, pass `--compat-duplicates`:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --compat-duplicates
```

In compat mode, identical duplicates become informational and no longer cause a `Warning`. Conflicting duplicates remain `Critical` regardless — a difference in definitions cannot be safely ignored in any mode.

### Coverage

Duplicate detection covers all five spec entry kinds: functions, structs, enums, unions, and error enums. Provenance (which section each entry came from, zero-indexed) is tracked through decoding and reported in every finding message and in the `scope` JSON so an operator can identify exactly which sections are involved.

## Zero-Trust RPC Baseline Retrieval

When using `--contract-id` and `--rpc-url` to fetch the on-chain baseline, the tool implements a **zero-trust pipeline** that protects against malicious or compromised RPC endpoints:

### Cryptographic Hash Verification

After fetching the contract bytecode from the RPC, the tool computes its SHA-256 hash and compares it against the hash stored in the contract instance's `ContractExecutable::Wasm` entry. If the hashes do not match — indicating tampered bytecode — execution aborts immediately with an `IntegrityError[HashMismatch]`.

### Defensive Key Matching

Every entry returned by `getLedgerEntries` is validated against the expected ledger key:

- The RPC response entry's `key` field must match the XDR-base64 encoding of the ledger key that was requested.
- Empty entry arrays are rejected.
- Duplicate entries (multiple responses sharing the same key) are rejected as possible RPC manipulation.
- Missing `key` or `xdr` fields in any entry are rejected.

This replaces the insecure `entries[0]` pattern that previously trusted the RPC to return the correct entry.

### StellarAsset Handling

Contracts that are built-in `StellarAsset` contracts (which have no WASM bytecode) are detected upfront with a clear error message rather than producing confusing downstream failures.

### Transport Security

- By default, only `https://` URLs are accepted for RPC connections.
- The `--allow-http-local` flag permits `http://` connections exclusively to `localhost` or `127.0.0.1` for local development.
- Remote HTTP URLs are rejected even when `--allow-http-local` is set.
- Redirect following is disabled in the HTTP client to prevent HTTPS-to-HTTP downgrade attacks.

### Expected Hash Pinning

The optional `--expected-wasm-hash <HEX>` flag lets callers pin the expected on-chain WASM hash. After the RPC fetch completes and the hash is verified against the instance entry, the tool also compares it against this user-supplied value. A mismatch fails immediately, providing an additional integrity check for CI/CD pipelines that know the expected deployment hash ahead of time.

### IntegrityError Types

| Error | Cause |
|-------|-------|
| `IntegrityError[HashMismatch]` | The SHA-256 of the fetched bytecode does not match the hash in the contract instance entry |
| `IntegrityError[KeyMismatch]` | The ledger key in the RPC response does not match the requested key |

### Report Metadata

When the baseline is fetched from RPC, the report includes:

- `baseline_source`: Set to `"RPC"` (or `"Local File"` for disk-based comparisons).
- `verified_code_hash`: The verified SHA-256 hash of the on-chain WASM, expressed as a hex string.

These fields appear in the JSON output (`--format json`) and in the text/Markdown summaries:

```bash
soroban-upgrade-safeguard --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  --format json \
  new.wasm
```

Example JSON excerpt:

```json
{
  "baseline_source": "RPC",
  "verified_code_hash": "a1b2c3d4e5f6..."
}
```

## Reading the Report

A run prints a header for each loaded contract with a one line summary of how many functions, structs, enums, unions, and error enums it contains. It then prints the safety report.

The report begins with an overall status line that is either passed or failed, followed by counts of critical, warning, and info findings. Below that, findings are grouped by category, sorted for stable output, and each line is prefixed with a colored marker that maps to its severity. When the run fails, a closing action-required notice explains the practical consequences of deploying anyway.

If the two contracts have identical exports and types, the report states that no relevant changes were detected and the run passes.

## Suppressing Known Breaking Changes

Sometimes a breaking change is deliberate and already accounted for — a planned
storage migration, a re-initialization gated behind an admin call, or a
deprecated function dropped on purpose. A suppression config lets a team
whitelist specific, reviewed findings so they no longer fail the run, while
keeping them visible in the report as explicitly acknowledged.

### Config file

By default the tool looks for `.safeguard.toml` in the current directory. You
can point at a different file with `--config <PATH>`:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm --config .safeguard.toml
```

If no `--config` is given and `.safeguard.toml` is absent, nothing is
suppressed and the tool behaves exactly as it always has. If you pass
`--config` explicitly and the file is missing or malformed, that is a hard
error rather than a silent no-op, so a typo never quietly disables suppression.

Each `[[suppress]]` entry acknowledges exactly one finding using the secure, content-bound format:

```toml
max_suppressions = 10
allow_targetless = false

[[suppress]]
category    = "Struct Field Removed"
target      = "ConfigData.threshold"
author      = "Alice <alice@example.com>"
reason      = "Planned storage migration in v2 drops the unused threshold field."
expiry      = "2026-12-31"
fingerprint = "8a3f..." # SHA-256 hex fingerprint
```

A ready-to-copy template lives at [`.safeguard.example.toml`](../.safeguard.example.toml).

### How matching works

Matching is **exact**: a rule applies only when its `category`, `target`, and `fingerprint` equal the finding's values:

- **Category & Target**: matched verbatim.
- **Fingerprint**: calculated as the SHA-256 hex hash of:
  `category:<category>\ntarget:<target_or_empty>\nmessage:<normalized_message>`
  where `<normalized_message>` has all consecutive whitespace collapsed to single spaces and leading/trailing whitespace removed. If the finding content changes or drifts, the fingerprint will mismatch and suppression stops applying.
- **Expiry**: evaluated against the current system date (`YYYY-MM-DD`). Expired rules trigger a hard failure during config loading.
- **Targetless Wildcards**: omitting `target` matches only targetless findings (e.g., `Environment`). This requires explicit opt-in (`allow_targetless = true`) and is capped at a ceiling of 3 rules.

### Legacy Format & Migration

For backwards compatibility, old-format rules (lacking `author`, `expiry`, or `fingerprint`) will trigger a warning on `stderr` during execution for one release before becoming a hard error. To migrate an old rule:
1. Run `soroban-upgrade-safeguard` with `--format json`.
2. Copy the finding's `category` and `target`.
3. Add `author`, `reason`, `expiry` (`YYYY-MM-DD`), and compute or copy the `fingerprint`.

### What suppression does and does not change

A suppressed finding is **not hidden**. It is still listed in the report, marked `[SUPPRESSED]`, and prominently summarized in the Applied Suppressions Audit Log in text and Markdown outputs. In JSON output, suppressed findings carry `"suppressed": true`, along with `suppression_reason`, `suppression_author`, `suppression_expiry`, and `suppression_fingerprint`.

If any Critical findings are suppressed and the gate passes, a prominent **Security Notice** warning is printed on `stderr` at exit.

## Resource Limits and Hardening Against Malicious Input

The tool runs as a CI gate and, in RPC mode, decodes WASM fetched for an arbitrary
contract ID. The input WASM and its embedded `contractspecv0` / `contractenvmetav0`
sections are therefore treated as **adversarial**. Without bounds, a crafted section
could declare an enormous vector length (a multi-gigabyte allocation) or nest a type
to arbitrary depth (a native stack overflow that aborts the process). A gate that can
be crashed on demand is a gate that can be bypassed.

A single resource policy is threaded through every decode and every recursive type
walk. Four limits, each independently configurable:

| Limit | Default | Bounds |
| :--- | :--- | :--- |
| `max_xdr_depth` | 64 | XDR recursion depth per entry. Guards against stack overflow at decode time. |
| `max_xdr_len` | 33554432 (32 MiB) | Bytes decoded per custom section — shared across every entry in the section, so it also caps the total decoded bytes. Guards against oversized-length allocations. |
| `max_entries` | 100000 | Decoded spec entries, **summed across all `contractspecv0` sections** (a module may carry more than one). Env-metadata entries are budgeted separately. |
| `max_walk_depth` | 128 | Recursion depth for the type walkers — structural equality, finding-message rendering, and cascade detection — which operate on already-decoded types. |

The distinction between `max_xdr_len` (a **per-section byte cap**) and `max_entries`
(a **cross-section count cap**) matters: many individually valid sections cannot be
summed to exhaust memory, and a single section cannot over-allocate before the entry
cap trips.

### Configuring limits

Set a `[limits]` table in `.safeguard.toml` (the same file used for suppressions).
Every field is optional; an omitted field keeps the default:

```toml
[limits]
max_xdr_depth  = 128
max_xdr_len    = 67108864   # 64 MiB
max_entries    = 200000
max_walk_depth = 256
```

Or override any single limit for one run with a flag. Precedence is **flags > file >
defaults**:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --max-xdr-depth 128 --max-walk-depth 256
```

The defaults accept every fixture and a representative corpus of real mainnet specs.
Raise a limit only if a legitimate, unusually large contract is rejected.

### Behavior when a limit is exceeded

An input that exceeds a limit is rejected with a controlled, typed error and the CLI
exits with **code 2** — distinct from `1` (breaking changes) so a pipeline can tell
"the input was rejected as adversarial" apart from "the upgrade is unsafe". The
process never aborts with a stack overflow or an out-of-memory kill.

In **batch mode**, the policy is enforced **per pair**: a pair that trips a limit (or
otherwise errors) fails only that pair and is reported as errored — the rest of the
run continues rather than aborting. The overall run then exits `2` if any pair hit a
limit, else `1` if any pair had breaking changes, else `0`.

## Exit Codes and CI Integration

The tool is designed to drop into a continuous integration pipeline.

- Exit code `0`: no critical findings. The upgrade is considered safe to deploy.
- Exit code `1`: at least one critical finding, or a fatal error such as a missing or malformed WASM file.
- Exit code `2`: a resource limit was exceeded on untrusted input (see [Resource Limits](#resource-limits-and-hardening-against-malicious-input)). Raise the relevant limit to proceed.

Because the process exits non-zero on critical findings, you can gate a deployment job on it directly:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm
```

If that command fails, the pipeline stops before the upgrade is published.

## Limitations

- **Storage layout is only analyzed when you declare it.** Without a storage schema, the tool sees only the exported interface and says so explicitly in every format. With one, coverage extends exactly as far as the types you declared and no further.
- **The schema is a declaration, not a measurement.** The tool trusts what you declare, after checking it does not contradict the exported spec. It does not read the compiled code to confirm that the declared types are the ones actually written to storage. Keeping the manifest truthful is the team's responsibility, in the same way a type signature is.
- Storage access patterns are not extracted from the WASM code section. A future change could infer storage writes and key construction statically, which would remove the need to declare them by hand. That work is deliberately out of scope here.
- Event detection relies on a name heuristic. A type that represents an event but does not contain `event` in its name will be analyzed as an ordinary struct or enum.
- The tool reasons about the declared interface in the spec sections. It does not analyze the function bodies, so a change in internal logic that keeps the same interface is invisible to it.
- Appended struct fields on values are reported as warnings rather than errors. Whether they are truly safe depends on having a migration or default in place, which the tool cannot verify.
- Comparison is by name. Renaming a type is seen as removing the old name and adding a new one, not as a rename.
- Storage schemas are not supported in batch mode, because a manifest describes one specific contract's layout.

## Migration Note

This release changes the wording of the verdict and adds a new optional input. Nothing you already run breaks, but two things look different.

### The verdict wording changed

The status line is now explicit about the scope it covers.

| Before | After |
| :--- | :--- |
| `✅ PASSED (No breaking changes detected)` | `✅ PASSED (No exported-interface breaking changes)` |
| `❌ FAILED (Critical breaking changes detected)` | `❌ FAILED (Exported-interface breaking changes detected)` |

When a storage schema is supplied, the passing wording widens to `✅ PASSED (No exported-interface or declared-storage breaks)`.

The old wording was not inaccurate about what had been checked, but it implied a broader guarantee than the analysis supported. A reader could reasonably take "no breaking changes detected" to mean "safe to upgrade", including storage. It did not mean that, and it never had. The new wording states the boundary instead of leaving it to be inferred, and every format now carries a scope line saying whether storage layout was analyzed.

**If you match on output text**, update any assertion on the old status strings. The severity counts, category names, `is_safe`, and exit-code semantics are unchanged, so tooling that keys on those needs no changes.

### JSON gained scope fields

Two additive fields appear at the top level. Existing fields are untouched, so consumers that ignore unknown keys need no changes.

```json
{
  "is_safe": true,
  "certifies": "Exported interface + environment metadata only — storage layout is NOT verified by this result.",
  "scope": {
    "exported_interface_analyzed": true,
    "env_metadata_analyzed": true,
    "storage_layout_analyzed": false,
    "summary": "..."
  }
}
```

If your pipeline treats `is_safe: true` as "storage compatible", check `scope.storage_layout_analyzed` as well. When it is `false`, storage was not examined at all. When it is `true`, `storage_key_types` and `storage_value_types` report how many declared types were covered.

### The new storage-schema input

`--old-storage-schema` and `--new-storage-schema` are optional. Omitting them reproduces the previous behavior exactly, now with honest scope reporting. Adopting them is incremental: declare your storage-key types and the internal types you serialize into storage, starting with the ones holding value-bearing data. Partial coverage is genuinely useful, and the report always states how far it reached. See [Storage Schema Analysis](#storage-schema-analysis) for the format.

## Frequently Asked Questions

**Does the tool need access to the Stellar network?**
No. It works entirely from the two local WASM files.

**Can I run it on contracts built by tools other than the standard Soroban SDK?**
It works on any WASM that embeds a standard `contractspecv0` custom section. If that section is missing, there is nothing to compare and the spec will appear empty.

**Why is an appended field only a warning?**
Appending a field does not move existing fields, so old data still deserializes for the fields that were already there. The new field, however, has no stored value in old entries, so you need a migration or a default. The tool flags this so you remember to handle it. Note that appending to a declared storage **key** is Critical rather than a warning, because it changes the address of every entry.

**What counts as a safe upgrade?**
Any run that finishes with zero critical findings, *within the scope that was analyzed*. Warnings and info findings are worth reviewing but do not block deployment. Read [What a Passing Verdict Guarantees](#what-a-passing-verdict-guarantees) before treating a pass as storage compatibility.

**Does a green run mean my upgrade is storage safe?**
Not on its own. By default the tool analyzes only the exported interface, and it says so in the report. Storage layout is analyzed only when you supply a [storage schema](#storage-schema-analysis), and then only for the types you declared.

**Do I have to declare every storage type?**
No. Partial coverage is useful and the report always states how far the analysis reached. Start with your storage-key types and the internal types that hold value-bearing data, since those are where a silent layout change is most costly.

**Why do I need two schema files instead of one?**
A layout change is only observable as a difference between two snapshots. One file describes one build, so detecting that a field moved requires the layout before and after. Keeping the manifest in version control means you usually already have both.

For guidance on contributing changes to this tool, see [contributing.md](contributing.md).
