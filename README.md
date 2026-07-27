# Soroban Upgrade Safeguard 🛡️

![Soroban Upgrade Safeguard Demo](assets/demo.png)

A powerful CLI tool to analyze and validate Soroban smart contract upgrades on the Stellar network. It detects breaking changes in storage layout, function signatures, and event schemas before you deploy.

> **What a pass means.** By default the tool analyzes the exported `contractspecv0` interface and environment metadata. A passing run certifies that the callable surface did not break. It does **not** by itself certify storage compatibility, because internal storage types and storage-key discriminants need not appear in the exported spec. To cover those, supply a [storage schema](#storage-layout-analysis). Every report states which scope it actually analyzed.

## Features

- **Bounded, Honest Verdicts**: The report says exactly what was analyzed and what was not, in text, JSON, and Markdown, so a green result is never mistaken for a broader guarantee than it is.
- **Storage Schema Analysis**: Declare your storage-key types and internal value types in a manifest, and they are diffed with the same engine and severities as exported types, catching layout breaks that are invisible in the public interface.
- **Storage Layout Protection**: Detects field removals, reorderings, and type changes in structs and enums that would corrupt on-chain data.
- **Function Signature Validation**: Flags changes in function names, parameters, and return types that break integration with existing clients/contracts.
- **Event Schema Analysis**: Heuristically identifies event-related types and ensures their structure remains backwards compatible for indexers.
- **Cascading Break Detection**: Uses dependency graphing to track how a change in a low-level type affects all parent structures.
- **Rich CLI Output**: Beautiful, color-coded reports with actionable severity levels (Critical, Warning, Info).
- **CI/CD Friendly**: Exits with a non-zero code if critical breaking changes are detected.
- **Suppression Config**: Acknowledge known, intentional breaking changes (e.g. a planned migration) in a `.safeguard.toml` so they no longer fail the run — while still listing them in the report.
- **Hardened Against Malicious Input**: The WASM and its embedded XDR are treated as untrusted. Configurable resource limits bound decode depth, decoded byte length, entry count, and type-walk depth, so a crafted contract cannot crash the gate with an out-of-memory allocation or a stack overflow.

## Installation

```bash
cargo install --path .
```

## Usage

Compare two WASM contract builds to see if the upgrade is safe:

```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
```

### Example

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

### Suppressing known breaking changes

If a breaking change is deliberate and already accounted for, list it in a
`.safeguard.toml` so it no longer fails the run. Rules require explicit `author`,
`reason`, expiry date (`YYYY-MM-DD`), and SHA-256 content `fingerprint` binding.
Matching is exact (by `category`, `target`, and `fingerprint`), and suppressed
findings are prominently audited in report outputs:

```toml
max_suppressions = 10
allow_targetless = false

[[suppress]]
category    = "Struct Field Removed"
target      = "ConfigData.threshold"
author      = "Alice <alice@example.com>"
reason      = "Planned storage migration in v2."
expiry      = "2026-12-31"
fingerprint = "8a3f..."  # SHA-256 hex of category + target + normalized message
```

The tool auto-loads `.safeguard.toml` from the current directory, or use
`--config <PATH>` to point at another file. See
[`.safeguard.example.toml`](.safeguard.example.toml) for a documented template
and the [documentation](docs/documentation.md#suppressing-known-breaking-changes)
for the full `target` convention.

### Storage layout analysis

The exported spec describes a contract's callable surface, not what it writes to storage. A contract can keep its public interface byte-identical while reordering the fields of an internal struct or shifting a storage-key discriminant, which corrupts every existing entry on upgrade.

Declare those types in a storage-schema manifest and they get diffed like any other type:

```toml
[[storage_key]]
name = "DataKey"
kind = "union"
durability = "persistent"

  [[storage_key.variant]]
  name = "Admin"

  [[storage_key.variant]]
  name = "Position"
  type = ["Address"]

[[value_type]]
name = "PositionState"
kind = "struct"

  [[value_type.field]]
  name = "collateral"
  type = "i128"

  [[value_type.field]]
  name = "debt"
  type = "i128"
```

A manifest describes one build, so pass one per side:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm \
  --old-storage-schema ./schemas/v1.toml \
  --new-storage-schema ./schemas/v2.toml
```

Declaration order is layout order. A reorder, an insertion, or a shifted discriminant is reported Critical and fails the run. See
[`.storage-schema.example.toml`](.storage-schema.example.toml) for a documented
template and the
[documentation](docs/documentation.md#storage-schema-analysis) for the full
format.

#### Security Model & Trust Implications

> [!WARNING]
> By default, the gate loads `.safeguard.toml` from the current working directory.
> Anyone with write access to the repository (such as PR contributors in CI)
> can modify `.safeguard.toml` to neutralize Critical finding gates.
> 
> To secure your pipeline:
> - Require mandatory code owners review for `.safeguard.toml`.
> - Or pass `--config <PATH>` pointing to a read-only, privileged path.
> - Wildcard/targetless rules require explicit opt-in (`allow_targetless = true`) capped at a ceiling of 3.
> - Expired rules or exceeding `max_suppressions` will cause hard load-time failures.

### Resource limits (untrusted input)

The tool runs as a CI gate and, in RPC mode, decodes WASM fetched for an arbitrary
contract ID — so the input and its embedded XDR are treated as **adversarial**. A
central resource policy bounds every decode and every recursive type walk. When an
input exceeds a limit, the run stops with a **controlled error and exit code 2**
(distinct from `1` = breaking changes), never a crash.

| Limit | Default | What it caps |
| :--- | :--- | :--- |
| `max_xdr_depth` | 64 | XDR nesting depth per entry (stack-overflow guard) |
| `max_xdr_len` | 33554432 (32 MiB) | Bytes decoded per custom section (allocation guard) |
| `max_entries` | 100000 | Decoded spec entries, summed across all sections |
| `max_walk_depth` | 128 | Recursive type-walk depth (equality, rendering, cascade detection) |

Defaults comfortably accept every real spec while blocking pathological input. To
raise a limit, set it in a `[limits]` table in `.safeguard.toml`:

```toml
[limits]
max_xdr_depth  = 128
max_xdr_len    = 67108864   # 64 MiB
max_entries    = 200000
max_walk_depth = 256
```

…or override any of them for a single run with a flag (flags win over the file):

```bash
soroban-upgrade-safeguard old.wasm new.wasm --max-xdr-depth 128 --max-walk-depth 256
```

In batch mode a pair that trips a limit fails **only that pair** — the rest of the
run continues — and the overall run exits `2` if any pair hit a limit.

### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Safe — no critical findings (or all suppressed). |
| `1` | Breaking changes detected, or a generic error (missing/malformed file). |
| `2` | A resource limit was exceeded on untrusted input (raise the relevant limit to proceed). |

## How it Works

The tool parses the `contractspecv0` and `contractenvmetav0` custom sections from both WASM files, decodes the XDR representations, and performs a deep structural comparison across **functions, structs, enums, unions, and error enums**. It also compares the environment metadata for protocol and SDK version changes. It builds a type dependency map to identify when a simple change in a shared type might cascade into breaking multiple storage entries. When storage-schema manifests are supplied, the declared types are resolved into the same model and run through the same comparison.

## Severity Levels

- **🔴 CRITICAL**: Breaking changes that WILL cause data corruption, serialization panics, or broken integrations. **Do not deploy.**
- **🟡 WARNING**: Changes that might affect external systems but won't necessarily corrupt local storage (e.g., adding elective parameters if supported).
- **🔵 INFO**: Informational logs about additions or non-breaking modifications.

## Documentation

More detailed guides live in the [docs](docs/) folder:

- [Documentation](docs/documentation.md): full explanation of how the analysis pipeline works, [what a passing verdict guarantees](docs/documentation.md#what-a-passing-verdict-guarantees), the [storage-schema format](docs/documentation.md#storage-schema-analysis), every detection category, severity levels, cascading layout breaks, CI integration, and a [migration note](docs/documentation.md#migration-note) for the verdict wording change.
- [Contributing](docs/contributing.md): development setup, project structure, testing, and how to add new detection rules.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
