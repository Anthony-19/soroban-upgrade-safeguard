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
`.safeguard.toml` so it no longer fails the run. Matching is exact (by
`category` and `target`), and suppressed findings are still shown in the report,
marked `[SUPPRESSED]`:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2."
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

## How it Works

The tool parses the `contractspecv0` custom sections from both WASM files, decodes the XDR representations of the contract's interface, and performs a deep structural comparison. It builds a type dependency map to identify when a simple change in a shared struct might cascade into breaking multiple storage entries. When storage-schema manifests are supplied, the declared types are resolved into the same model and run through the same comparison.

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
