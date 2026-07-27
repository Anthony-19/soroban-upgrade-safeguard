# Soroban Upgrade Safeguard 🛡️

[![CI](https://github.com/ShippedLabs/soroban-upgrade-safeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ShippedLabs/soroban-upgrade-safeguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Soroban Upgrade Safeguard Demo](assets/demo.png)

A powerful CLI tool to analyze and validate Soroban smart contract upgrades on the Stellar network. It detects breaking changes in storage layout, function signatures, and event schemas before you deploy.

> **What a pass means.** By default the tool analyzes the exported `contractspecv0` interface and environment metadata. A passing run certifies that the callable surface did not break. It does **not** by itself certify storage compatibility, because internal storage types and storage-key discriminants need not appear in the exported spec. To cover those, supply a [storage schema](#storage-layout-analysis). Every report states which scope it actually analyzed.

## Features

- **Bounded, Honest Verdicts**: The report says exactly what was analyzed and what was not, in text, JSON, and Markdown, so a green result is never mistaken for a broader guarantee than it is.
- **Storage Schema Analysis**: Declare your storage-key types and internal value types in a manifest, and they are diffed with the same engine and severities as exported types, catching layout breaks that are invisible in the public interface.
- **Storage Layout Protection**: Detects field removals, reorderings, and type changes in structs and enums that would corrupt on-chain data.
- **Function Signature Validation**: Flags changes in function names, parameters, and return types that break integration with existing clients/contracts.
- **Rename Detection**: Matches types structurally, not just by name, so renaming a type is reported as a rename rather than a spurious delete-plus-add — and an unrelated type reusing an old name is not mistaken for it.
- **Event Schema Analysis**: Types you declare as events in `[classification]` get indexer-focused findings and remediation. Classification is explicit, never inferred from the name, and never affects suppression keys.
- **Cascading Break Detection**: Uses dependency graphing to track how a change in a low-level type affects all parent structures.
- **Rich CLI Output**: Beautiful, color-coded reports with actionable severity levels (Critical, Warning, Info).
- **CI/CD Friendly**: Exits with a non-zero code if critical breaking changes are detected.
- **Suppression Config**: Acknowledge known, intentional breaking changes (e.g. a planned migration) in a `.safeguard.toml` so they no longer fail the run — while still listing them in the report.
- **Hardened Against Malicious Input**: The WASM and its embedded XDR are treated as untrusted. Configurable resource limits bound decode depth, decoded byte length, entry count, and type-walk depth, so a crafted contract cannot crash the gate with an out-of-memory allocation or a stack overflow.

## Installation

Install the latest published version from [crates.io](https://crates.io/crates/soroban-upgrade-safeguard):

```bash
cargo install soroban-upgrade-safeguard
```

Or install from a local checkout:

```bash
cargo install --path .
```

## Docker

You can use the published container image from the GitHub Container Registry without installing a Rust toolchain. Images are published on version tags (e.g. `v0.1.0`) for pinning in CI/CD pipelines, as well as on `main` and `latest`.

Pull the latest published image:

```bash
docker pull ghcr.io/shippedlabs/soroban-upgrade-safeguard:latest
```

Run against local WASM files by mounting your workspace into the container:

```bash
docker run --rm \
  -v $(pwd)/wasm:/wasms \
  ghcr.io/shippedlabs/soroban-upgrade-safeguard:latest \
  /wasms/v1.wasm /wasms/v2.wasm
```

To pin a specific released version in CI:

```bash
docker run --rm \
  -v $(pwd)/wasm:/wasms \
  ghcr.io/shippedlabs/soroban-upgrade-safeguard:v0.1.0 \
  /wasms/v1.wasm /wasms/v2.wasm
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

### Saving a report

Use `--output <PATH>` to write only the rendered report to a file. The format is
selected with `--format text`, `--format json`, or `--format markdown`; progress
messages are sent to stderr, leaving stdout and the file free of progress text.
The report is rendered before the file is opened, so a comparison that fails
before producing a report does not create or truncate the requested output file.

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format json --output ./upgrade-report.json
```

### Suppressing known breaking changes

If a breaking change is deliberate and already accounted for, list it in a
`.safeguard.toml` so it no longer fails the run. Matching is exact (by the
stable `rule_id` and `target`), and suppressed findings are still shown in the
report, marked `[SUPPRESSED]`:

```toml
max_suppressions = 10
allow_targetless = false

[[suppress]]
rule_id = "struct_field_removed"
target  = "ConfigData.threshold"
reason  = "Planned storage migration in v2."
```

Existing configs that still use `category = "..."` continue to work through a
compatibility mapping, but `rule_id` is the stable key going forward. The tool
auto-loads `.safeguard.toml` from the current directory, or use `--config <PATH>`
to point at another file. See [`.safeguard.example.toml`](.safeguard.example.toml)
for a documented template and the [documentation](docs/documentation.md#suppressing-known-breaking-changes)
for the full `target` convention.

### Comparing against a previous report (baseline)

A project mid-migration often carries a set of known findings, and repeating all
of them every run buries the one that is genuinely new. Save a JSON report and
pass it back as a baseline to see only what changed:

```bash
# Record the current state once.
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format json --output ./baseline.json

# Later runs classify each finding against it.
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v3.wasm \
  --baseline ./baseline.json
```

Every finding is labelled **new** (absent from the baseline) or **persisting**
(present in both), and findings the baseline had but this run does not are listed
as **resolved**. All three appear in text, JSON, and Markdown output. Matching is
on `rule_id`/`category` plus `target` — the same stable keys suppression uses —
so rewording a message never turns a persisting finding into a new one.

Unlike suppression, a baseline is a snapshot rather than a permanent,
hand-written acknowledgement, so it needs no rule per finding.

**Effect on the verdict and exit code.** By default a baseline only *labels*
findings: the verdict and exit code are unchanged, so a persisting Critical
finding still fails the run exactly as it would without a baseline. Add
`--baseline-fail-on-new` to gate the verdict on new findings only, which lets a
migration proceed while still failing on anything newly introduced:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v3.wasm \
  --baseline ./baseline.json --baseline-fail-on-new
```

Reports record the `tool_version` that produced them. A baseline from an
incompatible major version is rejected with a clear error rather than silently
mismatching; regenerate it with the current version. `--baseline` applies to a
single contract pair and cannot be combined with batch mode.

## GitHub Action

Use the reusable GitHub Action in your CI workflows to automatically check Soroban contract upgrades on pull requests.

### Quick Start

Create `.github/workflows/safeguard.yml`:

```yaml
name: Check upgrade safety

on:
  pull_request:
    paths:
      - 'wasm/**/*.wasm'

jobs:
  safeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: soroban-upgrade-safeguard/./
        with:
          old-wasm: ./wasm/current.wasm
          new-wasm: ./wasm/next.wasm
```

### Inputs

| Input | Description | Required | Default |
| :--- | :--- | :--- | :--- |
| `old-wasm` | Path to the old (baseline) WASM file | No | — |
| `new-wasm` | Path to the new (upgrade) WASM file | No | — |
| `contract-id` | Stellar/Soroban contract ID | No | — |
| `rpc-url` | Stellar RPC URL | No | — |
| `format` | Output format (`text`, `json`, `markdown`) | No | `text` |
| `strict` | Fail on warnings as well as critical findings | No | `false` |
| `explain` | Print remediation guidance for each finding | No | `false` |
| `config` | Path to a suppression config file | No | — |
| `expected-wasm-hash` | Expected SHA-256 hash of on-chain WASM | No | — |

### Outputs

| Output | Description |
| :--- | :--- |
| `verdict` | `passed` or `failed` |
| `critical-count` | Number of critical findings |
| `warning-count` | Number of warning findings |
| `info-count` | Number of info findings |

### JSON output in CI

```yaml
- uses: soroban-upgrade-safeguard/./
  with:
    old-wasm: ./wasm/v1.wasm
    new-wasm: ./wasm/v2.wasm
    format: json
```

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
| `1` | Unsafe — at least one critical finding (or warning in strict mode). |
| `2` | A resource limit was exceeded on untrusted input (raise the relevant limit to proceed). |
| `3` | Operational error — missing file, malformed WASM, bad manifest, unreachable RPC endpoint, etc. The tool could not run; the result carries no safety signal. |

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
