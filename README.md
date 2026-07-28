# Soroban Upgrade Safeguard 🛡️

![Soroban Upgrade Safeguard Demo](assets/demo.png)

A powerful CLI tool to analyze and validate Soroban smart contract upgrades on the Stellar network. It detects breaking changes in storage layout, function signatures, and event schemas before you deploy.

## Features

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

## How it Works

The tool parses the `contractspecv0` custom sections from both WASM files, decodes the XDR representations of the contract's interface, and performs a deep structural comparison. It builds a type dependency map to identify when a simple change in a shared struct might cascade into breaking multiple storage entries.

## Severity Levels

- **🔴 CRITICAL**: Breaking changes that WILL cause data corruption, serialization panics, or broken integrations. **Do not deploy.**
- **🟡 WARNING**: Changes that might affect external systems but won't necessarily corrupt local storage (e.g., adding elective parameters if supported).
- **🔵 INFO**: Informational logs about additions or non-breaking modifications.

## Documentation

More detailed guides live in the [docs](docs/) folder:

- [Documentation](docs/documentation.md): full explanation of how the analysis pipeline works, every detection category, severity levels, cascading layout breaks, and CI integration.
- [Contributing](docs/contributing.md): development setup, project structure, testing, and how to add new detection rules.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
