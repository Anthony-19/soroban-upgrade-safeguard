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
