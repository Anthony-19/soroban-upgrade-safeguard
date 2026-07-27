# Soroban Upgrade Safeguard - Configuration Guide

This guide describes the unified configuration resolution system, layering precedence, environment variable overrides, and the TOML configuration schema for the Soroban Upgrade Safeguard tool.

---

## Precedence Layering Model

Safeguard resolves configuration values by merging multiple sources in a strict descending order of priority. A source with higher priority always overrides values defined in lower-priority sources:

1. **CLI Flags & Arguments** (Highest Priority)
2. **Environment Variables** (e.g., prefixed with `SAFEGUARD_` or `NO_COLOR`)
3. **Project Configuration File** (loaded from `.safeguard.toml` or via `--config`)
4. **Built-in Defaults** (Lowest Priority)

---

## Configuration File Schema

You can customize Safeguard's behavior using a `.safeguard.toml` file in the root of your project directory, or by passing an explicit configuration file path using the `--config` flag.

The configuration file uses the following schema. All fields are optional:

```toml
# Output settings
format = "text"      # Options: "text", "json", "markdown"
explain = true       # Print concise remediation explanation for each finding
strict = true        # Exit with a non-zero code on Warnings or Critical findings
no_color = false     # Disable color output (terminal styling)

# Batch execution settings
manifest = "safeguard.manifest.toml"
old_dir = "wasm/old"
new_dir = "wasm/new"
wasm_paths = ["wasm/old/contract.wasm", "wasm/new/contract.wasm"]

# RPC fetching settings
contract_id = "CCIP..."
rpc_url = "https://soroban-testnet.stellar.org"

# Finding suppressions settings
max_suppressions = 10
allow_targetless = false

# Resource limits boundary checks
[limits]
max_xdr_depth = 128
max_xdr_len = 1048576
max_entries = 1000
max_walk_depth = 128
max_wasm_size = 26214400  # 25 MiB — reject inputs larger than this before reading
rpc_timeout_secs = 30    # per-request RPC timeout; set to 0 to disable

# Define one or more reviewed suppression rules
[[suppress]]
category = "Struct Field Removed"
target = "ConfigData.threshold"
author = "Alice"
expiry = "2026-12-31"
fingerprint = "a1b2c3d4e5f6..."
reason = "Intentional deprecation of threshold parameter for protocol V21 upgrade."
```

> [!IMPORTANT]
> The configuration file enforces strict key validation. Unrecognized keys will cause the run to fail immediately.

---

## Environment Variables Mapping

Each CLI flag and configuration parameter has a corresponding environment variable mapping:

| CLI Option | Config Key | Environment Variable | Type / Format |
| :--- | :--- | :--- | :--- |
| `--format` | `format` | `SAFEGUARD_FORMAT` | String (`text`, `json`, `markdown`) |
| `--explain` | `explain` | `SAFEGUARD_EXPLAIN` | Boolean (`true`/`1` or `false`/`0`) |
| `--strict` | `strict` | `SAFEGUARD_STRICT` | Boolean (`true`/`1` or `false`/`0`) |
| `--no-color` | `no_color` | `SAFEGUARD_NO_COLOR` / `NO_COLOR` | Boolean (`true`/`1` or `false`/`0`) |
| `--manifest` | `manifest` | `SAFEGUARD_MANIFEST` | Path (relative to CWD) |
| `--old-dir` | `old_dir` | `SAFEGUARD_OLD_DIR` | Path (relative to CWD) |
| `--new-dir` | `new_dir` | `SAFEGUARD_NEW_DIR` | Path (relative to CWD) |
| (Positional) | `wasm_paths` | `SAFEGUARD_WASM_PATHS` | Comma-separated paths |
| `--contract-id`| `contract_id`| `SAFEGUARD_CONTRACT_ID` | String |
| `--rpc-url` | `rpc_url` | `SAFEGUARD_RPC_URL` | String (URL) |
| `--no-cache` | — | `SAFEGUARD_NO_CACHE` | Boolean (`true`/`1` or `false`/`0`) |
| (TOML-only) | `max_suppressions`| `SAFEGUARD_MAX_SUPPRESSIONS` | Unsigned Integer |
| (TOML-only) | `allow_targetless`| `SAFEGUARD_ALLOW_TARGETLESS` | Boolean (`true`/`1` or `false`/`0`) |
| `--max-xdr-depth`| `limits.max_xdr_depth`| `SAFEGUARD_MAX_XDR_DEPTH`| Unsigned 32-bit Integer |
| `--max-xdr-len`| `limits.max_xdr_len`| `SAFEGUARD_MAX_XDR_LEN` | Unsigned Pointer Integer (usize)|
| `--max-entries`| `limits.max_entries`| `SAFEGUARD_MAX_ENTRIES` | Unsigned Pointer Integer (usize)|
| `--max-walk-depth`| `limits.max_walk_depth`| `SAFEGUARD_MAX_WALK_DEPTH`| Unsigned Pointer Integer (usize)|
| `--max-wasm-size`| `limits.max_wasm_size`| `SAFEGUARD_MAX_WASM_SIZE`| Unsigned Pointer Integer (usize, bytes)|
| `--rpc-timeout-secs`| `limits.rpc_timeout_secs`| `SAFEGUARD_RPC_TIMEOUT_SECS`| Unsigned 64-bit Integer (seconds)|

---

## Relative Path Resolution Rules

To prevent fragile paths when running the CLI from subdirectories or in CI pipelines, Safeguard applies context-specific path resolution:

* **Config File Sources**: Paths defined in `.safeguard.toml` (e.g. `manifest`, `old_dir`, `new_dir`, `wasm_paths`) are resolved **relative to the directory containing the configuration file**.
* **Manifest pair paths**: Relative `old` and `new` paths inside a `--manifest` file are resolved **relative to the directory that contains that manifest file**, not the working directory. Absolute paths are left unchanged. This means a manifest checked in at `ci/contracts.toml` works correctly regardless of which directory the tool is invoked from.
* **CLI & Environment Sources**: Paths passed on the command line or via environment variables are resolved **relative to the current working directory of the process**. This includes `--old-dir`, `--new-dir`, and positional WASM arguments.

---

## Safety Verdict Auditing

Every report execution generates a `VerdictSettings` metadata block captured within the safety report structure. This block is output in JSON, text, and markdown reports to serve as an immutable settings audit trail:

```json
{
  "is_safe": true,
  "strict": false,
  "counts": { "critical": 0, "warning": 0, "info": 0 },
  "settings": {
    "strict": false,
    "explain": false,
    "max_suppressions": 10,
    "allow_targetless": false,
    "max_xdr_depth": 128,
    "max_xdr_len": 1048576,
    "max_entries": 1000,
    "max_walk_depth": 128,
    "max_wasm_size": 26214400,
    "rpc_timeout_secs": 30
  }
}
```

---

## CLI Options Reference

Safeguard provides the following command line options. You can view them by running `soroban-upgrade-safeguard --help`:

* **`<OLD_WASM>`** (Positional, local mode only)
  Path to the older version of the contract's compiled WASM binary.
* **`<NEW_WASM>`** (Positional, local or RPC mode)
  Path to the new version of the contract's compiled WASM binary to check for compatibility.
* **`-c, --config <FILE>`**
  Explicit path to a `.toml` configuration file containing suppressions and limits. Defaults to looking for `.safeguard.toml` in the current working directory.
* **`-f, --format <FORMAT>`**
  Set the output report format. Options: `text` (default, user-friendly terminal output), `json` (for programmatic parsing), `markdown` (ideal for CI/CD job summaries).
* **`-s, --strict`**
  Enforces a strict exit policy. If any Warning or Critical breaking changes are detected, Safeguard will exit with code `1`.
* **`-e, --explain`**
  Prints concise explanations and remediation guidance for each breaking change category found.
* **`--no-color`**
  Disables colored terminal styling. Useful for plain text logs and environments that do not support ANSI colors.
* **`--contract-id <ID>`**
  The target contract ID deployed on the Stellar network (RPC mode only).
* **`--rpc-url <URL>`**
  The Stellar RPC server URL used to query and fetch the on-chain contract code (RPC mode only).
* **`--allow-http-local`**
  Allow plain `http://` RPC URLs when the host is `localhost` or `127.0.0.1`. Without this flag only `https://` URLs are accepted. Applies to both single-pair RPC mode and on-chain pairs declared in a manifest.
* **`--no-cache`** / `SAFEGUARD_NO_CACHE=1`
  Skip both reading from and writing to the local WASM cache for this run. By default, WASM fetched from RPC is cached on disk keyed by its code hash so repeat fetches of the same deployed code are served locally. Use this flag (or the environment variable) to force a fresh network fetch.

  To clear the cache entirely without disabling it, delete the platform cache directory:
  - **Linux / macOS**: `~/.cache/soroban-upgrade-safeguard/wasm/`
  - **Windows**: `%LOCALAPPDATA%\soroban-upgrade-safeguard\wasm\`
* **`--manifest <PATH>`**
  Path to a batch manifest configuration TOML file containing multiple contract pairs to compare (Manifest mode).
* **`--old-dir <PATH>`**
  Path to a directory containing old WASM contracts to scan (Directory Scan mode).
* **`--new-dir <PATH>`**
  Path to a directory containing new WASM contracts to scan (Directory Scan mode).
* **`--max-xdr-depth <N>`**
  Sets the maximum recursive depth allowed during XDR bytes decoding.
* **`--max-xdr-len <BYTES>`**
  Sets the maximum permitted length in bytes for any decoded WASM custom section.
* **`--max-entries <N>`**
  Sets the maximum allowed decoded spec entries across all sections.
* **`--max-walk-depth <N>`**
  Sets the maximum recursion depth for structural type walk evaluations.
* **`--max-wasm-size <BYTES>`**
  Sets the maximum raw WASM binary size in bytes (default: 26,214,400 — 25 MiB). For disk files the size is checked via `fs::metadata` before any bytes are read into memory; for RPC-fetched bytes it is checked after receipt. An input exceeding this limit exits with code 2 (resource-limit violation). Settable via `SAFEGUARD_MAX_WASM_SIZE` or `limits.max_wasm_size` in `.safeguard.toml`.
* **`--rpc-timeout-secs <SECS>`**
  Sets the overall per-request timeout for RPC calls in seconds (default: 30). The budget covers TCP connect, TLS handshake, sending the request body, and reading the full response. When the endpoint stalls and the timeout fires, the error message names the RPC URL and the configured timeout so the cause is immediately clear. Set to `0` to disable the timeout entirely (not recommended in CI). Settable via `SAFEGUARD_RPC_TIMEOUT_SECS` or `limits.rpc_timeout_secs` in `.safeguard.toml`.

---

## CLI Execution Modes

Safeguard resolves its operation mode dynamically based on the set of provided arguments. Exactly one of the following four modes is activated per run:

### 1. Local Mode
* **Trigger**: Exactly two positional arguments (`<OLD_WASM>` and `<NEW_WASM>`) are provided.
* **Behavior**: Safeguard compares the two local WASM files directly.
* **Restrictions**: Positional arguments must not conflict with batch/manifest modes.

### 2. RPC Mode
* **Trigger**: Exactly one positional argument (`<NEW_WASM>`) is provided, and both `--contract-id` and `--rpc-url` are specified.
* **Behavior**: Safeguard fetches the current active WASM bytecode of the contract from the network, and compares it against the local `<NEW_WASM>` binary.

### 3. Manifest Mode
* **Trigger**: `--manifest <PATH>` is specified.
* **Behavior**: Safeguard reads the manifest file (which lists pairs of contracts) and runs comparisons on all of them in batch.
* **Restrictions**: No positional arguments are allowed.

#### Manifest pair sources

Each side of a pair can be a **local file path** (string) or an **on-chain contract** (inline table with `contract_id` and `rpc_url`). The two forms can be mixed freely within the same manifest and across pairs.

**File-only pair** — backward-compatible, unchanged from previous versions:

```toml
[[pairs]]
old = "wasm/old/my_contract.wasm"
new = "wasm/new/my_contract.wasm"
name = "my_contract"
```

**Old side from RPC, new side from local file** — the primary upgrade-check workflow:

```toml
[[pairs]]
old = { contract_id = "CCONTRACT_ID_HERE", rpc_url = "https://soroban-testnet.stellar.org" }
new  = "target/wasm32-unknown-unknown/release/my_contract.wasm"
name = "my_contract"
```

**Both sides from RPC** — compare two deployed versions directly:

```toml
[[pairs]]
old = { contract_id = "COLD_CONTRACT_ID", rpc_url = "https://soroban-mainnet.stellar.org" }
new  = { contract_id = "CNEW_CONTRACT_ID", rpc_url = "https://soroban-mainnet.stellar.org" }
name = "my_contract"
```

**Mixed batch** — file and on-chain pairs in a single run:

```toml
[[pairs]]
old = "wasm/old/token.wasm"
new  = "wasm/new/token.wasm"
name = "token"

[[pairs]]
old = { contract_id = "CPOOL_CONTRACT_ID", rpc_url = "https://soroban-testnet.stellar.org" }
new  = "wasm/new/pool.wasm"
name = "pool"
```

**JSON manifest** — same syntax, just written as JSON objects:

```json
{
  "pairs": [
    {
      "old": { "contract_id": "CCONTRACT_ID_HERE", "rpc_url": "https://soroban-testnet.stellar.org" },
      "new": "target/wasm32-unknown-unknown/release/my_contract.wasm",
      "name": "my_contract"
    }
  ]
}
```

> **Derived names for on-chain pairs.** When a pair has no explicit `name`, the name is derived from the `new` side: the WASM file stem for a local file, or the full `contract_id` string for an on-chain source. Provide an explicit `name` to keep reports readable when contract IDs are long.

> **Caching.** WASM fetched from RPC is cached on disk keyed by code hash (see `--no-cache`). A batch is exactly where the cache matters most: if the same deployed contract appears in several pairs, it is fetched only once for the whole run.

> **URL security.** Each on-chain pair's `rpc_url` is validated independently. `https://` is always accepted. Plain `http://` is only permitted for `localhost` / `127.0.0.1` when `--allow-http-local` is passed.

### 4. Directory Scan Mode
* **Trigger**: Both `--old-dir <PATH>` and `--new-dir <PATH>` are specified.
* **Behavior**: Safeguard scans both directories for matching WASM binaries and runs comparisons on each pair.
* **Restrictions**: No positional arguments are allowed.

---

## Troubleshooting Configuration Issues

Here are the most common configuration mistakes and how to resolve them:

### 1. Unknown Key in `.safeguard.toml`
* **Symptom**: Safeguard fails immediately with an deserialization error mentioning an invalid key.
* **Reason**: To enforce strict schema validation and prevent typos from silently neutralizing checks, the configuration parser rejects unrecognized fields.
* **Remediation**: Double check that your config keys are spelled exactly as documented in the [Configuration File Schema](#configuration-file-schema) section. Common typos include writing `allow-targetless` (kebab-case) instead of `allow_targetless` (snake_case).

### 2. Relative Path Mismatch
* **Symptom**: Files are reported as not found, even though they exist on disk.
* **Reason**: Paths defined in `.safeguard.toml` are resolved relative to the configuration file's parent directory, not the current working directory of your shell.
* **Remediation**: 
  - Ensure that relative paths inside `.safeguard.toml` are relative to the folder where `.safeguard.toml` resides.
  - If you run the command using an explicit `--config` flag, paths inside that config will be resolved relative to the parent directory of that custom path.

### 3. Missing RPC Parameters Co-Dependency
* **Symptom**: Bail error: `Both --contract-id and --rpc-url must be specified together`.
* **Reason**: Safeguard requires both a Stellar RPC server endpoint and a target Contract ID to fetch the deployed WASM code from the chain. Providing only one makes fetching impossible.
* **Remediation**: Pass both flags on the CLI, or define both `contract_id` and `rpc_url` in your `.safeguard.toml` configuration.

### 4. Suppression Expiry Errors
* **Symptom**: Bail error: `Suppression rule for category '...' has expired on YYYY-MM-DD`.
* **Reason**: Suppression rules using the new format are validated for expiry. If the current date is past the expiry date, Safeguard rejects the suppression rule to prompt developers to re-review the upgrade risk.
* **Remediation**: Re-evaluate the breaking change. If it is still intentional, edit `.safeguard.toml` to update the `expiry` date to a future date.

### 5. Fingerprint Mismatches
* **Symptom**: The gate fails (exit code 1) indicating critical breaking changes are present, even though you have a suppression rule for the category and target.
* **Reason**: When using the strict new-format suppression, the calculated SHA-256 fingerprint of the diff finding must match the `fingerprint` property of the rule exactly.
* **Remediation**: Check the JSON output or standard error logs for the actual calculated fingerprint of the finding, and verify that the `fingerprint` field in your `.safeguard.toml` matches it exactly (character-for-character).

---

## Deep Dive: Understanding Resource Limits

Safeguard protects your CI runner systems and memory footprints from malicious, malformed, or pathologically nested contract metadata files. By default, standard resource limits are enforced. However, large enterprise contracts may occasionally exceed these safe defaults.

### Limits Reference & Tuning Strategy

#### 1. `max_xdr_depth` (CLI: `--max-xdr-depth`, Default: `128`)
* **Purpose**: Prevents stack overflows during deep recursive parsing of contract specs.
* **Symptom**: Panics or exit code 2 when parsing highly nested custom user-defined types (UDTs).
* **Remediation**: Increase the limit to `256` or higher if you have deeply nested generic structures.

#### 2. `max_xdr_len` (CLI: `--max-xdr-len`, Default: `1,048,576` bytes)
* **Purpose**: Restricts the maximum size allocated for a single custom WASM section.
* **Symptom**: Abort error: `Oversized section length relative to budget`.
* **Remediation**: Increase this threshold when utilizing contracts that export large metadata structures.

#### 3. `max_entries` (CLI: `--max-entries`, Default: `1,000`)
* **Purpose**: Caps the total count of exported contract spec entries (functions, structs, unions, enums).
* **Symptom**: Abort error: `Exceeded spec entries limit`.
* **Remediation**: Large monorepo-style contracts combining multiple modules might need this limit increased to `2000` or `3000`.

#### 4. `max_walk_depth` (CLI: `--max-walk-depth`, Default: `128`)
* **Purpose**: Restricts recursive structural comparison, formatting, and rendering algorithms.
* **Symptom**: Validation fails under complex nested structs check.
* **Remediation**: Raise this limit only if Safeguard explicitly recommends doing so during validation.

#### 5. `max_wasm_size` (CLI: `--max-wasm-size`, Default: `26,214,400` bytes / 25 MiB)
* **Purpose**: Caps the raw WASM binary size **before** the file is read into memory (disk) or accepted from an RPC response. A legitimate compiled Soroban contract is well under 1 MiB; the 25 MiB default is a wide safety margin that rejects multi-gigabyte adversarial inputs without allocating memory for them. Violations surface as exit code 2 (resource-limit violation), distinct from exit code 1 (breaking changes found).
* **Symptom**: Error message `WASM input size N bytes exceeds the maximum of M bytes (raise max_wasm_size)`.
* **Remediation**: If you have a genuinely large contract that exceeds the default, raise the limit via `--max-wasm-size`, `SAFEGUARD_MAX_WASM_SIZE`, or `limits.max_wasm_size` in `.safeguard.toml`. For adversarial inputs the correct response is to reject them rather than raise the limit.

#### 6. `rpc_timeout_secs` (CLI: `--rpc-timeout-secs`, Default: `30` seconds)
* **Purpose**: Bounds the total time allowed for each RPC round-trip (there are at most two per contract fetch: one to resolve the code hash, one to fetch the code entry). Without this limit an unresponsive endpoint stalls the process indefinitely, burning an entire CI job's time budget with no output.
* **Behaviour**: When the timeout fires, the error names the RPC URL and the configured limit so the cause is immediately actionable. The overall budget covers TCP connect, TLS handshake, sending the request, and reading the full response body.
* **Symptom**: Error message `RPC request to '<url>' timed out after N second(s)`.
* **Remediation**: If your endpoint is legitimately slow, raise the limit via `--rpc-timeout-secs`, `SAFEGUARD_RPC_TIMEOUT_SECS`, or `limits.rpc_timeout_secs` in `.safeguard.toml`. Set to `0` to disable the timeout entirely (not recommended in CI).

---

## CI/CD Pipeline Integration Patterns

Integrating Safeguard as a PR check is highly recommended to block accidental breaking changes.

### GitHub Actions Workflow Example

The following workflow compares a pull request's compiled WASM build against the on-chain deployed version of the contract:

```yaml
name: Soroban Upgrade Safeguard Gate

on:
  pull_request:
    paths:
      - 'contracts/**/*.rs'
      - 'contracts/**/*.wasm'

jobs:
  safeguard-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Install Rust Toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build Contracts
        run: cargo build --target wasm32-unknown-unknown --release

      - name: Install Safeguard CLI
        run: cargo install --path .

      - name: Run Upgrade Verification Gate
        run: |
          soroban-upgrade-safeguard \
            --contract-id ${{ secrets.STELLAR_CONTRACT_ID }} \
            --rpc-url https://soroban-testnet.stellar.org \
            --expected-wasm-hash ${{ secrets.STELLAR_EXPECTED_WASM_HASH }} \
            --strict \
            --explain \
            target/wasm32-unknown-unknown/release/my_contract.wasm
```

### GitLab CI/CD Pipeline Example

For GitLab CI, you can configure a similar gate:

```yaml
stages:
  - test

safeguard_gate:
  stage: test
  image: rust:latest
  script:
    - cargo build --target wasm32-unknown-unknown --release
    - cargo install --path .
    - soroban-upgrade-safeguard --contract-id $CONTRACT_ID --rpc-url $RPC_URL --strict --explain target/wasm32-unknown-unknown/release/my_contract.wasm
  only:
    - merge_requests
```


