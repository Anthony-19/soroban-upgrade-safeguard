# Soroban Upgrade Safeguard Documentation

This document explains what Soroban Upgrade Safeguard does, how it works internally, and how to read its output. It is meant for contract authors who want to understand exactly why a given upgrade is flagged as safe or unsafe.

## Table of Contents

1. [Overview](#overview)
2. [Why Upgrade Safety Matters](#why-upgrade-safety-matters)
3. [Installation](#installation)
4. [Docker](#docker)
5. [Command Line Usage](#command-line-usage)
6. [Inspecting a Single Build (`extract`)](#inspecting-a-single-build-extract)
7. [Re-rendering a Saved Report (`render`)](#re-rendering-a-saved-report-render)
8. [How the Analysis Works](#how-the-analysis-works)
9. [Detection Categories](#detection-categories)
10. [Severity Levels](#severity-levels)
11. [Cascading Layout Breaks](#cascading-layout-breaks)
12. [The Interface Hash](#the-interface-hash)
13. [Reading the Report](#reading-the-report)
14. [Suppressing Known Breaking Changes](#suppressing-known-breaking-changes)
15. [Exit Codes and CI Integration](#exit-codes-and-ci-integration)
16. [Limitations](#limitations)
17. [Frequently Asked Questions](#frequently-asked-questions)

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

Two subcommands do something other than compare a pair: `extract` dumps one build's decoded interface, and `render` turns a saved JSON report back into a human format. They are additive — every invocation form described above continues to work unchanged.

## Inspecting a Single Build (`extract`)

Comparing two builds is not the only useful thing to do with a decoded interface. `extract` emits what a single WASM actually exposes, so you can inspect a build directly or archive its interface as a pipeline artifact without reaching for separate Stellar tooling.

```bash
soroban-upgrade-safeguard extract ./wasm/v1.wasm
soroban-upgrade-safeguard extract --contract-id C... --rpc-url https://soroban-testnet.stellar.org
```

The output is a single JSON document on stdout:

```json
{
  "spec_schema_version": 1,
  "tool_version": "0.1.0",
  "source": "./wasm/v1.wasm",
  "interface_hash": "17618edb2d0d9911…",
  "env_meta": {
    "interface_version": 90194313216,
    "protocol_version": 21,
    "pre_release_version": 0
  },
  "functions":   [ { "name": "…", "doc": "…", "inputs": [ … ], "outputs": [ … ] } ],
  "structs":     [ { "name": "…", "doc": "…", "lib": "…", "fields": [ … ] } ],
  "enums":       [ { "name": "…", "doc": "…", "lib": "…", "cases": [ … ] } ],
  "unions":      [ { "name": "…", "doc": "…", "lib": "…", "cases": [ … ] } ],
  "error_enums": [ { "name": "…", "doc": "…", "lib": "…", "cases": [ … ] } ]
}
```

Notes on the shape, which is intended to be stable enough to consume:

- Every collection is **sorted by name**, so two extractions of the same build are byte-identical. The underlying spec maps have no inherent order, so without this the output would vary between runs.
- Within a function, `inputs` and `outputs` stay in **declaration order**, and struct `fields` and union `cases` likewise, because those positions are part of the serialized layout.
- `env_meta` is `null` when the WASM carries no `contractenvmetav0` section.
- Types are emitted **structurally**, tagged with a `kind` field, rather than as display strings: `{"kind":"u32"}`, `{"kind":"udt","name":"Data"}`, `{"kind":"option","value":{"kind":"address"}}`. A display string would be ambiguous, since a user-defined type named `u32` renders identically to the primitive.
- `spec_schema_version` is bumped only when a change would break a consumer reading the current shape. Adding a field is not such a change.

For scripting, `--hash-only` prints just the interface hash and nothing else, which makes it usable directly as a cache key:

```bash
$ soroban-upgrade-safeguard extract ./wasm/v1.wasm --hash-only
17618edb2d0d99112a446eec51b056ef59d07e2d1ffdbbb0656f48f62e4a4265
```

## Re-rendering a Saved Report (`render`)

The JSON report is the durable artifact. `render` turns a stored one back into text or Markdown, so a pipeline that archived the JSON can later produce the Markdown a reviewer wants without rerunning the comparison against inputs that may have moved.

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json > report.json
soroban-upgrade-safeguard render report.json --format markdown
cat report.json | soroban-upgrade-safeguard render - --format text
```

Pass `-` as the path to read from stdin. The available formats are `text` (default) and `markdown`; JSON is excluded because re-rendering JSON as JSON would be a plain copy.

The re-rendered output is identical to what the original run printed. That is structural rather than a promise: both the live run and `render` build the same `RenderableReport` model and call the same renderer, so the two paths cannot drift apart.

Two details worth knowing:

- **The exit code reflects the stored verdict.** Rendering a failing report exits 1, exactly as the original run did. `render` reports on a verdict; it does not re-derive one.
- **`--explain` guidance only appears if the original run recorded it.** Remediation text is stored in the JSON only when the comparison used `--explain`, so `render --explain` can surface it but cannot invent it.

An unreadable or incompatible report fails with a specific message rather than a parse error — a report written by a newer tool version names both the schema version it needs and the tool version that produced it.

## How the Analysis Works

The analysis runs as a short pipeline. Each stage lives in its own module under `src/`.

1. **Load and validate (`loader.rs`).** Each file is read from disk and checked for the WASM magic header. The tool then walks every WASM payload to confirm the binary is structurally well formed before any deeper work happens. A corrupt or non-WASM file fails fast with a clear message.

2. **Extract metadata (`parser.rs`).** The Soroban SDK stores the contract interface in custom WASM sections. The parser scans for the `contractspecv0` section and decodes the concatenated XDR `ScSpecEntry` objects it contains. The `contractenvmetav0` section is captured as well for completeness.

3. **Build the spec model (`spec.rs`).** Decoded entries are sorted into a `ContractSpec`, which groups functions, structs, enums, unions, and error enums into separate maps keyed by name. This gives the comparison stage fast lookups by type name.

4. **Compare (`diff.rs`).** The old and new specs are compared item by item. Functions, structs, and enums are matched by name and then examined for the specific breaking changes described below. Every difference becomes a `Finding` with a severity and a category.

5. **Map dependencies (`mapper.rs`).** A `LayoutMapper` builds a reverse dependency graph over user-defined types. This is what lets the tool understand that a change to a small shared type can break every larger type that embeds it.

6. **Report (`report.rs`).** All findings are aggregated into a `SafetyReport`, grouped by category, counted by severity, and rendered as a colored summary. The overall run is considered safe only when there are zero critical findings.

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

### Type Kind Changes

- **Type Kind Changed.** A user-defined type kept its name but became a different kind of type — a struct that is now an enum, an enum that is now a union, and so on. Critical.

This one is worth explaining, because it is easy to misread. Each of the per-kind comparison passes looks only at its own map: the struct pass compares structs against structs, the enum pass enums against enums. So when `Status` is a struct in the old build and an enum in the new one, the struct pass sees a struct that vanished and the enum pass sees an enum that appeared, and neither can tell that they are looking at two halves of the same change.

Reported that way it would read as a critical `Struct Removed` plus an informational `Enum Added` — and the informational half badly understates what happened. The type did not appear from nowhere; it replaced a struct of the same name, which invalidates every stored value of that type.

The tool therefore runs a pass after the per-kind comparisons that detects names defined as one kind in the old spec and another kind in the new one, reports a single critical **Type Kind Changed** finding, and retracts the spurious removal-plus-addition pair for that name. Findings about the type's *members* (for example `Status.field`) are untouched, and the kind change still propagates through [cascading layout breaks](#cascading-layout-breaks) to any type that embeds it.

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

## The Interface Hash

Every comparison also computes an **interface hash** for each build: a SHA-256 digest over a canonical form of the decoded spec, shown in the report and available on its own via `extract --hash-only`.

It answers, cheaply and directly, a question that otherwise requires a full pairwise diff: *do these two builds expose the same interface?* Two builds with the same interface hash expose the same functions and types, regardless of compiler noise, entry ordering, or byte-level differences in the WASM. That makes it useful for caching a comparison result, for indexing builds by interface, and for catching the case where a change you believed was interface-preserving quietly was not.

The hash is order-independent by construction. A `ContractSpec` is built from hash maps with no inherent iteration order, and two builds of semantically identical source may lay their `contractspecv0` entries out differently, so the canonical form sorts every collection whose order is not itself part of the interface.

### What the hash covers

Included, because changing any of these changes the interface:

| Included | Detail |
| :--- | :--- |
| Functions | Name, parameter names, parameter types, parameter **order**, and return types in order |
| Structs | Name, field names, field types, and field **order** — struct fields serialize positionally |
| Unions | Name, case names, case payload types, and case **order** — union cases serialize by positional discriminant |
| Enums, error enums | Name, and the set of `(case name, value)` pairs |
| Type kind | Whether a given name is a struct, enum, union, or error enum |

Two ordering rules deserve a note, because they are the part that had to be got right:

- Struct fields, union cases, and function parameters keep their **declared order** in the canonical form, since Soroban serializes and invokes them positionally. Reordering them is a breaking change, and the hash moves accordingly.
- Enum and error-enum cases are **sorted by name** instead. Their integer values are explicit and the comparison matches them by name, so reordering variants in the source is not an interface change and must not move the hash.

Deliberately **not** included, because these are prose or provenance rather than interface shape:

- **Doc strings**, on any entry, field, parameter, or case. Editing a comment must not invalidate a cached interface hash. Note that the comparison still *reports* doc changes as informational findings — the hash tracks the interface, not the full finding set.
- The **`lib`** field on user-defined types, which records the defining library and is never compared.
- Everything **outside the spec**: WASM bytes, compiler version, section ordering, `contractenvmetav0` (and therefore the Soroban protocol version), and `contractmetav0`. Two builds with the same interface hash may target different protocol versions, so the hash is not a substitute for the environment check.

### Stability

A canonical-form version is mixed into the digest, so if the encoding ever changes, every hash changes with it rather than silently colliding across tool versions. The canonical form is also length-prefixed throughout, which means no combination of type, field, or case names can collide by running together across a separator.

### Using it from a script

```bash
old=$(soroban-upgrade-safeguard extract ./wasm/v1.wasm --hash-only)
new=$(soroban-upgrade-safeguard extract ./wasm/v2.wasm --hash-only)

if [ "$old" = "$new" ]; then
  echo "Interface unchanged — skipping the full comparison"
fi
```

In a comparison report, both hashes appear in the header of every format, along with a line stating whether the interface changed, and in the JSON as `old_interface_hash` and `new_interface_hash`.

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

Each `[[suppress]]` entry acknowledges exactly one finding:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2 drops the unused threshold field."

[[suppress]]
category = "Function Signature Changed"
target   = "initialize"
reason   = "Re-init is intentional and gated behind the migration admin call."
```

A ready-to-copy template lives at [`.safeguard.example.toml`](../.safeguard.example.toml).

### How matching works

Matching is **exact**: a rule applies only when both its `category` and its
`target` equal the finding's own values. This strictness keeps a suppression
from over-applying to a sibling field, enum case, or parameter. A rule that
omits `target` matches only findings that themselves have no target (for
example `Environment` changes).

The `target` is a stable, structured identifier for the exact entity a finding
is about, independent of the human-readable message:

| Finding is about     | `target` form     | Example                  |
| -------------------- | ----------------- | ------------------------ |
| a function           | `function`        | `transfer`               |
| a function parameter | `function.param`  | `transfer.to`            |
| a type               | `Type`            | `ConfigData`             |
| a struct field       | `Type.field`      | `ConfigData.threshold`   |
| an enum case         | `Enum.case`       | `StatusEvent.Paused`     |

The easiest way to find the right `category` and `target` for a finding is to
run with `--format json`; every finding carries both fields verbatim.

### What suppression does and does not change

A suppressed finding is **not hidden**. It is still listed in the report, marked
`[SUPPRESSED]` along with its reason, and still counted in the severity totals.
What changes is the failing set: a suppressed Critical no longer contributes to
the exit code. The run passes only when no *unsuppressed* Critical remains. The
JSON output adds a top-level `suppressed_count`, and each suppressed finding
gains `"suppressed": true` (and a `"suppression_reason"` when one was given).

## Exit Codes and CI Integration

The tool is designed to drop into a continuous integration pipeline.

- Exit code `0`: no critical findings. The upgrade is considered safe to deploy.
- Exit code `1`: at least one critical finding, or a fatal error such as a missing or malformed WASM file.

Because the process exits non-zero on critical findings, you can gate a deployment job on it directly:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm
```

If that command fails, the pipeline stops before the upgrade is published.

## Limitations

- Event detection relies on a name heuristic. A type that represents an event but does not contain `event` in its name will be analyzed as an ordinary struct or enum.
- The tool reasons about the declared interface in the spec sections. It does not analyze the function bodies, so a change in internal logic that keeps the same interface is invisible to it.
- Appended struct fields are reported as warnings rather than errors. Whether they are truly safe depends on having a migration or default in place, which the tool cannot verify.
- Comparison is by name. Renaming a type is seen as removing the old name and adding a new one, not as a rename.

## Frequently Asked Questions

**Does the tool need access to the Stellar network?**
No. It works entirely from the two local WASM files.

**Can I run it on contracts built by tools other than the standard Soroban SDK?**
It works on any WASM that embeds a standard `contractspecv0` custom section. If that section is missing, there is nothing to compare and the spec will appear empty.

**Why is an appended field only a warning?**
Appending a field does not move existing fields, so old data still deserializes for the fields that were already there. The new field, however, has no stored value in old entries, so you need a migration or a default. The tool flags this so you remember to handle it.

**What counts as a safe upgrade?**
Any run that finishes with zero critical findings. Warnings and info findings are worth reviewing but do not block deployment.

For guidance on contributing changes to this tool, see [contributing.md](contributing.md).
