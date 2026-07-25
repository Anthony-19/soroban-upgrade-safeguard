# Soroban Upgrade Safeguard Documentation

This document explains what Soroban Upgrade Safeguard does, how it works internally, and how to read its output. It is meant for contract authors who want to understand exactly why a given upgrade is flagged as safe or unsafe.

## Table of Contents

1. [Overview](#overview)
2. [Why Upgrade Safety Matters](#why-upgrade-safety-matters)
3. [Installation](#installation)
4. [Docker](#docker)
5. [Command Line Usage](#command-line-usage)
6. [How the Analysis Works](#how-the-analysis-works)
7. [Detection Categories](#detection-categories)
8. [Type Identity](#type-identity)
9. [Type Classification](#type-classification)
10. [Severity Levels](#severity-levels)
11. [Cascading Layout Breaks](#cascading-layout-breaks)
12. [Reading the Report](#reading-the-report)
13. [Suppressing Known Breaking Changes](#suppressing-known-breaking-changes)
14. [Exit Codes and CI Integration](#exit-codes-and-ci-integration)
15. [Limitations](#limitations)
16. [Frequently Asked Questions](#frequently-asked-questions)

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

### Type Renames

Types are compared by structure, not only by name, so renaming a type is recognized as a rename instead of being reported as an unrelated removal plus addition. See [Type Identity](#type-identity) for how the matching works and what it deliberately refuses to match.

- **Type Renamed.** The old type was matched to a new one with an identical layout. Stored data stays compatible; only client-side type names need updating. Informational.
- **Type Renamed With Changes.** The old type was matched to a new one whose layout also changed. The rename itself is a warning, and the actual breaking changes are reported alongside it as ordinary field- or case-level findings.

### Events

Soroban's `contractspecv0` carries no marker that says "this type is an event", so the tool cannot infer it from the spec. Instead you declare it, in the `[classification]` table of `.safeguard.toml`. See [Type Classification](#type-classification).

Classification affects only the **wording** of a finding and the remediation advice attached to it — a type classified as an event gets guidance about off-chain indexers and subscribers, because a change that is merely awkward for storage can be fully breaking for an indexer. It never affects the finding's `category`.

## Type Identity

A contract spec identifies every user-defined type by name, but a name is not an identity. Two questions have to be kept apart:

- **Is this the same type as before?** — a *structural* question.
- **What kind of thing is it?** — a *semantic* question, covered in [Type Classification](#type-classification).

### Why name matching alone is not enough

Matching purely on name gets two cases wrong, in opposite directions.

- **Renames are false breaks.** Renaming `Config` to `Settings` without touching a single field produces "Struct Removed" plus "Struct Added" — two findings, one of them critical, for a change that is byte-for-byte compatible on chain.
- **Swaps are false matches.** If `Config` is deleted and an unrelated new type happens to be called `Config`, name matching reports only the field-level differences between two types that have nothing to do with each other, quietly treating a full replacement as an edit.

### How matching actually works

Types that exist under the same name in both specs are compared in place, exactly as before. The types left over — present only in the old spec, or only in the new one — are then matched against each other structurally, per kind (structs to structs, enums to enums, and so on; a struct is never matched to an enum).

Each type gets a **fingerprint**: a canonical string built from its members and their types, with the type's own name excluded. Matching then proceeds in two tiers:

1. **Identical fingerprint.** The layouts are the same, so this is a pure rename. Reported as **Type Renamed** (Info) — no migration needed.
2. **Similar member sets.** Otherwise the candidates are scored by [Jaccard similarity](https://en.wikipedia.org/wiki/Jaccard_index) over their member keys (name and type together). A pair must score at least `0.5` — more than half their members in common — to be considered a rename at all. Reported as **Type Renamed With Changes** (Warning), followed by the ordinary field- or case-level findings describing what actually changed.

Anything not matched under those rules is reported as a plain removal and a plain addition, which is the conservative outcome: an unmatched removal stays critical.

The matching is **deterministic** — candidates are iterated in sorted order and ties are broken by the lexicographically smaller new name, so the same pair of specs always produces the same output — and **bounded**, at one comparison per (removed, added) pair within a kind.

### What it deliberately does not do

- A removed type and an added type that share fewer than half their members are **not** matched. A rewrite is a rewrite.
- Each type participates in at most one rename. When several candidates are plausible, the best-scoring one wins and the rest fall back to removal/addition.
- Two unrelated types with coincidentally identical layouts (say, two distinct `struct Wrapper { value: u32 }`) can be matched. This is unavoidable — they are indistinguishable in the spec — and harmless: the finding is informational and the layouts really are compatible.
- Names are compared case-sensitively. `Config` and `config` are different names; if both exist, they are separate types.

## Type Classification

Classification answers the second question: what kind of thing a type is. Today that means one distinction — is it an **event**, consumed by off-chain indexers and subscribers, or an ordinary **storage/interface** type?

Nothing in `contractspecv0` records this. The tool used to guess from the name, treating any type whose name contained `event` as an event type. That guess is wrong in both directions: `PreventList` and `EventCounterCache` are not events, and a genuine `Transfer` event is not caught.

So it is configured explicitly, in `.safeguard.toml`:

```toml
[classification]
# Genuine events, by exact type name. Names need not contain "event".
events = ["Transfer", "LedgerEvent", "PriceUpdate"]

# Types to keep as ordinary storage. Takes precedence over everything below.
storage = ["PreventList", "EventCounterCache"]

# Opt-in fallback: treat any name containing "event" (case-insensitive) as an
# event. Off by default.
name_heuristic = false
```

Resolution precedence, first match wins:

1. listed in `storage` → storage
2. listed in `events` → event (declared)
3. `name_heuristic = true` and the name contains `event` → event (heuristic)
4. otherwise → storage

With no `[classification]` section, **nothing is treated as an event**. The tool makes no claim it cannot back up.

### Classification never affects the suppression key

This is the important property. A finding's `category` describes structure only — `Struct Field Removed`, `Enum Case Value Changed` — and never encodes classification. Event-ness is reported separately, in the finding's `classification` field:

```json
{
  "severity": "critical",
  "category": "Enum Case Value Changed",
  "target": "StatusEvent.Paused",
  "type_name": "StatusEvent",
  "classification": { "class": "event", "heuristic": false }
}
```

Because the suppression key (`category` + `target`) contains no classification, editing `[classification]` cannot move a finding out from under an existing suppression rule, and cannot pull an unrelated one under it. Reclassifying a type changes how a finding reads, never whether it fails the run.

When a classification came from the opt-in heuristic rather than a declaration, the report says so in the finding message and sets `"heuristic": true`, so a reviewer can always tell a guess from a fact.

### Category compatibility

Earlier versions folded the event guess into the category string itself. Those names are no longer emitted, but suppression configs that use them keep working — each is mapped onto its structural replacement:

| Pre-1.0 category | Stable category |
| :--- | :--- |
| `Event Definition Removed` | `Struct Removed` |
| `Event Field Removed` | `Struct Field Removed` |
| `Event Field Reordered` | `Struct Field Reordered` |
| `Event Field Type Changed` | `Struct Field Type Changed` |
| `Event Enum Removed` | `Enum Removed` |
| `Event Enum Case Removed` | `Enum Case Removed` |
| `Event Enum Case Value Changed` | `Enum Case Value Changed` |
| `Event Enum Case Added` | `Enum Case Added` |

New rules should use the stable names. `Error Enum …` categories are unrelated to events and were never remapped.

## Severity Levels

Every finding carries one of three severity levels.

- **Critical.** A change that will cause data corruption, serialization panics, or broken integrations. The presence of any critical finding marks the whole run as unsafe. Do not deploy.
- **Warning.** A change that may affect external systems or requires a migration step, but does not by itself corrupt local storage. Appended struct fields and parameter renames fall here.
- **Info.** A non-breaking, additive change recorded for visibility, such as a new function or a new enum case.

## Cascading Layout Breaks

The most subtle failures come from shared types. Suppose a small struct named `Money` is used as a field inside `Account`, and `Account` is used inside `Ledger`. If you change `Money`, the stored bytes for every `Account` and every `Ledger` are now wrong, even though you never touched those larger types directly.

To catch this, `mapper.rs` builds a reverse dependency graph: for each user-defined type, it records which other types embed it. After the direct comparison finds the set of types with critical changes, `diff.rs` walks that graph outward and marks every dependent type as broken too, transitively. These appear in the report under the **Cascading Layout Break** category, naming both the affected parent type and the underlying modified type that caused the break. Cyclic type references are handled safely so the walk always terminates.

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

`category` is always **structural** — it describes what changed in the shape of
the contract and nothing else. In particular it never encodes whether a type is
an event, so editing `[classification]` can never change which findings a rule
matches. Configs written against the older event-flavored category names still
work; see [Category compatibility](#category-compatibility) for the mapping.

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

- Event classification is configuration, not detection. A type is treated as an event only if you list it under `[classification]` (or opt into the name heuristic). The spec carries no signal the tool could use instead. See [Type Classification](#type-classification).
- The tool reasons about the declared interface in the spec sections. It does not analyze the function bodies, so a change in internal logic that keeps the same interface is invisible to it.
- Appended struct fields are reported as warnings rather than errors. Whether they are truly safe depends on having a migration or default in place, which the tool cannot verify.
- Rename detection is structural and conservative. A type that is renamed *and* substantially rewritten in the same change falls below the similarity threshold and is reported as a removal plus an addition. See [Type Identity](#type-identity).

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
