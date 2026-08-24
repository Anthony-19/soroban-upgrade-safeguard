Overview
Storage schema analysis is currently limited to individual comparisons, so batch mode can only certify exported interfaces. Protocol repositories commonly upgrade several contracts together and need each pair to carry its own declared storage layout.

Extend TOML and JSON batch manifests with optional old and new storage-schema sources per contract pair. Schema loading, reconciliation, findings, coverage, and errors should remain isolated to the pair they belong to while aggregate output continues to provide a deterministic deployment-level verdict.

The design should support mixed batches in which some contracts have complete storage declarations, some have partial declarations, and others intentionally run interface-only analysis. Reports must make those differences impossible to mistake for equivalent coverage.

Acceptance Criteria

Add optional old and new storage-schema fields to every TOML and JSON manifest pair.

Resolve schema paths relative to the manifest file rather than the process working directory.

Allow schema-backed and interface-only pairs to coexist in the same batch.

Treat schema parsing or validation failures as pair-level errors without aborting unrelated comparisons.

Include per-pair storage coverage and analysis scope in text, Markdown, JSON, and per-contract reports.

Preserve deterministic pair ordering, aggregate verdicts, and exit-code behavior across mixed-coverage batches.

Add manifest fixtures, failure-isolation tests, output tests, and documentation for schema-enabled batch workflows.
Getting Started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/batch-storage-schemas
Suggested commit message:

feat: support storage schemas in batch manifests
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then open a pull request from your fork against main and link this issue. See docs/contributing.md for the full contribution guide.