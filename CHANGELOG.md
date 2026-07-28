# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `.editorconfig` to enforce consistent whitespace and line endings across file types.
- CI concurrency group to cancel superseded workflow runs.
- Directory-scan warning routing now consistent with other batch output.

## [0.1.0] - 2026-07-27

### Added

- Initial release of Soroban Upgrade Safeguard.
- WASM module loader with file and RPC-based contract fetching.
- XDR custom section extraction and decoding.
- Contract spec model with function and type definitions.
- Structural comparison engine detecting breaking changes in functions, structs, enums, unions, and error enums.
- Storage layout mapping, type signature rendering, and cascading break detection.
- Event type heuristic detection and classification.
- Rename detection matching types structurally rather than by name.
- Rich CLI output with colored, severity-coded reports (Critical, Warning, Info).
- JSON and Markdown output formats for CI and PR comments.
- Strict mode treating warnings as failures.
- Explain flag with per-finding remediation guidance.
- Suppression config (`.safeguard.toml`) to acknowledge known, intentional breaking changes.
- Resource limits bounding XDR decode depth, byte length, entry count, and type-walk depth.
- Batch comparison mode with manifest file support.
- Directory-scan mode for pairing WASM files across directories.
- Dockerfile for containerized use.
- GitHub Action for CI integration.
- RPC mode with cryptographic hash verification and transport security.
- Storage-schema manifest for analyzing internal storage layouts.
- Library API exposing the comparison pipeline.
- Fuzz targets for the parsing and decode paths.
- JSON Schema for the report output.
- Cross-contract dependency propagation in batch comparisons.
- Category filtering (include/exclude) for findings.
- Snapshot testing for text, markdown, and JSON output formats.
- Duplicate spec entry detection with provenance tracking.
- Unused suppression rule warnings.
- WASM export and import comparison.
- Contract metadata parsing and comparison.
- Build metrics (byte size deltas, interface counts) in reports.
- Output file flag (`--output`) for writing reports to files.
- GitHub Actions annotation output format.
