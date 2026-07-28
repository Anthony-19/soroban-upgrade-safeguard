#!/usr/bin/env bash
# build_fixtures.sh — build, verify, or regenerate the fixture WASMs.
#
# Usage
# -----
#   tests/build_fixtures.sh              # build all fixtures (default)
#   tests/build_fixtures.sh --verify     # verify committed WASMs match checksums.sha256
#   tests/build_fixtures.sh --regen      # rebuild + update checksums.sha256
#
# Reproducibility
# ---------------
# Every fixture sub-crate carries its own rust-toolchain.toml (pinned to 1.91.0)
# and a committed Cargo.lock. This script always passes --locked so the exact
# same dependency graph is used on every machine, making the output byte-for-byte
# identical across rebuilds.
#
# Provenance record
# -----------------
# toolchain : 1.91.0  (tests/fixtures/v*/rust-toolchain.toml)
# soroban-sdk: 21.7.7 (tests/fixtures/v*/Cargo.lock)
# profile   : release (opt-level=z, lto=true, strip=symbols, panic=abort)
#
# Fixture pairs and the rules they cover
# ---------------------------------------
# v1 → v2  (CRITICAL)   function_signature_changed, parameter_type_changed,
#                        return_type_changed, struct_field_removed,
#                        enum_case_value_changed
# v1 → v3  (WARNING)    parameter_renamed
# v4 → v5  (CRITICAL)   union_case_removed, union_case_reordered,
#                        union_case_type_changed, error_enum_case_value_changed,
#                        error_enum_case_removed, struct_field_type_changed,
#                        cascading_layout_break
# v6 → v7  (WARNING)    union_case_type_widened, struct_field_added,
#                        struct_field_type_widened, error_enum_case_added
# vN → vN  (CLEAN)      identity pairs for every fixture — zero false positives

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WASM_DIR="${REPO_ROOT}/tests/wasm"
FIXTURES_DIR="${REPO_ROOT}/tests/fixtures"
CHECKSUMS="${WASM_DIR}/checksums.sha256"

MODE="build"
if [[ "${1:-}" == "--verify" ]]; then
    MODE="verify"
elif [[ "${1:-}" == "--regen" ]]; then
    MODE="regen"
fi

# ---------------------------------------------------------------------------
# Fixtures: (version_tag, crate_dir, output_stem)
# ---------------------------------------------------------------------------
declare -a FIXTURES=(
    "v1:${FIXTURES_DIR}/v1:mock_contract_v1"
    "v2:${FIXTURES_DIR}/v2:mock_contract_v2"
    "v3:${FIXTURES_DIR}/v3:mock_contract_v3"
    "v4:${FIXTURES_DIR}/v4:mock_contract_v4"
    "v5:${FIXTURES_DIR}/v5:mock_contract_v5"
    "v6:${FIXTURES_DIR}/v6:mock_contract_v6"
    "v7:${FIXTURES_DIR}/v7:mock_contract_v7"
)

# ---------------------------------------------------------------------------
verify_checksums() {
    echo "Verifying fixture WASMs against ${CHECKSUMS} ..."
    if [[ ! -f "${CHECKSUMS}" ]]; then
        echo "ERROR: checksums.sha256 not found at ${CHECKSUMS}" >&2
        exit 1
    fi
    # Run sha256sum --check from the wasm directory so relative paths resolve.
    # Filter comment lines (sha256sum --check rejects them).
    grep -v '^#' "${CHECKSUMS}" | (cd "${WASM_DIR}" && sha256sum --check --strict -)
    echo "All fixture checksums verified successfully."
}

# ---------------------------------------------------------------------------
build_fixtures() {
    local regen="${1:-false}"

    mkdir -p "${WASM_DIR}"

    for entry in "${FIXTURES[@]}"; do
        local tag="${entry%%:*}"
        local rest="${entry#*:}"
        local crate_dir="${rest%%:*}"
        local output_stem="${rest##*:}"

        echo "--- Building fixture ${tag} from ${crate_dir} ---"

        if [[ ! -f "${crate_dir}/Cargo.lock" ]]; then
            echo "ERROR: ${crate_dir}/Cargo.lock is missing." >&2
            echo "       Cargo.lock files must be committed for reproducible builds." >&2
            echo "       Generate one with: cd ${crate_dir} && cargo generate-lockfile" >&2
            exit 1
        fi

        (
            cd "${crate_dir}"
            cargo build --target wasm32-unknown-unknown --release --locked
        )

        local src="${crate_dir}/target/wasm32-unknown-unknown/release/${output_stem}.wasm"
        local dst="${WASM_DIR}/${tag}.wasm"
        cp "${src}" "${dst}"
        echo "  → copied to ${dst}"
    done

    echo ""
    if [[ "${regen}" == "true" ]]; then
        echo "Regenerating checksums.sha256 ..."
        {
            cat << 'HDR'
# SHA-256 checksums for committed fixture WASMs.
#
# These hashes are the ground truth for reproducibility verification.
# `tests/build_fixtures.sh --verify` re-hashes every file and fails if any
# hash does not match. CI runs this check on every pull request so a silent
# binary change cannot reach main.
#
# Provenance
# ----------
# toolchain : 1.91.0 (tests/fixtures/v*/rust-toolchain.toml)
# soroban-sdk: 21.7.7 (tests/fixtures/v*/Cargo.lock)
# profile   : release (opt-level=z, lto=true, strip=symbols, panic=abort)
#
# To regenerate after an intentional change:
#   tests/build_fixtures.sh --regen
# Then review the diff, commit the updated WASMs + this file together.
#
# Format: sha256sum(1) output — "<hash>  <filename>"
HDR
        } > "${CHECKSUMS}"

        (cd "${WASM_DIR}" && sha256sum v1.wasm v2.wasm v3.wasm v4.wasm v5.wasm v6.wasm v7.wasm) >> "${CHECKSUMS}"
        echo "checksums.sha256 updated."
        echo ""
        echo "IMPORTANT: review the diff of tests/wasm/*.wasm and checksums.sha256 before"
        echo "committing. Any WASM that changed without a corresponding source change"
        echo "indicates SDK drift or a toolchain mismatch — investigate before merging."
    else
        echo "Build complete. Run with --verify to confirm WASMs match checksums.sha256"
        echo "or --regen to rebuild and update checksums after an intentional change."
    fi
}

# ---------------------------------------------------------------------------
case "${MODE}" in
    verify)
        verify_checksums
        ;;
    regen)
        build_fixtures "true"
        ;;
    build)
        build_fixtures "false"
        ;;
esac
