# ── Base image pinning policy ─────────────────────────────────────────────────
# Both stages pin an explicit version tag AND a content digest (`tag@sha256:…`)
# so a given commit always builds from exactly one image: the tag documents the
# human-readable version, and the digest is what Docker actually resolves and
# verifies. This makes "which toolchain produced this binary" a question the repo
# can answer, and turns a toolchain bump into a visible, reviewable diff.
#
# How to bump (routine, reviewable):
#   1. Pick the new version and pull it, e.g.
#        docker pull rust:<X.Y.Z>-slim-bookworm      # builder
#        docker pull debian:bookworm-slim            # runtime
#   2. Resolve the digest it now points at:
#        docker inspect --format '{{index .RepoDigests 0}}' rust:<X.Y.Z>-slim-bookworm
#        docker inspect --format '{{index .RepoDigests 0}}' debian:bookworm-slim
#   3. Replace both the tag and the `@sha256:…` digest on the matching FROM line.
# Dependabot (see .github/dependabot.yml, `docker` ecosystem) opens these bumps
# automatically so the pins are kept current rather than quietly rotting.

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# rustc 1.97.1 — pinned by tag + digest (see base image pinning policy above).
FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

# ring 0.17 compiles C code via the `cc` crate; gcc and pkg-config are required.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Dependency cache layer ────────────────────────────────────────────────────
# Copy manifests first. Create minimal stubs for both declared targets (lib +
# bin) so `cargo build --release` can resolve and compile all dependencies
# without any application source. This layer is only invalidated when
# Cargo.toml or Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs
RUN cargo build --release
# Remove stub root-crate artifacts so the real binary is always relinked.
RUN rm -f target/release/soroban-upgrade-safeguard \
         target/release/deps/soroban_upgrade_safeguard* \
         target/release/deps/soroban-upgrade-safeguard*

# ── Application build layer ───────────────────────────────────────────────────
# Only this layer rebuilds when src/ changes; all dependencies are already
# compiled and cached in the layer above.
COPY src/ ./src/
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Debian 12 (bookworm) slim — pinned by tag + digest (see policy above).
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

# ca-certificates is required by rustls/ureq when using --rpc-url (HTTPS).
# Local-mode users (two WASM paths, no network) are unaffected but it is
# included so both modes work out of the box.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --no-create-home --shell /bin/false appuser

COPY --from=builder /app/target/release/soroban-upgrade-safeguard /usr/local/bin/soroban-upgrade-safeguard

LABEL org.opencontainers.image.title="soroban-upgrade-safeguard" \
      org.opencontainers.image.description="Detect breaking changes in Soroban smart contract upgrades"

USER appuser

ENTRYPOINT ["soroban-upgrade-safeguard"]
