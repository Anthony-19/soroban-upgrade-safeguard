# Security Policy

## Supported Versions

Only the latest release receives security patches. Users are always encouraged to update to the newest version.

## Reporting a Vulnerability

We take the security of soroban-upgrade-safeguard seriously. If you believe you have found a security vulnerability, please report it privately.

**Preferred method:** Use GitHub's private vulnerability reporting under the repository's **Security > Advisories** tab. This creates a draft advisory visible only to the maintainers.

**Fallback:** If you cannot use GitHub's reporting, email the maintainers at **flashwebtechnology@gmail.com**.

### What to include

- The affected version (commit SHA or release tag)
- A clear description of the vulnerability
- Steps to reproduce, including any WASM files or XDR payloads if possible
- Your assessment of the potential impact
- Any suggested mitigation (optional)

### What to expect

- **Acknowledgment** within 48 hours of your report
- An initial assessment and expected timeline within 5 business days
- Regular updates from the maintainers as the investigation progresses
- A coordinated disclosure date once a fix is ready

## Disclosure Policy

We follow a **coordinated disclosure** process:

1. The report is acknowledged and investigated privately.
2. A fix is developed and tested in a private fork.
3. The fix is released in a new version, and a GitHub Security Advisory is published.
4. Public disclosure happens 90 days after the fix is released, or earlier if a mitigation is already in place.

We ask that reporters not publicly disclose the vulnerability until the fix is released and users have had a reasonable window to upgrade.

## Scope

**In scope:** The soroban-upgrade-safeguard CLI tool, including:
- WASM binary parsing and validation
- XDR decoding and type walking
- RPC-based contract fetching
- Resource-limit enforcement

**Out of scope:**
- The Rust compiler, toolchain, or standard library
- The Stellar network or Soroban host environment
- Third-party dependencies (report those vulnerabilities upstream to the respective projects)

## Recognition

We are grateful to security researchers who follow responsible disclosure. Reporters will be credited in the advisory published after the fix (unless they prefer to remain anonymous).
