Add a --color flag with auto, always, and never so color can be forced when piping
Repo Avatar
ShippedLabs/soroban-upgrade-safeguard
Description
Color control today is binary. should_disable_color in src/lib.rs turns color
off when --no-color is passed, when NO_COLOR is set, or when stdout is not a
terminal.

That last rule means there is no way to keep color when the output is piped or
redirected. A user capturing a text report into a file for later viewing, or
feeding it to a pager or a CI log viewer that renders ANSI, cannot get colored
output at all, because the not-a-terminal check overrides everything.

Suggested approach
Add a --color flag with auto, always, and never, following the
convention used by common CLI tools. auto preserves today's behaviour including
the NO_COLOR and terminal checks, always forces color even when piped, and
never disables it. Decide how --color and the existing --no-color interact,
keeping --no-color working so nothing breaks, and reflect the resolution in
should_disable_color, which is already the unit-tested seam for this decision.

Acceptance criteria
 --color always produces colored output even when stdout is not a terminal.
 --color never disables color, and --color auto matches today's default
behaviour including NO_COLOR.
 The interaction between --color and --no-color is defined and documented.
 The resolution logic is covered by tests through should_disable_color.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/tri-state-color-flag
Suggested commit message:

feat: add a tri-state --color flag
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then
open a pull request from your fork against main and link this issue. See
docs/contributing.md for the full contribution guide.