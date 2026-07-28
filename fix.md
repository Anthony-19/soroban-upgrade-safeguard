Add a --quiet flag to suppress decorative and progress output
Repo Avatar
ShippedLabs/soroban-upgrade-safeguard
Description
There is no way to silence the decorative output. Every run prints the banner, the
loading lines, the per-spec summaries, and in batch mode the per-pair progress,
through the progress closure in src/main.rs.

For scripting and for CI logs that only care about the verdict and the findings,
that is noise. In text mode it is mixed into stdout with the report itself, so it
cannot even be filtered out by discarding stderr.

Suggested approach
Add a --quiet flag that suppresses the decorative and progress output while still
emitting the report and preserving the exit code. In text mode the report itself
must still reach stdout; only the progress and banner lines are suppressed. Make
sure it composes sensibly with the JSON and Markdown formats, which already route
progress to stderr, so --quiet there simply silences that stderr chatter.

Acceptance criteria
 --quiet suppresses the banner and progress lines in all formats.
 The report and the exit code are unchanged by the flag.
 In text mode the report still reaches stdout with the decoration removed.
 The flag is documented and covered by a test.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/quiet-flag
Suggested commit message:

feat: add a --quiet flag
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then
open a pull request from your fork against main and link this issue. See
docs/contributing.md for the full contribution guide.


