Support reading a WASM input from stdin
Repo Avatar
ShippedLabs/soroban-upgrade-safeguard
Description
load_wasm in src/loader.rs only reads from a filesystem path. There is no way
to stream a WASM binary in on stdin, which is the natural thing to do when the
build artifact is produced by an earlier pipeline stage and never written to disk,
or when it is piped out of another tool.

Supporting stdin, conventionally spelled as a - argument, removes a forced round
trip through a temporary file in exactly the CI setting this tool targets.

Suggested approach
Treat a - positional path as stdin and read the bytes from there, then run the
same validation the file path already runs. Because the tool takes up to two
positional paths, decide and document what happens if - is given for both, since
stdin can only be consumed once. The RPC mode already supplies the old side from
elsewhere, so - for the single new-side path is the most useful case to get
right.

Acceptance criteria
 A - argument reads a WASM binary from stdin and validates it like a file.
 Using - for both positions is either handled clearly or rejected with a
helpful message.
 Invalid data on stdin produces the same class of error as an invalid file.
 The behaviour is documented and covered by a test.
Description
detect_cascading_layout_breaks in src/diff.rs emits one Critical finding for
every type that transitively embeds a modified type. A widely shared type
therefore produces a fan-out of near-identical findings, one per dependent, on top
of the direct findings already emitted for the change itself. Nothing deduplicates
a direct finding against a cascade finding for the same type, and nothing groups
the fan-out under the single root cause that produced it. A large but routine
refactor can produce a report where the one change a reviewer needs to act on is
indistinguishable from dozens of mechanical consequences of it.

Why this matters
A safety report only works if a human reads it. Report volume that scales with the
dependency graph rather than with the number of decisions to make is the classic
failure mode of static analysis tools: reviewers stop reading, start scanning for
the summary line, and eventually rubber stamp the run. The severity counts are
also distorted, because one root cause inflates the Critical count by its fan-out,
which makes counts useless for tracking whether an upgrade is getting safer across
iterations. Suppression compounds the problem, since acknowledging a root cause
today requires writing one rule per affected dependent.

Root cause
Findings are modeled as a flat list with no identity and no relationships. The
cascade pass appends to the same list as the direct passes, with no link recording
that a cascade finding was derived from a specific root finding, so nothing
downstream can group, collapse, or suppress by root cause.

Acceptance criteria
Findings carry a stable identity suitable for deduplication.
A direct finding and a cascade finding for the same type are reconciled rather than both listed independently.
Cascade findings record the root finding they were derived from.
The report groups a cascade fan-out under its root cause.
Severity counts distinguish root causes from derived consequences.
A single root cause can be suppressed without writing one rule per dependent.
The full expanded list remains available in JSON for tooling that wants it.
The human-readable report defaults to the rolled-up view.
Rollup behavior is deterministic and consistent across all three formats.
A change to a type embedded by fifty others produces a report a reviewer can act on.
Multiple independent root causes are grouped separately, not merged.
A type broken by two distinct root causes appears under both with no double counting in totals.
Tests cover deep transitive chains, diamond-shaped dependency graphs, and cyclic type references.
The verdict is unchanged by rollup; only presentation and counting change.
Edge cases
Diamond dependencies where one type is reached through two paths. Cyclic type
references. A type that is both a root cause and a dependent of another root
cause. Cascade findings whose root was suppressed. Very deep chains where the
rollup itself becomes large. Dependents that appear only in the new spec.
SafetyReport::with_suppressions in src/report.rs increments critical_count,
warning_count, and info_count for every finding regardless of suppression, and
tracks the failing (unsuppressed) counts separately only to decide is_safe.

The summary the user reads prints the raw counts. So a run where the only critical
finding is suppressed shows:

Status: ✅ PASSED
Critical: 1
That reads as a contradiction. The verdict says safe, the count says one critical.
A reviewer has no way to tell from the numbers that the critical was acknowledged,
short of reading every finding line for the [SUPPRESSED] marker.

Expected behaviour
The displayed counts should make the suppressed portion legible, so the numbers
next to the verdict cannot contradict it. At minimum the active (failing) count
should be distinguishable from the suppressed count.

Suggested approach
Show the active and suppressed portions separately, for example an active critical
count with the suppressed count called out alongside, in the text summary, the
Markdown summary table, and the JSON counts. The report already carries
suppressed_count; the per-severity split needs to be tracked the same way the
failing counts already are. Keep the raw totals available where a consumer might
still want them.

Acceptance criteria

A report whose only critical finding is suppressed does not show a bare
Critical: 1 next to a PASSED verdict.

The active and suppressed portions of each severity are distinguishable in
text, Markdown, and JSON.

The verdict logic is unchanged; only the presentation of counts changes.

Tests cover a report with suppressed findings across all three formats.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/read-wasm-from-stdin
Suggested commit message:

feat: support reading a wasm input from stdin
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then
open a pull request from your fork against main and link this issue. See
docs/contributing.md for the full contribution guide.


git checkout -b fix/suppressed-counts-in-summary
Suggested commit message:

fix: reflect suppression in the displayed severity counts
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then
