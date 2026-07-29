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

git checkout -b fix/suppressed-counts-in-summary
Suggested commit message:

fix: reflect suppression in the displayed severity counts
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then