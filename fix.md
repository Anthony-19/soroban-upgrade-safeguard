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
