recommended_bump in src/report.rs maps any run with Info findings and no
higher severity to minor. Its own doc comment states this is deliberate: "Info
findings present -> minor".

But the Info category includes documentation string changes, which alter no
interface, no storage layout, and no runtime behaviour. Under SemVer a change that
affects neither the API nor behaviour is a patch, not a minor. So a build whose
only difference is a reworded doc comment is told to cut a minor release, which
overstates the change.

Expected behaviour
A run whose only findings are non-functional, such as documentation changes,
should recommend patch. Additive-but-functional Info findings, such as a new
function or a new enum case, should still recommend minor.

Suggested approach
Distinguish the non-functional Info categories, principally the documentation-change
categories, from the additive ones when computing the bump. The distinction can key
on category, which is already the stable identifier used elsewhere. Update the doc
comment on recommended_bump to describe the refined rule.

Acceptance criteria

A run whose only findings are documentation changes recommends patch.

A run with additive Info findings such as a new function still recommends
minor.

Warning and Critical behaviour is unchanged.

The existing semver-bump test is extended to cover the documentation-only
case.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/doc-only-change-recommends-patch
Suggested commit message:

feat: recommend patch for documentation-only changes
Run cargo fmt --check, cargo clippy, and cargo test before pushing, then