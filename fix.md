A change from BytesN<32> to BytesN<64> is reported through the generic
type-changed path in src/diff.rs. The message is "type changed from BytesN<32>
to BytesN<64>" and the guidance is the generic advice to revert or migrate.

A fixed-size byte array is a common, meaningful type in Soroban contracts: 32-byte
hashes, keys, and identifiers. Changing its length is a specific and recognisable
migration, distinct from swapping one type for an unrelated other, and the report
gives no signal that this is a size change rather than an arbitrary type swap.

Expected behaviour
A change that only alters the N of a BytesN<N>, on either side of a field,
parameter, return, or union case, should be reported as a byte-array size change
with guidance specific to it.

Suggested approach
Detect the BytesN(a) -> BytesN(b) case before falling back to the generic
type-changed finding, everywhere a type change is currently reported. Add a
dedicated category with its own remediation guidance, since src/report.rs
asserts every emitted category has guidance.

Acceptance criteria

A BytesN<N> size change is reported as a distinct, clearly worded finding.

The classification applies to struct fields, parameters, return types, and
union case payloads.

A change between BytesN and an unrelated type still falls through to the
generic finding.

The new category has remediation guidance and unit tests in src/diff.rs.
Getting started
Fork this repository, clone your fork, and add this repo as upstream:

git clone https://github.com/<your-username>/soroban-upgrade-safeguard.git
cd soroban-upgrade-safeguard
git remote add upstream https://github.com/ShippedLabs/soroban-upgrade-safeguard.git
Create a branch for this issue:

git checkout -b feat/classify-bytesn-size-changes
Suggested commit message:

feat: report BytesN size changes as a distinct finding
Run cargo fmt --check, cargo clippy, and cargo test