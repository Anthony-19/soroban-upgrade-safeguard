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


