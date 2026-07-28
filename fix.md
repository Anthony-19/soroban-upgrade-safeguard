When a field or parameter is a container such as Vec<T>, Map<K, V>,
Option<T>, or a tuple, and only the inner type changes, src/diff.rs reports the
change by stringifying the entire outer type on each side.

So a field going from Map<Address, u32> to Map<Address, u64> produces:

type changed from `Map<Address, u32>` to `Map<Address, u64>`
leaving the reader to diff two signatures by eye to find that only the value type
changed. For deeply nested types such as Vec<Map<Address, Vec<u32>>> this gets
progressively harder to read, which defeats the point of a message that is
supposed to make the change obvious.

Expected behaviour
The finding should point at the specific inner type that changed rather than
restating the whole outer signature, while still giving enough context to locate
it.

Suggested approach
When the outer type constructors match and differ only in a type argument, recurse
to describe the innermost difference, for example "the value type of Map changed
from u32 to u64". Keep the full-signature form as a fallback for cases where the
outer constructors themselves differ. This is presentation only and should not
change severity or which findings are produced.

Acceptance criteria

A change confined to an inner type of a container names the inner type that
changed rather than restating the whole signature.

A change to the outer constructor itself still reports clearly.

Severity and the set of findings produced are unchanged.

Unit tests in src/diff.rs cover nested Vec, Map, Option, and tuple
cases.
