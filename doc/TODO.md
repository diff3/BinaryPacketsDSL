# TODO – BinaryPacketsDSL

## High Priority

### Bitmask Handler
- Description: Support for fields represented as bitmasks (e.g., 1B, 2B), where each bit can indicate a separate flag or condition.
- Importance: Essential for decoding control flags and option sets, heavily used in protocols like WoW.

### If / Elif / Else
- Description: Conditional parsing based on previously extracted values.
- Importance: Required for dynamic packet structures where content depends on flags or types.

### Zip / Unpack
- Description: Ability to combine multiple values into a single field or expand a group into subfields.
- Importance: Simplifies expression of tightly packed fields and grouped data structures.

## Medium Priority

### Enum / Get_Value
- Description: Use constants or value lookups from external files (e.g., `AUTH_OK = 12`).
- Importance: Enables semantic value parsing and validation against known sets.

### Enhanced Slicing
- Description: Advanced slicing for variables (e.g., `€var[1:4]`) on strings and byte sequences.
- Importance: Improves expressiveness and allows finer control over variable content.

### Improved Arithmetic
- Description: Support for more complex math operations (e.g., `€a + €b * 2`, `€len - 1`).
- Importance: Necessary to reduce the need for manual pre-calculation and support compact logic in DSL.