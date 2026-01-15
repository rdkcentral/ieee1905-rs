# ADR-0006: Use `nom` for IEEE 1905 TLV/CMDU Parsing and (De)Serialization

## Status
Accepted

## Context
The IEEE 1905 protocol core processes CMDUs containing TLV-encoded
payloads. This requires:
- Robust parsing of untrusted network input (including malformed frames)
- Strict conformance to binary layout (length fields, endianness, bounds)
- Efficient handling on embedded Linux (avoid unnecessary allocations)
- Support for incremental evolution (new TLVs, vendor-specific TLVs)
- Clear separation between parsing/validation and protocol logic

A hand-rolled parser/serializer increases risk of:
- Boundary and length bugs
- Inconsistent parsing behavior across TLV types
- Drift between parsing and serialization logic over time
- Hard-to-test error handling for malformed/partial inputs

## Decision
We will use the Rust `nom` crate as the primary mechanism for:
- Parsing CMDU headers and TLV payloads
- Enforcing bounds checks and length-driven parsing
- Producing structured protocol types from byte slices
- Supporting symmetric (de)serialization by pairing each parser with a
  corresponding serializer at the same abstraction layer

Parsing functions will follow a consistent contract:
- Input: `&[u8]` (or `Bytes` / `&[u8]` views)
- Output: strongly typed protocol structs + remaining slice
- Errors: explicit, categorized parsing errors suitable for telemetry
  and interoperability debugging

Serialization will be implemented as explicit “write” functions colocated
with the parse definitions, designed to be the inverse of the parser for
each TLV/CMDU structure (round-trip stable).

## Rationale
`nom` is well suited for standards-based binary protocols because it:
- Encourages length-safe, composable parsers (critical for TLV formats)
- Supports zero-copy parsing patterns where feasible
- Makes parsing behavior explicit and testable
- Provides structured error handling paths for malformed inputs
- Scales with protocol growth through reusable combinators

For IEEE 1905 specifically, `nom` helps reduce risk in the most sensitive
area of the stack: interpreting externally sourced binary data.

Colocating parse/serialize logic at the same layer reduces long-term
protocol drift and improves maintainability as new TLVs and extensions
are introduced.

## Consequences

### Positive
- Reduced likelihood of buffer/length handling bugs in TLV/CMDU parsing
- Cleaner, composable parsing structure aligned with TLV semantics
- Better testability (unit tests, property tests, fuzzing, round-trips)
- Easier extension for vendor-specific and optional TLVs
- Potential for zero-copy parsing to reduce allocations on embedded targets

### Negative
- Contributor learning curve for parser combinator style
- Error types and debugging require discipline and conventions
- Risk of overly “clever” combinator usage reducing readability
- Serialization must be carefully kept symmetric with parsing to avoid
  interoperability issues

## Notes
- Parsing is treated as a two-phase process:
  1) Parse (structure and bounds)
  2) Validate (semantic checks, protocol constraints)
- Each TLV/CMDU type must provide:
  - `parse(...) -> Result<(remaining, value), error>`
  - `write(...) -> Result<(), error>` (or equivalent)
- Round-trip tests are mandatory for new TLVs:
  `bytes -> parse -> write -> bytes'` (and equivalence rules where
  normalization applies).
