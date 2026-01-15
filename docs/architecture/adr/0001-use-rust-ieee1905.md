# ADR-0001: Use Rust for IEEE 1905 Protocol Core

## Status
Accepted

## Context
The system implements core components of the IEEE 1905 family of
protocols, including message parsing, validation, state management,
and inter-component communication across heterogeneous networking
technologies.

Key characteristics of IEEE 1905 protocol implementations include:
- Binary, TLV-based message formats
- Strict conformance to protocol specifications
- Concurrent handling of multiple control messages
- Long-lived processes with continuous network interaction
- High sensitivity to malformed or unexpected input
- Operation on embedded Linux platforms with limited resources

Historically, protocol stacks of this nature have been implemented
in C or C++, which exposes the system to risks related to memory
safety, buffer management, and concurrency correctness—especially
when handling externally sourced network data.

## Decision
We will use **Rust** as the primary implementation language for the
IEEE 1905 protocol core, including:
- CMDU encoding and decoding
- TLV parsing and serialization
- Protocol state machines
- Internal message dispatching and event handling

Rust is selected due to its ability to express protocol constraints
and ownership semantics at compile time, reducing the risk of
runtime failures in protocol-critical paths.

C or other languages may still be used for:
- Integration with existing C-based networking stacks or SDKs
- Platform-specific bindings where Rust support is not available
- Performance-critical paths requiring direct hardware interaction

## Rationale
Rust provides specific advantages for protocol design and development:

- Memory-safe handling of untrusted network input
- Strong typing for protocol fields and TLVs
- Explicit ownership and lifetime management aligned with protocol
  message lifecycles
- Safer concurrency for handling parallel CMDU processing
- Clear separation between parsing, validation, and execution phases

These characteristics align closely with the requirements of
standards-based protocol implementations, where correctness and
robustness are more critical than raw developer convenience.

## Consequences

### Positive
- Elimination of buffer overflows and use-after-free issues in TLV
  and CMDU handling
- Safer evolution of protocol features and extensions
- Improved clarity in protocol state transitions
- Easier reasoning about message ownership and lifetimes
- Increased confidence when handling malformed or non-compliant peers

### Negative
- Higher entry barrier for contributors unfamiliar with Rust
- Increased upfront design effort for type-safe protocol models
- More complex FFI boundaries when integrating with C components like RBUS
- Potential compile-time overhead during development

## Notes
This decision reflects a long-term strategy prioritizing protocol
correctness, robustness, and maintainability for IEEE 1905-based
systems operating in heterogeneous and potentially hostile network
environments.
