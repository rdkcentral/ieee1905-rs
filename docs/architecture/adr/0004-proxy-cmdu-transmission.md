# ADR-0004: Use Proxy Pattern for CMDU Transmission

## Status
Accepted

## Context
The IEEE 1905 protocol core must transmit CMDUs across multiple
interfaces and transport mechanisms (e.g., different link layers,
bridged domains, platform integration points).

CMDU transmission is not a simple "send bytes" operation. It commonly
requires:
- Selection of egress interface(s) based on topology and policy
- Addressing decisions (unicast vs multicast)
- Message decoration (e.g., insertion/normalization of TLVs)
- Validation and conformance checks before emission
- Observability (logging, metrics, tracing)
- Rate limiting, retries, and error mapping to protocol outcomes
- Platform-specific transmission constraints and API differences

If protocol components send directly via low-level platform/network
APIs, the codebase becomes tightly coupled to transport details and
inconsistent behavior can emerge (different validation, logging,
or policy across call sites).

## Decision
We will introduce a **CMDU Transmission Proxy** that acts as the
single entry point for emitting CMDUs.

All protocol subsystems will request transmission through the proxy,
which will:
- Enforce consistent validation and conformance checks
- Apply policy (interface selection, addressing mode, rate limits)
- Perform message finalization (normalization / optional TLV injection)
- Provide a stable interface independent of platform specifics
- Centralize observability and error reporting

The proxy will delegate the actual send operation to transport-
specific adapters/drivers behind a common interface.

## Rationale
The Proxy pattern provides controlled access to a complex operation
while keeping protocol logic decoupled from transport mechanisms.

For IEEE 1905 implementations, this yields:
- A consistent, auditable transmission path for all CMDUs
- Reduced coupling between protocol logic and platform APIs
- A natural place to implement cross-cutting concerns (policy,
  observability, rate limiting)
- Improved testability through mockable transmission interfaces
- Easier evolution as new interfaces or transport requirements appear

This is especially valuable in heterogeneous environments where
CMDU emission behavior must remain uniform across devices and
platform configurations.

## Consequences

### Positive
- Single, consistent transmission policy across the system
- Centralized conformance validation reduces protocol drift
- Improved observability and easier debugging of "why was this sent?"
- Simplified unit/integration testing via mocked proxy/adapters
- Cleaner separation between protocol state machines and I/O details
- Easier integration of future transports or platform APIs

### Negative
- Additional abstraction layer may increase perceived complexity
- Risk of creating a "god object" if responsibilities are not kept
  tightly scoped
- Potential performance overhead if the proxy performs excessive
  copying or synchronization
- Requires clear contracts for error semantics and retry behavior

## Notes
The transmission proxy is responsible for **how** a CMDU is emitted,
not **what** the protocol decides to emit.

Protocol subsystems remain the authority for message intent and
state transitions, while the proxy provides uniform enforcement of
policies, conformance, and transport delegation.
