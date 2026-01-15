# ADR-0003: Use Observer Pattern for CMDU Reception and Processing

## Status
Accepted

## Context
The IEEE 1905 protocol core receives Control Message Data Units
(CMDUs) from multiple sources, including different network interfaces
and internal control-plane components.

Once a CMDU is decoded and validated, it may require processing by
multiple, logically independent subsystems, such as:
- Protocol state machines
- Topology discovery and maintenance
- Link and neighbor management
- Vendor-specific extensions
- Diagnostics, logging, or metrics collection

A tightly coupled, direct-dispatch model (e.g., large switch
statements or hard-wired call chains) would increase coupling between
CMDU reception and processing logic, making the system harder to
extend, test, and evolve as the protocol or its extensions grow.

## Decision
We will adopt an **Observer (publish–subscribe) design pattern** for
CMDU reception and processing.

After a CMDU is received, parsed, and validated, it will be published
as an event to a set of registered observers. Each observer will:
- Declare interest in specific CMDU types or events
- Process the CMDU independently
- Operate without direct knowledge of other observers

The CMDU reception pipeline remains the single authority for:
- Message decoding
- Validation and normalization
- Lifetime and ownership of CMDU data

## Rationale
The Observer pattern aligns naturally with the characteristics of
IEEE 1905 control-plane protocols:

- Multiple protocol functions may react to the same CMDU
- Processing paths vary by CMDU type and system configuration
- Extensions (including vendor-specific TLVs) must not impact core
  protocol handling
- Protocol logic benefits from loose coupling and explicit boundaries

Using observers enables:
- Decoupling of message reception from protocol logic
- Independent evolution of protocol subsystems
- Clear ownership and lifecycle management of CMDUs
- Easier testing of individual CMDU consumers

## Consequences

### Positive
- Reduced coupling between CMDU reception and processing logic
- Improved extensibility for new CMDU types or protocol features
- Cleaner separation of concerns across protocol subsystems
- Simplified integration of vendor-specific or experimental handlers
- Ability to enable or disable observers without altering core logic

### Negative
- Increased indirection when tracing CMDU processing paths
- Potential ordering concerns when multiple observers act on the same
  CMDU
- Need for well-defined observer registration and filtering rules
- Risk of hidden dependencies if observers are not carefully designed

## Notes
The Observer pattern is applied strictly at the **protocol event
distribution level**.

Observers must remain side-effect aware and must not implicitly
depend on execution order unless explicitly documented. Protocol
state transitions remain explicit and deterministic within each
observer, preserving clarity and correctness of the overall system.
