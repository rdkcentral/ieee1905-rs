# ADR-0005: Use Facade Pattern for IEEE 1905 AL-SAP Integration

## Status
Accepted

## Context
The IEEE 1905 protocol core consists of multiple tightly coordinated
subsystems, including:
- CMDU reception and transmission pipelines
- TLV parsing, validation, and serialization
- Protocol state machines
- Event dispatching and observer coordination
- Platform and transport-specific integration layers

External consumers—such as EasyMesh control logic and higher-level
management components—require interaction with IEEE 1905 without
being exposed to its internal complexity, lifecycle management, or
protocol-specific execution model.

Direct access to internal subsystems would:
- Increase coupling between IEEE 1905 internals and external components
- Expose protocol lifecycle and concurrency details unnecessarily
- Complicate evolution of the IEEE 1905 core implementation
- Risk inconsistent usage patterns across integrations

## Decision
We will introduce an **AL-SAP (Abstraction Layer – Service Access Point)**
implemented as a **Facade** over the IEEE 1905 protocol core.

The AL-SAP facade will:
- Expose a small, stable, and intentional public API
- Encapsulate lifecycle management of the IEEE 1905 core
- Hide internal concurrency, threading, and async execution details
- Provide controlled access points for CMDU transmission and reception
- Serve as the primary integration boundary for EasyMesh and other
  external protocol consumers

Internal IEEE 1905 subsystems will remain inaccessible outside the
facade, enforcing architectural boundaries.

## Rationale
The Facade pattern is well suited for protocol stacks where:
- Internal complexity is high and unavoidable
- External integrations require a simplified interaction model
- Stability of the public interface is critical
- Internal refactoring should not ripple into dependent systems

In the context of IEEE 1905, AL-SAP provides:
- A clear ownership boundary for protocol lifecycle and resources
- Isolation of protocol internals from EasyMesh semantics
- A natural anchor point for validation, policy enforcement, and
  cross-cutting concerns
- A stable contract that can evolve independently of internal design

This approach aligns with standards-based protocol architecture, where
Service Access Points are explicitly defined to decouple layers.

## Consequences

### Positive
- Reduced coupling between IEEE 1905 internals and external consumers
- Clear architectural boundary for protocol integration
- Simplified usage for EasyMesh and higher-level components
- Improved maintainability and refactorability of the IEEE 1905 core
- Centralized enforcement of lifecycle and usage policies

### Negative
- Additional abstraction layer introduces some indirection
- Risk of the facade growing too large if responsibilities are not
  carefully scoped
- Requires discipline to prevent leakage of internal types or concepts
- Facade API must be designed carefully to avoid premature constraints

## Notes
The AL-SAP facade is responsible for **how** external components
interact with IEEE 1905, not **how** the protocol is internally
implemented.

Translation between EasyMesh and IEEE 1905 semantics is handled by
dedicated adapter components behind the facade, preserving separation
of concerns and preventing the facade from becoming a “god object”.
