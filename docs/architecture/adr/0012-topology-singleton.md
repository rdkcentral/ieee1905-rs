# ADR-0012: Topology Map Is Implemented as a Singleton

## Status
Accepted

## Context
The IEEE 1905 protocol core maintains a logical representation of the
network topology derived from discovery, signaling, and observation.
This topology map aggregates information such as:
- Devices and identifiers
- Neighbor relationships
- Media capabilities and interfaces
- Observed connectivity and attributes

Multiple subsystems consume topology information, including:
- Protocol state machines
- CMDU observers and handlers
- EasyMesh integration adapters
- Diagnostics, logging, and observability components

If each subsystem were to maintain its own topology view or copy of
topology state, this would introduce risks of:
- Divergent or inconsistent topology representations
- Complex synchronization and reconciliation logic
- Increased memory usage and lifecycle complexity
- Ambiguity about which view represents the current network state

## Decision
The topology map is implemented as a **Singleton**, representing a
single, authoritative in-memory view of observed IEEE 1905 topology
within the protocol instance.

All components:
- Read topology state from the same shared instance
- Update topology through well-defined mutation paths
- Observe changes via events or notifications, not by duplicating state

The singleton topology map exists within the scope of a single IEEE
1905 runtime instance (e.g., process or container).

## Rationale
IEEE 1905 topology is **informational and descriptive**, but it must
remain internally consistent at any given point in time.

Using a singleton topology map:
- Establishes a clear single source of truth for observed topology
- Eliminates ambiguity about topology ownership
- Simplifies reasoning about state changes and convergence
- Avoids costly synchronization between multiple topology replicas
- Aligns with the control-plane nature of IEEE 1905

Because topology updates originate from serialized protocol events
(CMDU reception, aging, refresh), a shared instance is both safe and
natural.

The singleton is scoped to the runtime instance and does not imply
global or distributed uniqueness beyond that boundary.

## Consequences

### Positive
- Single, consistent topology view across all subsystems
- Simplified integration with observers and adapters
- Reduced memory footprint and duplication
- Clear ownership and lifecycle management of topology state
- Easier debugging and observability
- Natural fit for event-driven update models

### Negative
- Requires discipline to avoid uncontrolled mutation
- May limit flexibility for isolated “what-if” simulations
- Testing requires explicit reset or reinitialization mechanisms
- Singleton misuse could lead to hidden dependencies if not scoped
  carefully

## Notes
- The singleton is **logically singular**, not globally static; it is
  created, owned, and destroyed with the IEEE 1905 runtime instance.
- Mutation of topology state must occur through explicit, controlled
  APIs to prevent accidental coupling.
- Consumers must treat the topology map as read-mostly and react to
  changes via events rather than polling or caching.

The topology map answers **“what do we currently observe?”**  
Having more than one answer inside a single control-plane instance
would undermine correctness.
