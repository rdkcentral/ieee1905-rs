# ADR-0013: Controlled Mutation and Locking Strategy for the Topology Map

## Status
Accepted

## Context
The topology map is a singleton, shared across multiple subsystems in
the IEEE 1905 runtime instance, including:
- CMDU reception observers and handlers
- Protocol state machines and timers
- EasyMesh integration adapters
- Diagnostics and observability components

The topology map is read frequently and updated when:
- Topology discovery/response CMDUs are processed
- Link/neighborhood events are observed
- Aging/expiration timers fire
- Capabilities or attributes change

Because the runtime uses asynchronous execution (Tokio) and an
event-driven processing model, concurrent access is expected.
Uncontrolled mutation (e.g., multiple components writing directly)
would introduce risks of:
- Races and inconsistent partial updates
- Hidden dependencies on execution order
- Deadlocks or priority inversions
- Difficult-to-reproduce concurrency bugs

## Decision
Topology mutation is **centralized and serialized** through a single
controlled update path, while read access remains broadly available.

Specifically:
1) **Single-writer principle**
   - All topology updates are performed by a designated Topology
     Manager (or equivalent owner component).
   - Other components must request changes by emitting events or
     update intents, not by mutating topology directly.

2) **Locking model**
   - The topology map is protected by an async-aware read/write lock
     (e.g., `tokio::sync::RwLock`) or equivalent concurrency primitive.
   - Read operations acquire a read lock.
   - Write operations acquire a write lock and are executed only by
     the single writer component.

3) **Short critical sections**
   - Write lock hold times must be minimized.
   - No blocking I/O, await points, or external calls are permitted
     while holding the write lock.
   - Updates are computed outside the lock when possible, then applied
     atomically within the lock.

4) **Event-driven propagation**
   - After mutation, the writer publishes a topology-changed event to
     observers (including EasyMesh integration).
   - Consumers should not rely on polling or caching mutable state.

## Rationale
This strategy balances correctness and performance:

- A single-writer model prevents conflicting concurrent writes and
  reduces the complexity of reasoning about topology evolution.
- An async-aware `RwLock` supports a read-mostly workload efficiently,
  while preserving safe concurrent access patterns.
- Short critical sections avoid runtime stalls and reduce contention,
  which is important on embedded platforms.
- Event-driven propagation aligns with the overall architecture
  (Observer pattern for CMDU processing) and supports eventual
  consistency between IEEE 1905 observations and EasyMesh intent.

This approach preserves a clear ownership boundary:
- Many readers
- Exactly one writer
- Explicit, observable update points

## Consequences

### Positive
- Strong consistency of the in-memory topology within a runtime instance
- Reduced risk of race conditions and partial/inconsistent updates
- Clear ownership model and easier architectural enforcement
- Efficient read performance under read-mostly workload
- Improved debuggability through explicit update events
- Easier testing by controlling mutation through one component

### Negative
- Writer component becomes a central dependency for topology evolution
- Some updates may be delayed if the writer event queue is backlogged
- Requires discipline to prevent “escape hatches” that mutate topology
  from other components
- Readers must avoid long-lived read locks to prevent writer starvation

## Notes
- If lock contention becomes measurable, consider:
  - Snapshot reads (copy-on-write or versioned snapshots)
  - Fine-grained internal partitioning of topology structures
  - Batched updates applied by the single writer
- Readers should prefer immutable snapshots or extracted views when
  performing non-trivial computations.
- The locking primitive is an implementation detail; the architectural
  requirement is **single-writer + controlled mutation**.

The topology map is shared, but topology updates are deliberate,
serialized, and observable.
