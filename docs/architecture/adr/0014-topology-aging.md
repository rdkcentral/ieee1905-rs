# ADR-0014: Topology Aging and Garbage-Collection Strategy

## Status
Accepted

## Context
The IEEE 1905 topology map represents an observed view of network
connectivity derived from distributed discovery and signaling.

Topology entries (devices, neighbors, links, capabilities) may become
stale due to:
- Device removal or power-off
- Link failure or media changes
- Temporary network partitions
- Missed or delayed protocol messages
- Asynchronous convergence between IEEE 1905 and EasyMesh

Because topology is **informational and eventually consistent**, the
protocol must tolerate transient inaccuracies while ensuring that
obsolete state does not persist indefinitely.

Relying solely on explicit teardown or removal events is insufficient,
as such events are not guaranteed to be observed in distributed
networks.

## Decision
Topology state is subject to **explicit aging and garbage collection
(GC)** based on time and observation activity.

The topology map implements the following strategy:

1) **Timestamped observations**
   - Each topology element (device, neighbor, link, capability) carries
     a `last_seen` or equivalent timestamp.
   - Timestamps are updated only when relevant protocol evidence is
     observed (e.g., valid CMDUs, refresh events).

2) **Aging thresholds**
   - Configurable aging intervals define when topology elements are
     considered *stale*.
   - Staleness does not immediately imply removal; it marks entries as
     candidates for garbage collection.

3) **Garbage-collection cycles**
   - A periodic GC task evaluates topology entries against aging rules.
   - Entries exceeding defined expiration thresholds are removed in a
     controlled manner.
   - GC runs under the same single-writer mutation model as other
     topology updates.

4) **Event-driven notification**
   - Removals caused by aging or GC trigger topology-change events.
   - Consumers (including EasyMesh integration) are notified explicitly
     rather than inferring disappearance implicitly.

## Rationale
Aging and garbage collection are essential for maintaining a usable
topology view in a distributed control-plane protocol.

This strategy:
- Avoids permanent retention of obsolete or misleading topology state
- Tolerates partial, delayed, or missing observations
- Preserves robustness under network churn and failure conditions
- Aligns with the eventual consistency model between IEEE 1905 and
  EasyMesh
- Keeps topology maintenance independent of explicit teardown semantics

By decoupling topology removal from instantaneous observations, the
system avoids oscillations and overreaction to transient conditions.

## Consequences

### Positive
- Prevents unbounded growth of topology state
- Improves accuracy of long-lived topology views
- Graceful handling of silent failures and disappearances
- Clear, observable lifecycle for topology elements
- Consistent behavior across heterogeneous media and platforms
- Simplifies reasoning about convergence and recovery

### Negative
- Topology entries may persist briefly after actual disappearance
- Aging parameters require tuning for different deployment scenarios
- GC cycles introduce periodic mutation activity
- Consumers must tolerate delayed removal of stale information

## Notes
- Aging thresholds should reflect protocol characteristics and expected
  refresh behavior, not instantaneous data-plane dynamics.
- Different topology elements may use different aging intervals
  (e.g., devices vs links vs capabilities).
- GC must not run concurrently with other writers; it follows the same
  controlled mutation and locking strategy.
- Aging state is **heuristic**, not authoritative, and must be treated
  as such by consumers.

Topology is maintained as a **living, self-healing view**:
it decays gracefully when observations stop, rather than failing
abruptly or persisting indefinitely.
