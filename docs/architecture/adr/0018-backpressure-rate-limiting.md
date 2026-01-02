# ADR-0018: Backpressure and Rate-Limiting of Topology Events

## Status
Accepted

## Context
The IEEE 1905 topology map emits events in response to observed changes,
including:
- Discovery and refresh CMDUs
- Neighbor/link updates
- Capability changes
- Aging and garbage-collection removals

These events are consumed by multiple subsystems, most notably the
EasyMesh integration layer, which may perform non-trivial processing
(policy evaluation, coordination, reporting).

In dynamic or unstable network environments, topology updates may occur
in bursts (e.g., link flaps, device restarts, network partitions).
Unbounded event emission risks:
- Overwhelming downstream consumers
- Excessive CPU and memory usage
- Event queue growth and increased latency
- Feedback loops that delay convergence
- Reduced system stability on resource-constrained platforms

## Decision
Topology event emission is subject to **explicit backpressure and
rate-limiting mechanisms**.

The system applies the following controls:

1) **Bounded event queues**
   - Topology-change events are delivered through bounded queues or
     channels.
   - Queue capacity limits prevent unbounded memory growth.
   - Backpressure signals are propagated to the event producer.

2) **Event coalescing**
   - Multiple topology changes occurring within a short window may be
     coalesced into a single composite event.
   - Coalesced events represent the *net effect* of changes rather than
     each intermediate state.

3) **Rate limiting**
   - Event emission is rate-limited using configurable thresholds
     (e.g., maximum events per time window).
   - Rate limiting applies per consumer or per integration boundary,
     not globally.

4) **Loss-tolerant semantics**
   - Topology events are advisory signals, not transactional messages.
   - Dropped or coalesced events do not compromise correctness because
     consumers can always re-read current topology state or request a
     snapshot.

## Rationale
IEEE 1905 topology is informational and eventually consistent.
Therefore, correctness does not depend on delivering every intermediate
topology transition.

Applying backpressure and rate limiting:
- Preserves system stability under churn
- Prevents slow consumers from degrading the control plane
- Aligns with snapshot-based and event-driven consumption models
- Encourages consumers to react to *state*, not event volume
- Improves convergence behavior by focusing on stable outcomes

This design treats topology events as **signals**, not as a lossless
stream requiring guaranteed delivery.

## Consequences

### Positive
- Improved resilience under bursty or unstable conditions
- Bounded resource usage and predictable behavior
- Reduced coupling between topology producers and consumers
- Better convergence characteristics under load
- Simplified failure recovery (snapshots over replay)

### Negative
- Intermediate topology transitions may be skipped
- Consumers must not assume one-to-one correspondence between events
  and state changes
- Requires careful tuning of queue sizes and rate limits
- Additional implementation complexity for coalescing and signaling

## Notes
- Consumers must be designed to tolerate missed events and rely on
  snapshots or live reads for authoritative state.
- Event coalescing boundaries should be documented to avoid ambiguity.
- Rate-limiting parameters may vary by deployment profile.
- Backpressure applies only to event delivery, not to topology mutation,
  which remains serialized and controlled.

Topology events communicate **that something changed**,
not **everything that happened**.
