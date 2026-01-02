# ADR-0016: Observability and Debugging of Convergence Between IEEE 1905 and EasyMesh

## Status
Accepted

## Context
The integration between IEEE 1905 and EasyMesh follows an **eventual
consistency model**, where:
- IEEE 1905 produces asynchronous observations (topology, capabilities)
- EasyMesh produces policy-driven intent and configuration
- Convergence emerges over time through repeated observation,
  decision, and enforcement cycles

During normal operation, temporary divergence is expected. However,
without explicit observability, it becomes difficult to:
- Distinguish normal convergence from fault conditions
- Understand why convergence is slow or stalled
- Diagnose mismatches between observed topology and management intent
- Debug issues in multi-node or heterogeneous deployments

Traditional logging alone is insufficient to reason about distributed,
time-dependent convergence behavior.

## Decision
The system provides **explicit observability for convergence**, treating
convergence as a first-class operational concern.

This includes:

1) **Topology versioning**
   - Each topology update increments a monotonic version or generation
     identifier.
   - Version identifiers are propagated in events delivered to EasyMesh
     integration layers.

2) **Event correlation**
   - Topology-change events, policy decisions, and enforcement actions
     carry correlation metadata (timestamps, source, version).
   - This enables tracing “observation → decision → action” chains.

3) **Convergence state signals**
   - The system exposes high-level indicators such as:
     - “Topology stable / unstable”
     - “Convergence in progress”
     - “Convergence stalled”
   - These are derived from activity and aging heuristics, not strict
     correctness assertions.

4) **Structured diagnostics**
   - Debug output favors structured, machine-readable formats over
     free-form logs.
   - Observability data can be consumed by diagnostics tools, tests,
     or higher-level management systems.

## Rationale
Convergence is not a single event, but a process.

Explicit observability:
- Makes expected temporary divergence visible and understandable
- Prevents misinterpretation of normal convergence as failure
- Enables targeted debugging without invasive instrumentation
- Supports validation, interoperability testing, and field diagnosis
- Aligns with distributed-systems best practices

By exposing convergence signals, the system becomes diagnosable without
requiring deep protocol knowledge at every integration point.

## Consequences

### Positive
- Clear visibility into convergence progress and health
- Faster root-cause analysis of integration issues
- Reduced reliance on ad-hoc logging and guesswork
- Improved confidence during deployment and evolution
- Better tooling and testability for multi-node scenarios

### Negative
- Additional metadata and bookkeeping overhead
- Requires discipline to maintain correlation semantics
- Observability signals may be heuristic, not definitive

## Notes
- Convergence observability does not imply convergence guarantees.
- Signals are advisory and intended for debugging and monitoring.
- Consumers must not block or gate functionality on convergence
  indicators alone.

Convergence is **observable**, not instantaneous.
