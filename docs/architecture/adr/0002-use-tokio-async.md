# ADR-0002: Use Tokio and Asynchronous Programming for IEEE 1905 Processing

## Status
Accepted

## Context
The IEEE 1905 protocol core operates as a long-lived control-plane
component responsible for receiving, parsing, processing, and
emitting CMDUs across multiple networking interfaces.

Key characteristics of the workload include:
- Concurrent reception of CMDUs from multiple interfaces
- Event-driven processing triggered by network input
- Interaction with timers, retries, and protocol state machines
- Integration with platform services and control-plane components
- Requirement for responsiveness under variable network conditions

A traditional synchronous or thread-per-connection model would
require explicit thread management, locking, and blocking I/O,
increasing complexity and risk of contention or deadlocks in a
protocol-critical path.

## Decision
We will use **Tokio** as the asynchronous runtime and adopt an
**event-driven, asynchronous programming model** for the IEEE 1905
protocol core.

Asynchronous execution will be used for:
- Network I/O (CMDU send/receive)
- Internal message dispatching
- Timer-based protocol events
- Coordination between protocol state machines

Synchronous code will still be used where appropriate for:
- Pure computation
- Deterministic state transitions
- Protocol validation logic
- Small, self-contained operations without I/O

## Rationale
Tokio provides a mature and widely adopted asynchronous runtime
aligned with Rust’s ownership and safety guarantees.

Specific benefits for IEEE 1905 protocol development include:
- Efficient handling of multiple concurrent CMDU streams without
  blocking threads
- Clear separation between I/O-bound and CPU-bound logic
- Scalable event handling with predictable resource usage
- Natural modeling of protocol events, timers, and retries
- Reduced need for explicit locking through structured concurrency

The asynchronous model aligns closely with the inherently
event-driven nature of IEEE 1905 control-plane protocols.

## Consequences

### Positive
- Improved scalability when handling multiple simultaneous CMDUs
- Better responsiveness under load or slow I/O conditions
- Reduced risk of deadlocks compared to blocking designs
- Clearer expression of protocol workflows driven by events
- Efficient use of limited resources on embedded Linux platforms

### Negative
- Increased conceptual complexity for contributors unfamiliar
  with asynchronous Rust
- More difficult debugging compared to purely synchronous code
- Risk of misuse of blocking operations within async contexts
- Need for discipline in separating async orchestration from
  synchronous protocol logic

## Notes
Asynchronous programming is treated as an **execution model**, not
a replacement for clear protocol design.

Protocol state machines and validation logic remain explicit and
deterministic, while Tokio is used to orchestrate concurrency,
I/O, and timing concerns around them.
