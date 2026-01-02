# ADR-0017: Failure Isolation Between IEEE 1905 and EasyMesh

## Status
Accepted

## Context
IEEE 1905 and EasyMesh operate as distinct control-plane components with
different responsibilities, lifecycles, and failure modes.

Failures may occur independently in either component, including:
- IEEE 1905 protocol errors or restarts
- EasyMesh controller/agent crashes or misconfiguration
- Temporary loss of communication between components
- Partial platform failures or resource exhaustion

Tightly coupling failure handling between the two systems would risk:
- Cascading failures across control planes
- Loss of discovery due to management instability
- Loss of management due to protocol-level issues
- Reduced system resilience and recoverability

## Decision
Failures in IEEE 1905 and EasyMesh are **explicitly isolated**.

Specifically:
- IEEE 1905 continues discovery and topology maintenance regardless
  of EasyMesh availability.
- EasyMesh tolerates temporary loss or restart of IEEE 1905 and
  reconsumes topology upon recovery.
- No component assumes continuous availability of the other.
- Integration boundaries (AL-SAP, adapters) are designed to degrade
  gracefully and recover automatically.

State synchronization is **reconstructive**, not incremental:
- Upon recovery, components re-establish state from fresh observations
  rather than attempting to replay missed events.

## Rationale
Failure isolation is critical in distributed control-plane systems.

This approach:
- Prevents cascading failures
- Enables independent restart and upgrade of components
- Supports containerized and isolated deployment models
- Aligns with the eventual consistency integration model
- Simplifies recovery logic by favoring re-observation over replay

IEEE 1905 is resilient by design; EasyMesh must be able to reattach to
an evolving topology without assuming uninterrupted history.

## Consequences

### Positive
- Improved overall system robustness
- Independent lifecycle management of control-plane components
- Faster recovery from partial failures
- Simplified error-handling and restart semantics
- Better alignment with containerization and isolation strategies

### Negative
- Temporary loss of coordination during component outages
- Reconciliation logic required after recovery
- Some management actions may need to be retried or rederived

## Notes
- Failure isolation does not imply lack of coordination, only lack of
  hard dependency.
- Observability mechanisms (see ADR-0016) are critical for diagnosing
  failure-induced divergence.
- EasyMesh must treat IEEE 1905 as a dynamic signal source, not a
  transactional data provider.

IEEE 1905 and EasyMesh **cooperate**, but they do not **fail together**.
