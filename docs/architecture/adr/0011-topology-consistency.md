# ADR-0011: Eventual Consistency Model Between IEEE 1905 and EasyMesh

## Status
Accepted

## Context
IEEE 1905 and EasyMesh operate as complementary control-plane systems
with distinct responsibilities:

- IEEE 1905 provides distributed discovery and signaling across
  heterogeneous media, producing an observed view of network topology
  and capabilities.
- EasyMesh provides centralized or logically centralized management,
  policy, and coordination, producing an intended or desired network
  state.

Both systems exchange information and influence network behavior, but
they operate with different scopes, timing, and update mechanisms.

Due to the distributed nature of IEEE 1905 discovery and the
policy-driven nature of EasyMesh management, it is not feasible to
maintain a strictly synchronized or strongly consistent shared state
between the two systems at all times.

## Decision
The integration between IEEE 1905 and EasyMesh follows an **eventual
consistency model**.

Specifically:
- IEEE 1905 produces topology and capability updates asynchronously
  based on observed network events.
- EasyMesh consumes these updates as informational input and applies
  policy decisions independently.
- Temporary divergence between observed topology (IEEE 1905) and
  intended state (EasyMesh) is expected and acceptable.
- The system converges over time as discovery, policy application, and
  enforcement cycles progress.

No attempt is made to enforce immediate or global consistency between
the two control planes.

## Rationale
Strong consistency between IEEE 1905 and EasyMesh would require:
- Tight coupling between discovery and management operations
- Global synchronization and blocking behavior
- Explicit coordination across distributed nodes and media
- Complex rollback or transactional semantics

Such requirements conflict with:
- The asynchronous and distributed design of IEEE 1905
- The need for responsiveness and resilience in management operations
- The realities of heterogeneous and dynamic network environments

An eventual consistency model:
- Aligns with the asynchronous nature of discovery and signaling
- Avoids circular dependencies between observation and enforcement
- Allows each system to operate independently within its domain
- Provides robustness against transient failures and partial views

## Consequences

### Positive
- Clear separation of control-plane responsibilities
- Improved resilience to network churn and transient failures
- Reduced complexity in integration logic
- Better scalability in large or dynamic deployments
- Natural tolerance of delayed or out-of-order updates
- Easier reasoning about failure and recovery scenarios

### Negative
- Temporary discrepancies between observed and intended state
- Management actions may be based on stale or partial topology data
- Requires careful handling of convergence and reconciliation logic
- Debugging may involve understanding asynchronous interactions
  across control planes

## Notes
- Convergence is driven by repeated discovery, signaling, and policy
  enforcement cycles rather than strict synchronization.
- EasyMesh should treat IEEE 1905 inputs as **signals**, not
  assertions.
- IEEE 1905 does not attempt to validate or enforce EasyMesh intent.
- Integration components must be designed to tolerate drift and
  reordering of events.

IEEE 1905 answers **“what do we observe now?”**  
EasyMesh answers **“what should the network look like?”**  
Convergence happens **over time**, not instantaneously.
