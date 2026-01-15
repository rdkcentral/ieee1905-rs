# ADR-0010: How IEEE 1905 Topology Is Consumed by EasyMesh

## Status
Accepted

## Context
IEEE 1905 provides mechanisms for discovering and maintaining a
logical view of network topology across heterogeneous media. This
topology includes:
- Device identifiers and roles
- Neighbor relationships
- Supported interfaces and media
- Observed connectivity and capabilities

EasyMesh, on the other hand, operates as a **network management and
coordination framework** responsible for:
- Network-wide policy decisions
- Controller/Agent coordination
- Steering, onboarding, and configuration
- Enforcement of management intent

Both systems interact closely, but they operate at different layers
and with different responsibilities.

A naïve integration could treat IEEE 1905 topology as authoritative
input for EasyMesh decision-making, tightly coupling the two protocols
and blurring control boundaries.

## Decision
IEEE 1905 topology is consumed by EasyMesh as **informational input**,
not as an authoritative or prescriptive data source.

Specifically:
- IEEE 1905 provides **observed topology signals** to EasyMesh
- EasyMesh uses these signals as one input among others
- EasyMesh remains the authority for policy, configuration, and
  management decisions
- IEEE 1905 does not enforce or validate EasyMesh decisions

The interaction between the two protocols is mediated through a
well-defined integration boundary (e.g., AL-SAP + adapters), preserving
loose coupling.

## Rationale
IEEE 1905 and EasyMesh serve complementary but distinct roles:

- IEEE 1905 excels at **discovery and coordination** across media
- EasyMesh excels at **management and control** at the network level

Treating IEEE 1905 topology as advisory allows EasyMesh to:
- Correlate topology with additional information sources
  (policy, configuration state, runtime metrics)
- Tolerate partial, delayed, or transient topology views
- Make decisions based on intent rather than raw observations
- Evolve independently of IEEE 1905 protocol details

This approach avoids circular dependencies where management decisions
would depend on topology that is itself influenced by management actions.

## Consequences

### Positive
- Clear separation of responsibilities between protocols
- Reduced coupling between IEEE 1905 and EasyMesh implementations
- Improved robustness against transient topology inconsistencies
- Easier evolution of both protocols and their implementations
- Ability for EasyMesh to apply policy without being constrained by
  protocol-level discovery semantics
- Simplified interoperability testing and reasoning

### Negative
- EasyMesh decisions may occasionally diverge from observed topology
- Additional correlation logic required at the integration layer
- Debugging may require understanding both observed and intended state

## Notes
- IEEE 1905 topology should be treated as **descriptive**, not
  prescriptive.
- EasyMesh may enrich IEEE 1905 topology with:
  - Configuration state
  - Policy constraints
  - Historical data
  - Vendor-specific knowledge
- Discrepancies between IEEE 1905 observations and EasyMesh intent are
  expected and must be handled gracefully.

IEEE 1905 answers **“what do we see?”**  
EasyMesh answers **“what should we do?”**
