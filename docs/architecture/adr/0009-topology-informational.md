# ADR-0009: IEEE 1905 Topology Is Informational, Not Authoritative

## Status
Accepted

## Context
IEEE 1905 provides mechanisms for topology discovery and maintenance
across heterogeneous networking technologies. Through CMDUs such as
Topology Discovery and Topology Response messages, the protocol builds
a view of the network that includes:
- Devices and their identifiers
- Neighbor relationships
- Supported media and capabilities
- Observed connectivity paths

This topology information is derived from protocol exchanges and
reflects the current observations of participating nodes.

An alternative architectural interpretation would be to treat the
IEEE 1905 topology as **authoritative**, meaning:
- The protocol dictates actual forwarding paths
- The topology view is the single source of truth for connectivity
- Lower layers must conform to the topology state maintained by
  IEEE 1905

Such an interpretation would elevate IEEE 1905 from a control-plane
coordination protocol to a data-plane authority.

## Decision
The IEEE 1905 topology is treated as **informational**, not
authoritative.

Specifically:
- IEEE 1905 topology represents an observed and reported view of
  network connectivity
- It does not mandate forwarding behavior or enforce data-plane paths
- It is not used as the sole source of truth for packet forwarding
- Actual forwarding decisions remain under the control of the
  platform networking stack and media-specific components

IEEE 1905 topology is consumed as **input for coordination and
decision-making**, not as a command to the underlying network.

## Rationale
Treating topology as informational preserves a strict separation
between control-plane and data-plane responsibilities.

Making IEEE 1905 topology authoritative would:
- Duplicate responsibilities already handled by bridges, switches,
  and media-specific forwarding logic
- Require tight synchronization with rapidly changing data-plane
  state
- Introduce race conditions and inconsistency risks
- Reduce portability across platforms and hardware implementations
- Conflict with existing Linux networking and hardware offload models

By contrast, an informational topology:
- Reflects network state without enforcing it
- Tolerates transient inconsistencies and partial views
- Aligns with the distributed and best-effort nature of discovery
- Allows platforms to optimize forwarding independently

This interpretation is consistent with IEEE-style layering, where
discovery and coordination protocols inform—but do not control—the
data plane.

## Consequences

### Positive
- Clear boundary between topology knowledge and forwarding authority
- Reduced complexity and tighter protocol scope
- Improved robustness in the presence of transient or partial views
- Better alignment with Linux bridge and hardware forwarding models
- Easier integration with EasyMesh and other higher-level controllers
- Simplified reasoning about protocol correctness and failure modes

### Negative
- Topology information may lag behind actual forwarding state
- Consumers must treat topology as advisory, not definitive
- Debugging requires correlating topology data with platform state
- No guarantee that reported paths exactly match forwarding behavior

## Notes
- IEEE 1905 topology is inherently distributed and eventually
  consistent.
- Temporary discrepancies between reported topology and actual
  forwarding are expected and acceptable.
- Higher-level systems (e.g., EasyMesh controllers) may combine IEEE
  1905 topology with additional signals and policies to make
  authoritative decisions.
- The protocol communicates **what is visible**, not **what must be
  enforced**.

IEEE 1905 topology answers **“what do we observe?”**, not
**“how must traffic flow?”**.
