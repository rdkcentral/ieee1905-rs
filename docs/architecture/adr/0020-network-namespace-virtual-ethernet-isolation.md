# ADR-0020: Isolate IEEE1905 Virtual Ethernet in a Dedicated Network Namespace

## Status
Under discussion

## Context
The IEEE1905 control plane uses a virtual Ethernet interface to send
and receive CMDU traffic. Without network isolation, this interface
shares the host namespace with unrelated services and links.

This can increase operational risk:
- Broader blast radius for misconfiguration
- Harder policy enforcement for control-plane traffic
- More complex troubleshooting when host networking changes
- Higher chance of unintended packet paths

We need a predictable way to isolate the IEEE1905 control interface
while preserving expected protocol behavior.

## Decision
Use a dedicated Linux network namespace for the IEEE1905 virtual
Ethernet control interface.

Specifically:
- Create/manage a namespace dedicated to IEEE1905 control-plane traffic
- Move the virtual Ethernet endpoint used by IEEE1905 into that
  namespace
- Expose only required connectivity between host namespace and IEEE1905
  namespace
- Apply namespace-scoped security policy (routes, firewall, permissions)

## Rationale
Network namespaces provide a kernel-native isolation boundary for
interfaces, routes, sockets, and firewall state. This keeps control
traffic separated from unrelated host networking and improves
operational determinism.

Compared to running everything in the host namespace, this approach:
- Reduces accidental coupling with non-IEEE1905 services
- Simplifies least-privilege policy for control-plane interfaces
- Improves clarity for observability and incident response
- Aligns with containerized and multi-service Linux deployments

## Consequences

### Positive
- Stronger isolation for IEEE1905 control-plane traffic
- Reduced impact of host networking changes on control paths
- Cleaner security policy scope for interfaces and sockets
- Better troubleshooting boundaries (namespace-local diagnostics)

### Negative
- Additional lifecycle management (create/attach/recover namespace)
- Startup ordering requirements (namespace must exist before service)
- Extra operational complexity in tooling/scripts
- Namespace-aware diagnostics required by operators

## Notes
- This ADR does not change IEEE1905 CMDU semantics.
- Startup and recovery flows should validate namespace/interface state.
- Monitoring should include namespace-scoped health checks.
- This ADR is complementary to link-local IPv6 usage on the control
  interface.
