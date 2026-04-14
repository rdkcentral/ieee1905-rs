# ADR-0019: Use Link-Local IPv6 on Control Interface to Reuse IP-Based Services

## Status
Under discussion

## Context
IEEE 1905 CMDU transport is fundamentally Ethernet-based, but some
operational capabilities needed by the platform are already available
as IP-based services. In this scope, the targeted services are:
- Syslog integration (log forwarding/collection over IP)
- Firmware upgrade workflows over HTTPS

Reimplementing these functions directly on raw Ethernet would duplicate
logic, increase maintenance cost, and reduce reuse of existing platform
infrastructure.

The control plane already uses a virtual Ethernet interface. We need a
simple addressing model to run selected IP services on that interface
without introducing dependency on globally routable addressing.

## Decision
Use a private IPv6 link-local address on the IEEE1905 control virtual
Ethernet interface, derived from the AL MAC using EUI-64 rules.

This enables reuse of services implemented on top of IP while keeping
scope local to the link/home network boundary.

Specifically:
- Address scope is link-local (`fe80::/64`)
- Interface ID is derived from AL MAC (EUI-64 conversion)
- Communication stays local and is not routed outside the home link

## Rationale
This approach provides a pragmatic middle ground:
- Keeps IEEE 1905 Ethernet semantics for CMDU transport
- Reuses mature IP socket-based components with minimal changes
- Avoids global addressing dependencies and WAN exposure
- Preserves isolation boundaries when control interfaces are in
  dedicated network namespaces

Using link-local IPv6 avoids the operational burden of DHCPv6/SLAAC
coordination for this internal control path while still allowing
standard IP tooling.

## Consequences

### Positive
- Faster integration by reusing existing IP-based services
- Lower implementation complexity than Ethernet-only equivalents
- Better observability with existing IP diagnostics tools
- Reduced external attack surface versus globally routable addresses
- Clear locality semantics for control-plane exchanges

### Negative
- Link-local addressing requires interface-scoped handling
  (zone index / interface binding)
- Services cannot rely on generic routed reachability
- Multi-link scenarios require careful interface selection
- Some components may need adaptation for scoped IPv6 endpoints

## Notes
- This ADR does not change IEEE 1905 frame transport behavior.
- The IP-based services in scope are syslog and HTTPS-based firmware
  upgrade flows.
- IP-based helpers are an implementation convenience layer, not a
  replacement for CMDU mechanisms.
- Security controls (namespace isolation, firewall policy, process
  permissions) remain mandatory.
