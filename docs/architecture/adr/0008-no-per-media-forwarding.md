# ADR-0008: IEEE 1905 Does Not Own Per-Media Forwarding State

## Status
Accepted

## Context
IEEE 1905 is defined as a **control-plane protocol** that operates
across heterogeneous link-layer technologies (Ethernet, Wi-Fi,
MoCA, Powerline), providing unified discovery, topology visibility,
and coordination.

Each underlying media technology already maintains its own forwarding
and connectivity state, typically implemented by:
- The Linux networking stack (bridges, drivers, forwarding tables)
- Media-specific protocols and firmware
- Hardware offload and acceleration paths

An alternative design would be for the IEEE 1905 stack to explicitly
track and manage per-media forwarding state, including:
- Interface-specific reachability
- Per-link forwarding decisions
- Media-aware frame replication logic

However, this would blur the boundary between control-plane and
data-plane responsibilities.

## Decision
The IEEE 1905 implementation **does not maintain per-media forwarding
state**.

Instead:
- IEEE 1905 maintains **logical topology and control-plane state**
- Media-specific forwarding decisions are delegated to the underlying
  networking stack and media subsystems
- CMDUs are emitted without encoding per-media forwarding intent

IEEE 1905 uses the Linux bridge and platform networking components as
the authoritative source of forwarding behavior.

## Rationale
Owning per-media forwarding state within IEEE 1905 would:
- Duplicate functionality already present in the kernel and drivers
- Introduce tight coupling to media-specific semantics
- Increase complexity and risk of inconsistencies
- Require constant synchronization with lower layers
- Undermine portability across platforms and hardware vendors

By contrast, treating forwarding as an external responsibility:
- Preserves a clean separation between control-plane and data-plane
- Aligns with IEEE layering principles
- Allows IEEE 1905 to remain media-agnostic
- Leverages mature, optimized, and hardware-accelerated forwarding
  implementations provided by the platform

IEEE 1905 focuses on **coordination and intent**, not on packet
forwarding mechanics.

## Consequences

### Positive
- Clear architectural separation between control-plane and forwarding
- Reduced protocol complexity and state explosion
- Improved portability across platforms and media technologies
- Natural alignment with Linux bridge and hardware offload models
- Lower risk of forwarding inconsistencies or race conditions
- Easier integration with containerized and isolated deployments
- Simplified reasoning about protocol correctness

### Negative
- Reduced visibility into per-media forwarding behavior from within
  the IEEE 1905 stack
- Debugging forwarding issues may require inspecting platform
  networking components
- Limited ability to express media-specific forwarding preferences
  directly in the protocol layer

## Notes
- IEEE 1905 topology information is **descriptive**, not prescriptive:
  it reflects observed connectivity rather than enforcing forwarding.
- Media-specific optimizations and policies remain the responsibility
  of lower layers or platform management components.
- This design choice ensures that IEEE 1905 remains scalable and
  maintainable as new media technologies are introduced.

IEEE 1905 decides **what should happen** at the control-plane level;
the platform decides **how frames are forwarded**.
