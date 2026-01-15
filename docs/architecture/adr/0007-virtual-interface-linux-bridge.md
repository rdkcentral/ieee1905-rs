# ADR-0007: Use a Virtual Interface Attached to a Linux Bridge for CMDU Transmission

## Status
Accepted

## Context
IEEE 1905 operates across heterogeneous link-layer technologies
(Ethernet, Wi-Fi, MoCA, Powerline), while presenting a unified
control-plane protocol abstraction.

On Linux-based platforms, CMDUs could theoretically be transmitted by:
- Creating raw Ethernet frames per media interface
- Injecting frames directly using low-level libraries (e.g., `pnet`)
- Managing per-interface addressing, encapsulation, and dispatch logic

However, this approach would require the IEEE 1905 stack to:
- Maintain explicit knowledge of all media interfaces
- Handle media-specific transmission semantics
- Replicate logic for multicast, flooding, and forwarding
- Track dynamic interface topology changes
- Reimplement behavior already provided by the Linux networking stack

This significantly increases complexity and coupling between the
protocol layer and link-layer media details.

## Decision
We will transmit IEEE 1905 CMDUs via a **virtual network interface**
connected to a **Linux bridge**, instead of transmitting directly
over individual media interfaces using raw Ethernet frame injection.

The IEEE 1905 protocol core will:
- Bind to a single virtual interface
- Emit CMDUs as standard Ethernet frames
- Delegate media forwarding and replication to the Linux bridge

The Linux bridge becomes the authoritative entity for:
- Frame forwarding across media
- Multicast and broadcast distribution
- Interface membership and topology changes
- Media-specific encapsulation behavior

## Rationale
The Linux bridge already implements the precise semantics required
by IEEE 1905 for multi-interface environments.

Using a virtual interface provides:
- A single, stable transmission endpoint for the protocol
- Media-agnostic CMDU emission
- Natural alignment with Linux networking abstractions
- Reduced protocol complexity and fewer failure modes

Attempting to transmit directly via `pnet` on each media interface
would:
- Duplicate bridge and forwarding logic in user space
- Increase risk of inconsistent behavior across interfaces
- Tie protocol correctness to platform-specific media details
- Complicate interoperability, testing, and maintenance

By contrast, the virtual interface + bridge approach allows IEEE 1905
to focus on protocol correctness while delegating frame distribution
to a well-tested kernel component.

## Consequences

### Positive
- Single, media-independent transmission path for CMDUs
- Reduced coupling between protocol logic and link-layer details
- Correct multicast and broadcast behavior by construction
- Automatic handling of interface add/remove events
- Improved maintainability and portability across platforms
- Easier testing and debugging via standard Linux networking tools
- **Enables clean containerization of the IEEE 1905 stack by placing
  the virtual interface and bridge inside a dedicated network
  namespace**
- **Supports strong isolation from the host networking stack while
  preserving correct multi-interface forwarding semantics**
- **Facilitates deployment models where IEEE 1905 runs as a
  containerized or sandboxed control-plane component**

### Negative
- Dependence on Linux bridge behavior and configuration
- Reduced fine-grained control over per-interface transmission timing
- Less visibility into per-media frame emission from user space
- Requires correct bridge and virtual interface setup at system level
- Network namespace configuration adds operational considerations
  during system integration

## Notes
- The use of a virtual interface does not preclude low-level inspection
  or validation of frames before transmission.
- `pnet` remains appropriate for frame construction and inspection,
  but not for media-specific dispatch.
- Network namespaces allow the IEEE 1905 stack to be isolated,
  restarted, or replaced without impacting host networking.
- This design aligns with IEEE 1905’s goal of presenting a unified
  abstraction over heterogeneous networking technologies.

The protocol layer is responsible for **what** is transmitted;
the Linux networking stack is responsible for **where and how** it
is forwarded.
