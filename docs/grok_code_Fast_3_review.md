Patch Phase 6.5 and Phase 7: Implement Linux TUN index binding and combined indices update in Phase 6.5. Add a best-effort approach to read the TUN ifindex and wire to BPF maps, plus an attempt to derive a default physical interface and update combined tun/phys indices. Phase 7: Prepare eBPF verifier fixes and toolchain pinning for future commits, plus a lightweight throughput test scaffold.

Patch plan:
- Phase 6.5 patch set 1 (Phase 6.5). Changes:
  - omni-daemon/src/main.rs: After TUN creation, read /sys/class/net/<tun>/ifindex and call bpf_sync.set_tun_index(ifindex). If a default physical interface is found, attempt to read its ifindex and call bpf_sync.update_indices(tun_ifindex, phys_ifindex).
  - omni-daemon/src/bpf_sync.rs: Implement update_indices and wire safe no-op stubs for Linux/non-Linux builds. Ensure that the patch compiles cleanly on non-Linux systems.
  - omni-daemon/src/session.rs: Introduce last_seq tracking and helpers for future replay protection.
  - Tests: add light unit tests for Linux path (conditional).
- Phase 7 patch set 2 (Phase 7). Changes:
  - omni-ebpf-core updates with verifier fixes (u64 XOR, unrolling) and loader alignment (documented in the future patch).
  - CI: pin toolchain versions (Rust nightly, Aya) and add a lightweight throughput test scaffold.
  - Metrics: expand to surface throughput per path, handshake counts, and drop counters for observability.

Rationale:
- Phase 6.5 requires reliable dynamic index updates in the BPF maps to ensure the L3 offload and Hybrid L2 paths reflect real-time interface topology. This patch lays the groundwork for those bindings.
- Phase 7 requires verifiable improvements and performance benchmarking. The patch will align toolchain and verifier expectations, then introduce measurable performance tests and metrics.

Risks:
- Linux-specific changes may not compile on non-Linux CI. We isolate with cfg flags and ensure non-Linux builds stay stable.
- eBPF verifier changes require close coordination with the ebpf core module; we’ll merge in a follow-up patch after the ebpf-core PRs land.