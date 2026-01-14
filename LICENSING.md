# OmniNervous Licensing

## Dual License Model

OmniNervous uses a dual licensing model:

### Open Source Core (Apache 2.0)

The following components are licensed under **Apache License 2.0** and are free for all use:

| Component | Path | Description |
|:---|:---|:---|
| **omni-common** | `/omni-common` | Shared types and protocol definitions |
| **omni-daemon** | `/omni-daemon` | Userspace control plane daemon |
| **omni-ebpf-core** | `/omni-ebpf` | XDP/eBPF data plane engine |
| **Scripts** | `/scripts` | Build, test, and deployment tools |
| **Documentation** | `/docs` | Technical documentation |

You may use, modify, and redistribute these components for any purpose, including commercial applications, subject to the terms of the Apache 2.0 license.

### Enterprise Plugins (Commercial License)

The following plugins are available under a **Commercial License**:

| Plugin | Description | Availability |
|:---|:---|:---|
| **omni-ros2** | ROS2 DDS QoS integration | Enterprise |
| **omni-opcua** | OPC-UA tunnel for industrial automation | Enterprise |
| **omni-ptp** | IEEE 1588 PTP time synchronization | Enterprise |
| **omni-fips** | FIPS 140-3 certified cryptography | Enterprise |
| **omni-ha** | High availability and clustering | Enterprise |
| **omni-audit** | Compliance and audit logging | Enterprise |

For Enterprise licensing inquiries, contact: [enterprise@omniedge.io](mailto:enterprise@omniedge.io)

## FAQ

### Can I use OmniNervous Core commercially?
**Yes.** The Apache 2.0 license permits commercial use without any fees or restrictions.

### Can I modify the Core and keep changes private?
**Yes.** Unlike copyleft licenses (GPL/AGPL), Apache 2.0 does not require you to publish modifications.

### Do I need an Enterprise license for production use?
**No.** The Core is production-ready. Enterprise plugins add optional features for specific industries.

### Can I build my own plugins?
**Yes.** You're free to create plugins for the Apache 2.0 core. Only the plugins listed above require a commercial license.

---

*© 2026 OmniEdge Inc. All rights reserved.*
