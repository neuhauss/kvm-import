# SUSE HA cluster management plan

## Product goal

Add an extension-owned **Clusters** experience beside **Hosts**. It should guide an operator from existing SLES/KVM hosts to a reviewed, supportable SUSE Linux Enterprise High Availability cluster, and then provide a focused operational view. The extension must not patch Rancher or SUSE Virtualization. All UI, API integration, permissions, and audit records belong to this extension.

Use SUSE-provided and SUSE-supported components for the cluster workflow. The target stack is SLE HA with `crmsh`, Pacemaker, Corosync using `knet`, Hawk, QDevice/QNetd where appropriate, and supported fencing agents/SBD. Do not make cluster creation depend on community add-ons, third-party orchestration, or an alternative cluster manager.

## Design principles

- Discover and report first. A registered KVM host is not automatically a cluster-ready node.
- Separate read-only checks from changes. Show the commands/actions and their expected effects before each change.
- Keep each mutating phase explicit, resumable, and auditable. Do not send a single opaque shell script that installs and bootstraps everything.
- Use typed, allow-listed operations in the extension API. Reuse the current host connection and Rancher RBAC mapping; viewers can inspect, host administrators can prepare or operate.
- Do not store HA registration codes or `hacluster` passwords. Submit secrets only for the operation that needs them, and never write them to logs.
- Preserve the SUSE-supported `crm cluster init` and `crm cluster join` workflow. Avoid hand-building Corosync or Pacemaker configuration as a substitute for the SUSE tooling.
- Treat Hawk as a complementary native administration surface. Link or proxy it only after HA is detected, and only with an explicit secure authentication design.
- Make unsupported states clear. A green “connected” host status must never imply quorum, fencing, or HA readiness.

## Recommended experience

### 1. Cluster inventory

The new page starts with registered hosts and their SSH reachability. Future cluster objects will be separate from host records and will appear only after cluster membership is confirmed from the HA stack. The current release implements the host inventory and this roadmap only; it does not create clusters.

### 2. Create-cluster wizard

1. **Select hosts:** select at least two compatible SLES hosts, display OS/release/architecture and connection freshness, and warn when hosts are already members of a cluster.
2. **HA entitlement and packages:** report SLES registration and the SLE HA extension state. Let the operator activate the SUSE extension using a one-time registration code where licensing permits. Preview package changes and repositories before applying them.
3. **Read-only preflight:** check supported release compatibility, stable hostname and static addressing, time synchronization, inter-node SSH, required firewall reachability, candidate Corosync interfaces/subnets, and watchdog/fencing capabilities. Separate blockers from warnings.
4. **Topology and quorum:** select Corosync communication links, fencing method, and QDevice/QNetd placement. Explain votes and expected failure behavior in plain language. For a two-node cluster, explicitly plan a QNetd witness server outside the cluster; SUSE recommends QDevice/QNetd for even-sized clusters, especially two-node clusters.
5. **Review and bootstrap:** produce a human-readable change plan. Run first-node `crm cluster init`, then `crm cluster join` on additional selected nodes as distinct operations, showing progress and per-node output. Require confirmation before every operation that changes a host.
6. **Verify and hand off:** verify node membership, Pacemaker/Corosync health, quorum, fencing, and Hawk service. Save the cluster only after the cluster reports the expected state.

### 3. Cluster operations

The cluster detail view should prioritize node membership, quorum, Corosync links, Pacemaker resources, fencing state, and last successful check. Offer safe operations first: refresh status, open Hawk, and maintenance-mode actions with clear confirmation and status polling. Resource creation can follow in a separate phase, using SUSE resource agents and visible constraints/colocation rules.

## Safety and permission model

- Map Rancher permissions through the extension API: read-only viewers inspect status; host administrators can run host/cluster mutations. Do not infer permission from UI visibility alone; enforce it on each API route.
- Capture actor, operation, target nodes, start/end time, result, and sanitized output in the extension audit log.
- Use operation IDs and server-side state so a browser refresh does not launch a second bootstrap.
- Serialize cluster mutations per cluster and reject conflicting operations.
- Provide cancellation only before a destructive step begins; for in-progress operations report the current step and recovery guidance.
- Never claim rollback when cluster changes are not transactionally reversible. Offer phase-specific recovery steps instead.

## Practical constraints from SUSE documentation

- SUSE HA uses Corosync for membership, messaging, and quorum and Pacemaker as the cluster resource manager.
- SUSE requires at least one node fencing device for supported clusters. Fencing prevents an isolated or uncertain node from continuing to access workloads and shared data. For critical workloads, plan multiple fencing devices; diskless SBD depends on watchdog support.
- Quorum requires a majority of votes. Two-node partitions have no natural majority; QDevice/QNetd provides an arbitrator vote and is recommended by SUSE for two-node clusters.
- The basic two-node setup assumes static host addressing and names, time synchronization, SSH between nodes, suitable network channels, HA registered on all cluster nodes, and a QNetd server outside the cluster.
- `crm cluster init` checks/configures time, SSH, firewall, Csync2, Corosync, SBD/watchdog, Hawk and optional floating IP/QDevice. `crm cluster join` adds nodes.
- Hawk requires the `hawk2` package and enabled `hawk` and `hawk-backend` services. It is available over HTTPS on port 7630 and uses the `hacluster` account by default; Hawk ACLs can refine permissions.

## Delivery phases

1. Host inventory and design page (current): no cluster mutation.
2. HA discovery and read-only preflight, with capability and privilege checks.
3. HA extension activation and controlled `crm cluster init/join`, after review of generated API operations and recovery paths.
4. Verified cluster inventory, status, quorum, fencing, Hawk access, and audit trail.
5. SUSE resource management and lifecycle operations, introduced only after the node and resource workflows are testable on supported SLES/HA versions.

## References

- [SUSE Linux Enterprise High Availability 16.0: Introduction](https://documentation.suse.com/sle-ha/16.0/html/HA-introduction/index.html)
- [SUSE Linux Enterprise High Availability 16.0: Installing a Basic Two-Node Cluster](https://documentation.suse.com/sle-ha/16.0/html/HA-installing-two-node-cluster/index.html)
- [SUSE Linux Enterprise High Availability 16.0: QDevice and QNetd](https://documentation.suse.com/sle-ha/16.0/html/HA-qdevice-configuring/index.html)
- [SUSE Linux Enterprise High Availability 16.0: Hawk Web Interface](https://documentation.suse.com/sle-ha/16.0/html/HA-hawk-introduction/)
- [SUSE Linux Enterprise High Availability 16.0: Managing Cluster Resources](https://documentation.suse.com/sle-ha/16.0/html/HA-resources-managing/index.html)
