# Cluster experience architecture

## Purpose

Give every cluster template a clear lifecycle and a type-specific administration page. A template is a guided starting point, not a cluster and not proof that its prerequisites are satisfied. A cluster appears in **Clusters** only after the relevant host-side state has been applied and independently verified.

All UI, API routes, persistence, authorization, and deployment stay inside Rancher KVM Manager. The extension imports and manages existing SUSE Linux KVM hosts; it does not install or configure Rancher, Harvester, or SUSE Virtualization.

## Product model

Keep three concepts distinct:

1. **Template** — a versioned blueprint containing supported capabilities, requirements, preflight checks, setup steps, and the detail-page module to use. It can be evaluated without making changes.
2. **Cluster plan** — a user's selected hosts and proposed configuration. It records preflight results and choices, but it is not shown as an active cluster.
3. **Cluster** — a persistent extension resource created only after a supported workflow succeeds and host-side discovery confirms its identity and membership.

Use one shared cluster record with a type discriminator, rather than treating every host group as the same technology. Initial types:

| Type | Meaning | Primary authority |
|---|---|---|
| `kvm-virtualization` | A group of existing libvirt hosts intended to run and move workloads between hosts. A logical group alone does not provide HA. | libvirt on each host; extension inventory and orchestration |
| `suse-ha-service` | A real SUSE HA cluster managing a service such as NFS through Pacemaker, Corosync, and SUSE-supported resource agents. | Pacemaker/Corosync on the cluster nodes |

The NFS template should create a `suse-ha-service` cluster with the NFS workload profile. It should not imply that an NFS export by itself is a virtualization cluster. The existing KVM VM failover profile is a workload that can be configured on a real SUSE HA cluster; it is distinct from a KVM virtualization cluster. The wizard must explain which model it is creating before it applies anything.

Suggested cluster states: `draft` → `preflight` → `applying` → `verifying` → `active`, with explicit `degraded`, `failed`, and `deleting` states. Preserve the plan and per-host results after partial failure so the operator can resume or follow recovery guidance. Never set `active` based solely on a successful SSH command.

## Navigation and user experience

### Clusters landing page

- Separate **Active clusters** from **Plans and templates**. Do not mix detected SUSE HA clusters with un-applied plans.
- Each active cluster card shows name, type, status, verified host count, workload count where applicable, and last successful check. One clear **Open cluster** action enters its type-specific page.
- Template cards show purpose, required hosts, detected blockers, warnings, and a concise **Prepare** action. Provide a contextual **Fix** only for a safe, allow-listed prerequisite with a clear host-level effect.
- After successful verification, move the plan into Active clusters and link to the new detail page. If verification fails, retain it under Plans with per-node results.

### Cluster detail shell

Reuse Cloud Native host UI patterns: Rancher headings, status badges, section navigation, compact summaries, accessible dialogs, theme-aware tables, responsive layouts, and clear freshness timestamps. Keep a persistent cluster breadcrumb and show type and health in the page header.

Shared sections, when supported by the type:

- **Overview** — health, last check, member count, key capacity or service status, and actionable blockers.
- **Hosts / Nodes** — members, readiness, roles, and navigation to the host's local administration page.
- **Workloads** — VMs for KVM virtualization; Pacemaker resources and service components for SUSE HA.
- **Network and storage** — cluster-wide compatibility and attachment state; do not present local host settings as shared resources.
- **Activity** — verified state transitions, operations, failures, and sanitized diagnostics.
- **Settings** — cluster metadata and supported policies, with a review step before changes.

Render sections from the template's declared capabilities. Do not show empty, non-functional menu items, and do not force the NFS page to look like a VM manager. Each type can have a focused overview while preserving the same navigation and visual grammar.

### Where operations belong

- Put **multi-host decisions** on the cluster page: VM migration, placement, evacuation, shared-storage/network validation, and cluster policies.
- Put **node-local administration** on the host page: host interfaces and services, local libvirt networks/pools, repositories, subscriptions, accounts, and maintenance-specific host facts.
- Link between the views and reflect cluster membership in both. Do not duplicate the same action in both places unless it has a different, clearly described scope.

## KVM virtualization workflow

### Create and verify

1. Select already imported hosts and show SUSE release, architecture, libvirt/QEMU versions, reachability freshness, current memberships, and capacity.
2. Run read-only preflight. Compare CPU compatibility and virtualization capabilities; inspect memory and CPU headroom; map host bridges, VLANs, MTU, and VM network sources; identify storage pools and volume backing paths on every host.
3. Require an explicit shared-storage decision. A matching pool name or path is not proof of shared storage. Verify a stable backing identity and safe access from every selected host; report local-only disks as a migration blocker. Never write a probe file into an operator's storage without a separate reviewed operation.
4. Review the resulting membership and limitations. If the workflow only records a logical group, label it **KVM host group** and do not claim shared-storage, live-migration, or HA capability.
5. Apply only supported changes, display per-host progress, then rediscover cluster membership and capabilities before creating the active cluster record.

### Cluster VM administration

Deliver in this order:

1. **Cross-host VM inventory** — combine host inventories while preserving the source host and avoiding duplicate VM identity assumptions. Display VM configuration, host, state, storage source, network attachments, and last check.
2. **Migration preflight** — choose a destination and explain blockers before a command is run: source/destination compatibility, available CPU and memory, storage accessibility, network mapping, VM device constraints, and permissions.
3. **Single-VM migration** — initially offer only a reviewed, explicit migration. Track it as a server-side operation with an ID, source, destination, phase, timestamps, sanitized progress, timeout, and a truthful final state. Do not label it live migration unless libvirt confirms that the selected mode and VM support it.
4. **Host maintenance** — after migration is reliable, add a review that lists all VMs and classifies each as migratable, stoppable with approval, or blocking. Do not mark a host in maintenance while an unhandled VM remains.
5. **Placement policy** — only after reliable inventory and operation history exist. Start with advisory placement recommendations; make automatic balancing a separate, opt-in phase.

Do not use host-local VM configuration actions as a substitute for cross-host orchestration. Serialize conflicting mutations per cluster and per VM.

## SUSE HA and NFS workflow

- Continue using SUSE-documented `crm cluster init` / `crm cluster join`, Pacemaker, Corosync/knet, Hawk, QDevice/QNetd, and supported fencing/SBD workflows.
- Retain the existing HA preflight and best-practice warnings. Connectivity, installed packages, quorum, and fencing are separate checks.
- Build an NFS service template around the installed SUSE-supported agents and the documented resource order/dependencies. Show the filesystem, NFS server, export, and client-facing address as a dependency graph; discover required parameters from host agent metadata rather than guessing.
- Create/apply resources only through explicit typed operations, after showing nodes, storage assumptions, quorum/witness, fencing, effects, and unresolved blockers. Verify Pacemaker state after each operation and retain per-resource results.
- Treat Hawk as a complementary native view. Keep extension navigation and governance in Rancher; only open Hawk after HA detection and preserve its existing authentication and TLS boundary.

For KVM VM failover under SUSE HA, assess the SUSE-supported `ocf:heartbeat:VirtualDomain` agent as a separate workload workflow. Verify the exact agent metadata and SLE HA release support on the hosts. Check shared disk and configuration consistency, fencing, and recovery policy. Prevent simultaneous independent control by libvirt/UI actions and Pacemaker; identify the Pacemaker-managed VM clearly and disable conflicting direct lifecycle actions where appropriate.

## API, persistence, and governance

- Add a persistent `clusters` model with a generated ID, type, name, template/version, lifecycle state, verified identity, member host IDs, capabilities, created/updated/check timestamps, and sanitized preflight result references.
- Keep host records independent: a host may be a member of at most one incompatible cluster type at a time. Reconcile membership against the live SUSE HA/libvirt state; surface mismatches as degraded rather than silently rewriting either source.
- Use cluster-scoped API routes for inventory and operations. Resolve every member host server-side and enforce Rancher RBAC on every call; UI visibility is not authorization.
- Extend current coarse roles in stages toward cluster scope: viewer, cluster operator, host administrator, and cluster administrator. Define whether a permission applies to the cluster object, all member hosts, or only a given workload/resource.
- Persist long-running operations server-side. An operation ID must survive browser navigation and refresh, support safe polling, prevent accidental duplicate submissions, and have an auditable actor, target, start/end time, result, and sanitized output.
- Use per-cluster/per-resource locks for mutations, bounded host concurrency, idempotency keys, explicit timeouts, and recovery instructions. Do not promise rollback for host or Pacemaker operations that are not transactional.
- Keep secret input transient and operation-scoped; never persist registration codes or passwords in plans, audit events, progress output, or browser storage.

## Delivery phases and acceptance criteria

### Phase 0 — product and safety contract

- Finalize the two distinct cluster types, lifecycle states, capability vocabulary, and template-to-detail-page mapping.
- Document what a logical KVM host group can and cannot do before shared-storage and network verification.
- Define migration and Pacemaker ownership boundaries, RBAC scope, error states, and recovery behavior.

**Complete when:** every template explicitly declares what it creates, what it configures, the authority that reports its state, and the first page shown after verification.

### Phase 1 — persistent cluster inventory and navigation

- Create extension-owned cluster records and show Active clusters separately from Plans.
- Reconcile existing SUSE HA cluster identity/member data and retain host links.
- Add type-aware detail-page shells and capability-driven navigation; do not add placeholder controls.

**Complete when:** a verified cluster survives UI/API restarts, opens its correct detail view, and a failed/incomplete plan never appears as active.

### Phase 2 — KVM cross-host readiness

- Add cross-host inventory and explicit shared-storage/network/capacity diagnostics.
- Show the exact source and freshness for each check and distinguish blocker, warning, and unverified assumption.

**Complete when:** an operator can determine why a VM cannot move before any mutating request, including local-only disks and mismatched networks.

### Phase 3 — single-VM migration

- Implement one reviewed, explicit migration path with operation IDs, per-host/VM locking, progress polling, cancellation only where libvirt supports it, and final rediscovery.

**Complete when:** supported test cases finish with the VM at exactly one host, failed/ambiguous outcomes remain visible, and repeated requests cannot start conflicting migrations.

### Phase 4 — host maintenance and workload placement

- Add evacuation review and host maintenance lifecycle; then advisory capacity/placement recommendations.

**Complete when:** no host enters maintenance with an unexplained running VM and destination capacity is checked against the defined reserve policy.

### Phase 5 — SUSE NFS and VM HA workflows

- Turn the NFS service profile into a type-specific SUSE HA cluster view and reviewed agent workflow.
- Evaluate the `VirtualDomain` workload profile with safeguards against double control.

**Complete when:** agent compatibility, prerequisite checks, ordered changes, per-resource status, and post-change verification are backed by supported SLE HA documentation and tested on the target release.

### Later phases

- Add VM templates, cloning, image import/export, storage movement, off-host backups, restore, historical metrics, alerting, and finer object-scoped RBAC only after the core cluster inventory and operation lifecycle are dependable.

## Non-goals for the first delivery

- Recreating the full oVirt Engine, VDSM, data-center hierarchy, scheduling engine, or complete administration portal.
- Installing an operating system or KVM on a new server; this product manages already existing, imported hosts.
- Treating a list of hosts, libvirt pools, network bridges, or a cluster plan as evidence of a functioning shared cluster.
- Automatically balancing or failing over VMs before migration, shared-resource checks, fencing, and recovery have been validated.
- Adding continuously refreshed graph dashboards before a bounded metrics-retention and refresh policy is agreed.

## Reference basis

- [oVirt Administration Guide](https://ovirt.org/documentation/administration_guide/)
- [oVirt Virtual Machine Management Guide](https://ovirt.org/documentation/virtual_machine_management_guide/)
- [SUSE Linux Enterprise High Availability virtualization](https://documentation.suse.com/sle-ha/15-SP7/html/SLE-HA-all/cha-ha-virtualization.html)
- [SUSE Linux Enterprise High Availability resource constraints and utilization](https://documentation.suse.com/sle-ha/15-SP7/html/SLE-HA-all/sec-ha-config-basics-constraints.html)

## Current implementation status

The extension currently includes persistent, extension-owned KVM host groups with a separate group inventory view. It combines per-host VM, storage-pool, and libvirt-network inventory and records the group as `setup` with all cross-host capabilities false. This is a useful inventory foundation, not an active virtualization cluster. Live migration, shared-storage identity checks, network equivalence, placement, and SUSE HA are not implemented by this host-group record. The SUSE HA inventory and operations remain a separate path.

Next, add source-backed storage and network compatibility checks, then an explicitly reviewed migration operation with durable progress and rediscovery. Do not enable a migration control until those checks and safe operation handling are complete.
