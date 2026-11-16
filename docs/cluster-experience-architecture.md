# Cluster experience architecture

## Purpose

Give every cluster template a clear lifecycle and a type-specific administration page. A template is a guided starting point, not a cluster and not proof that its prerequisites are satisfied. A cluster appears in **Clusters** only after the relevant host-side state has been applied and independently verified.

All UI, API routes, persistence, authorization, and deployment stay inside Rancher KVM Manager. The extension imports and manages existing SUSE Linux KVM hosts; it does not install or configure Rancher, Harvester, or SUSE Virtualization.

## Product model

Keep three concepts distinct:

1. **Template** — a versioned blueprint containing supported capabilities, requirements, preflight checks, setup steps, and the detail-page module to use. It can be evaluated without making changes.
2. **Cluster plan** — a user's selected hosts and proposed configuration. A persisted plan is a draft only; it records the selected profile, wizard position, and topology choices. Preflight output is transient and rerun when a draft resumes, and plans never appear as active clusters.
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
2. Run read-only preflight. Compare CPU compatibility and virtualization capabilities; inspect memory and CPU headroom; map host bridges, VLANs, MTU, and VM network sources; identify storage pools and volume backing paths on every host. For SUSE HA planning, probe each peer's registered SSH TCP port from every selected host while clearly stating that this does not validate SSH authentication or Corosync traffic.
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
- For workload prerequisites, check that the package and systemd unit are installed on each eligible node; do not require the service to be active on every node. The template's safe package fix must not enable or start the service directly. Pacemaker owns workload runtime after resource configuration. Older APIs that expose only active state must report installation as unknown rather than treating an inactive unit as missing.
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
- Keep secret input transient and operation-scoped; never persist registration codes or passwords in plans, audit events, progress output, or browser storage. Persisted plans are visible to their creator and cluster administrators, and contain no preflight output or host connection material.

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
- [SUSE Linux Enterprise High Availability resource monitoring and promotable clones](https://documentation.suse.com/sle-ha/15-SP7/single-html/SLE-HA-administration/book-administration.html)
- [SUSE Linux Enterprise Server 15 SP7 Security and Hardening Guide](https://documentation.suse.com/sles/15-SP7/html/SLES-all/book-security.html)
- [SUSE Linux Enterprise Server 15 SP7 Virtualization Guide](https://documentation.suse.com/en-us/sles/15-SP7/single-html/SLES-virtualization/index.html)

## Current implementation status

The extension currently includes persistent, extension-owned KVM host groups with a separate group inventory view, plus persistent private `draft` records for SUSE HA plans. It combines per-host VM, storage-pool, filesystem, host-interface, and libvirt-network inventory and records a KVM host group as `setup` with all cross-host capabilities false. The group assessment compares common pool names by visible type and target path and reports the filesystem source/type/mountpoint containing each target. It compares common network names by visible forwarding mode and bridge, then reports whether that bridge interface is present on the host and its observed state/MTU. When an active libvirt pool target is on the same reported NFS export, filesystem type, and mountpoint on every host, the assessment marks it as a shared-storage candidate. This does not prove export options, QEMU access, locking, or write availability. The remaining checks describe host-local observations and do not prove VLAN identity or physical network reachability. A draft survives browser refresh, contains no host credentials or old preflight output, and reruns preflight when resumed. Neither record is treated as an active cluster. The SUSE HA path separately detects actual host-reported membership, exposes verified cluster operations, and guides first-node `crm cluster init` / member `crm cluster join` through the host terminal; the interactive SUSE CLI remains the authority for bootstrap. For plans using QDevice/QNetd, the wizard adds a separate reviewed `crm cluster init qdevice` step after every selected node is confirmed in the same live cluster. The backend reruns read-only checks for exact membership, online nodes, quorum, and whether a witness is already configured before opening its restricted PTY. Live status uses `corosync-quorumtool -s` and, when QDevice is configured, SUSE's `crm corosync status qdevice` to report connection, QNetd host, and TLS state; unavailable output remains unknown rather than being presented as a disconnected witness. These controls do not configure the external QNetd server automatically or claim that a connected witness proves fencing safety. Verified clusters support stopped primitive creation with per-agent parameters and monitor operations, safe editing of standalone stopped primitives' monitor operations, and stopped Pacemaker resource groups with explicit start order, add/remove membership, and reordering through SUSE's XML update workflow. The monitor editor preserves parameters, meta attributes, and non-monitor operations, detects stale CIB forms by operation IDs, and includes interval-zero probe and Stopped-role checks. Standard clones can wrap stopped standalone primitives or top-level groups. Promotable clones are limited to primitives and are rejected unless the CIB has distinct role monitors and the installed agent advertises promote/demote actions. Live status reconciles monitor operations and clone/group wrappers with `crm_mon` and the CIB, and mutations remain permission-checked, reviewed, serialized, and audited. STONITH agent discovery, agent guidance, stopped-device creation, and stopped top-level-device removal are integrated. Parameter edits are limited to stopped devices with one current target, preserve target mapping and monitor operations, expose parameter names but never existing values, and apply through the SUSE CIB XML update interface. Stopped top-level clone metadata editing supports documented clone instance limits and placement options, preserves unknown metadata and the child resource, and checks for stale configuration before applying. Clone deletion is now available for stopped, non-failed top-level clones with exactly one non-STONITH primitive and no related constraints; the backend rechecks the current CIB before deletion. Clones wrapping groups, nested clones, active or failed resources, and constraint-linked clones remain excluded from this shortcut. A vendor-specific physical fencing connectivity test remains a gap. Live migration remains disabled; NFS candidate detection is only a preliminary identity comparison. Network equivalence and placement checks are not implemented by the KVM host-group record.

The `VirtualDomain` template now has a read-only cross-node preflight. It maps live Pacemaker node names to unique extension host records, queries each mapped host concurrently for the selected VM's state, UUID, disk sources, network sources, and installed `ocf:heartbeat:VirtualDomain` agent, and reports incomplete/ambiguous host mappings explicitly. Comparisons describe only the definitions returned by libvirt; matching paths do not prove shared storage. SUSE's documented flow requires the VM to be shut down before adding it, places its XML configuration and lock files on cluster-shared storage, warns against unshared local paths in the XML, requires fencing, passwordless root SSH, and a VM bridge separate from cluster communication/management networks, and shows `remoteuri="qemu+ssh://%n/system"` for host-to-host libvirt access. The UI lists shared XML, disk, network, lock-space ordering, stable device IDs, fencing, and SSH-authentication checks as manual gates. The preflight tests noninteractive root SSH from each mapped node to the other Pacemaker node names using strict existing `known_hosts` entries; it reports only a safe status and does not prompt, accept new keys, or expose stderr. It can run without an XML path, checking disks found in the selected VM's libvirt definition. If both QEMU user and group are explicitly set in `/etc/libvirt/qemu.conf`, a child process drops to that UID/GID and checks required Unix read/write permissions on each local file-backed disk. It also reports read-only SELinux mode, AppArmor enabled state, explicitly configured libvirt security drivers/confinement flags, and the current VM process security context when that VM is running on the node. A host-policy consistency indicator compares only settings across all mapped nodes; it deliberately excludes per-VM labels. These observations are not proof that QEMU can open storage or that a VM is safely confined: service-level confinement, SELinux/AppArmor access decisions, and non-file sources still require review. When an XML path is supplied, the read-only per-node probe also reports its parent directory and mount identity; matching identities remain candidates, never proof, and no files or directories are written. The same node cards read the SLE HA 15 SP7 libvirt lock-manager setting, configured lock-space directory, its mount, and virtlockd service/socket state. The cluster diagnostics view parses the live CIB without returning resource parameters, identifies a DLM and GFS2 primitive in one resource group and clone, checks that the configured lock-space path sits under the GFS2 directory, and inspects each VirtualDomain resource for ordering and colocation references to the lock clone. It also reads `crm_mon` on the selected cluster host and maps active DLM/GFS2 primitive instances to online cluster nodes; the UI reports all-node activity only when each required component was found and observed on every online node. This does not prove the full qemu+ssh connection, application-specific network equivalence, or safe storage behavior under failure. A reviewed preparation operation now rechecks membership, quorum/fencing, DLM/GFS2 activity, VM state/UUID, shared GFS2 paths, disk access, and explicit operator confirmations inside a serialized cluster mutation. It writes the VM XML exclusively to the selected shared directory and submits a Pacemaker `VirtualDomain` primitive plus order/colocation constraints as one CIB update with `target-role=Stopped`; it does not boot or migrate the guest. The operation is stored with an ID and can be resumed after page refresh. Failures remain visible as operation results; if CIB application fails after XML export, the XML is retained and its path is reported for manual review rather than deleted blindly. While Pacemaker is active, VM creation rejects names already defined by a `VirtualDomain` resource, and direct lifecycle, deletion, snapshot, autostart, graphics, device, and configuration routes match managed guest XML by UUID/name; such guests must be managed under the Clusters resources view. If the cluster state, CIB, or a relevant shared guest XML cannot be verified, direct mutation is rejected instead of risking two controllers. Non-clustered hosts and hosts with Pacemaker definitively inactive retain the normal libvirt UI workflow.

Next, test the prepared resource against supported SLE HA releases and real shared-storage/fencing behavior, tighten post-change reconciliation and recovery guidance, then implement durable Pacemaker ownership in host-level VM actions so direct libvirt controls cannot compete with a managed resource. Do not enable live migration until shared storage, equivalent networks, CPU compatibility, the full libvirt remote URI, and safe operation handling are verified.
