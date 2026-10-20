# Rancher RBAC mapping

The extension maps Rancher **Global Role IDs** to four access tiers. Configure
the role IDs in the KVM chart values; access is checked by the extension API on
every request.

| Tier | Capabilities |
| --- | --- |
| Viewer | View hosts, VM state, metrics, and host inventory. |
| VM operator | Viewer access plus VM lifecycle actions and host refresh. |
| Host operator | VM operator access plus network, storage, account, repository, subscription, service, and security changes. |
| Host administrator | Host operator access plus importing, editing, and removing hosts, Cockpit access, terminal, and audit log. |

Example values (replace the IDs with Global Role IDs from the target Rancher):

```yaml
rancher:
  viewerGlobalRoles: ["role-viewer"]
  vmOperatorGlobalRoles: ["role-vm-operator"]
  hostOperatorGlobalRoles: ["role-kvm-operator"]
  allowedGlobalRoles: ["admin", "role-kvm-admin"]
```

`allowedGlobalRoles` keeps its existing name for backward compatibility. Its
members receive the highest tier. A user assigned to multiple configured roles
receives the highest matching tier. This mapping does not modify Rancher roles
or permissions; it is enforced inside the KVM extension API.
