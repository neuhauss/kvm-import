export type ClusterPermissionSummary = {
  canManageClusters?: unknown;
  canAdministerHost?: unknown;
  canManageHostResources?: unknown;
};

/** Match the API's cluster_admin policy; host-resource access alone is insufficient. */
export function canManageClusterOperations(permissions: ClusterPermissionSummary): boolean {
  return permissions.canManageClusters === true || permissions.canAdministerHost === true;
}
