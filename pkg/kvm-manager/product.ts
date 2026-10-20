import { IPlugin } from '@shell/core/types';
import { defineAsyncComponent } from 'vue';
import Hosts from './pages/Hosts.vue';
import Clusters from './pages/Clusters.vue';
import Deploy from './pages/Deploy.vue';
const Backups = defineAsyncComponent(() => import('./pages/Backups.vue'));
import CloudNative from './pages/CloudNative.vue';
const ManagedKvmClusters = defineAsyncComponent(() => import('./pages/ManagedKvmClusters.vue'));
import './assets/kvm.css';

export function init($plugin: IPlugin, store: any): void {
  $plugin.addProduct({
    name: 'kvm',
    label: 'KVM',
    sideBar: { icon: { name: 'kvm' }, weight: 95 },
    resources: { store: 'management' },
  }, [{
    name: 'hosts',
    label: 'Hosts',
    component: Hosts,
  }, {
    name: 'clusters',
    label: 'Clusters',
    component: Clusters,
  }, {
    name: 'deploy',
    label: 'Deploy',
    component: Deploy,
  }, {
    name: 'backups',
    label: 'Backups',
    component: Backups,
  }]);

  // Keep this page reachable from the per-host administration menu only.
  $plugin.addRoute('default', {
    name: 'kvm-c-cluster-cloud-native',
    path: '/kvm/c/:cluster/cloud-native',
    component: CloudNative,
    params: { product: 'kvm', cluster: '_' },
    meta: { product: 'kvm', cluster: '_' },
  });
  $plugin.addRoute('default', {
    name: 'kvm-c-managed-clusters',
    path: '/kvm/c/:cluster/managed-clusters',
    component: ManagedKvmClusters,
    params: { product: 'kvm', cluster: '_' },
    meta: { product: 'kvm', cluster: '_' },
  });
}

export default { init };
