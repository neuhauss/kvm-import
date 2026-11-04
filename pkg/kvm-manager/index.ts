import { importTypes } from '@rancher/auto-import';
import { IPlugin } from '@shell/core/types';
import { defineAsyncComponent } from 'vue';
import Hosts from './pages/Hosts.vue';
import Clusters from './pages/Clusters.vue';
import Deploy from './pages/Deploy.vue';
const Backups = defineAsyncComponent(() => import('./pages/Backups.vue'));
const ManagedKvmClusters = defineAsyncComponent(() => import('./pages/ManagedKvmClusters.vue'));
const CloudNative = defineAsyncComponent(() => import(/* webpackChunkName: "kvm-cloud-native" */ './pages/CloudNative.vue'));
import './assets/kvm.css';

// Init the package
export default function(plugin: IPlugin): void {
  // Auto-import model, detail, edit from the folders
  importTypes(plugin);

  // Provide plugin metadata from package.json
  plugin.metadata = require('./package.json');

  plugin.addProduct({
    name: 'kvm',
    label: 'KVM',
    // KVM is not part of Rancher's built-in icon set. Supplying the SVG here
    // prevents the product sidebar from falling back to the puzzle icon.
    sideBar: { icon: { svg: require('./assets/kvm.svg') }, weight: 95 },
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

  // Keep the Cloud Native page routable for the per-host administration menu,
  // without exposing it as a second item in the KVM side navigation.
  plugin.addRoute('default', {
    name: 'kvm-c-cluster-cloud-native',
    path: '/kvm/c/:cluster/cloud-native',
    component: CloudNative,
    // Keep this route available for the per-host menu without registering a
    // second page in the KVM product side navigation.
    params: { product: 'kvm', cluster: '_' },
    meta: { product: 'kvm', cluster: '_' },
  });
  plugin.addRoute('default', {
    name: 'kvm-c-managed-clusters',
    path: '/kvm/c/:cluster/managed-clusters',
    component: ManagedKvmClusters,
    params: { product: 'kvm', cluster: '_' },
    meta: { product: 'kvm', cluster: '_' },
  });
}
