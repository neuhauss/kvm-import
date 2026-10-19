import { importTypes } from '@rancher/auto-import';
import { IPlugin } from '@shell/core/types';
import Hosts from './pages/Hosts.vue';
import Clusters from './pages/Clusters.vue';
import CloudNative from './pages/CloudNative.vue';
import Deploy from './pages/Deploy.vue';
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
}
