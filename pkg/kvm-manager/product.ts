import { IPlugin } from '@shell/core/types';
import Hosts from './pages/Hosts.vue';
import CloudNative from './pages/CloudNative.vue';
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
  }]);

  $plugin.addRoute('default', {
    name: 'kvm-c-cluster-cloud-native',
    path: 'kvm/c/:cluster/cloud-native',
    component: CloudNative,
    params: { cluster: '_' },
  });
}

export default { init };
