import Hosts from '../pages/Hosts.vue';

const routes = [
  {
    name: 'kvm-hosts',
    path: '/kvm/hosts',
    component: Hosts,
    meta: { product: 'kvm', pkg: 'kvm-manager' },
  },
];

export default routes;
