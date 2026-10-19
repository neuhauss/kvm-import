<template>
  <div class="kvm-page deploy-page">
    <header class="deploy-header">
      <div><span class="eyebrow">{{ t('deploy.eyebrow') }}</span><h1>{{ t('deploy.title') }}</h1><p>{{ t('deploy.subtitle') }}</p></div>
      <button class="btn role-secondary" :disabled="loading" @click="loadAll">{{ loading ? t('deploy.loading') : t('deploy.refresh') }}</button>
    </header>

    <div v-if="error" class="banner error" role="alert">{{ error }}</div>
    <div v-if="creationWarning" class="banner warning" role="status">{{ creationWarning }}</div>
    <div class="deploy-callout" role="note"><strong>{{ t('deploy.sessionTitle') }}</strong><p>{{ t('deploy.sessionHelp') }}</p></div>
    <div class="deploy-callout warning" role="note"><strong>{{ t('deploy.nestedTitle') }}</strong><p>{{ t('deploy.nestedHelp') }}</p></div>

    <section class="deploy-panel">
      <header class="panel-heading"><div><span class="eyebrow">{{ t('deploy.stepOne') }}</span><h2>{{ t('deploy.targetTitle') }}</h2><p>{{ t('deploy.targetHelp') }}</p></div><span v-if="targetReady" class="deploy-badge ready">{{ t('deploy.connected') }}</span><span v-else-if="targetChecked" class="deploy-badge warning-state">{{ t('deploy.targetNotReady') }}</span></header>
      <div class="deploy-grid">
        <label class="rancher-field field-wide"><span>{{ t('deploy.cluster') }} *</span><select v-model="form.clusterId" required @change="onClusterChanged"><option value="">{{ t('deploy.selectCluster') }}</option><option v-for="cluster in clusters" :key="cluster.id" :value="cluster.id">{{ cluster.displayName || cluster.name }} ({{ cluster.id }})</option></select></label>
        <label class="rancher-field"><span>{{ t('deploy.namespace') }} *</span><select v-model="form.namespace" required :disabled="!targetReady" @change="onNamespaceChanged"><option value="">{{ t('deploy.selectNamespace') }}</option><option v-for="item in namespaces" :key="item" :value="item">{{ item }}</option></select></label>
        <label class="rancher-field"><span>{{ t('deploy.image') }} *</span><select v-model="form.imageKey" required :disabled="!targetReady"><option value="">{{ t('deploy.selectImage') }}</option><option v-for="image in images" :key="imageKey(image)" :value="imageKey(image)">{{ imageLabel(image) }}</option></select><small>{{ t('deploy.imageHelp') }}</small></label>
        <label class="rancher-field"><span>{{ t('deploy.network') }} *</span><select v-model="form.networkName" required :disabled="!form.namespace || networkLoading"><option value="">{{ networkLoading ? t('deploy.loading') : t('deploy.selectNetwork') }}</option><option v-for="network in networks" :key="network.metadata.name" :value="network.metadata.name">{{ network.metadata.name }}</option></select><small>{{ t('deploy.networkHelp') }}</small></label>
      </div>
      <div v-if="targetChecked && !targetReady" class="banner warning" role="status">{{ targetMessage }}</div>
    </section>

    <section class="deploy-panel">
      <header class="panel-heading"><div><span class="eyebrow">{{ t('deploy.stepTwo') }}</span><h2>{{ t('deploy.vmTitle') }}</h2><p>{{ t('deploy.vmHelp') }}</p></div></header>
      <div class="deploy-grid">
        <label class="rancher-field"><span>{{ t('deploy.vmName') }} *</span><input v-model.trim="form.name" required maxlength="50" autocomplete="off" placeholder="kvm-host-01"></label>
        <label class="rancher-field"><span>{{ t('deploy.cpu') }} *</span><input v-model.number="form.cpus" type="number" min="2" max="128" step="1" required></label>
        <label class="rancher-field"><span>{{ t('deploy.memory') }} *</span><input v-model.number="form.memoryGi" type="number" min="4" max="512" step="1" required><small>GiB</small></label>
        <label class="rancher-field"><span>{{ t('deploy.disk') }} *</span><input v-model.number="form.diskGi" type="number" :min="minimumDiskGi" max="2048" step="1" required><small>{{ t('deploy.diskHelp', { min: minimumDiskGi }) }}</small></label>
        <label class="rancher-field"><span>{{ t('deploy.sshUser') }} *</span><input v-model.trim="form.username" required maxlength="32" autocomplete="username" placeholder="sles"></label>
        <label class="rancher-field"><span>{{ t('deploy.initialPassword') }} *</span><input v-model="form.initialPassword" type="password" required minlength="12" maxlength="128" autocomplete="new-password"><small>{{ t('deploy.initialPasswordHelp') }}</small></label>
        <label class="rancher-field field-wide"><span>{{ t('deploy.sshPublicKey') }} *</span><textarea v-model.trim="form.sshPublicKey" rows="3" required autocomplete="off" spellcheck="false" placeholder="ssh-ed25519 AAAA… user@workstation"></textarea><small>{{ t('deploy.sshPublicKeyHelp') }}</small></label>
      </div>
      <label class="rancher-check deploy-check"><input v-model="form.installKvm" type="checkbox"><span><strong>{{ t('deploy.installKvm') }}</strong><small>{{ t('deploy.installKvmHelp') }}</small></span></label>
    </section>

    <section class="deploy-panel">
      <header class="panel-heading"><div><span class="eyebrow">{{ t('deploy.stepThree') }}</span><h2>{{ t('deploy.reviewTitle') }}</h2><p>{{ t('deploy.reviewHelp') }}</p></div></header>
      <div v-if="!preview" class="deploy-actions"><button class="btn role-primary" :disabled="!canPreview" @click="showPreview">{{ t('deploy.preview') }}</button></div>
      <ul v-if="!preview && validationMessages.length" class="validation-list" role="status" :aria-label="t('deploy.validationSummary')"><li v-for="issue in validationMessages" :key="issue">{{ issue }}</li></ul>
      <div v-else class="deploy-review">
        <dl><div><dt>{{ t('deploy.cluster') }}</dt><dd>{{ selectedClusterLabel }}</dd></div><div><dt>{{ t('deploy.namespace') }}</dt><dd>{{ form.namespace }}</dd></div><div><dt>{{ t('deploy.vmName') }}</dt><dd>{{ form.name }}</dd></div><div><dt>{{ t('deploy.image') }}</dt><dd>{{ selectedImageLabel }}</dd></div><div><dt>{{ t('deploy.network') }}</dt><dd>{{ form.namespace }}/{{ form.networkName }}</dd></div><div><dt>{{ t('deploy.resources') }}</dt><dd>{{ form.cpus }} vCPU · {{ form.memoryGi }} GiB RAM · {{ form.diskGi }} GiB disk</dd></div><div><dt>{{ t('deploy.sshUser') }}</dt><dd>{{ form.username }}</dd></div><div><dt>{{ t('deploy.guestSetup') }}</dt><dd>{{ form.installKvm ? t('deploy.guestSetupKvm') : t('deploy.guestSetupKeyOnly') }}</dd></div></dl>
        <div class="deploy-actions"><button class="btn role-secondary" :disabled="creating" @click="preview = false">{{ t('deploy.back') }}</button><button class="btn role-primary" :disabled="creating" @click="createVm">{{ creating ? t('deploy.creating') : t('deploy.create') }}</button></div>
      </div>
    </section>

    <section v-if="managedVms.length" class="deploy-panel">
      <header class="panel-heading"><div><span class="eyebrow">{{ t('deploy.createdHosts') }}</span><h2>{{ t('deploy.vmListTitle') }}</h2></div><button class="btn role-secondary btn-sm" :disabled="vmLoading" @click="loadVms">{{ vmLoading ? t('deploy.loading') : t('deploy.refresh') }}</button></header>
      <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('deploy.vmName') }}</th><th>{{ t('deploy.state') }}</th><th>{{ t('deploy.address') }}</th><th>{{ t('deploy.actions') }}</th></tr></thead><tbody><tr v-for="vm in managedVms" :key="vm.metadata.uid || vm.metadata.name"><td><strong>{{ vm.metadata.name }}</strong><small>{{ vm.metadata.namespace }}</small></td><td><span class="deploy-badge" :class="vmStateClass(vm)">{{ vmState(vm) }}</span><small v-if="vm.status?.conditions?.length">{{ conditionMessage(vm) }}</small></td><td>{{ vmAddresses(vm).join(', ') || '—' }}</td><td><button class="btn role-link btn-sm" :disabled="!vmAddresses(vm).length" @click="importVm(vm)">{{ t('deploy.importHost') }}</button></td></tr></tbody></table></div>
        <p class="deploy-footnote">{{ t('deploy.importHelp') }}</p>
      </section>

    <footer v-if="creating" class="deploy-progress" role="status"><span class="spinner" aria-hidden="true"></span>{{ progressMessage }}</footer>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

type RancherCluster = { id: string; name: string; displayName?: string; state?: string };
type VmImage = { metadata: { name: string; namespace: string; labels?: Record<string, string> }; spec?: { displayName?: string; targetStorageClassName?: string }; status?: { imported?: boolean; progress?: number; size?: number; virtualSize?: number; storageClassName?: string; conditions?: Array<{ type?: string; status?: string }> } };
type KvmVm = { apiVersion: string; kind: string; metadata: { name: string; namespace: string; uid?: string; labels?: Record<string, string>; annotations?: Record<string, string> }; spec?: any; status?: any };

export default defineComponent({
  name: 'KvmDeploy',
  data() {
    return {
      clusters: [] as RancherCluster[], namespaces: [] as string[], images: [] as VmImage[], networks: [] as Array<{ metadata: { name: string } }>, managedVms: [] as KvmVm[],
      form: { clusterId: '', namespace: '', imageKey: '', networkName: '', name: '', cpus: 4, memoryGi: 8, diskGi: 40, username: 'sles', initialPassword: '', sshPublicKey: '', installKvm: true },
      loading: false, networkLoading: false, vmLoading: false, creating: false, targetChecked: false, targetReady: false, targetMessage: '', error: '', creationWarning: '', preview: false, progressMessage: '', refreshTimer: 0 as number,
    };
  },
  computed: {
    selectedImage(): VmImage | undefined { return this.images.find((item) => this.imageKey(item) === this.form.imageKey); },
    selectedClusterLabel(): string { const item = this.clusters.find((cluster) => cluster.id === this.form.clusterId); return item ? `${item.displayName || item.name} (${item.id})` : this.form.clusterId; },
    selectedImageLabel(): string { return this.selectedImage ? this.imageLabel(this.selectedImage) : ''; },
    minimumDiskGi(): number { const bytes = this.selectedImage?.status?.virtualSize || 0; return Math.max(10, Math.ceil(bytes / (1024 ** 3))); },
    validationMessages(): string[] {
      const issues: string[] = [];
      if (!this.form.clusterId) issues.push(this.t('validationCluster'));
      if (!this.targetReady) issues.push(this.t('validationTarget'));
      if (!this.form.namespace) issues.push(this.t('validationNamespace'));
      if (!this.selectedImage) issues.push(this.t('validationImage'));
      if (!this.form.networkName) issues.push(this.t('validationNetwork'));
      if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(this.form.name)) issues.push(this.t('validationVmName'));
      if (!Number.isInteger(this.form.cpus) || this.form.cpus < 2 || this.form.cpus > 128) issues.push(this.t('validationCpu'));
      if (!Number.isInteger(this.form.memoryGi) || this.form.memoryGi < 4 || this.form.memoryGi > 512) issues.push(this.t('validationMemory'));
      if (!Number.isInteger(this.form.diskGi) || this.form.diskGi < this.minimumDiskGi || this.form.diskGi > 2048) issues.push(this.t('validationDisk', { min: this.minimumDiskGi }));
      if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(this.form.username)) issues.push(this.t('validationSshUser'));
      if (this.form.initialPassword.length < 12 || this.form.initialPassword.length > 128) issues.push(this.t('validationPassword'));
      if (!/^(ssh-(ed25519|rsa|ecdsa)|ecdsa-sha2-nistp[0-9]+)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$/.test(this.form.sshPublicKey.trim())) issues.push(this.t('validationSshKey'));
      return issues;
    },
    canPreview(): boolean { return this.validationMessages.length === 0; },
  },
  watch: { form: { deep: true, handler() { this.preview = false; } } },
  mounted() { this.loadAll(); this.refreshTimer = window.setInterval(() => { if (document.visibilityState === 'visible' && this.form.clusterId && this.form.namespace && !this.creating) this.loadVms(); }, 30000); },
  beforeUnmount() { window.clearInterval(this.refreshTimer); },
  methods: {
    t(key: string, args?: Record<string, unknown>): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.deploy.${key}`, args) : key; },
    async request(url: string, method = 'GET', data?: unknown) {
      const options: Record<string, unknown> = { url, method, redirectUnauthorized: false, headers: { Accept: 'application/json' } };
      if (data !== undefined) { options.data = data; options.headers = { ...(options.headers as Record<string, string>), 'Content-Type': method === 'PATCH' ? 'application/merge-patch+json' : 'application/json' }; }
      return (this as any).$store.dispatch('management/request', options);
    },
    async loadAll() {
      this.loading = true; this.error = '';
      try {
        const result = await this.request('/v3/clusters?limit=-1');
        this.clusters = (result?.data || []).filter((item: RancherCluster) => !item.state || item.state === 'active').sort((a: RancherCluster, b: RancherCluster) => (a.displayName || a.name).localeCompare(b.displayName || b.name));
        if (!this.clusters.length) throw new Error(this.t('noClusters'));
        if (!this.form.clusterId || !this.clusters.some((item) => item.id === this.form.clusterId)) this.form.clusterId = this.clusters.find((item) => item.id === 'local')?.id || this.clusters[0].id;
        await this.loadTarget();
      } catch (error) { this.error = `${this.t('loadError')}: ${this.safeMessage(error)}`; this.targetReady = false; }
      finally { this.loading = false; }
    },
    async onClusterChanged() { this.form.namespace = ''; this.form.imageKey = ''; this.form.networkName = ''; this.managedVms = []; this.preview = false; await this.loadTarget(); },
    async onNamespaceChanged() { this.form.networkName = ''; this.preview = false; await this.loadNetworks(); await this.loadVms(); },
    async loadTarget() {
      if (!this.form.clusterId) return;
      this.targetChecked = true; this.targetReady = false; this.targetMessage = ''; this.loading = true;
      try {
        const [namespaceResult, imageResult] = await Promise.all([
          this.request(`/k8s/clusters/${encodeURIComponent(this.form.clusterId)}/api/v1/namespaces?limit=1000`),
          this.request(`/k8s/clusters/${encodeURIComponent(this.form.clusterId)}/apis/harvesterhci.io/v1beta1/virtualmachineimages?limit=1000`),
        ]);
        this.namespaces = (namespaceResult?.items || []).filter((item: any) => item.status?.phase === 'Active' && !item.metadata?.deletionTimestamp).map((item: any) => item.metadata.name).sort();
        this.images = (imageResult?.items || []).filter((image: VmImage) => this.imageReady(image)).sort((a: VmImage, b: VmImage) => this.imageLabel(a).localeCompare(this.imageLabel(b)));
        this.targetReady = true; this.targetMessage = '';
        if (!this.form.namespace || !this.namespaces.includes(this.form.namespace)) this.form.namespace = this.namespaces.includes('default') ? 'default' : (this.namespaces[0] || '');
        if (!this.form.imageKey || !this.images.some((item) => this.imageKey(item) === this.form.imageKey)) this.form.imageKey = this.imageKey(this.images[0]) || '';
        await this.onNamespaceChanged();
      } catch (error) { this.targetMessage = this.safeMessage(error); this.targetReady = false; this.namespaces = []; this.images = []; this.networks = []; }
      finally { this.loading = false; }
    },
    async loadNetworks() {
      if (!this.form.clusterId || !this.form.namespace) { this.networks = []; return; }
      this.networkLoading = true;
      try {
        const result = await this.request(`/k8s/clusters/${encodeURIComponent(this.form.clusterId)}/apis/k8s.cni.cncf.io/v1/namespaces/${encodeURIComponent(this.form.namespace)}/network-attachment-definitions?limit=1000`);
        this.networks = (result?.items || []).filter((item: any) => !item.metadata?.deletionTimestamp).sort((a: any, b: any) => a.metadata.name.localeCompare(b.metadata.name));
        if (!this.networks.some((item) => item.metadata.name === this.form.networkName)) this.form.networkName = this.networks[0]?.metadata.name || '';
      } catch (error) { this.networks = []; this.targetMessage = this.safeMessage(error); }
      finally { this.networkLoading = false; }
    },
    async loadVms() {
      if (!this.form.clusterId || !this.form.namespace) return;
      this.vmLoading = true;
      try {
        const result = await this.request(`/k8s/clusters/${encodeURIComponent(this.form.clusterId)}/apis/kubevirt.io/v1/namespaces/${encodeURIComponent(this.form.namespace)}/virtualmachines?labelSelector=kvm-manager.suse.com%2Fmanaged%3Dtrue`);
        this.managedVms = result?.items || [];
      } catch { /* Keep the last loaded deployments visible if a refresh is temporarily denied. */ }
      finally { this.vmLoading = false; }
    },
    imageKey(image?: VmImage): string { return image ? `${image.metadata.namespace}/${image.metadata.name}` : ''; },
    imageLabel(image: VmImage): string { const display = image.metadata.labels?.['harvesterhci.io/imageDisplayName'] || image.spec?.displayName || image.metadata.name; return `${display} · ${image.metadata.namespace}`; },
    imageReady(image: VmImage): boolean { const imported = image.status?.conditions?.find((condition) => condition.type === 'Imported')?.status === 'True'; return Boolean((imported || image.status?.imported === true) && (image.status?.progress === undefined || image.status.progress >= 100) && image.status?.storageClassName); },
    showPreview() { this.error = ''; this.preview = true; },
    async createVm() {
      if (!this.canPreview || !this.selectedImage) return;
      this.error = ''; this.creationWarning = ''; this.creating = true; this.progressMessage = this.t('creatingSecret');
      const secretName = `${this.form.name}-cloud-${Math.random().toString(36).slice(2, 7)}`;
      const apiRoot = `/k8s/clusters/${encodeURIComponent(this.form.clusterId)}`;
      const secretPath = `${apiRoot}/api/v1/namespaces/${encodeURIComponent(this.form.namespace)}/secrets`;
      const vmPath = `${apiRoot}/apis/kubevirt.io/v1/namespaces/${encodeURIComponent(this.form.namespace)}/virtualmachines`;
      let secretCreated = false;
      try {
        const userData = this.buildCloudConfig();
        const secret = await this.request(secretPath, 'POST', { apiVersion: 'v1', kind: 'Secret', metadata: { name: secretName, namespace: this.form.namespace, labels: { 'kvm-manager.suse.com/managed': 'true' } }, type: 'Opaque', stringData: { userdata: userData, networkdata: this.networkConfig() } });
        secretCreated = true;
        this.progressMessage = this.t('creatingVm');
        const volumeClaim = {
          metadata: { name: `${this.form.name}-disk-0`, annotations: { 'harvesterhci.io/imageId': this.form.imageKey } },
          spec: { accessModes: ['ReadWriteMany'], resources: { requests: { storage: `${this.form.diskGi}Gi` } }, volumeMode: 'Block', storageClassName: this.selectedImage.status?.storageClassName || this.selectedImage.spec?.targetStorageClassName },
        };
        const vm: KvmVm = {
          apiVersion: 'kubevirt.io/v1', kind: 'VirtualMachine',
          metadata: { name: this.form.name, namespace: this.form.namespace, labels: { 'kvm-manager.suse.com/managed': 'true' }, annotations: { 'harvesterhci.io/vmRunStrategy': 'RerunOnFailure', 'harvesterhci.io/volumeClaimTemplates': JSON.stringify([volumeClaim]), 'kvm-manager.suse.com/ssh-user': this.form.username } },
          spec: { runStrategy: 'RerunOnFailure', template: { spec: {
            domain: { cpu: { cores: this.form.cpus, sockets: 1, threads: 1, model: 'host-passthrough' }, memory: { guest: `${this.form.memoryGi}Gi` }, machine: { type: 'q35' }, resources: { requests: { cpu: String(this.form.cpus), memory: `${this.form.memoryGi}Gi` } }, devices: { disks: [{ name: 'disk-0', disk: { bus: 'virtio' }, bootOrder: 1 }, { name: 'cloudinitdisk', disk: { bus: 'virtio' } }], interfaces: [{ name: 'default', model: 'virtio', bridge: {} }] } },
            networks: [{ name: 'default', multus: { networkName: `${this.form.namespace}/${this.form.networkName}` } }],
            volumes: [{ name: 'disk-0', persistentVolumeClaim: { claimName: `${this.form.name}-disk-0` } }, { name: 'cloudinitdisk', cloudInitNoCloud: { secretRef: { name: secretName } } }],
          } } },
        };
        const createdVm = await this.request(vmPath, 'POST', vm);
        if (secret?.metadata?.uid && createdVm?.metadata?.uid) {
          this.progressMessage = this.t('linkingSecret');
          try { await this.request(`${secretPath}/${encodeURIComponent(secretName)}`, 'PATCH', { metadata: { ownerReferences: [{ apiVersion: 'kubevirt.io/v1', kind: 'VirtualMachine', name: this.form.name, uid: createdVm.metadata.uid, controller: true, blockOwnerDeletion: true }] } }); } catch { this.creationWarning = this.t('secretCleanupWarning'); }
        }
        this.preview = false; await this.loadVms();
      } catch (error) {
        if (secretCreated) { try { await this.request(`${secretPath}/${encodeURIComponent(secretName)}`, 'DELETE'); } catch { /* Preserve the original VM creation error. */ } }
        this.error = `${this.t('createError')}: ${this.safeMessage(error)}`;
      } finally { this.creating = false; this.progressMessage = ''; }
    },
    buildCloudConfig(): string {
      const user = this.form.username;
      const key = this.form.sshPublicKey.trim();
      const lines = ['#cloud-config', 'ssh_pwauth: false', 'users:', '  - default', `  - name: ${user}`, '    groups: [users]', '    shell: /bin/bash', '    sudo: ALL=(ALL) NOPASSWD:ALL', '    lock_passwd: false', '    ssh_authorized_keys:', `      - ${JSON.stringify(key)}`, 'chpasswd:', '  expire: false', '  users:', `    - name: ${user}`, `      password: ${JSON.stringify(this.form.initialPassword)}`, '      type: text'];
      if (this.form.installKvm) lines.push('runcmd:', '  - [zypper, --non-interactive, refresh]', '  - [zypper, --non-interactive, install, --type, pattern, kvm_server, kvm_tools]', '  - [zypper, --non-interactive, install, --no-recommends, cockpit, cockpit-machines]', '  - [/bin/bash, -lc, "systemctl enable --now cockpit.socket && (systemctl enable --now libvirtd.socket || systemctl enable --now virtqemud.socket)"]');
      return `${lines.join('\n')}\n`;
    },
    networkConfig(): string { return 'network:\n  version: 1\n  config:\n    - type: physical\n      name: eth0\n      subnets:\n        - type: dhcp\n'; },
    vmState(vm: KvmVm): string { return vm.status?.printableStatus || vm.status?.phase || (vm.status?.ready ? this.t('running') : this.t('pending')); },
    vmStateClass(vm: KvmVm): string { const state = String(this.vmState(vm)).toLowerCase(); return state.includes('running') || state.includes('ready') ? 'ready' : state.includes('error') || state.includes('failed') ? 'unreachable' : 'warning-state'; },
    conditionMessage(vm: KvmVm): string { return (vm.status?.conditions || []).find((condition: any) => condition.status === 'False')?.message || ''; },
    vmAddresses(vm: KvmVm): string[] {
      const statusIps = (vm.status?.interfaces || []).flatMap((iface: any) => iface.ipAddresses || (iface.ipAddress ? [iface.ipAddress] : []));
      let annotationIps: string[] = [];
      const raw = vm.metadata.annotations?.['network.harvesterhci.io/ips'];
      if (raw) { try { const parsed = JSON.parse(raw); annotationIps = Array.isArray(parsed) ? parsed.map((item: any) => typeof item === 'string' ? item : item.ipAddress || item.ip || '').filter(Boolean) : []; } catch { /* Ignore malformed Harvester status data. */ } }
      return [...new Set([...statusIps, ...annotationIps].filter((ip) => !String(ip).includes(':') && String(ip).trim()))];
    },
    importVm(vm: KvmVm) {
      const address = this.vmAddresses(vm)[0]; if (!address) return;
      const username = vm.metadata.annotations?.['kvm-manager.suse.com/ssh-user'] || this.form.username;
      (this as any).$router.push({ name: 'kvm-hosts', query: { deployAddress: address, deployUsername: username, deployName: vm.metadata.name } });
    },
    safeMessage(error: unknown): string {
      const item: any = error as any;
      const message = item?.data?.message || item?.data?.detail || item?.response?.data?.message || item?.response?.data?.detail || item?.message || this.t('genericError');
      let safe = String(message);
      if (this.form.initialPassword) safe = safe.split(this.form.initialPassword).join('[redacted]');
      return safe.replace(/\s+/g, ' ').trim().slice(0, 600);
    },
  },
});
</script>

<style scoped>
.deploy-page { max-width:1260px; margin:0 auto; padding:26px; }.deploy-header,.panel-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }.deploy-header { margin-bottom:22px; }.deploy-header h1 { margin:4px 0 0; font-size:24px; font-weight:500; }.deploy-header p,.panel-heading p { margin:6px 0 0; color:var(--muted,#8b95a5); }.eyebrow { color:var(--muted,#8b95a5); font-size:11px; font-weight:700; letter-spacing:.06em; }.deploy-callout { margin-bottom:14px; padding:14px 16px; border:1px solid var(--border,#394452); border-left:3px solid var(--primary,#4b91e2); border-radius:6px; background:var(--body-bg,#252b33); }.deploy-callout p { margin:5px 0 0; color:var(--muted,#8b95a5); font-size:13px; line-height:1.5; }.deploy-callout.warning { border-left-color:#d6a63e; }.deploy-panel { margin:16px 0; padding:20px; border:1px solid var(--border,#394452); border-radius:8px; background:var(--body-bg,#252b33); }.panel-heading { align-items:center; margin-bottom:18px; }.panel-heading h2 { margin:4px 0 0; font-size:19px; }.panel-heading p { font-size:13px; line-height:1.5; }.deploy-grid { display:grid; grid-template-columns:repeat(2,minmax(220px,1fr)); gap:16px; }.rancher-field { display:flex; flex-direction:column; gap:7px; min-width:0; color:var(--body-text,#f5f6f7); font-size:13px; }.rancher-field>span { font-weight:600; }.rancher-field input,.rancher-field select,.rancher-field textarea { width:100%; min-height:40px; padding:9px 11px; border:1px solid var(--border,#4b5665); border-radius:5px; background:var(--input-bg,#1c2128); color:var(--body-text,#f5f6f7); font:inherit; }.rancher-field textarea { resize:vertical; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }.rancher-field input:focus,.rancher-field select:focus,.rancher-field textarea:focus { outline:2px solid var(--primary,#4b91e2); outline-offset:1px; }.rancher-field small,.deploy-footnote { color:var(--muted,#8b95a5); font-size:12px; line-height:1.5; }.field-wide { grid-column:1/-1; }.deploy-check { margin-top:18px; }.deploy-badge { display:inline-flex; align-items:center; border:1px solid var(--border,#394452); border-radius:99px; padding:5px 9px; color:var(--muted,#9ca6b4); font-size:11px; white-space:nowrap; }.deploy-badge.ready { color:#4dc48a; border-color:rgba(77,196,138,.45); background:rgba(77,196,138,.1); }.deploy-badge.warning-state { color:#d6a63e; }.deploy-actions { display:flex; justify-content:flex-end; gap:10px; margin-top:18px; }.deploy-review { padding:15px; border:1px solid var(--border,#394452); border-radius:6px; background:rgba(127,140,158,.06); }.deploy-review dl { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px 24px; margin:0; }.deploy-review dl>div { min-width:0; }.deploy-review dt { color:var(--muted,#8b95a5); font-size:11px; }.deploy-review dd { margin:4px 0 0; overflow-wrap:anywhere; font-size:13px; }.deploy-progress { position:sticky; bottom:0; display:flex; align-items:center; gap:10px; padding:12px 16px; border:1px solid var(--border,#394452); border-radius:6px; background:var(--body-bg,#252b33); }.spinner { width:16px; height:16px; border:2px solid var(--border,#394452); border-top-color:var(--primary,#4b91e2); border-radius:50%; animation:spin .8s linear infinite; }@keyframes spin { to { transform:rotate(360deg); } }.table-wrap { overflow:auto; }.table { width:100%; border-collapse:collapse; }.table th,.table td { padding:11px 12px; border-bottom:1px solid var(--border,#394452); text-align:left; font-size:12px; vertical-align:top; }.table th { color:var(--muted,#8b95a5); font-size:10px; text-transform:uppercase; white-space:nowrap; }.table td small { display:block; margin-top:4px; color:var(--muted,#8b95a5); }.deploy-footnote { margin-bottom:0; }.banner.error,.banner.warning { margin:12px 0; padding:12px; border-radius:5px; }.banner.error { color:#8f211a; background:#fff0ee; }.banner.warning { color:#7a5710; background:#fff6db; }
.validation-list { margin:12px 0 0; padding:11px 14px 11px 32px; border:1px solid color-mix(in srgb,#d6a63e 45%,var(--border,#394452)); border-left:3px solid #d6a63e; border-radius:5px; color:var(--body-text,#e7e9ec); background:color-mix(in srgb,#d6a63e 8%,var(--body-bg,#252b33)); font-size:12px; line-height:1.6; }
@media(max-width:760px) { .deploy-page { padding:18px 12px; }.deploy-grid,.deploy-review dl { grid-template-columns:1fr; }.deploy-header,.panel-heading { flex-direction:column; align-items:flex-start; }.deploy-panel { padding:15px; } }
</style>
