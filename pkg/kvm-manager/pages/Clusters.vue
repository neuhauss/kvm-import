<template>
  <div class="kvm-page clusters-page">
    <header class="clusters-header">
      <div><span class="eyebrow">SUSE LINUX ENTERPRISE HIGH AVAILABILITY</span><h1>{{ t('clusters.title') }}</h1><p>{{ t('clusters.subtitle') }}</p></div>
      <button class="btn role-secondary" :disabled="loading || refreshingStale" @click="load">{{ loading || refreshingStale ? t('clusters.refreshing') : t('clusters.refresh') }}</button>
    </header>

    <div v-if="error" class="banner error" role="alert">{{ error }}</div>
    <div v-if="loading && !loaded" class="loading">{{ t('clusters.loading') }}</div>
    <template v-else>
      <div class="cluster-stats">
        <article><span>{{ t('clusters.registeredHosts') }}</span><strong>{{ hosts.length }}</strong></article>
        <article><span>{{ t('clusters.haEnabledHosts') }}</span><strong>{{ haEnabledCount }}</strong><small>{{ t('clusters.haEnabledHostsHelp') }}</small></article>
        <article><span>{{ t('clusters.activeClusters') }}</span><strong>{{ clusterCount }}</strong><small>{{ t('clusters.activeClustersHelp') }}</small></article>
      </div>

      <section class="cluster-panel">
        <div class="panel-heading"><div><span class="eyebrow">{{ t('clusters.readiness') }}</span><h2>{{ t('clusters.hostsTitle') }}</h2><p>{{ t('clusters.hostsDescription') }}</p></div><button class="btn role-primary" @click="goToHosts">{{ t('clusters.manageHosts') }}</button></div>
        <div v-if="!hosts.length" class="empty-state"><h3>{{ t('clusters.noHosts') }}</h3><p>{{ t('clusters.noHostsHelp') }}</p><button class="btn role-primary" @click="goToHosts">{{ t('clusters.addHost') }}</button></div>
        <div v-else class="table-wrap"><table class="table"><thead><tr><th>{{ t('clusters.host') }}</th><th>{{ t('clusters.hostState') }}</th><th>{{ t('clusters.haAddon') }}</th><th>{{ t('clusters.clusterStack') }}</th><th>{{ t('clusters.clusterState') }}</th><th>{{ t('clusters.resources') }}</th><th>{{ t('clusters.checkedAt') }}</th><th></th></tr></thead>
          <tbody><tr v-for="host in hosts" :key="host.id">
            <td><strong>{{ host.hostname || host.name }}</strong><small>{{ host.address }}:{{ host.port }}</small></td>
            <td><span class="state" :class="host.status"><i></i>{{ statusLabel(host.status) }}</span><small v-if="host.last_error">{{ host.last_error }}</small></td>
            <td><span class="state" :class="haClass(host)"><i></i>{{ haLabel(host) }}</span><small v-if="host.ha?.ha_product">{{ host.ha.ha_product }}</small><small v-else-if="host.ha?.inspection_error">{{ host.ha.inspection_error }}</small><small v-else-if="host.ha?.extension_error">{{ host.ha.extension_error }}</small></td>
            <td><div class="stack-status"><span :class="serviceClass(host,'pacemaker')">{{ t('clusters.pacemaker') }}: {{ serviceLabel(host,'pacemaker') }}</span><span :class="serviceClass(host,'corosync')">{{ t('clusters.corosync') }}: {{ serviceLabel(host,'corosync') }}</span><span :class="serviceClass(host,'hawk')">{{ t('clusters.hawk') }}: {{ serviceLabel(host,'hawk') }}</span></div></td>
            <td><span class="state" :class="clusterStateClass(host)"><i></i>{{ t(clusterStateKey(host)) }}</span><small v-if="host.ha?.cluster_summary" class="cluster-summary">{{ host.ha.cluster_summary }}</small></td>
            <td>{{ host.cpu_count ? `${host.cpu_count} vCPU` : '—' }}<small>{{ memoryLabel(host.memory_total_bytes) }}</small></td>
            <td>{{ dateLabel(host.ha?.checked_at || host.last_checked_at) }}</td>
            <td><button class="btn role-link btn-sm" @click="goToSubscriptions(host)">{{ t('clusters.manageSubscription') }}</button></td>
          </tr></tbody>
        </table></div>
        <p class="safety-note">{{ t('clusters.readOnlyNote') }}</p>
      </section>

      <section class="cluster-panel hawk-panel">
        <div class="panel-heading"><div><span class="eyebrow">HAWK · PACEMAKER · COROSYNC</span><h2>{{ t('clusters.hawkTitle') }}</h2><p>{{ t('clusters.hawkDescription') }}</p></div><span class="planned-badge">{{ t('clusters.planned') }}</span></div>
        <div class="hawk-grid"><article v-for="area in hawkAreas" :key="area" class="hawk-area"><div class="area-icon" aria-hidden="true">{{ areaIcon(area) }}</div><div><h3>{{ t(`clusters.area_${area}`) }}</h3><p>{{ t(`clusters.area_${area}_description`) }}</p><span class="planned-badge small">{{ t('clusters.availableAfterCluster') }}</span></div></article></div>
        <p class="safety-note">{{ t('clusters.hawkRoadmapSafety') }}</p>
      </section>
    </template>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

type HaStatus = { suseconnect_available?: boolean; ha_available?: boolean; ha_active?: boolean; ha_product?: string; ha_product_name?: string; extension_error?: string; commands?: Record<string, boolean>; services?: Record<string, string>; cluster_detected?: boolean; cluster_summary?: string; inspection_error?: string; checked_at?: string };
type Host = { id: string; name: string; address: string; port: number; hostname?: string; status: string; cpu_count?: number; memory_total_bytes?: number; last_checked_at?: string; last_error?: string; ha?: HaStatus };
const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmClusters',
  data() { return { hosts: [] as Host[], loading: false, loaded: false, error: '', refreshTimer: 0 as number, refreshingStale: false, hawkAreas: ['overview','nodes','resources','constraints','activity','fencing'] }; },
  mounted() { this.load(); this.refreshTimer = window.setInterval(() => { if (document.visibilityState === 'visible') this.refreshStale(); }, 60000); },
  beforeUnmount() { window.clearInterval(this.refreshTimer); },
  computed: {
    haEnabledCount(): number { return this.hosts.filter((host) => host.ha?.ha_active).length; },
    clusterCount(): number { return this.hosts.filter((host) => host.ha?.cluster_detected).length; },
  },
  methods: {
    t(key: string, args?: Record<string, unknown>): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.${key}`, args) : key; },
    async load() {
      this.loading = true; this.error = '';
      try { await this.fetchReadiness(); }
      catch (error) { this.error = `${this.t('clusters.loadError')}: ${(error as Error).message}`; }
      finally { this.loading = false; this.loaded = true; }
    },
    async fetchReadiness() {
      const response = await fetch(`${apiBase}/clusters/readiness`, { credentials: 'include', cache: 'no-store' });
      if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail || `API request failed (${response.status})`); }
      this.hosts = await response.json();
    },
    async refreshStale() {
      if (this.refreshingStale || !this.hosts.length) return;
      this.refreshingStale = true;
      try { await this.fetchReadiness(); }
      catch { /* Keep the most recent host status visible while a refresh is unavailable. */ }
      finally { this.refreshingStale = false; }
    },
    goToHosts() { this.$router.push({ name: 'kvm-hosts' }); },
    goToSubscriptions(host: Host) { this.$router.push({ name: 'kvm-c-cluster-cloud-native', query: { hostId: host.id, tab: 'subscriptions' } }); },
    statusLabel(status: string) { return this.t(`hosts.${status === 'ready' ? 'ready' : status === 'unreachable' ? 'unreachable' : 'unknown'}`); },
    haLabel(host: Host) { const ha = host.ha; if (ha?.inspection_error || ha?.extension_error || !ha?.suseconnect_available) return this.t('clusters.haUnknown'); if (ha.ha_active) return this.t('clusters.haEnabled'); if (ha.ha_available) return this.t('clusters.haAvailable'); return this.t('clusters.haUnavailable'); },
    haClass(host: Host) { const ha = host.ha; return ha?.inspection_error || ha?.extension_error || !ha?.suseconnect_available ? 'unknown' : ha.ha_active ? 'ready' : ha.ha_available ? 'warning-state' : 'unreachable'; },
    serviceLabel(host: Host, name: string) { const state = host.ha?.services?.[name]; return this.t(state === 'active' ? 'clusters.active' : state === 'inactive' || state === 'failed' ? 'clusters.inactive' : 'clusters.notInstalled'); },
    serviceClass(host: Host, name: string) { const state = host.ha?.services?.[name]; return state === 'active' ? 'service-active' : state === 'inactive' || state === 'failed' ? 'service-inactive' : 'service-missing'; },
    clusterStateKey(host: Host) { const ha = host.ha; if (ha?.inspection_error) return 'clusters.haUnknown'; if (!ha?.ha_active) return 'clusters.notApplicable'; if (ha.cluster_detected) return 'clusters.clusterDetected'; if (!ha.commands?.crm || !ha.commands?.crm_mon) return 'clusters.haStackMissing'; if (ha.services?.pacemaker !== 'active' || ha.services?.corosync !== 'active') return 'clusters.haStackStopped'; return 'clusters.clusterNotInitialized'; },
    clusterStateClass(host: Host) { const key = this.clusterStateKey(host); return key === 'clusters.clusterDetected' ? 'ready' : key === 'clusters.haUnknown' ? 'unknown' : key === 'clusters.clusterNotInitialized' ? 'warning-state' : 'unreachable'; },
    areaIcon(area: string) { return ({ overview: '◉', nodes: '▤', resources: '◆', constraints: '⌘', activity: '≋', fencing: '⬡' } as Record<string,string>)[area] || '•'; },
    memoryLabel(bytes?: number) { if (!bytes) return '—'; const gib = bytes / 1024 ** 3; return `${gib.toFixed(gib >= 10 ? 0 : 1)} GiB`; },
    dateLabel(value?: string) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString(); },
  },
});
</script>

<style scoped>
.clusters-page { padding:26px; }.clusters-header,.panel-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; }.clusters-header { margin-bottom:22px; }.clusters-header h1 { margin:4px 0 0; font-size:24px; font-weight:500; }.clusters-header p,.panel-heading p { margin:6px 0 0; color:var(--muted,#8b95a5); }.eyebrow { color:var(--muted,#8b95a5); font-size:11px; font-weight:700; letter-spacing:.06em; }
.cluster-stats { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; margin-bottom:20px; }.cluster-stats article,.cluster-panel { padding:18px; border:1px solid var(--border,#394452); border-radius:8px; background:var(--body-bg,#252b33); }.cluster-stats article { display:grid; gap:8px; }.cluster-stats article>span,.cluster-stats small { color:var(--muted,#8b95a5); font-size:12px; }.cluster-stats strong { font-size:24px; }
.cluster-panel { margin-bottom:18px; }.panel-heading { align-items:center; margin-bottom:16px; }.panel-heading h2 { margin:4px 0 0; font-size:19px; }.panel-heading p { max-width:900px; font-size:13px; line-height:1.5; }.cluster-panel .empty-state { padding:32px 20px; }.empty-state h3 { margin:0 0 6px; }.empty-state p { margin:0 0 18px; }
.table-wrap { overflow:auto; }.table { width:100%; border-collapse:collapse; }.table th,.table td { padding:11px 12px; border-bottom:1px solid var(--border,#394452); text-align:left; font-size:12px; vertical-align:top; }.table th { color:var(--muted,#8b95a5); font-size:10px; text-transform:uppercase; white-space:nowrap; }.table td small { display:block; max-width:220px; margin-top:4px; color:var(--muted,#8b95a5); overflow-wrap:anywhere; }.state { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; }.state i { width:7px; height:7px; border-radius:50%; background:#a1a8b3; }.state.ready i { background:#45b879; }.state.unreachable i { background:#e36c68; }.state.warning-state i { background:#e6b84c; }
.stack-status { display:grid; gap:5px; white-space:nowrap; font-size:11px; }.service-active { color:#65d39b; }.service-inactive { color:#e6b84c; }.service-missing { color:var(--muted,#8b95a5); }.safety-note { margin:14px 0 0; color:var(--muted,#8b95a5); font-size:12px; line-height:1.5; }.planned-badge { display:inline-flex; align-items:center; border:1px solid var(--border,#394452); border-radius:99px; padding:5px 10px; color:var(--muted,#9ca6b4); font-size:11px; white-space:nowrap; }.planned-badge.small { margin-top:8px; padding:3px 8px; }
.cluster-summary { max-width:260px !important; white-space:pre-line; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:10px !important; }
.hawk-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; }.hawk-area { display:flex; gap:12px; min-height:132px; padding:15px; border:1px solid var(--border,#394452); border-radius:7px; }.area-icon { display:grid; width:34px; height:34px; flex:0 0 34px; place-items:center; border-radius:7px; color:#79d4a6; background:rgba(65,180,124,.13); font-size:17px; }.hawk-area h3 { margin:0; font-size:14px; }.hawk-area p { margin:5px 0 0; color:var(--muted,#8b95a5); font-size:12px; line-height:1.45; }
.loading { padding:48px; text-align:center; color:var(--muted,#8b95a5); }.banner.error { margin:14px 0; padding:13px; border-radius:6px; color:#8f211a; background:#fff0ee; }
@media (max-width:1060px) { .hawk-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }.table { min-width:1120px; } }
@media (max-width:760px) { .clusters-page { padding:18px 12px; }.cluster-stats,.hawk-grid { grid-template-columns:1fr; }.clusters-header,.panel-heading { flex-direction:column; align-items:flex-start; } }
</style>
