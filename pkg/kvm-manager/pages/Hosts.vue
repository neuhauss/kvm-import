<template>
  <div class="hosts-layout-frame">
  <div class="kvm-page">
    <section v-if="dialog" class="host-editor" :aria-label="editing ? t('hosts.editTitle') : t('hosts.addTitle')">
      <header class="host-editor-header">
        <h1><span>KVM:</span> {{ editing ? t('hosts.editTitle') : t('hosts.addTitle') }}</h1>
        <p class="text-muted">{{ t('hosts.hostDescription') }}</p>
      </header>

      <form class="host-editor-form" @submit.prevent="save">
        <div class="host-editor-content">
          <div class="host-editor-callout" role="note">{{ t('hosts.editorIntro') }}</div>
          <div v-if="deployPrefill" class="banner warning" role="note">{{ t('hosts.deployPrefill') }}</div>

          <section class="host-form-section" aria-labelledby="host-details-heading">
            <header class="host-form-section-heading">
              <h2 id="host-details-heading">{{ t('hosts.hostDetails') }}</h2>
              <p class="text-muted">{{ t('hosts.hostDetailsDescription') }}</p>
            </header>
            <div class="host-field-grid">
              <label class="rancher-field field-name">
                <span>{{ t('hosts.displayName') }} <b aria-hidden="true">*</b></span>
                <input v-model.trim="form.name" required maxlength="80" autocomplete="off" placeholder="kvm-prod-01">
              </label>
              <label class="rancher-field field-address">
                <span>{{ t('hosts.ipDns') }} <b aria-hidden="true">*</b></span>
                <input v-model.trim="form.address" required autocomplete="url" placeholder="192.0.2.10">
              </label>
              <label class="rancher-field field-port">
                <span>{{ t('hosts.sshPort') }} <b aria-hidden="true">*</b></span>
                <input v-model.number="form.port" type="number" min="1" max="65535" required inputmode="numeric">
              </label>
            </div>
          </section>

          <section class="host-form-section" aria-labelledby="host-credentials-heading">
            <header class="host-form-section-heading">
              <h2 id="host-credentials-heading">{{ t('hosts.sshCredentials') }}</h2>
              <p class="text-muted">{{ t('hosts.sshCredentialsDescription') }}</p>
            </header>
            <div class="host-field-grid">
              <label class="rancher-field field-wide">
                <span>{{ t('hosts.sshUser') }} <b aria-hidden="true">*</b></span>
                <input v-model.trim="form.username" required autocomplete="username" placeholder="sles">
              </label>
              <label class="rancher-field field-wide">
                <span>{{ t('hosts.password') }}<b v-if="!editing" aria-hidden="true"> *</b></span>
                <input v-model="form.password" type="password" :required="!editing" autocomplete="new-password" :placeholder="editing ? t('hosts.keepPassword') : ''">
                <small>{{ t('hosts.passwordHelp') }}</small>
              </label>
              <label class="rancher-field field-wide">
                <span>{{ t('hosts.sshKey') }}</span>
                <textarea v-model="form.ssh_private_key" rows="4" autocomplete="off" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                <small>{{ t('hosts.sshKeyHelp') }}</small>
              </label>
              <label v-if="form.ssh_private_key" class="rancher-field field-wide">
                <span>{{ t('hosts.keyPassphrase') }}</span>
                <input v-model="form.ssh_key_passphrase" type="password" autocomplete="new-password" :placeholder="t('common.optional')">
              </label>
            </div>
          </section>

          <section class="host-form-section host-trust-section" aria-label="SSH host verification">
            <label v-if="editing" class="rancher-check">
              <input v-model="form.remove_ssh_key" type="checkbox">
              <span>{{ t('hosts.removeSavedKey') }}</span>
            </label>
            <label class="rancher-check">
              <input v-model="form.accept_new_host_key" type="checkbox">
              <span><strong>{{ t('hosts.acceptHostKey') }}</strong><small>{{ t('hosts.trustKeyHelp') }}</small></span>
            </label>
          </section>

          <section v-if="!editing" class="host-form-section preflight-section">
            <div class="row-actions"><div><h2>{{ t('hosts.preflightTitle') }}</h2><p class="text-muted">{{ t('hosts.preflightHelp') }}</p><small>{{ t('hosts.compatibilityMatrix') }}</small></div><button type="button" class="btn role-secondary" :disabled="probeLoading || !form.address || !form.username || !form.password" @click="runProbe">{{ probeLoading ? t('hosts.probing') : t('hosts.testConnection') }}</button></div>
            <ul v-if="probeChecks.length" class="preflight-checks"><li v-for="check in probeChecks" :key="check.id" :class="check.status"><strong aria-hidden="true">{{ check.status === 'success' ? '✓' : check.status === 'warning' ? '!' : '×' }}</strong><span>{{ check.id === 'compatibility' ? t(check.status === 'success' ? 'hosts.compatibilityOk' : 'hosts.compatibilityWarning', { os: `${check.os_id || 'unknown'} ${check.os_version || ''}`.trim(), libvirt: check.libvirt_version || 'unavailable' }) : check.status === 'failure' ? t('hosts.preflightFailed') : check.id === 'optional' ? t('hosts.optionalCheckUnavailable') : check.message }}</span></li></ul>
          </section>

          <div v-if="formError" class="banner error" role="alert">{{ formError }}</div>
        </div>

        <footer class="host-editor-footer">
          <button type="button" class="btn role-secondary" :disabled="saving" @click="closeForm">{{ t('hosts.cancel') }}</button>
          <button class="btn role-primary" :disabled="saving || (!editing && (!probeOk || probeSignature !== formSignature()))">{{ saving ? t('hosts.validating') : (editing ? t('hosts.save') : t('hosts.import')) }}</button>
        </footer>
      </form>
    </section>

    <template v-else>
    <div class="header">
      <div>
        <h1>{{ t('hosts.title') }}</h1>
        <p class="text-muted">{{ t('hosts.description') }}</p>
      </div>
      <div class="header-actions"><button v-if="permissions.canAdministerHost" class="btn role-secondary" @click="toggleAudit">{{ showingAudit ? t('hosts.title') : t('hosts.audit') }}</button><button v-if="permissions.canAdministerHost" class="btn role-primary" @click="openAdd">{{ t('hosts.add') }}</button></div>
    </div>

    <div v-if="error" class="banner error" role="alert">{{ error }}</div>
    <div v-if="refreshWarning" class="banner warning" role="status">{{ refreshWarning }}</div>
    <section v-if="showingAudit" class="table-wrap">
      <h2>{{ t('hosts.auditTitle') }}</h2>
      <p class="text-muted">{{ t('hosts.auditDescription') }}</p>
      <div class="audit-filters"><input v-model="auditSearch" class="search-input" :placeholder="t('hosts.auditSearch')" /><select v-model="auditHost" class="search-input"><option value="">{{ t('hosts.allHosts') }}</option><option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.hostname || host.name }}</option></select><select v-model="auditOutcome" class="search-input"><option value="">{{ t('hosts.allResults') }}</option><option value="success">success</option><option value="failure">failure</option></select><button class="btn role-secondary" :disabled="auditLoading" @click="exportAudit">{{ t('hosts.exportCsv') }}</button></div>
      <div v-if="auditLoading">{{ t('hosts.loading') }}</div>
      <div v-else-if="auditError" class="banner error">{{ auditError }}</div>
      <table v-else class="table"><thead><tr><th>{{ t('hosts.date') }}</th><th>{{ t('hosts.rancherUser') }}</th><th>{{ t('hosts.action') }}</th><th>{{ t('hosts.target') }}</th><th>{{ t('hosts.result') }}</th></tr></thead>
        <tbody><tr v-for="event in filteredAuditEvents" :key="`${event.occurred_at}-${event.action}-${event.target}`"><td>{{ dateLabel(event.occurred_at) }}</td><td>{{ event.actor }}</td><td>{{ event.action }}</td><td>{{ event.detail || event.target }}</td><td>{{ event.outcome }}</td></tr>
          <tr v-if="!filteredAuditEvents.length"><td colspan="5">{{ t('hosts.noAudit') }}</td></tr></tbody></table>
    </section>
    <div v-else-if="loading" class="loading">{{ t('hosts.loading') }}</div>
    <div v-else-if="hosts.length === 0" class="empty-state">
      <h2>{{ t('hosts.emptyTitle') }}</h2>
      <p>{{ t('hosts.emptyDescription') }}</p>
      <button v-if="permissions.canAdministerHost" class="btn role-primary" @click="openAdd">{{ t('hosts.add') }}</button>
    </div>
    <div v-else class="table-wrap host-table-wrap">
      <div class="hosts-filter-bar" role="search" :aria-label="t('hosts.filterHosts')">
        <label class="hosts-search-field">
          <span>{{ t('hosts.searchHosts') }}</span>
          <input v-model.trim="hostSearch" class="search-input" type="search" :placeholder="t('hosts.searchHostsPlaceholder')" :aria-label="t('hosts.searchHosts')">
        </label>
        <label class="hosts-state-field">
          <span>{{ t('hosts.filterByState') }}</span>
          <select v-model="hostStateFilter" class="search-input" :aria-label="t('hosts.filterByState')">
            <option value="all">{{ t('hosts.allStates') }}</option>
            <option value="ready">{{ t('hosts.ready') }}</option>
            <option value="unreachable">{{ t('hosts.unreachable') }}</option>
            <option value="unknown">{{ t('hosts.unknown') }}</option>
          </select>
        </label>
        <span class="hosts-filter-count" role="status">{{ t('hosts.hostFilterCount', { shown: filteredHosts.length, total: hosts.length }) }}</span>
      </div>
      <table class="table">
        <thead class="hosts-table-head">
          <tr><th>{{ t('hosts.hostname') }}</th><th>{{ t('hosts.address') }}</th><th>{{ t('hosts.state') }}</th><th>{{ t('hosts.cpu') }}</th><th>{{ t('hosts.memory') }}</th><th>{{ t('hosts.lastCheck') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="host in filteredHosts" :key="host.id">
            <td :data-label="t('hosts.hostname')"><div class="host-identity"><div><strong>{{ host.hostname || host.name }}</strong><small>{{ host.name }}</small></div><div class="host-actions">
              <button class="btn role-secondary btn-sm host-ui-button" @click="openCloudNative(host)">{{ t('hosts.uiMenu') }}</button>
              <div v-if="permissions.canOperateVms || permissions.canAdministerHost" class="host-menu-wrap">
                <button :id="`host-actions-${host.id}`" class="btn role-link btn-sm host-menu-trigger" :aria-expanded="openMenu === host.id" aria-haspopup="menu" :aria-controls="`host-actions-menu-${host.id}`" :aria-label="`${t('hosts.moreActions')} ${host.hostname || host.name}`" @click.stop="toggleMenu(host, $event)"><span aria-hidden="true">⋮</span></button>
                <div v-if="openMenu === host.id" :id="`host-actions-menu-${host.id}`" class="host-menu" :style="hostMenuStyle" role="menu" :aria-label="`${t('hosts.moreActions')} ${host.hostname || host.name}`">
                  <button v-if="permissions.canOperateVms" class="host-menu-item" role="menuitem" :disabled="refreshing === host.id" @click="closeMenu(); refresh(host)">{{ refreshing === host.id ? t('hosts.refreshing') : t('hosts.refresh') }}</button>
                  <button v-if="permissions.canAdministerHost" class="host-menu-item" role="menuitem" @click="closeMenu(); edit(host)">{{ t('hosts.edit') }}</button>
                  <button v-if="permissions.canAdministerHost" class="host-menu-item danger-text" role="menuitem" @click="closeMenu(); remove(host)">{{ t('hosts.remove') }}</button>
                </div>
              </div>
            </div></div></td>
            <td :data-label="t('hosts.address')">{{ host.address }}:{{ host.port }}</td>
            <td :data-label="t('hosts.state')"><span class="state" :class="host.status">{{ statusLabel(host.status) }}</span><small v-if="host.last_error">{{ t('hosts.hostUnreachableHelp') }}</small></td>
            <td :data-label="t('hosts.cpu')">{{ host.cpu_count ? `${host.cpu_count} vCPU` : '—' }}</td>
            <td :data-label="t('hosts.memory')">{{ memoryLabel(host.memory_total_bytes) }}</td>
            <td :data-label="t('hosts.lastCheck')"><span :class="{ stale: isHostStale(host) }">{{ dateLabel(host.last_checked_at) }}</span><small v-if="isHostStale(host)" class="stale-text">{{ t('hosts.dataStale') }}</small></td>
          </tr>
          <tr v-if="!filteredHosts.length"><td colspan="6" class="hosts-filter-empty">{{ t('hosts.noHostMatches') }}</td></tr>
        </tbody>
      </table>
    </div>

    </template>
  </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import { apiErrorDetail } from '../utils/api-errors';

type Host = {
  id: string; name: string; address: string; port: number; username: string; hostname?: string;
  status: 'ready' | 'unreachable' | 'unknown'; cpu_count?: number; memory_total_bytes?: number;
  last_checked_at?: string; last_error?: string;
};
type AuditEvent = { occurred_at: string; actor: string; action: string; target: string; outcome: string; detail?: string };
type Permissions = { canOperateVms: boolean; canAdministerHost: boolean };

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmHosts',
  data() {
    return {
      hosts: [] as Host[], permissions: { canOperateVms: false, canAdministerHost: false } as Permissions, loading: false, refreshing: '' as string, dialog: false, editing: '' as string,
      saving: false, error: '', refreshWarning: '', formError: '', openMenu: '' as string, hostMenuStyle: {} as Record<string, string>,
      form: { name: '', address: '', port: 22, username: '', password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false },
      showingAudit: false, auditEvents: [] as AuditEvent[], auditLoading: false, auditError: '', deployPrefill: false,
      probeChecks: [] as { id: string; status: string; message: string; os_id?: string; os_version?: string; libvirt_version?: string }[], probeLoading: false, probeOk: false, probeSignature: '', auditSearch: '', auditHost: '', auditOutcome: '', refreshTimer: 0 as number, refreshingStale: false, hostSearch: '', hostStateFilter: 'all',
    };
  },
    mounted() {
    this.load();
    this.applyDeployPrefill();
    this.refreshTimer = window.setInterval(() => { if (document.visibilityState === 'visible' && !this.dialog && !this.showingAudit) this.refreshStale(); }, 60000);
    document.addEventListener('click', this.closeMenu);
    document.addEventListener('keydown', this.onMenuKeydown);
    window.addEventListener('resize', this.closeMenu);
    window.addEventListener('scroll', this.closeMenu, true);
  },
  beforeUnmount() {
    window.clearInterval(this.refreshTimer);
    document.removeEventListener('click', this.closeMenu);
    document.removeEventListener('keydown', this.onMenuKeydown);
    window.removeEventListener('resize', this.closeMenu);
    window.removeEventListener('scroll', this.closeMenu, true);
  },
  methods: {
    t(key: string, args?: Record<string, unknown>): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.${key}`, args) : key; },
    async request(path: string, options: RequestInit = {}) {
      let response: Response;
      try {
        response = await fetch(`${apiBase}${path}`, {
          ...options,
          headers: { 'Content-Type': 'application/json', ...options.headers },
          credentials: 'include',
          cache: 'no-store',
        });
      } catch { throw new Error(this.t('hosts.errorNetwork')); }
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const detail = apiErrorDetail(body, options.body);
        const key = response.status === 401 ? 'hosts.errorSessionExpired'
          : response.status === 403 ? 'hosts.errorPermissionDenied'
            : response.status === 422 ? 'hosts.errorValidation'
              : response.status === 502 ? 'hosts.errorHostConnection'
                : response.status >= 500 ? 'hosts.errorExtensionApi' : 'hosts.errorRequest';
        if (detail && response.status !== 401 && response.status !== 403) {
          const detailKey = response.status === 422 ? 'hosts.errorValidationDetail'
            : response.status === 502 ? 'hosts.errorHostConnectionDetail'
              : response.status >= 500 ? 'hosts.errorExtensionApiDetail' : 'hosts.errorRequestDetail';
          throw new Error(this.t(detailKey, { detail }));
        }
        throw new Error(this.t(key));
      }
      return response.status === 204 ? null : response.json();
    },
    async load() {
      this.loading = true; this.error = '';
      try {
        const [hosts, permissions] = await Promise.all([this.request('/hosts'), this.request('/permissions')]);
        this.hosts = hosts; this.permissions = permissions;
        this.refreshStale();
      }
      catch (e) {
        this.hosts = [];
        this.error = `${this.t('hosts.cannotLoad')}: ${(e as Error).message}`;
      }
      finally { this.loading = false; }
    },
    formSignature(): string { return JSON.stringify([this.form.address.trim(), Number(this.form.port), this.form.username.trim(), this.form.password, this.form.ssh_private_key, this.form.ssh_key_passphrase, this.form.accept_new_host_key]); },
    async runProbe() {
      this.probeLoading = true; this.probeChecks = []; this.probeOk = false; this.formError = '';
      try { const result = await this.request('/hosts/probe', { method: 'POST', body: JSON.stringify(this.form) }); this.probeChecks = result.checks || []; this.probeOk = Boolean(result.ok); this.probeSignature = this.formSignature(); }
      catch { this.probeChecks = [{ id: 'ssh_libvirt', status: 'failure', message: this.t('hosts.preflightFailed') }]; }
      finally { this.probeLoading = false; }
    },
    async refreshStale() {
      if (this.refreshingStale || !this.hosts.length) return;
      this.refreshingStale = true;
      try { this.hosts = await this.request('/hosts/refresh-stale?max_age_seconds=120&limit=10', { method: 'POST' }); this.refreshWarning = ''; }
      catch { this.refreshWarning = this.t('hosts.backgroundRefreshFailed'); }
      finally { this.refreshingStale = false; }
    },
    isHostStale(host: Host): boolean { return !host.last_checked_at || Date.now() - Date.parse(host.last_checked_at) > 180000; },
    openAdd() {
      this.editing = ''; this.formError = '';
      this.form = { name: '', address: '', port: 22, username: '', password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false }; this.dialog = true; this.deployPrefill = false;
    },
    applyDeployPrefill() {
      const query = (this as any).$route?.query || {};
      const address = typeof query.deployAddress === 'string' ? query.deployAddress : '';
      if (!address) return;
      this.openAdd();
      this.form.address = address;
      this.form.username = typeof query.deployUsername === 'string' ? query.deployUsername : 'sles';
      this.form.name = typeof query.deployName === 'string' ? query.deployName : '';
      this.deployPrefill = true;
      const cleanQuery = { ...query }; delete cleanQuery.deployAddress; delete cleanQuery.deployUsername; delete cleanQuery.deployName;
      (this as any).$router.replace({ query: cleanQuery });
    },
    closeForm() {
      this.dialog = false; this.editing = ''; this.formError = '';
      this.form = { name: '', address: '', port: 22, username: '', password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false };
    },
    edit(host: Host) {
      this.editing = host.id; this.formError = '';
      this.form = { name: host.name, address: host.address, port: host.port, username: host.username, password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false }; this.dialog = true;
    },
    async save() {
      this.saving = true; this.formError = '';
      try {
        const payload: Record<string, unknown> = { ...this.form };
        if (!payload.password) delete payload.password;
        if (!payload.ssh_private_key) delete payload.ssh_private_key;
        if (!payload.ssh_key_passphrase) delete payload.ssh_key_passphrase;
        const host = this.editing
          ? await this.request(`/hosts/${this.editing}`, { method: 'PUT', body: JSON.stringify(payload) })
          : await this.request('/hosts', { method: 'POST', body: JSON.stringify(payload) });
        if (!this.editing) this.hosts.unshift(host);
        else Object.assign(this.hosts.find((item) => item.id === this.editing) || {}, host);
        this.closeForm();
      } catch (e) { this.formError = (e as Error).message; }
      finally { this.saving = false; }
    },
    async refresh(host: Host) {
      this.refreshing = host.id;
      try { Object.assign(host, await this.request(`/hosts/${host.id}/refresh`, { method: 'POST' })); }
      catch (e) { this.error = `${this.t('hosts.refreshError', { name: host.name })}: ${(e as Error).message}`; }
      finally { this.refreshing = ''; }
    },
    openCloudNative(host: Host) {
      this.openMenu = '';
      const path = window.location.pathname.replace(/\/hosts\/?$/, '/cloud-native');
      // Rancher replaces unmatched extension routes with /dashboard/fail-whale
      // when navigating to a sibling page through this router instance. A
      // full navigation keeps the request on this extension's own page route.
      window.location.assign(`${path}?hostId=${encodeURIComponent(host.id)}`);
    },
    toggleMenu(host: Host, event: MouseEvent) {
      if (this.openMenu === host.id) { this.openMenu = ''; return; }
      const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
      const menuHeight = 144;
      const top = rect.bottom + menuHeight <= window.innerHeight - 12 ? rect.bottom + 4 : Math.max(12, rect.top - menuHeight - 4);
      const width = 190;
      const left = Math.min(Math.max(12, rect.right - width), window.innerWidth - width - 12);
      this.hostMenuStyle = { top: `${top}px`, left: `${left}px` };
      this.openMenu = host.id;
      this.$nextTick(() => document.querySelector<HTMLElement>(`#host-actions-menu-${CSS.escape(host.id)} [role=menuitem]`)?.focus());
    },
    closeMenu() { this.openMenu = ''; },
    onMenuKeydown(event: KeyboardEvent) { if (event.key === 'Escape' && this.openMenu) { const hostId = this.openMenu; this.openMenu = ''; this.$nextTick(() => document.getElementById(`host-actions-${CSS.escape(hostId)}`)?.focus()); return; } if (!this.openMenu || !['ArrowDown','ArrowUp','Home','End'].includes(event.key)) return; const items = Array.from(document.querySelectorAll<HTMLElement>(`#host-actions-menu-${CSS.escape(this.openMenu)} [role=menuitem]:not(:disabled)`)); if (!items.length) return; event.preventDefault(); const current = items.indexOf(document.activeElement as HTMLElement); const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : event.key === 'ArrowDown' ? (current + 1) % items.length : (current - 1 + items.length) % items.length; items[next].focus(); },
    async toggleAudit() {
      this.showingAudit = !this.showingAudit;
      if (!this.showingAudit) return;
      this.auditLoading = true; this.auditError = '';
      try { this.auditEvents = await this.request('/audit?limit=500'); }
      catch (e) { this.auditError = (e as Error).message; }
      finally { this.auditLoading = false; }
    },
    exportAudit() {
      const quote = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
      const rows = [[this.t('hosts.date'), this.t('hosts.rancherUser'), this.t('hosts.action'), this.t('hosts.target'), this.t('hosts.result'), this.t('hosts.detail')], ...this.filteredAuditEvents.map((event) => [event.occurred_at, event.actor, event.action, event.target, event.outcome, event.detail || ''])];
      const blob = new Blob([`\uFEFF${rows.map((row) => row.map(quote).join(',')).join('\r\n')}`], { type: 'text/csv;charset=utf-8' });
      const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'kvm-audit.csv'; link.click(); URL.revokeObjectURL(link.href);
    },
    vmStateClass(state: string) { return state.toLowerCase().includes('running') ? 'ready' : 'unreachable'; },
    async remove(host: Host) {
      try { await this.request(`/hosts/${host.id}`, { method: 'DELETE' }); this.hosts = this.hosts.filter((item) => item.id !== host.id); }
      catch (e) { this.error = `${this.t('hosts.removeError', { name: host.name })}: ${(e as Error).message}`; }
    },
    statusLabel(status: string) { return this.t(`hosts.${status}`); },
    memoryLabel(bytes?: number) { return bytes ? `${(bytes / (1024 ** 3)).toFixed(1)} GiB` : '—'; },
    dateLabel(value?: string) { const locale = (this as any).$store?.state?.i18n?.selected; return value ? new Date(value).toLocaleString(locale || undefined) : '—'; },
  },
  computed: {
    filteredHosts(): Host[] {
      const term = this.hostSearch.toLowerCase();
      return this.hosts.filter((host) => {
        const matchesTerm = !term || `${host.hostname || ''} ${host.name} ${host.address}`.toLowerCase().includes(term);
        return matchesTerm && (this.hostStateFilter === 'all' || host.status === this.hostStateFilter);
      }).sort((a, b) => (a.hostname || a.name).localeCompare(b.hostname || b.name));
    },
    filteredAuditEvents(): AuditEvent[] {
      const term = this.auditSearch.toLowerCase().trim();
      return this.auditEvents.filter((event) => (!this.auditOutcome || event.outcome === this.auditOutcome) && (!this.auditHost || event.target === this.auditHost || event.target.startsWith(`${this.auditHost}/`)) && (!term || `${event.actor} ${event.action} ${event.target} ${event.detail || ''} ${event.outcome}`.toLowerCase().includes(term)));
    },
  },
});
</script>

<style scoped>
.kvm-page { container-type:inline-size; container-name:hosts-layout; width:100%; min-width:0; max-width:100%; min-height:calc(100vh - 100px); padding:24px; box-sizing:border-box; }
.header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 24px; }
.header-actions { display: flex; gap: 8px; }
h1 { margin: 0 0 6px; }
.text-muted, small { color: var(--muted, #727b8a); }
small { display: block; font-size: 12px; margin-top: 4px; }
.table-wrap { overflow-x: auto; }
.table { width: 100%; border-collapse: collapse; color:var(--body-text); background:var(--input-bg, var(--body-bg)); }
.table th, .table td { padding: 12px; color:var(--body-text); text-align: left; border-bottom: 1px solid var(--border, #d8dde6); white-space: nowrap; }
.host-table-wrap { border:1px solid var(--border,#39414d); border-radius:6px; background:var(--body-bg,#252b33); }
.hosts-filter-bar { display:flex; align-items:flex-end; gap:12px; flex-wrap:wrap; padding:14px 16px; border-bottom:1px solid var(--border,#39414d); background:var(--body-bg,#252b33); }
.hosts-filter-bar label { display:grid; gap:5px; color:var(--muted,#929baa); font-size:12px; font-weight:600; }
.hosts-search-field { flex:1 1 260px; min-width:190px; }
.hosts-state-field { flex:0 1 200px; min-width:160px; }
.hosts-filter-bar .search-input { width:100%; min-height:36px; padding:7px 10px; box-sizing:border-box; border:1px solid var(--input-border,var(--border,#4b5563)); border-radius:4px; color:var(--input-text,var(--body-text,#e5e7eb)); background:var(--input-bg,var(--body-bg,#252b33)); font:inherit; }
.hosts-filter-bar .search-input:focus-visible { border-color:var(--primary,#53c99a); outline:2px solid color-mix(in srgb,var(--primary,#53c99a) 45%,transparent); outline-offset:1px; }
.hosts-filter-count { margin:0 0 9px auto; color:var(--muted,#929baa); font-size:12px; white-space:nowrap; }
.table thead.hosts-table-head { background:#20252b; }
.table thead.hosts-table-head th { padding:12px; color:#e5e7eb; background:#20252b; border-bottom:1px solid #414852; font-size:12px; font-weight:600; }
.hosts-filter-empty { padding:24px !important; color:var(--muted,#929baa) !important; text-align:center !important; }
.state { display: inline-block; padding: 3px 9px; border-radius: 12px; background: #edf0f4; }
.state.ready { background: #e3f5e8; color: #23733a; }
.state.unreachable { background: #fde8e7; color: #a52822; }
.stale,.stale-text { color:var(--warning-text,var(--body-text)); font-weight:600; }
.actions { text-align: right !important; }
.host-menu-wrap { position:relative; display:inline-flex; }
.host-menu-trigger { display:inline-flex; align-items:center; justify-content:center; min-width:36px; font-size:18px; line-height:1; }
.host-menu { position:fixed; z-index:2000; width:190px; padding:6px; border:1px solid var(--border, #d8dde6); border-radius:var(--border-radius, 6px); background:var(--input-bg, var(--body-bg, #fff)); box-shadow:0 8px 24px #0003; text-align:left; }
.host-menu-item { display:block; width:100%; border:0; border-radius:var(--border-radius); padding:9px 11px; color:var(--body-text); background:transparent; cursor:pointer; text-align:left; font:inherit; }
.host-menu-item:hover,.host-menu-item:focus-visible { background:var(--hover-bg, rgba(120,135,160,.12)); outline:2px solid var(--primary,#4b91e2); outline-offset:-2px; }
.host-menu-item:disabled { cursor:wait; opacity:.7; }
.host-identity { display:flex; align-items:center; justify-content:space-between; gap:12px; min-width:220px; }
.host-identity strong { display:block; }
.host-actions { display:inline-flex; align-items:center; justify-content:flex-end; gap:6px; flex:0 0 auto; }
.host-actions .btn-sm { margin:0; }
.danger-text { color: #b42318; }
.banner { padding: 12px; border-radius: 4px; margin: 12px 0; }
.error { background: color-mix(in srgb,#d45b52 16%,var(--body-bg,#252b33)); color:var(--body-text); }
.empty-state { padding: 64px 16px; text-align: center; border: 1px dashed var(--border, #d8dde6); }
.host-editor { min-height: calc(100vh - 148px); display: flex; flex-direction: column; }
.host-editor-header { padding: 0 0 20px; margin-bottom: 24px; border-bottom: 1px solid var(--border, #39414d); }
.host-editor-header h1 { margin: 0 0 12px; font-size: 24px; font-weight: 400; }
.host-editor-header h1 span { color: var(--link, #7aa7e8); }
.host-editor-header p { margin: 0; }
.host-editor-form { flex: 1; display: flex; flex-direction: column; }
.host-editor-content { width: min(100%, 1100px); padding-bottom: 32px; }
.host-editor-callout { margin-bottom: 22px; padding: 12px 14px; border-left: 4px solid var(--primary, #3d98ff); color: var(--body-text, #e5e7eb); background: color-mix(in srgb, var(--primary, #3d98ff) 14%, var(--body-bg, #252b33)); }
.host-form-section { padding: 20px 0; border-bottom: 1px solid var(--border, #39414d); }
.preflight-section .row-actions { display:flex; align-items:center; justify-content:space-between; gap:16px; }.preflight-section h2 { margin:0 0 5px; font-size:17px; }.preflight-section p { margin:0; }.preflight-checks { display:grid; gap:7px; margin:14px 0 0; padding:0; list-style:none; }.preflight-checks li { display:flex; gap:9px; padding:9px 11px; border-radius:4px; color:var(--body-text); background:color-mix(in srgb,var(--body-text) 7%,var(--body-bg)); }.preflight-checks li.success>strong { color:#2e9e5b; }.preflight-checks li.warning>strong { color:#b27a16; }.preflight-checks li.failure>strong { color:#c43e36; }
.host-form-section-heading { margin-bottom: 18px; }
.host-form-section-heading h2 { margin: 0 0 6px; font-size: 18px; }
.host-form-section-heading p { margin: 0; }
.host-field-grid { display: grid; grid-template-columns: repeat(12,minmax(0,1fr)); gap: 18px 16px; }
.rancher-field { position: relative; display: flex; flex-direction: column; min-width: 0; }
.rancher-field > span { position: absolute; z-index: 1; top: 9px; left: 12px; color: var(--muted, #8b95a5); font-size: 12px; line-height: 16px; pointer-events: none; }
.rancher-field > span b { color: var(--primary, #53c99a); font-weight: 600; }
.rancher-field input,.rancher-field textarea { width: 100%; min-height: 68px; padding: 27px 12px 10px; box-sizing: border-box; border: 1px solid var(--input-border, var(--border, #4b5563)); border-radius: 4px; outline: none; color: var(--input-text, var(--body-text, #e5e7eb)); background: var(--input-bg, var(--body-bg, #252b33)); font: inherit; }
.rancher-field textarea { min-height: 108px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.rancher-field input:focus,.rancher-field textarea:focus { border-color: var(--primary, #53c99a); box-shadow: 0 0 0 1px var(--primary, #53c99a); }
.rancher-field input::placeholder,.rancher-field textarea::placeholder { color: var(--muted, #8b95a5); opacity: .78; }
.rancher-field small,.rancher-check small { display: block; margin-top: 7px; color: var(--muted, #8b95a5); font-size: 12px; line-height: 1.45; }
.field-wide { grid-column: 1 / -1; }
.field-name { grid-column: span 6; }
.field-address { grid-column: span 8; }
.field-port { grid-column: span 4; }
.host-trust-section { display: grid; gap: 16px; border-bottom: 0; }
.rancher-check { display: flex; align-items: flex-start; gap: 10px; color: var(--body-text); }
.rancher-check input { flex: 0 0 auto; width: 16px; height: 16px; margin: 2px 0 0; accent-color: var(--primary, #53c99a); }
.rancher-check span { min-width: 0; }
.rancher-check small { max-width: 760px; }
.host-editor-footer { position: sticky; bottom: 0; display: flex; justify-content: flex-end; gap: 12px; margin: auto -24px -24px; padding: 14px 24px; border-top: 1px solid var(--border, #39414d); background: var(--body-bg, #252b33); }
.audit-filters { display:flex; flex-wrap:wrap; gap:8px; margin:14px 0; }.audit-filters .search-input { min-width:180px; padding:8px 10px; border:1px solid var(--border,#d8dde6); border-radius:4px; color:var(--body-text); background:var(--input-bg,var(--body-bg)); }
.banner { padding: 12px; border-radius: 4px; margin: 12px 0; }
.error { background: color-mix(in srgb,#d45b52 16%,var(--body-bg,#252b33)); color:var(--body-text); }
.warning { background:color-mix(in srgb,#d99c30 18%,var(--body-bg,#252b33)); color:var(--body-text); }
@media (max-width: 700px) { .kvm-page { padding: 16px; }.header { flex-direction: column; }.header-actions { width: 100%; flex-wrap: wrap; }.host-editor { min-height: calc(100vh - 120px); }.host-editor-header h1 { font-size: 21px; }.field-wide,.field-name,.field-address,.field-port { grid-column: 1 / -1; }.host-editor-footer { margin: auto -16px -16px; padding: 12px 16px; } }
@container hosts-layout (max-width: 700px) { .kvm-page { padding:16px; }.header { align-items:flex-start; flex-direction:column; }.header-actions { width:100%; flex-wrap:wrap; }.host-editor { min-height:calc(100vh - 120px); }.host-editor-header h1 { font-size:21px; }.field-wide,.field-name,.field-address,.field-port { grid-column:1/-1; }.host-editor-footer { margin:auto -16px -16px; padding:12px 16px; }.host-editor-form,.host-editor-content { min-width:0; }.table-wrap { max-width:100%; min-width:0; overflow-x:auto; overscroll-behavior-x:contain; } }
@container hosts-layout (max-width: 700px) { .hosts-filter-bar { align-items:stretch; padding:12px; }.hosts-search-field,.hosts-state-field { flex:1 1 100%; min-width:0; }.hosts-filter-count { margin:0; } }
@container hosts-layout (max-width: 460px) { .header-actions { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); }.header-actions .btn { min-width:0; white-space:normal; }.host-form-section { padding:14px 12px; }.host-editor-footer { gap:8px; }.host-editor-footer .btn { flex:1 1 auto; }.audit-filters { display:grid; grid-template-columns:minmax(0,1fr); }.audit-filters .search-input { min-width:0; width:100%; box-sizing:border-box; } }
@container hosts-layout (max-width: 920px) { .host-table-wrap { overflow:visible; border:0; background:transparent; }.host-table-wrap :deep(.table) { display:block; width:100%; border-collapse:separate; background:transparent; }.host-table-wrap :deep(.table thead) { position:absolute; width:1px; height:1px; padding:0; overflow:hidden; clip:rect(0,0,0,0); clip-path:inset(50%); white-space:nowrap; }.host-table-wrap :deep(.table tbody) { display:grid; gap:10px; }.host-table-wrap :deep(.table tbody tr) { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); min-width:0; overflow:hidden; border:1px solid var(--border,#394452); border-radius:8px; background:var(--body-bg,#252b33); }.host-table-wrap :deep(.table tbody td) { display:grid; align-content:start; gap:4px; min-width:0; padding:10px 12px; border:0; white-space:normal; overflow-wrap:anywhere; }.host-table-wrap :deep(.table tbody td::before) { content:attr(data-label); color:var(--muted,#8b95a5); font-size:10px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }.host-table-wrap :deep(.table tbody td:first-child) { grid-column:1/-1; border-bottom:1px solid var(--border,#394452); }.host-table-wrap :deep(.host-identity) { min-width:0; flex-wrap:wrap; }.host-table-wrap :deep(.host-actions) { justify-content:flex-start; flex-wrap:wrap; }.host-table-wrap :deep(.host-actions .btn) { margin:0; }.host-ui-button { margin:0; }.host-menu { text-align:left; } }
@container hosts-layout (max-width: 460px) { .host-table-wrap :deep(.table tbody tr) { grid-template-columns:minmax(0,1fr); }.host-table-wrap :deep(.table tbody td:first-child) { grid-column:1; } }
.hosts-layout-frame { container-type:inline-size; container-name:hosts-layout; width:100%; min-width:0; max-width:100%; }.kvm-page { container-type:normal; container-name:none; }
</style>
