<template>
  <div class="kvm-page">
    <div class="header">
      <div>
        <h1>{{ t('hosts.title') }}</h1>
        <p class="text-muted">{{ t('hosts.description') }}</p>
      </div>
      <div class="header-actions"><button class="btn role-secondary" @click="toggleAudit">{{ showingAudit ? t('hosts.title') : t('hosts.audit') }}</button><button class="btn role-primary" @click="openAdd">{{ t('hosts.add') }}</button></div>
    </div>

    <div v-if="error" class="banner error">{{ error }}</div>
    <section v-if="showingAudit" class="table-wrap">
      <h2>{{ t('hosts.auditTitle') }}</h2>
      <p class="text-muted">{{ t('hosts.auditDescription') }}</p>
      <div v-if="auditLoading">{{ t('hosts.loading') }}</div>
      <div v-else-if="auditError" class="banner error">{{ auditError }}</div>
      <table v-else class="table"><thead><tr><th>{{ t('hosts.date') }}</th><th>{{ t('hosts.rancherUser') }}</th><th>{{ t('hosts.action') }}</th><th>{{ t('hosts.target') }}</th><th>{{ t('hosts.result') }}</th></tr></thead>
        <tbody><tr v-for="event in auditEvents" :key="`${event.occurred_at}-${event.action}-${event.target}`"><td>{{ dateLabel(event.occurred_at) }}</td><td>{{ event.actor }}</td><td>{{ event.action }}</td><td>{{ event.detail || event.target }}</td><td>{{ event.outcome }}</td></tr>
          <tr v-if="!auditEvents.length"><td colspan="5">{{ t('hosts.noAudit') }}</td></tr></tbody></table>
    </section>
    <div v-else-if="loading" class="loading">{{ t('hosts.loading') }}</div>
    <div v-else-if="hosts.length === 0" class="empty-state">
      <h2>{{ t('hosts.emptyTitle') }}</h2>
      <p>{{ t('hosts.emptyDescription') }}</p>
      <button class="btn role-primary" @click="openAdd">{{ t('hosts.add') }}</button>
    </div>
    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr><th>{{ t('hosts.hostname') }}</th><th>{{ t('hosts.address') }}</th><th>{{ t('hosts.state') }}</th><th>{{ t('hosts.cpu') }}</th><th>{{ t('hosts.memory') }}</th><th>{{ t('hosts.lastCheck') }}</th><th>{{ t('hosts.manage') }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="host in hosts" :key="host.id">
            <td><strong>{{ host.hostname || host.name }}</strong><small>{{ host.name }}</small></td>
            <td>{{ host.address }}:{{ host.port }}</td>
            <td><span class="state" :class="host.status">{{ statusLabel(host.status) }}</span><small v-if="host.last_error">{{ host.last_error }}</small></td>
            <td>{{ host.cpu_count ? `${host.cpu_count} vCPU` : '—' }}</td>
            <td>{{ memoryLabel(host.memory_total_bytes) }}</td>
            <td>{{ dateLabel(host.last_checked_at) }}</td>
            <td class="actions">
              <div class="host-menu-wrap">
                <button :id="`host-ui-${host.id}`" class="btn role-secondary btn-sm host-menu-trigger" :aria-expanded="openMenu === host.id" :aria-controls="`host-ui-menu-${host.id}`" :aria-label="`${t('hosts.uiMenu')} ${host.hostname || host.name}`" @click.stop="toggleMenu(host, $event)"><span aria-hidden="true">☰</span><span>{{ t('hosts.uiMenu') }}</span></button>
                <div v-if="openMenu === host.id" :id="`host-ui-menu-${host.id}`" class="host-menu" :style="hostMenuStyle" role="menu">
                  <button class="host-menu-item" role="menuitem" @click="openCloudNative(host)">{{ t('hosts.uiMenu') }}</button>
                </div>
              </div>
              <button class="btn role-link btn-sm" :disabled="refreshing === host.id" @click="refresh(host)">{{ refreshing === host.id ? t('hosts.refreshing') : t('hosts.refresh') }}</button>
              <button class="btn role-link btn-sm" @click="edit(host)">{{ t('hosts.edit') }}</button>
              <button class="btn role-link btn-sm danger-text" @click="remove(host)">{{ t('hosts.remove') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="dialog" class="modal-backdrop" @click.self="dialog = false">
      <section class="modal">
        <h2>{{ editing ? t('hosts.editTitle') : t('hosts.addTitle') }}</h2>
        <p class="text-muted">{{ t('hosts.hostDescription') }}</p>
        <form @submit.prevent="save">
          <label>{{ t('hosts.displayName') }}<input v-model.trim="form.name" required maxlength="80" placeholder="kvm-prod-01"></label>
          <div class="form-row">
            <label>{{ t('hosts.ipDns') }}<input v-model.trim="form.address" required placeholder="192.0.2.10"></label>
            <label>{{ t('hosts.sshPort') }}<input v-model.number="form.port" type="number" min="1" max="65535" required></label>
          </div>
          <label>{{ t('hosts.sshUser') }}<input v-model.trim="form.username" required autocomplete="username"></label>
          <label>{{ t('hosts.password') }}<input v-model="form.password" type="password" :required="!editing" autocomplete="new-password" :placeholder="editing ? t('hosts.keepPassword') : ''"><small>{{ t('hosts.passwordHelp') }}</small></label>
          <label>{{ t('hosts.sshKey') }}<textarea v-model="form.ssh_private_key" rows="5" autocomplete="off" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea><small>{{ t('hosts.sshKeyHelp') }}</small></label>
          <label v-if="form.ssh_private_key" class="key-passphrase">{{ t('hosts.keyPassphrase') }}<input v-model="form.ssh_key_passphrase" type="password" autocomplete="new-password" :placeholder="t('common.optional')"></label>
          <label v-if="editing" class="trust-key-option"><input v-model="form.remove_ssh_key" type="checkbox"><span>{{ t('hosts.removeSavedKey') }}</span></label>
          <label class="trust-key-option">
            <input v-model="form.accept_new_host_key" type="checkbox">
            <span><strong>{{ t('hosts.acceptHostKey') }}</strong><small>{{ t('hosts.trustKeyHelp') }}</small></span>
          </label>
          <div v-if="formError" class="banner error">{{ formError }}</div>
          <div class="modal-actions">
            <button type="button" class="btn role-secondary" @click="dialog = false">{{ t('hosts.cancel') }}</button>
            <button class="btn role-primary" :disabled="saving">{{ saving ? t('hosts.validating') : (editing ? t('hosts.save') : t('hosts.import')) }}</button>
          </div>
        </form>
      </section>
    </div>

  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

type Host = {
  id: string; name: string; address: string; port: number; username: string; hostname?: string;
  status: 'ready' | 'unreachable' | 'unknown'; cpu_count?: number; memory_total_bytes?: number;
  last_checked_at?: string; last_error?: string;
};
type AuditEvent = { occurred_at: string; actor: string; action: string; target: string; outcome: string; detail?: string };

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmHosts',
  data() {
    return {
      hosts: [] as Host[], loading: false, refreshing: '' as string, dialog: false, editing: '' as string,
      saving: false, error: '', formError: '', openMenu: '' as string, hostMenuStyle: {} as Record<string, string>,
      form: { name: '', address: '', port: 22, username: '', password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false },
      showingAudit: false, auditEvents: [] as AuditEvent[], auditLoading: false, auditError: '',
    };
  },
  mounted() {
    this.load();
    document.addEventListener('click', this.closeMenu);
    document.addEventListener('keydown', this.onMenuKeydown);
    window.addEventListener('resize', this.closeMenu);
    window.addEventListener('scroll', this.closeMenu, true);
  },
  beforeUnmount() {
    document.removeEventListener('click', this.closeMenu);
    document.removeEventListener('keydown', this.onMenuKeydown);
    window.removeEventListener('resize', this.closeMenu);
    window.removeEventListener('scroll', this.closeMenu, true);
  },
  methods: {
    t(key: string, args?: Record<string, unknown>): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.${key}`, args) : key; },
    async request(path: string, options: RequestInit = {}) {
      const response = await fetch(`${apiBase}${path}`, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...options.headers },
        credentials: 'include',
        cache: 'no-store',
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `API request failed (${response.status})`);
      }
      return response.status === 204 ? null : response.json();
    },
    async load() {
      this.loading = true; this.error = '';
      try { this.hosts = await this.request('/hosts'); }
      catch (e) {
        this.hosts = [];
        this.error = `${this.t('hosts.cannotLoad')}: ${(e as Error).message}. ${this.t('hosts.verifyService')}`;
      }
      finally { this.loading = false; }
    },
    openAdd() {
      this.editing = ''; this.formError = '';
      this.form = { name: '', address: '', port: 22, username: '', password: '', ssh_private_key: '', ssh_key_passphrase: '', remove_ssh_key: false, accept_new_host_key: false }; this.dialog = true;
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
        this.dialog = false;
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
      const menuHeight = 48;
      const top = rect.bottom + menuHeight <= window.innerHeight - 12 ? rect.bottom + 4 : Math.max(12, rect.top - menuHeight - 4);
      const width = 210;
      const left = Math.min(Math.max(12, rect.right - width), window.innerWidth - width - 12);
      this.hostMenuStyle = { top: `${top}px`, left: `${left}px` };
      this.openMenu = host.id;
    },
    closeMenu() { this.openMenu = ''; },
    onMenuKeydown(event: KeyboardEvent) { if (event.key === 'Escape') this.openMenu = ''; },
    async toggleAudit() {
      this.showingAudit = !this.showingAudit;
      if (!this.showingAudit) return;
      this.auditLoading = true; this.auditError = '';
      try { this.auditEvents = await this.request('/audit'); }
      catch (e) { this.auditError = (e as Error).message; }
      finally { this.auditLoading = false; }
    },
    vmStateClass(state: string) { return state.toLowerCase().includes('running') ? 'ready' : 'unreachable'; },
    async remove(host: Host) {
      if (!window.confirm(this.t('hosts.removeConfirm', { name: host.name }))) return;
      try { await this.request(`/hosts/${host.id}`, { method: 'DELETE' }); this.hosts = this.hosts.filter((item) => item.id !== host.id); }
      catch (e) { this.error = `${this.t('hosts.removeError', { name: host.name })}: ${(e as Error).message}`; }
    },
    statusLabel(status: string) { return this.t(`hosts.${status}`); },
    memoryLabel(bytes?: number) { return bytes ? `${(bytes / (1024 ** 3)).toFixed(1)} GiB` : '—'; },
    dateLabel(value?: string) { const locale = (this as any).$store?.state?.i18n?.selected; return value ? new Date(value).toLocaleString(locale || undefined) : '—'; },
  },
});
</script>

<style scoped>
.kvm-page { padding: 24px; }
.header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 24px; }
.header-actions { display: flex; gap: 8px; }
h1 { margin: 0 0 6px; }
.text-muted, small { color: var(--muted, #727b8a); }
small { display: block; font-size: 12px; margin-top: 4px; }
.table-wrap { overflow-x: auto; }
.table { width: 100%; border-collapse: collapse; color:var(--body-text); background:var(--input-bg, var(--body-bg)); }
.table th, .table td { padding: 12px; color:var(--body-text); text-align: left; border-bottom: 1px solid var(--border, #d8dde6); white-space: nowrap; }
.state { display: inline-block; padding: 3px 9px; border-radius: 12px; background: #edf0f4; }
.state.ready { background: #e3f5e8; color: #23733a; }
.state.unreachable { background: #fde8e7; color: #a52822; }
.actions { text-align: right !important; }
.host-menu-wrap { display:inline-block; margin-right:5px; }
.host-menu-trigger { display:inline-flex; align-items:center; gap:8px; }
.host-menu { position:fixed; z-index:2000; width:210px; padding:6px; border:1px solid var(--border, #d8dde6); border-radius:var(--border-radius, 6px); background:var(--input-bg, var(--body-bg, #fff)); box-shadow:0 8px 24px #0003; text-align:left; }
.host-menu-item { display:block; width:100%; border:0; border-radius:var(--border-radius); padding:9px 11px; color:var(--body-text); background:transparent; cursor:pointer; text-align:left; font:inherit; }
.host-menu-item:hover,.host-menu-item:focus-visible { background:var(--hover-bg, rgba(120,135,160,.12)); outline:none; }
.btn-sm { margin-left: 4px; }
.danger-text { color: #b42318; }
.banner { padding: 12px; border-radius: 4px; margin: 12px 0; }
.error { background: #fff0ee; color: #8f211a; }
.empty-state { padding: 64px 16px; text-align: center; border: 1px dashed var(--border, #d8dde6); }
.modal-backdrop { position: fixed; inset: 0; z-index: 1000; display: grid; place-items: center; background: #0008; }
.modal { width: min(520px, calc(100vw - 32px)); padding: 24px; border-radius: 6px; background: var(--body-bg, white); box-shadow: 0 8px 32px #0003; }
.modal form { display: grid; gap: 14px; }
.modal label { display: grid; gap: 6px; }
.modal input,.modal textarea { color:var(--input-text, var(--body-text)); background:var(--input-bg, var(--body-bg)); border:1px solid var(--input-border, var(--border)); }
.modal input { width: 100%; padding: 9px 10px; border-radius: 4px; box-sizing: border-box; }
.modal textarea { width: 100%; padding: 9px 10px; border-radius: 4px; box-sizing: border-box; resize: vertical; font-family: monospace; }
.modal .trust-key-option { display: flex; align-items: flex-start; gap: 10px; padding: 10px; border: 1px solid var(--border, #d8dde6); border-radius: 4px; }
.trust-key-option input { width: auto; margin-top: 3px; }
.trust-key-option span { display: grid; gap: 4px; }
.form-row { display: grid; grid-template-columns: 1fr 130px; gap: 12px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
@media (max-width: 700px) { .header { flex-direction: column; } .header-actions { width: 100%; flex-wrap: wrap; } .form-row { grid-template-columns: 1fr; } }
</style>
