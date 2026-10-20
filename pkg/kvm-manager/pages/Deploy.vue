<template>
  <div class="deploy-layout-frame">
    <main class="kvm-page deploy-page">
      <header class="deploy-header">
        <div><span class="eyebrow">{{ t('eyebrow') }}</span><h1>{{ t('title') }}</h1><p>{{ t('subtitle') }}</p></div>
      </header>

      <div class="deploy-callout"><strong>{{ t('existingMachineTitle') }}</strong><p>{{ t('existingMachineHelp') }}</p></div>
      <div v-if="error" class="banner error" role="alert">{{ error }}</div>
      <div v-if="success" class="banner success" role="status"><strong>{{ success }}</strong><button class="btn role-link btn-sm" @click="$router.push({ name: 'kvm-c-cluster-cloud-native', query: { hostId: importedHost.id } })">{{ t('openHost') }}</button></div>

      <section class="deploy-panel">
        <header class="panel-heading"><div><span class="eyebrow">{{ t('stepOne') }}</span><h2>{{ t('connectionTitle') }}</h2><p>{{ t('connectionHelp') }}</p></div></header>
        <div class="deploy-grid">
          <label class="rancher-field"><span>{{ t('hostName') }} *</span><input v-model.trim="form.name" maxlength="80" autocomplete="off" :placeholder="t('hostNamePlaceholder')"></label>
          <label class="rancher-field"><span>{{ t('address') }} *</span><input v-model.trim="form.address" maxlength="253" autocomplete="off" placeholder="192.0.2.10"></label>
          <label class="rancher-field"><span>{{ t('sshPort') }}</span><input v-model.number="form.port" type="number" min="1" max="65535"></label>
          <label class="rancher-field"><span>{{ t('sshUser') }} *</span><input v-model.trim="form.username" maxlength="128" autocomplete="username" placeholder="sles"></label>
          <label class="rancher-field"><span>{{ t('sshPassword') }} *</span><input v-model="form.password" type="password" maxlength="1024" autocomplete="current-password"></label>
          <label class="rancher-check deploy-check"><input v-model="form.accept_new_host_key" type="checkbox"><span><strong>{{ t('trustHostKey') }}</strong><small>{{ t('trustHostKeyHelp') }}</small></span></label>
        </div>
      </section>

      <section class="deploy-panel preparation-panel">
        <header class="panel-heading"><div><span class="eyebrow">{{ t('stepTwo') }}</span><h2>{{ t('preparationTitle') }}</h2><p>{{ t('preparationHelp') }}</p></div></header>
        <ul class="preparation-list"><li>{{ t('preparationSles') }}</li><li>{{ t('preparationKvm') }}</li><li>{{ t('preparationCockpit') }}</li><li>{{ t('preparationImport') }}</li></ul>
        <p class="deploy-footnote">{{ t('preparationSafety') }}</p>
      </section>

      <div v-if="reviewing" class="deploy-panel review-panel">
        <header class="panel-heading"><div><span class="eyebrow">{{ t('stepThree') }}</span><h2>{{ t('reviewTitle') }}</h2><p>{{ t('reviewHelp') }}</p></div></header>
        <dl class="review-grid"><div><dt>{{ t('hostName') }}</dt><dd>{{ form.name }}</dd></div><div><dt>{{ t('address') }}</dt><dd>{{ form.address }}:{{ form.port }}</dd></div><div><dt>{{ t('sshUser') }}</dt><dd>{{ form.username }}</dd></div><div><dt>{{ t('changes') }}</dt><dd>{{ t('changesSummary') }}</dd></div></dl>
        <div class="deploy-actions"><button class="btn role-secondary" :disabled="working" @click="reviewing = false">{{ t('edit') }}</button><button class="btn role-primary" :disabled="working" @click="prepareAndImport">{{ working ? progress : t('prepareImport') }}</button></div>
      </div>

      <footer v-else class="deploy-actions"><button class="btn role-primary" :disabled="!canReview" @click="reviewing = true">{{ t('review') }}</button></footer>
      <footer v-if="working" class="deploy-progress" role="status"><span class="spinner" aria-hidden="true"></span>{{ progress }}</footer>
    </main>
  </div>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

type ImportedHost = { id: string; name: string; hostname?: string; address: string };

export default defineComponent({
  name: 'KvmDeploy',
  data() {
    return {
      form: { name: '', address: '', port: 22, username: 'sles', password: '', accept_new_host_key: false },
      reviewing: false, working: false, progress: '', error: '', success: '', importedHost: null as ImportedHost | null,
    };
  },
  computed: {
    canReview(): boolean {
      return /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$/.test(this.form.name)
        && /^[A-Za-z0-9_.:-]+$/.test(this.form.address)
        && Number.isInteger(this.form.port) && this.form.port >= 1 && this.form.port <= 65535
        && /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(this.form.username)
        && this.form.password.length > 0;
    },
  },
  methods: {
    t(key: string, args?: Record<string, unknown>): string {
      const translate = (this as any).$store?.getters?.['i18n/t'];
      return translate ? translate(`kvmManager.deploy.${key}`, args) : key;
    },
    async prepareAndImport() {
      if (!this.canReview || this.working) return;
      this.working = true; this.error = ''; this.success = ''; this.progress = this.t('preparing');
      try {
        const response = await fetch('/kvm-api/hosts/prepare-import', {
          method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify(this.form),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.detail || `${this.t('prepareFailed')} (${response.status})`);
        this.importedHost = body;
        this.success = this.t('preparedImported', { host: body.hostname || body.name });
        this.form.password = ''; this.reviewing = false;
      } catch (error) {
        this.error = (error as Error).message || this.t('prepareFailed');
      } finally { this.working = false; this.progress = ''; }
    },
  },
});
</script>

<style scoped>
.deploy-layout-frame { container-type:inline-size; container-name:deploy; width:100%; min-width:0; max-width:100%; }
.deploy-page { width:100%; max-width:1100px; margin:0 auto; padding:26px; box-sizing:border-box; }
.deploy-header,.panel-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }
.deploy-header { margin-bottom:20px; }.deploy-header h1 { margin:4px 0 0; font-size:24px; font-weight:500; }.deploy-header p,.panel-heading p { margin:6px 0 0; color:var(--muted,#8b95a5); line-height:1.5; }
.eyebrow { color:var(--muted,#8b95a5); font-size:11px; font-weight:700; letter-spacing:.06em; }
.deploy-callout,.deploy-panel { margin:14px 0; padding:18px; border:1px solid var(--border,#394452); border-radius:7px; background:var(--body-bg,#252b33); }
.deploy-callout { border-left:3px solid var(--primary,#4b91e2); }.deploy-callout p { margin:5px 0 0; color:var(--muted,#8b95a5); font-size:13px; line-height:1.5; }
.panel-heading { align-items:center; margin-bottom:16px; }.panel-heading h2 { margin:4px 0 0; font-size:18px; font-weight:600; }.panel-heading p { font-size:13px; }
.deploy-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }.rancher-field { display:flex; flex-direction:column; gap:7px; min-width:0; font-size:13px; }.rancher-field>span { font-weight:600; }
.rancher-field input { width:100%; min-height:40px; padding:9px 11px; border:1px solid var(--border,#4b5665); border-radius:5px; background:var(--input-bg,#1c2128); color:var(--input-text,var(--body-text,#f5f6f7)); font:inherit; box-sizing:border-box; }.rancher-field input:focus { outline:2px solid var(--primary,#4b91e2); outline-offset:1px; }
.deploy-check { grid-column:1/-1; margin:0; }.deploy-check small { display:block; margin-top:4px; color:var(--muted,#8b95a5); font-size:12px; line-height:1.45; }
.preparation-list { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px 20px; margin:0; padding:0; list-style:none; }.preparation-list li { display:flex; align-items:flex-start; gap:9px; font-size:13px; line-height:1.45; }.preparation-list li::before { content:'✓'; color:var(--success,#53ba84); font-weight:700; }
.deploy-footnote { margin:14px 0 0; color:var(--muted,#8b95a5); font-size:12px; line-height:1.5; }
.review-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px 22px; margin:0; }.review-grid dt { color:var(--muted,#8b95a5); font-size:11px; }.review-grid dd { margin:4px 0 0; font-size:13px; overflow-wrap:anywhere; }
.deploy-actions { display:flex; justify-content:flex-end; gap:10px; margin-top:18px; }.deploy-progress { position:sticky; bottom:0; display:flex; align-items:center; gap:10px; padding:12px 16px; border:1px solid var(--border,#394452); border-radius:6px; background:var(--body-bg,#252b33); }.spinner { width:16px; height:16px; border:2px solid var(--border,#394452); border-top-color:var(--primary,#4b91e2); border-radius:50%; animation:spin .8s linear infinite; }@keyframes spin { to { transform:rotate(360deg); } }
.banner.error,.banner.success { display:flex; align-items:center; justify-content:space-between; gap:12px; margin:12px 0; padding:12px; border:1px solid var(--border,#394452); border-radius:5px; background:color-mix(in srgb,var(--body-text,#eee) 6%,var(--body-bg,#252b33)); }.banner.error { border-color:color-mix(in srgb,#d45b52 55%,var(--border,#394452)); }.banner.success { border-color:color-mix(in srgb,#53ba84 55%,var(--border,#394452)); }
@container deploy (max-width:700px) { .deploy-page { padding:18px 12px; }.deploy-grid,.review-grid,.preparation-list { grid-template-columns:minmax(0,1fr); }.deploy-panel,.deploy-callout { padding:14px; }.deploy-header,.panel-heading { flex-direction:column; align-items:stretch; }.deploy-actions { flex-wrap:wrap; }.deploy-actions .btn { flex:1 1 auto; } }
</style>
