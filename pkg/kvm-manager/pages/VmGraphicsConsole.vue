<template>
  <section class="graphics-console" role="dialog" aria-modal="true" :aria-label="t('cloudNative.graphicsConsole')" :class="{ expanded }">
    <header class="graphics-header">
      <div><span class="eyebrow">{{ t('cloudNative.graphicsConsole') }} · noVNC</span><h2>{{ vmName }}</h2></div>
      <div class="graphics-controls">
        <span class="console-status" :class="status" aria-live="polite"><i></i>{{ t(`cloudNative.graphics_${status}`) }}</span>
        <button class="btn role-secondary btn-sm" :disabled="status === 'connecting'" @click="connect">{{ t('cloudNative.reconnectConsole') }}</button>
        <button class="btn role-secondary btn-sm" :aria-expanded="expanded" @click="expanded = !expanded">{{ t(expanded ? 'cloudNative.collapseGraphics' : 'cloudNative.expandGraphics') }}</button>
        <button class="btn role-secondary btn-sm" @click="$emit('close')">{{ t('cloudNative.close') }}</button>
      </div>
    </header>
    <p class="graphics-note">{{ t('cloudNative.graphicsConsoleWarning') }}</p>
    <form v-if="credentialsRequired" class="graphics-credentials" @submit.prevent="provideCredentials">
      <label>{{ t('cloudNative.graphicsPassword') }}<input v-model="password" class="search-input" type="password" autocomplete="off" maxlength="256" required /></label>
      <button class="btn role-primary btn-sm" :disabled="!password">{{ t('cloudNative.graphicsAuthenticate') }}</button>
    </form>
    <p v-if="error" class="graphics-error" role="alert">{{ error }}</p>
    <div ref="displayElement" class="graphics-display" :aria-label="t('cloudNative.graphicsConsole')"></div>
  </section>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import RFB from '@novnc/novnc/lib/rfb.js';

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmVmGraphicsConsole',
  props: {
    hostId: { type: String, required: true },
    vmName: { type: String, required: true },
  },
  emits: ['close'],
  data() {
    return {
      rfb: null as RFB | null,
      status: 'connecting' as 'connecting' | 'connected' | 'disconnected' | 'error',
      error: '',
      expanded: false,
      credentialsRequired: false,
      password: '',
    };
  },
  mounted() { this.connect(); },
  beforeUnmount() {
    this.rfb?.disconnect();
    this.rfb = null;
    this.password = '';
  },
  methods: {
    t(key: string): string {
      const translate = (this as any).$store?.getters?.['i18n/t'];
      return translate ? translate(`kvmManager.${key}`) : key;
    },
    connect() {
      this.rfb?.disconnect();
      this.rfb = null;
      this.password = '';
      this.credentialsRequired = false;
      this.error = '';
      this.status = 'connecting';
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const endpoint = `${protocol}//${window.location.host}${apiBase}/hosts/${encodeURIComponent(this.hostId)}/vms/graphics-console?vm_name=${encodeURIComponent(this.vmName)}`;
      const target = this.$refs.displayElement as HTMLElement;
      target.replaceChildren();
      const rfb = new RFB(target, endpoint, { shared: true });
      rfb.scaleViewport = true;
      rfb.resizeSession = false;
      rfb.background = '#111820';
      this.rfb = rfb;
      rfb.addEventListener('connect', () => {
        if (this.rfb !== rfb) return;
        this.status = 'connected';
        this.credentialsRequired = false;
      });
      rfb.addEventListener('disconnect', (event: Event) => {
        if (this.rfb !== rfb) return;
        const clean = Boolean((event as CustomEvent<{ clean?: boolean }>).detail?.clean);
        this.status = this.status === 'error' ? 'error' : clean ? 'disconnected' : 'error';
        if (!clean && !this.error) this.error = this.t('cloudNative.graphicsConnectionError');
        this.password = '';
      });
      rfb.addEventListener('credentialsrequired', () => {
        if (this.rfb !== rfb) return;
        this.credentialsRequired = true;
        this.status = 'error';
        this.error = this.t('cloudNative.graphicsPasswordRequired');
      });
      rfb.addEventListener('securityfailure', () => {
        if (this.rfb !== rfb) return;
        this.status = 'error';
        this.error = this.t('cloudNative.graphicsAuthenticationFailed');
      });
    },
    provideCredentials() {
      if (!this.password || !this.rfb) return;
      this.rfb.sendCredentials({ password: this.password });
      this.password = '';
      this.credentialsRequired = false;
      this.error = '';
      this.status = 'connecting';
    },
  },
});
</script>

<style scoped>
.graphics-console { position:fixed; z-index:1110; inset:4vh 3vw; display:flex; flex-direction:column; min-width:0; min-height:0; padding:16px; border:1px solid var(--border,#44505d); border-radius:8px; color:var(--body-text,#243043); background:var(--body-bg,#fff); box-shadow:0 18px 55px rgba(0,0,0,.48); }
.graphics-console.expanded { inset:0; border-radius:0; }
.graphics-header { display:flex; align-items:center; justify-content:space-between; gap:14px; padding-bottom:12px; border-bottom:1px solid var(--border,#394452); }
.graphics-header h2 { margin:4px 0 0; overflow-wrap:anywhere; font-size:18px; }
.eyebrow { color:var(--muted,#657286); font-size:11px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
.graphics-controls { display:flex; align-items:center; justify-content:flex-end; flex-wrap:wrap; gap:8px; }
.console-status { display:inline-flex; align-items:center; gap:7px; color:var(--muted,#657286); font-size:12px; }
.console-status i { width:8px; height:8px; border-radius:50%; background:#9aa4b2; }
.console-status.connected i { background:#53d6aa; }.console-status.error i { background:#e77d7d; }.console-status.connecting i { background:#f0b94b; }
.graphics-note { margin:10px 0; color:var(--muted,#657286); font-size:12px; }
.graphics-display { flex:1; min-height:0; overflow:hidden; border:1px solid #303b46; border-radius:5px; background:#111820; }
.graphics-display :deep(canvas) { width:100%; height:100%; object-fit:contain; }
.graphics-credentials { display:flex; align-items:flex-end; gap:10px; margin:4px 0 10px; }
.graphics-credentials label { display:grid; flex:1; gap:5px; max-width:360px; font-size:12px; }
.graphics-error { margin:0 0 8px; color:var(--error-text,var(--error,#b42318)); font-size:12px; }
@media (max-width:700px) { .graphics-console { inset:0; padding:10px; border-radius:0; }.graphics-header { align-items:flex-start; flex-direction:column; }.graphics-controls { width:100%; justify-content:flex-start; }.console-status { width:100%; }.graphics-credentials { align-items:stretch; flex-direction:column; }.graphics-credentials label { max-width:none; } }
</style>
