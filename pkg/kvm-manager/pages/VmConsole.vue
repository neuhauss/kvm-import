<template>
      <section class="console-dock" role="region" :aria-label="t(clusterBootstrapPlanId ? 'clusters.bootstrapTerminalTitle' : hostTerminal ? 'cloudNative.hostTerminal' : 'cloudNative.vmConsole')" :class="{ expanded, resizing }" :style="dockStyle">
      <button class="dock-grip" type="button" :aria-label="t('cloudNative.resizeTerminal')" @pointerdown="beginResize"></button>
      <header class="console-header">
        <div>
          <span class="eyebrow">{{ t(clusterBootstrapPlanId ? 'clusters.bootstrapTerminalTitle' : hostTerminal ? 'cloudNative.hostTerminal' : 'cloudNative.vmConsole') }} · {{ t(hostTerminal ? 'cloudNative.sshTerminal' : 'cloudNative.serialConsole') }}</span>
        <h2>{{ vmName }}</h2>
        </div>
        <div class="console-controls">
          <span class="console-status" :class="status"><i></i>{{ t(`cloudNative.console_${status}`) }}</span>
          <button v-if="!clusterBootstrapPlanId" class="btn role-secondary btn-sm" :disabled="status === 'connecting'" @click="connect">{{ t('cloudNative.reconnectConsole') }}</button>
          <button class="btn role-secondary btn-sm" :aria-expanded="expanded" @click="expanded = !expanded">{{ t(expanded ? 'cloudNative.collapseTerminal' : 'cloudNative.expandTerminal') }}</button>
          <button class="btn role-secondary btn-sm" @click="requestClose">{{ t('cloudNative.close') }}</button>
        </div>
      </header>
      <p class="console-note">{{ t(clusterBootstrapPlanId ? 'clusters.bootstrapTerminalNote' : hostTerminal ? 'cloudNative.hostTerminalWarning' : 'cloudNative.consoleWarning') }}</p>
      <div v-if="clusterBootstrapPlanId && status === 'connected' && confirmBootstrapClose" class="bootstrap-close-review" role="alert">
        <p>{{ t('clusters.bootstrapCloseWarning') }}</p>
        <div><button class="btn role-danger btn-sm" @click="$emit('close')">{{ t('clusters.bootstrapCloseConfirm') }}</button><button class="btn role-secondary btn-sm" @click="confirmBootstrapClose = false">{{ t('clusters.bootstrapCloseKeepOpen') }}</button></div>
      </div>
      <p v-else-if="clusterBootstrapPlanId && (status === 'disconnected' || status === 'error')" class="console-note">{{ t('clusters.bootstrapNoReconnect') }}</p>
      <div v-if="showBootstrapCredentialHardening" class="bootstrap-close-review" role="alert"><p>{{ t('clusters.bootstrapCredentialHardening') }}</p></div>
      <p v-if="hostTerminal && initialCommand" class="console-note staged-command-note">{{ t('cloudNative.hostTerminalCommandStaged') }}</p>
      <div ref="terminalElement" class="terminal-surface" @click="terminal?.focus()"></div>
      <p v-if="error" class="console-error">{{ error }}</p>
  </section>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { bootstrapErrorTranslationKey, needsBootstrapCredentialHardening } from '../utils/cluster-bootstrap';
import { terminalPrefillCommand } from '../utils/terminal-prefill';
import '@xterm/xterm/css/xterm.css';

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmVmConsole',
  props: {
    hostId: { type: String, required: true },
    vmName: { type: String, default: '' },
    hostTerminal: { type: Boolean, default: false },
    initialCommand: { type: String, default: '' },
    clusterBootstrapPlanId: { type: String, default: '' },
    clusterBootstrapOperation: { type: String, default: '' },
  },
  emits: ['close'],
  data() {
    return {
      terminal: null as Terminal | null,
      fitAddon: null as FitAddon | null,
      socket: null as WebSocket | null,
      status: 'connecting' as 'connecting' | 'connected' | 'disconnected' | 'error',
      error: '',
      bootstrapExitStatus: null as number | null,
      confirmBootstrapClose: false,
      expanded: false,
      panelHeight: 0,
      resizing: false,
      resizeStartY: 0,
      resizeStartHeight: 0,
      resizeObserver: null as ResizeObserver | null,
    };
  },
  mounted() {
    this.terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 14,
      theme: { background: '#111820', foreground: '#e6edf3', cursor: '#53d6aa', selectionBackground: '#345348' },
    });
    this.fitAddon = new FitAddon();
    this.terminal.loadAddon(this.fitAddon);
    this.terminal.open(this.$refs.terminalElement as HTMLElement);
    this.terminal.onData((data) => {
      if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(data);
    });
    this.terminal.onResize(({ cols, rows }) => {
      if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(`KVM_CONTROL:${JSON.stringify({ type: 'resize', cols, rows })}`);
    });
    window.addEventListener('resize', this.fitTerminal);
    window.addEventListener('pointermove', this.resizePanel);
    window.addEventListener('pointerup', this.endResize);
    this.panelHeight = Math.round(window.innerHeight * 0.44);
    this.resizeObserver = new ResizeObserver(() => this.fitTerminal());
    this.resizeObserver.observe(this.$refs.terminalElement as HTMLElement);
    this.$nextTick(this.fitTerminal);
    this.connect();
  },
  beforeUnmount() {
    window.removeEventListener('resize', this.fitTerminal);
    window.removeEventListener('pointermove', this.resizePanel);
    window.removeEventListener('pointerup', this.endResize);
    this.resizeObserver?.disconnect();
    this.socket?.close();
    this.terminal?.dispose();
  },
  methods: {
    t(key: string, args?: Record<string, unknown>): string {
      const translate = (this as any).$store?.getters?.['i18n/t'];
      return translate ? translate(`kvmManager.${key}`, args) : key;
    },
    fitTerminal() { this.fitAddon?.fit(); },
    requestClose() {
      if (this.clusterBootstrapPlanId && this.status === 'connected') {
        this.confirmBootstrapClose = true;
        return;
      }
      this.$emit('close');
    },
    beginResize(event: PointerEvent) {
      this.resizing = true;
      this.resizeStartY = event.clientY;
      this.resizeStartHeight = this.panelHeight || Math.round(window.innerHeight * 0.44);
      (event.currentTarget as HTMLElement).setPointerCapture?.(event.pointerId);
      event.preventDefault();
    },
    resizePanel(event: PointerEvent) {
      if (!this.resizing) return;
      const min = 220;
      const max = Math.round(window.innerHeight * 0.88);
      this.panelHeight = Math.min(max, Math.max(min, this.resizeStartHeight + this.resizeStartY - event.clientY));
      this.$nextTick(this.fitTerminal);
    },
    endResize() { this.resizing = false; },
    connect() {
      this.socket?.close();
      this.error = '';
      this.status = 'connecting';
      this.terminal?.reset();
      this.terminal?.writeln(this.t(this.hostTerminal ? 'cloudNative.hostTerminalStarting' : 'cloudNative.consoleStarting'));
      this.terminal?.focus();
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const endpoint = this.hostTerminal
        ? this.clusterBootstrapPlanId
          ? `${protocol}//${window.location.host}${apiBase}/clusters/plans/${encodeURIComponent(this.clusterBootstrapPlanId)}/bootstrap/${encodeURIComponent(this.hostId)}/${encodeURIComponent(this.clusterBootstrapOperation)}`
          : `${protocol}//${window.location.host}${apiBase}/hosts/${encodeURIComponent(this.hostId)}/terminal`
        : `${protocol}//${window.location.host}${apiBase}/hosts/${encodeURIComponent(this.hostId)}/vms/console?vm_name=${encodeURIComponent(this.vmName)}`;
      const socket = new WebSocket(endpoint);
      socket.binaryType = 'arraybuffer';
      this.socket = socket;
      socket.onopen = () => {
        if (this.socket !== socket) return;
        this.fitTerminal();
        this.terminal?.focus();
        const command = terminalPrefillCommand(this.initialCommand);
        if (this.hostTerminal && command) socket.send(command);
      };
      socket.onmessage = (event: MessageEvent) => {
        if (this.socket !== socket) return;
        if (typeof event.data === 'string') {
          if (event.data.startsWith('KVM_CONTROL:')) {
            try {
              const message = JSON.parse(event.data.slice('KVM_CONTROL:'.length));
              if (message.type === 'status') { this.status = message.status; return; }
              if (message.type === 'progress' && message.step === 'preflight') { this.terminal?.writeln(`\r\n${this.t('clusters.bootstrapPreflightRunning')}`); return; }
              if (message.type === 'exit') { this.bootstrapExitStatus = Number.isInteger(message.exit_status) ? message.exit_status : null; this.status = message.exit_status === 0 ? 'disconnected' : 'error'; if (message.exit_status !== 0) this.error = this.t('clusters.bootstrapCommandFailed', { status: message.exit_status }); return; }
              if (message.type === 'error') { this.status = 'error'; this.error = this.t(bootstrapErrorTranslationKey(message.code)); this.terminal?.writeln(`\r\n${this.error}`); return; }
            } catch (_) { /* Invalid control frames are rendered as terminal output. */ }
          }
          this.terminal?.write(event.data);
        } else {
          this.terminal?.write(new Uint8Array(event.data));
        }
      };
      socket.onclose = (event) => {
        if (this.socket !== socket) return;
        if (event.code === 4401) { this.status = 'error'; this.error = this.t('cloudNative.consoleSessionExpired'); }
        else if (event.code === 4403) { this.status = 'error'; this.error = this.t('cloudNative.consolePermissionDenied'); }
        else if (event.code === 4404) { this.status = 'error'; this.error = this.t('cloudNative.consoleHostNotFound'); }
        else if (event.code === 4400) { this.status = 'error'; this.error = this.t('cloudNative.consoleInvalidVm'); }
        else if (this.status !== 'error') {
          this.status = event.code === 1000 || event.code === 1005 ? 'disconnected' : 'error';
          if (event.code !== 1000 && event.code !== 1005) this.error = this.t(this.hostTerminal ? 'cloudNative.hostTerminalConnectionError' : 'cloudNative.consoleConnectionError');
        }
      };
      socket.onerror = () => { /* onclose carries the useful auth or transport code */ };
    },
  },
  computed: {
    showBootstrapCredentialHardening(): boolean {
      return needsBootstrapCredentialHardening(this.clusterBootstrapOperation, this.bootstrapExitStatus);
    },
    dockStyle(): Record<string, string> {
      return { height: this.expanded ? 'min(78vh, 760px)' : `${this.panelHeight || 320}px` };
    },
  },
});
</script>

<style scoped>
.staged-command-note { border-left:3px solid var(--success,#53ba84); padding:8px 10px; background:color-mix(in srgb,var(--success,#53ba84) 9%,transparent); }
.bootstrap-close-review { margin:0 0 8px; padding:10px 12px; border:1px solid color-mix(in srgb,var(--warning,#d99a26) 45%,var(--border,#44505d)); border-radius:5px; background:color-mix(in srgb,var(--warning,#d99a26) 10%,var(--body-bg,#fff)); }
.bootstrap-close-review p { margin:0 0 8px; color:var(--body-text,#243043); font-size:13px; line-height:1.45; }
.bootstrap-close-review>div { display:flex; flex-wrap:wrap; gap:8px; }
</style>

<style scoped>
.console-dock { position:fixed; z-index:1100; inset:auto 0 0; display:flex; flex-direction:column; min-height:220px; max-height:88vh; padding:0 16px 12px; border:1px solid var(--border,#44505d); border-bottom:0; border-radius:8px 8px 0 0; color:var(--body-text,#243043); background:var(--body-bg,#fff); box-shadow:0 -12px 35px rgba(0,0,0,.3); }
.console-dock.resizing { user-select:none; }
.dock-grip { width:100%; height:20px; flex:0 0 20px; align-self:center; margin:0 0 5px; padding:0; border:0; background:transparent; cursor:ns-resize; touch-action:none; }
.dock-grip::after { content:""; display:block; width:44px; height:4px; margin:auto; border-radius:4px; background:var(--muted,#65717e); }
.console-header { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:14px; margin-bottom:8px; }
.eyebrow { color:var(--muted,#9ba7b4); font-size:11px; font-weight:700; letter-spacing:.1em; }
.console-header h2 { margin:4px 0 0; color:var(--body-text,#243043); font-size:20px; }
.console-controls { display:flex; align-items:center; gap:8px; }
.console-status { display:inline-flex; align-items:center; gap:7px; margin-right:6px; color:var(--muted,#657286); font-size:12px; }
.console-status i { width:8px; height:8px; border-radius:50%; background:#9aa4b2; }
.console-status.connected i { background:#53d6aa; }.console-status.error i { background:#e77d7d; }.console-status.connecting i { background:#f0b94b; }
.console-note { margin:0 0 8px; color:var(--muted,#657286); font-size:12px; }
.terminal-surface { flex:1; min-height:0; padding:8px 10px; overflow:hidden; border:1px solid #303b46; border-radius:5px; background:#111820; }
.terminal-surface :deep(.xterm) { height:100%; }
.console-error { margin:10px 0 0; color:var(--error-text,var(--error,#b42318)); font-size:13px; }
@media (max-width:700px) { .console-dock { height:52vh; min-height:220px; padding:0 8px 8px; }.console-dock.expanded { height:84vh; }.console-header { gap:8px; }.console-controls { flex-wrap:wrap; justify-content:flex-end; }.console-status { width:100%; justify-content:flex-end; } }
</style>
