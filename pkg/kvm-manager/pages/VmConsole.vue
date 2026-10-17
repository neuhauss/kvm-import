<template>
  <section class="console-dock" role="region" :aria-label="t('cloudNative.vmConsole')" :class="{ expanded }">
      <div class="dock-grip" aria-hidden="true"></div>
      <header class="console-header">
        <div>
          <span class="eyebrow">{{ t('cloudNative.vmConsole') }} · {{ t('cloudNative.serialConsole') }}</span>
          <h2>{{ vmName }}</h2>
        </div>
        <div class="console-controls">
          <span class="console-status" :class="status"><i></i>{{ t(`cloudNative.console_${status}`) }}</span>
          <button class="btn role-secondary btn-sm" :disabled="status === 'connecting'" @click="connect">{{ t('cloudNative.reconnectConsole') }}</button>
          <button class="btn role-secondary btn-sm" :aria-expanded="expanded" @click="expanded = !expanded">{{ t(expanded ? 'cloudNative.collapseTerminal' : 'cloudNative.expandTerminal') }}</button>
          <button class="btn role-secondary btn-sm" @click="$emit('close')">{{ t('cloudNative.close') }}</button>
        </div>
      </header>
      <p class="console-note">{{ t('cloudNative.consoleWarning') }}</p>
      <div ref="terminalElement" class="terminal-surface" @click="terminal?.focus()"></div>
      <p v-if="error" class="console-error">{{ error }}</p>
  </section>
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmVmConsole',
  props: {
    hostId: { type: String, required: true },
    vmName: { type: String, required: true },
  },
  emits: ['close'],
  data() {
    return {
      terminal: null as Terminal | null,
      fitAddon: null as FitAddon | null,
      socket: null as WebSocket | null,
      status: 'connecting' as 'connecting' | 'connected' | 'disconnected' | 'error',
      error: '',
      expanded: false,
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
    this.resizeObserver = new ResizeObserver(() => this.fitTerminal());
    this.resizeObserver.observe(this.$refs.terminalElement as HTMLElement);
    this.$nextTick(this.fitTerminal);
    this.connect();
  },
  beforeUnmount() {
    window.removeEventListener('resize', this.fitTerminal);
    this.resizeObserver?.disconnect();
    this.socket?.close();
    this.terminal?.dispose();
  },
  methods: {
    t(key: string): string {
      const translate = (this as any).$store?.getters?.['i18n/t'];
      return translate ? translate(`kvmManager.${key}`) : key;
    },
    fitTerminal() { this.fitAddon?.fit(); },
    connect() {
      this.socket?.close();
      this.error = '';
      this.status = 'connecting';
      this.terminal?.reset();
      this.terminal?.writeln(this.t('cloudNative.consoleStarting'));
      this.terminal?.focus();
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const endpoint = `${protocol}//${window.location.host}${apiBase}/hosts/${encodeURIComponent(this.hostId)}/vms/console?vm_name=${encodeURIComponent(this.vmName)}`;
      const socket = new WebSocket(endpoint);
      socket.binaryType = 'arraybuffer';
      this.socket = socket;
      socket.onopen = () => { if (this.socket === socket) { this.fitTerminal(); this.terminal?.focus(); } };
      socket.onmessage = (event: MessageEvent) => {
        if (this.socket !== socket) return;
        if (typeof event.data === 'string') {
          if (event.data.startsWith('KVM_CONTROL:')) {
            try {
              const message = JSON.parse(event.data.slice('KVM_CONTROL:'.length));
              if (message.type === 'status') { this.status = message.status; return; }
              if (message.type === 'error') { this.status = 'error'; this.error = message.message; this.terminal?.writeln(`\r\n${message.message}`); return; }
            } catch (_) { /* Invalid control frames are rendered as terminal output. */ }
          }
          this.terminal?.write(event.data);
        } else {
          this.terminal?.write(new Uint8Array(event.data));
        }
      };
      socket.onerror = () => {
        if (this.socket !== socket) return;
        this.status = 'error'; this.error = this.t('cloudNative.consoleConnectionError');
      };
      socket.onclose = (event) => {
        if (this.socket !== socket || this.status === 'error') return;
        this.status = 'disconnected';
        if (event.code !== 1000 && event.code !== 1005) this.error = `${this.t('cloudNative.consoleClosed')} (${event.code})`;
      };
    },
  },
});
</script>

<style scoped>
.console-dock { position:fixed; z-index:1100; inset:auto 0 0; display:flex; flex-direction:column; height:min(44vh,440px); min-height:240px; padding:0 16px 12px; border:1px solid var(--border,#44505d); border-bottom:0; border-radius:8px 8px 0 0; background:var(--body-bg,#20262e); box-shadow:0 -12px 35px rgba(0,0,0,.3); }
.console-dock.expanded { height:min(78vh,760px); }
.dock-grip { width:44px; height:4px; flex:0 0 4px; align-self:center; margin:7px 0 9px; border-radius:4px; background:var(--muted,#65717e); }
.console-header { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:14px; margin-bottom:8px; }
.eyebrow { color:var(--muted,#9ba7b4); font-size:11px; font-weight:700; letter-spacing:.1em; }
.console-header h2 { margin:4px 0 0; color:var(--body-text,#edf2f7); font-size:20px; }
.console-controls { display:flex; align-items:center; gap:8px; }
.console-status { display:inline-flex; align-items:center; gap:7px; margin-right:6px; color:var(--muted,#aab3bf); font-size:12px; }
.console-status i { width:8px; height:8px; border-radius:50%; background:#9aa4b2; }
.console-status.connected i { background:#53d6aa; }.console-status.error i { background:#e77d7d; }.console-status.connecting i { background:#f0b94b; }
.console-note { margin:0 0 8px; color:var(--muted,#aab3bf); font-size:12px; }
.terminal-surface { flex:1; min-height:0; padding:8px 10px; overflow:hidden; border:1px solid #303b46; border-radius:5px; background:#111820; }
.terminal-surface :deep(.xterm) { height:100%; }
.console-error { margin:10px 0 0; color:#ff9690; font-size:13px; }
@media (max-width:700px) { .console-dock { height:52vh; min-height:220px; padding:0 8px 8px; }.console-dock.expanded { height:84vh; }.console-header { gap:8px; }.console-controls { flex-wrap:wrap; justify-content:flex-end; }.console-status { width:100%; justify-content:flex-end; } }
</style>
