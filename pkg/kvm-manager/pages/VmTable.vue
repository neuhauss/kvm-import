<template>
  <div class="table-wrap vm-table-wrap">
    <table class="table">
      <thead><tr><th>{{ t('vm') }}</th><th>{{ t('state') }}</th><th>{{ t('ipAddresses') }}</th><th>vCPU</th><th>{{ t('memory') }}</th><th>{{ t('autostart') }}</th><th>{{ t('actions') }}</th></tr></thead>
      <tbody>
        <tr v-for="vm in vms" :key="vm.uuid || vm.name">
          <td :data-label="t('vm')"><button class="vm-name" @click="$emit('details', vm)">{{ vm.name }}</button><small>{{ vm.uuid }}</small></td>
          <td :data-label="t('state')"><span class="state" :class="stateClass(vm.state)"><i></i>{{ vm.state }}</span></td>
          <td class="vm-addresses" :data-label="t('ipAddresses')">{{ vm.ip_addresses?.join(', ') || '—' }}</td>
          <td data-label="vCPU">{{ vm.current_vcpus || vm.vcpus }}</td>
          <td :data-label="t('memory')">{{ (Number(vm.memory_kib || 0) / 1048576).toFixed(1) }} GiB</td>
          <td :data-label="t('autostart')"><button v-if="canOperate" class="toggle-pill" :class="{ enabled: isAutostart(vm) }" :disabled="busy === vm.name" @click="$emit('autostart', vm)">{{ t(isAutostart(vm) ? 'enabled' : 'disabled') }}</button><span v-else>{{ t(isAutostart(vm) ? 'enabled' : 'disabled') }}</span></td>
          <td class="row-actions" :data-label="t('actions')"><div class="vm-actions">
            <button class="btn role-link btn-sm" @click="$emit('details', vm)">{{ t('details') }}</button>
            <button v-if="canOperate" class="btn role-secondary btn-sm" @click="$emit('snapshots', vm)">{{ t('snapshots') }}</button>
            <details v-if="canOperate" class="vm-action-menu">
              <summary class="btn role-secondary btn-sm" :aria-label="`${t('actions')}: ${vm.name}`">{{ t('moreActions') }}</summary>
              <div class="vm-action-menu-list">
              <button class="btn role-secondary btn-sm" @click="$emit('configure', vm)">{{ t('configure') }}</button>
              <button v-if="isRunning(vm) || isPaused(vm)" class="btn role-secondary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, isPaused(vm) ? 'resume' : 'pause')">{{ isPaused(vm) ? t('resume') : t('pause') }}</button>
              <button v-if="!isRunning(vm) && !isPaused(vm)" class="btn role-primary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, 'start')">{{ t('start') }}</button>
              <button v-else class="btn role-secondary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, 'shutdown')">{{ t('shutdown') }}</button>
              <button class="btn role-link btn-sm" :disabled="busy === vm.name || !isRunning(vm)" @click="$emit('action', vm, 'reboot')">{{ t('restart') }}</button>
              </div>
            </details>
          </div></td>
        </tr>
        <tr v-if="!vms.length"><td colspan="7" class="empty-row">{{ t('empty') }}</td></tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from 'vue';

type VmRow = { name: string; uuid: string; state: string; vcpus: number; current_vcpus: number; memory_kib: number; autostart: string; ip_addresses?: string[] };

export default defineComponent({
  name: 'KvmVmTable',
  props: { vms: { type: Array as PropType<VmRow[]>, required: true }, busy: { type: String, default: '' }, canOperate: { type: Boolean, default: false } },
  emits: ['action', 'details', 'snapshots', 'configure', 'autostart'],
  methods: {
    t(key: string): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.vmTable.${key}`) : key; },
    isRunning(vm: VmRow) { return vm.state.toLowerCase().includes('running'); },
    isPaused(vm: VmRow) { return vm.state.toLowerCase().includes('paused'); },
    isAutostart(vm: VmRow) { return vm.autostart === 'enable' || vm.autostart === 'yes'; },
    stateClass(state: string) { const value = state.toLowerCase(); return value.includes('running') ? 'ready' : value.includes('paused') ? 'warning-state' : 'unknown'; },
  },
});
</script>

<style scoped>
/* Keep VM controls legible against Rancher's dark theme. These styles belong
   to this component because the Cloud Native page's scoped CSS cannot reach
   its buttons directly. */
.vm-name {
  max-width: 100%;
  border: 0 !important;
  padding: 2px 0 !important;
  color: var(--link, #7db8ff) !important;
  background: transparent !important;
  cursor: pointer;
  text-align: left;
  font: inherit;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.vm-name:hover { text-decoration: underline; }
.vm-addresses { min-width: 120px; max-width: 240px; white-space: normal !important; overflow-wrap: anywhere; }
.toggle-pill {
  min-width: 70px;
  border: 1px solid var(--border, #4b5563) !important;
  border-radius: 5px !important;
  padding: 6px 10px !important;
  color: var(--body-text, #e5e7eb) !important;
  background: var(--body-bg, #252b33) !important;
  cursor: pointer;
  font: inherit;
  font-size: 12px;
}
.toggle-pill.enabled {
  border-color: #3b8458 !important;
  color: #b9f0ca !important;
  background: #173d2b !important;
}
.toggle-pill:disabled { cursor: wait; opacity: .72; }
.vm-table-wrap { container-type:inline-size; container-name:vm-table; min-width:0; max-width:100%; overflow-x:auto; overscroll-behavior-x:contain; }
.vm-action-menu { position:relative; display:inline-block; }
.vm-action-menu summary { list-style:none; cursor:pointer; }
.vm-action-menu summary::-webkit-details-marker { display:none; }
.vm-action-menu summary::after { content:' ▾'; }
.vm-action-menu-list { position:static; display:grid; gap:3px; min-width:180px; margin-top:6px; max-width:min(260px,calc(100vw - 32px)); padding:6px; border:1px solid var(--border,#394452); border-radius:6px; background:var(--body-bg,#252b33); box-shadow:0 8px 24px #0003; }
.vm-action-menu-list .btn { width:100%; margin:0; text-align:left; }
.vm-action-menu summary:focus-visible { outline:2px solid var(--primary,#4b91e2); outline-offset:2px; }
.vm-table-wrap :deep(td.row-actions) { display:table-cell; }.vm-actions { display:flex; align-items:center; flex-wrap:wrap; gap:8px; }.vm-table-wrap :deep(.row-actions) { min-width:170px; }
.vm-table-wrap :deep(.row-actions .btn) { margin:0; }
@container vm-table (max-width: 760px) {
  .vm-table-wrap { overflow:visible; border:0; background:transparent; }
  .vm-table-wrap :deep(.table) { display:block; width:100%; border-collapse:separate; background:transparent; }
  .vm-table-wrap :deep(.table thead) { position:absolute; width:1px; height:1px; padding:0; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; clip-path:inset(50%); }
  .vm-table-wrap :deep(.table tbody) { display:grid; gap:10px; }
  .vm-table-wrap :deep(.table tbody tr) { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); min-width:0; overflow:hidden; border:1px solid var(--border,#394452); border-radius:8px; background:var(--body-bg,#252b33); }
  .vm-table-wrap :deep(.table tbody td) { display:grid; align-content:start; gap:4px; min-width:0; padding:10px 12px; border:0; white-space:normal; overflow-wrap:anywhere; }
  .vm-table-wrap :deep(.table tbody td::before) { content:attr(data-label); color:var(--muted,#8b95a5); font-size:10px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }
  .vm-table-wrap :deep(.table tbody td:first-child) { grid-column:1/-1; border-bottom:1px solid var(--border,#394452); }
  .vm-table-wrap :deep(.table tbody td.row-actions) { grid-column:1/-1; display:grid; gap:6px; border-top:1px solid var(--border,#394452); }
  .vm-table-wrap :deep(.table tbody td.row-actions::before) { display:block; }
  .vm-table-wrap :deep(.table tbody td.row-actions .btn) { margin:0; }
  .vm-table-wrap :deep(.table tbody td.empty-row) { grid-column:1/-1; display:block; }
  .vm-table-wrap :deep(.table tbody td.empty-row::before) { content:none; }
}
@container vm-table (max-width: 380px) { .vm-table-wrap :deep(.table tbody tr) { grid-template-columns:minmax(0,1fr); }.vm-table-wrap :deep(.table tbody td:first-child),.vm-table-wrap :deep(.table tbody td.row-actions) { grid-column:1; } }
</style>
