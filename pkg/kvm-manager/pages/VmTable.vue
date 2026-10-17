<template>
  <div class="table-wrap">
    <table class="table">
      <thead><tr><th>{{ t('vm') }}</th><th>{{ t('state') }}</th><th>{{ t('ipAddresses') }}</th><th>vCPU</th><th>{{ t('memory') }}</th><th>{{ t('autostart') }}</th><th>{{ t('actions') }}</th></tr></thead>
      <tbody>
        <tr v-for="vm in vms" :key="vm.uuid || vm.name">
          <td><button class="vm-name" @click="$emit('details', vm)">{{ vm.name }}</button><small>{{ vm.uuid }}</small></td>
          <td><span class="state" :class="stateClass(vm.state)"><i></i>{{ vm.state }}</span></td>
          <td class="vm-addresses">{{ vm.ip_addresses?.join(', ') || '—' }}</td>
          <td>{{ vm.current_vcpus || vm.vcpus }}</td>
          <td>{{ (Number(vm.memory_kib || 0) / 1048576).toFixed(1) }} GiB</td>
          <td><button class="toggle-pill" :class="{ enabled: isAutostart(vm) }" :disabled="busy === vm.name" @click="$emit('autostart', vm)">{{ t(isAutostart(vm) ? 'enabled' : 'disabled') }}</button></td>
          <td class="row-actions">
            <button class="btn role-link btn-sm" @click="$emit('details', vm)">{{ t('details') }}</button>
            <button class="btn role-primary btn-sm vm-console-action" :aria-label="`${t('console')}: ${vm.name}`" :disabled="!isRunning(vm) || busy === vm.name" :title="!isRunning(vm) ? t('consoleRequiresRunning') : t('console')" @click="$emit('console', vm)">{{ t('console') }}</button>
            <button v-if="isRunning(vm) || isPaused(vm)" class="btn role-secondary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, isPaused(vm) ? 'resume' : 'pause')">{{ isPaused(vm) ? t('resume') : t('pause') }}</button>
            <button v-if="!isRunning(vm) && !isPaused(vm)" class="btn role-primary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, 'start')">{{ t('start') }}</button>
            <button v-else class="btn role-secondary btn-sm" :disabled="busy === vm.name" @click="$emit('action', vm, 'shutdown')">{{ t('shutdown') }}</button>
            <button class="btn role-link btn-sm" :disabled="busy === vm.name || !isRunning(vm)" @click="$emit('action', vm, 'reboot')">{{ t('restart') }}</button>
          </td>
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
  props: { vms: { type: Array as PropType<VmRow[]>, required: true }, busy: { type: String, default: '' } },
  emits: ['action', 'details', 'autostart', 'console'],
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
</style>
