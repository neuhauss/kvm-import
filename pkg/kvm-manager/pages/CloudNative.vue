<template>
  <div class="cloud-native-page">
    <div class="breadcrumbs"><button @click="backToHosts">KVM</button><span>›</span><button @click="backToHosts">{{ t('hosts.title') }}</button><span>›</span><strong>{{ host?.hostname || host?.name || t('cloudNative.title') }}</strong></div>
    <header class="page-header">
      <div class="title-block"><span class="eyebrow">{{ t('cloudNative.title') }}</span><h1>{{ host ? host.hostname || host.name : t('cloudNative.title') }}</h1><p class="muted">{{ t('cloudNative.subtitle') }}</p><small v-if="dataUpdatedAt" class="updated-at" :class="{ stale: !!error || dataIsStale }">{{ t(error ? 'cloudNative.updateFailedAt' : dataIsStale ? 'cloudNative.updateStaleAt' : 'cloudNative.lastUpdatedAt', { time: dateLabel(dataUpdatedAt) }) }}</small></div>
      <div v-if="host" class="toolbar">
        <span class="state" :class="host.status"><i></i>{{ statusLabel(host.status) }}</span>
        <span v-if="permissions.accessLevel" class="permission-badge">{{ t('cloudNative.accessLevelLabel', { level: t(`cloudNative.role_${permissions.accessLevel}`) }) }}</span>
        <form v-if="permissions.canAdministerHost" :action="cockpitUrl(host)" method="post" target="_blank"><button class="btn role-secondary" type="submit">{{ t('cloudNative.openCockpit') }}</button></form>
        <button class="btn role-primary" :disabled="loading" @click="load">{{ loading ? t('cloudNative.updating') : t('cloudNative.updateData') }}</button>
      </div>
    </header>

    <div v-if="error" class="banner error" role="alert">{{ error }}</div>
    <div v-if="busy" class="banner progress" role="status" aria-live="polite">{{ t('cloudNative.operationInProgress', { host: host?.hostname || host?.name || t('cloudNative.title') }) }}</div>
    <div v-if="loading && !inventory" class="loading">{{ t('cloudNative.queryHost') }}</div>
    <template v-else-if="inventory">
      <div class="cluster-summary">
        <article class="summary-card host-card"><div><span>{{ t('cloudNative.host') }}</span><strong>{{ inventory.system.hostname }}</strong><small>{{ inventory.system.os }} · {{ inventory.system.kernel }}</small></div><span class="state ready"><i></i>{{ t('cloudNative.connected') }}</span></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.vms') }}</span></div><strong class="metric">{{ inventory.vms.length }}</strong><small>{{ t('cloudNative.runningStopped', { running: runningVmCount, stopped: inventory.vms.length - runningVmCount }) }}</small><div class="metric-track"><i :style="{ width: vmRunningPercent + '%' }"></i></div></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.hostCpu') }}</span></div><strong class="metric">{{ inventory.system.cpu_count }} <small>{{ t('cloudNative.cores') }}</small></strong><small>Load average {{ inventory.system.load_average.map((n) => n.toFixed(2)).join(' · ') }}</small><div class="metric-track"><i :style="{ width: cpuLoadPercent + '%' }"></i></div></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.memory') }}</span></div><strong class="metric">{{ memoryLabel(inventory.system.memory_total_kib) }}</strong><small>{{ memoryLabel(inventory.system.memory_total_kib - inventory.system.memory_available_kib) }} {{ t('cloudNative.inUse') }}</small><div class="metric-track"><i :style="{ width: memoryUsedPercent + '%' }"></i></div></article>
      </div>
      <div class="health-summary" :class="{ 'health-warning': failedServiceCount || criticalFilesystemCount }">
        <span class="health-indicator" :class="failedServiceCount || criticalFilesystemCount ? 'warning' : 'healthy'"><i></i>{{ failedServiceCount || criticalFilesystemCount ? t('cloudNative.attentionRequired') : t('cloudNative.hostHealthy') }}</span>
        <span>{{ t('cloudNative.failedServicesShort', { count: failedServiceCount }) }}</span><span>{{ t('cloudNative.fullFilesystems', { count: criticalFilesystemCount }) }}</span>
      </div>

      <div class="admin-layout">
      <nav class="admin-tabs" :aria-label="t('cloudNative.adminAreas')">
        <section v-for="group in navGroups" :key="group.id" class="nav-group">
          <h2>{{ t(`cloudNative.group_${group.id}`) }}</h2>
          <button v-for="tab in availableTabs.filter((item) => item.group === group.id)" :key="tab.id" :class="{ active: activeTab === tab.id }" :aria-current="activeTab === tab.id ? 'page' : undefined" @click="selectTab(tab.id)"><span class="nav-icon" aria-hidden="true"><svg v-if="tab.id === 'services'" viewBox="0 0 24 24" fill="none"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/><path d="m19.4 15 .1.1a1.8 1.8 0 0 1-2.5 2.5l-.1-.1a1.8 1.8 0 0 0-3 .8v.2a1.8 1.8 0 0 1-3.6 0v-.2a1.8 1.8 0 0 0-3-.8l-.1.1a1.8 1.8 0 1 1-2.5-2.5l.1-.1a1.8 1.8 0 0 0-.8-3h-.2a1.8 1.8 0 0 1 0-3.6H4a1.8 1.8 0 0 0 .8-3l-.1-.1a1.8 1.8 0 1 1 2.5-2.5l.1.1a1.8 1.8 0 0 0 3-.8v-.2a1.8 1.8 0 0 1 3.6 0V2a1.8 1.8 0 0 0 3 .8l.1-.1a1.8 1.8 0 1 1 2.5 2.5l-.1.1a1.8 1.8 0 0 0 .8 3h.2a1.8 1.8 0 0 1 0 3.6H20a1.8 1.8 0 0 0-.6 3.1Z"/></svg><template v-else>{{ tab.icon }}</template></span><span>{{ t(`cloudNative.${tab.id}`) }}</span><span v-if="tab.countKey !== undefined" class="nav-count">{{ tabCount(tab.countKey) }}</span></button>
        </section>
      </nav>
      <main class="admin-content">
      <div v-if="inventory.errors.length" class="banner warning">{{ t('cloudNative.loadError') }}: {{ inventory.errors.join('; ') }}</div>
      <div v-if="actionError" class="banner error" role="alert">{{ actionError }}</div>
      <div v-else-if="actionSuccess" class="banner success" role="status">{{ t('cloudNative.actionSucceeded') }}</div>
      <section v-if="activeTab === 'overview'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">{{ t('cloudNative.systemSummary') }}</span><h2>{{ t('cloudNative.overview') }}</h2></div><span class="updated-at">{{ t('cloudNative.uptime') }} {{ uptimeLabel(inventory.system.uptime_seconds) }}</span></div>
        <div class="overview-grid">
          <article class="info-panel"><div class="panel-heading"><div><h3>{{ t('cloudNative.system') }}</h3><p>{{ t('cloudNative.hostIdentity') }}</p></div></div><dl><dt>{{ t('cloudNative.os') }}</dt><dd>{{ inventory.system.os }}</dd><dt>{{ t('cloudNative.kernel') }}</dt><dd>{{ inventory.system.kernel }}</dd><dt>{{ t('cloudNative.architecture') }}</dt><dd>{{ inventory.system.architecture }}</dd><dt>{{ t('cloudNative.uptime') }}</dt><dd>{{ uptimeLabel(inventory.system.uptime_seconds) }}</dd></dl></article>
          <article class="info-panel"><div class="panel-heading"><div><h3>{{ t('cloudNative.resources') }}</h3><p>{{ t('cloudNative.currentUsage') }}</p></div></div><div class="resource-row"><span>CPU</span><strong>{{ inventory.system.cpu_count }} {{ t('cloudNative.cores') }}</strong></div><div class="resource-row"><span>Load average</span><strong>{{ inventory.system.load_average.map((n) => n.toFixed(2)).join(' · ') }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.availableMemory') }}</span><strong>{{ memoryLabel(inventory.system.memory_available_kib) }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.devices') }}</span><strong>{{ inventory.storage.devices.length }}</strong></div></article>
        </div>
        <div class="section-heading vm-heading"><div><span class="eyebrow">LIBVIRT</span><h2>{{ t('cloudNative.vms') }}</h2></div><button class="text-button" @click="selectTab('vms')">{{ t('cloudNative.fullInventory') }}</button></div>
        <VmTable :vms="inventory.vms.slice(0, 5)" :busy="busy" :can-operate="permissions.canOperateVms" @action="actOnVm" @details="showVmDetails" @autostart="setAutostart" @console="openVmConsole" />
      </section>

      <section v-else-if="activeTab === 'vms'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">LIBVIRT</span><h2>{{ t('cloudNative.vms') }}</h2><p class="muted">{{ t('cloudNative.vmLifecycle') }}</p></div><div class="vm-list-toolbar"><div class="filter-bar"><input v-model="vmFilter" class="search-input" :placeholder="t('cloudNative.filterVms')" :aria-label="t('cloudNative.filterVms')" /><select v-model="vmStateFilter" class="search-input" :aria-label="t('cloudNative.filterVmState')"><option value="all">{{ t('cloudNative.allVmStates') }}</option><option value="running">{{ t('cloudNative.running') }}</option><option value="paused">{{ t('cloudNative.paused') }}</option><option value="stopped">{{ t('cloudNative.stopped') }}</option></select></div><button v-if="permissions.canOperateVms" class="btn role-primary" :disabled="busy !== ''" @click="openVmCreateForm">{{ t('cloudNative.createVm') }}</button></div></div>
        <form v-if="showVmCreateForm" class="admin-form guided-admin-form vm-create-form" @submit.prevent="createVm">
          <h3>{{ t('cloudNative.createVm') }}</h3><p class="muted">{{ t('cloudNative.createVmHelp') }}</p>
          <div class="admin-field-grid"><label>{{ t('cloudNative.vmName') }}<input v-model.trim="vmCreateForm.name" class="search-input" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*" autocomplete="off" /></label>
            <label>{{ t('cloudNative.vcpuCount') }}<input v-model.number="vmCreateForm.vcpus" class="search-input" type="number" min="1" max="512" step="1" required /></label><label>{{ t('cloudNative.memoryMiB') }}<input v-model.number="vmCreateForm.memory_mib" class="search-input" type="number" min="128" max="1048576" step="128" required /></label>
            <label>{{ t('cloudNative.storagePool') }}<select v-model="vmCreateForm.pool" class="search-input" required @change="vmCreateForm.volume = ''"><option disabled value="">{{ t('cloudNative.selectPool') }}</option><option v-for="pool in availableVmPools" :key="pool.name" :value="pool.name">{{ pool.name }}</option></select></label>
            <label>{{ t('cloudNative.bootDisk') }}<select v-model="vmCreateForm.volume" class="search-input" required><option disabled value="">{{ t('cloudNative.selectVolume') }}</option><option v-for="volume in availableVmCreateVolumes" :key="`${volume.pool}/${volume.name}`" :value="volume.name">{{ volume.name }} · {{ volume.format }} · {{ bytesLabel(volume.capacity_bytes) }}</option></select></label>
            <label>{{ t('cloudNative.virtualNetwork') }}<select v-model="vmCreateForm.network" class="search-input" required><option disabled value="">{{ t('cloudNative.selectNetwork') }}</option><option v-for="network in activeVmNetworks" :key="network.name" :value="network.name">{{ network.name }}</option></select></label>
            <label class="field-wide">{{ t('cloudNative.installerIsoPath') }}<input v-model.trim="vmCreateForm.iso_path" class="search-input" type="text" maxlength="1024" :placeholder="t('cloudNative.installerIsoOptional')" /><small>{{ t('cloudNative.installerIsoHelp') }}</small></label>
            <label class="vm-autostart-option"><input v-model="vmCreateForm.autostart" type="checkbox" />{{ t('cloudNative.enableAutostart') }}</label>
          </div>
          <div v-if="vmCreateError" class="banner error" role="alert">{{ vmCreateError }}</div>
          <div class="row-actions"><button type="button" class="btn role-secondary" @click="showVmCreateForm = false">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'vm-create' || !vmCreateForm.volume || !vmCreateForm.network">{{ busy === 'vm-create' ? t('cloudNative.creatingVm') : t('cloudNative.createVm') }}</button></div>
        </form>
        <div v-if="!filteredVms.length && !showVmCreateForm" class="empty-state">{{ t(vmFilter || vmStateFilter !== 'all' ? 'cloudNative.noVmMatch' : 'cloudNative.noVm') }}</div><VmTable v-else-if="filteredVms.length" :vms="filteredVms" :busy="busy" :can-operate="permissions.canOperateVms" @action="actOnVm" @details="showVmDetails" @autostart="setAutostart" @console="openVmConsole" />
      </section>

      <section v-else-if="activeTab === 'storage'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">HOST + LIBVIRT</span><h2>{{ t('cloudNative.storage') }}</h2><p class="muted">{{ t('cloudNative.storageDescription') }}</p></div><div class="section-tools"><input v-model="storageFilter" class="search-input" :placeholder="t('cloudNative.searchStorage')" :aria-label="t('cloudNative.searchStorage')" /><button v-if="permissions.canManageHostResources" class="btn role-primary" @click="showPoolForm = !showPoolForm">{{ t(showPoolForm ? 'cloudNative.cancel' : 'cloudNative.addPool') }}</button></div></div>
        <div class="storage-summary"><article><span>{{ t('cloudNative.storagePools') }}</span><strong>{{ inventory.storage_pools.length }}</strong></article><article><span>{{ t('cloudNative.devicesTitle') }}</span><strong>{{ inventory.storage.devices.length }}</strong></article><article><span>{{ t('cloudNative.mountedFilesystems') }}</span><strong>{{ inventory.storage.filesystems.length }}</strong><small v-if="criticalFilesystemCount">{{ t('cloudNative.fullFilesystems', { count: criticalFilesystemCount }) }}</small><small v-else>{{ t('cloudNative.noCapacityWarnings') }}</small></article></div>
        <form v-if="showPoolForm" class="admin-form guided-admin-form" @submit.prevent="savePool">
          <header class="form-intro"><span class="eyebrow">{{ t('cloudNative.storagePoolType') }}</span><h3>{{ t(poolForm.action === 'edit' ? 'cloudNative.editPool' : 'cloudNative.addPool') }}</h3><p>{{ t('cloudNative.storagePoolFormHelp') }}</p></header>
          <div class="admin-field-grid">
            <label class="field-wide">{{ t('cloudNative.poolName') }}<input v-model.trim="poolForm.name" class="search-input" required maxlength="128" pattern="[A-Za-z0-9_.+-]+" :readonly="poolForm.action === 'edit'" autocomplete="off" /><small>{{ t('cloudNative.poolNameHelp') }}</small></label>
            <label class="field-wide">{{ t('cloudNative.poolPath') }}<input v-model.trim="poolForm.target" class="search-input" required placeholder="/var/lib/libvirt/images" autocomplete="off" /><small>{{ t('cloudNative.poolPathHelp') }}</small></label>
          </div>
          <div class="row-actions"><button type="button" class="btn role-secondary" @click="showPoolForm = false">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'storage-pool'">{{ t('cloudNative.saveChanges') }}</button></div>
        </form>
        <div class="subsection"><div class="subsection-heading"><div><h3>{{ t('cloudNative.storagePools') }}</h3><p>{{ t('cloudNative.storagePoolHelp') }}</p></div><span class="count-badge">{{ filteredStoragePools.length }}</span></div><div v-if="!filteredStoragePools.length" class="empty-state">{{ t(storageFilter ? 'cloudNative.noStorageMatch' : 'cloudNative.noPool') }}</div><div v-else class="pool-grid"><article v-for="pool in filteredStoragePools" :key="pool.name" class="pool-card"><div><strong>{{ pool.name }}</strong><span class="state" :class="pool.state.toLowerCase()">{{ pool.state }}</span></div><dl><dt>{{ t('cloudNative.poolPath') }}</dt><dd>{{ pool.target || '—' }}</dd><dt>{{ t('cloudNative.capacity') }}</dt><dd>{{ pool.capacity }}</dd><dt>{{ t('cloudNative.allocated') }}</dt><dd>{{ pool.allocation }}</dd><dt>{{ t('cloudNative.available') }}</dt><dd>{{ pool.available }}</dd><dt>{{ t('cloudNative.autostart') }}</dt><dd>{{ pool.autostart }}</dd></dl><div class="resource-actions"><button class="btn role-link btn-sm" @click="inspectResource('pool', pool)">{{ t('cloudNative.details') }}</button><button v-if="permissions.canManageHostResources && pool.type === 'dir' && pool.state.toLowerCase() !== 'running'" class="btn role-secondary btn-sm" :disabled="busy === `storage:${pool.name}`" @click="editPool(pool)">{{ t('cloudNative.edit') }}</button><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === `storage:${pool.name}`" @click="actOnLibvirt('storage-pools', pool.name, pool.state.toLowerCase() === 'running' ? 'stop' : 'start')">{{ pool.state.toLowerCase() === 'running' ? t('cloudNative.stop') : t('cloudNative.start') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `storage:${pool.name}`" @click="actOnLibvirt('storage-pools', pool.name, pool.autostart === 'yes' ? 'disable' : 'enable')">{{ pool.autostart === 'yes' ? t('cloudNative.disableAutostart') : t('cloudNative.enableAutostart') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `storage:${pool.name}`" @click="deletePool(pool.name)">{{ t('cloudNative.delete') }}</button></div></article></div></div>
        <div class="subsection">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.storageVolumes') }}</h3><p>{{ t('cloudNative.storageVolumesHelp') }}</p></div><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" @click="showVolumeForm = !showVolumeForm">{{ t(showVolumeForm ? 'cloudNative.cancel' : 'cloudNative.createVolume') }}</button></div>
          <form v-if="showVolumeForm" class="admin-form" @submit.prevent="saveVolume"><label>{{ t('cloudNative.poolName') }}<select v-model="volumeForm.pool" class="search-input" required><option disabled value="">{{ t('cloudNative.selectPool') }}</option><option v-for="pool in inventory.storage_pools.filter((item) => item.type === 'dir' && item.state.toLowerCase() === 'running')" :key="pool.name" :value="pool.name">{{ pool.name }}</option></select></label><label>{{ t('cloudNative.volumeName') }}<input v-model.trim="volumeForm.name" class="search-input" required maxlength="128" pattern="[A-Za-z0-9_.+-]+" /></label><label>{{ t('cloudNative.capacityGiB') }}<input v-model.number="volumeForm.capacity_gib" class="search-input" type="number" min="0.001" max="10240" step="0.001" required /></label><label>{{ t('cloudNative.volumeFormat') }}<select v-model="volumeForm.format" class="search-input"><option value="qcow2">qcow2</option><option value="raw">raw</option></select></label><div class="row-actions"><button type="button" class="btn role-secondary" @click="showVolumeForm = false">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'storage-volume' || !volumeForm.pool">{{ t('cloudNative.createVolume') }}</button></div></form>
          <div v-if="volumesLoading" class="loading">{{ t('cloudNative.loadingVolumes') }}</div><div v-else-if="!storageVolumes.length" class="empty-state">{{ t('cloudNative.noVolumes') }}</div><div v-else class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.volumeName') }}</th><th>{{ t('cloudNative.poolName') }}</th><th>{{ t('cloudNative.volumeFormat') }}</th><th>{{ t('cloudNative.capacity') }}</th><th>{{ t('cloudNative.allocated') }}</th><th>{{ t('cloudNative.actions') }}</th></tr></thead><tbody><tr v-for="volume in storageVolumes" :key="`${volume.pool}/${volume.name}`"><td><strong>{{ volume.name }}</strong><small>{{ volume.path }}</small></td><td>{{ volume.pool }}</td><td>{{ volume.format }}</td><td>{{ bytesLabel(volume.capacity_bytes) }}</td><td>{{ bytesLabel(volume.allocation_bytes) }}</td><td><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm danger-text" :disabled="busy === 'storage-volume'" @click="deleteVolume(volume)">{{ t('cloudNative.delete') }}</button></td></tr></tbody></table></div>
        </div>
        <div class="subsection"><div class="subsection-heading"><div><h3>{{ t('cloudNative.devicesTitle') }}</h3><p>{{ t('cloudNative.storageDevicesHelp') }}</p></div><span class="count-badge">{{ filteredStorageDevices.length }}</span></div><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.devices') }}</th><th>{{ t('cloudNative.type') }}</th><th>{{ t('cloudNative.size') }}</th><th>{{ t('cloudNative.filesystem') }}</th><th>{{ t('cloudNative.mount') }}</th><th>{{ t('cloudNative.model') }}</th></tr></thead><tbody><tr v-for="disk in filteredStorageDevices" :key="disk.path || disk.name"><td><button class="resource-name" @click="inspectResource('disk', disk)">{{ disk.name }}</button><small>{{ disk.path }}</small></td><td>{{ disk.type }}</td><td>{{ bytesLabel(disk.size) }}</td><td>{{ disk.filesystem || '—' }}</td><td>{{ disk.mountpoints.join(', ') || '—' }}</td><td>{{ disk.model || '—' }}</td></tr><tr v-if="!filteredStorageDevices.length"><td colspan="6" class="empty-row">{{ t(storageFilter ? 'cloudNative.noStorageMatch' : 'cloudNative.noDevice') }}</td></tr></tbody></table></div></div>
        <div class="subsection"><div class="subsection-heading"><div><h3>{{ t('cloudNative.mountedFilesystems') }}</h3><p>{{ t('cloudNative.filesystemUsageHelp') }}</p></div><span class="count-badge">{{ filteredFilesystems.length }}</span></div><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.device') }}</th><th>{{ t('cloudNative.type') }}</th><th>{{ t('cloudNative.size') }}</th><th>{{ t('cloudNative.used') }}</th><th>{{ t('cloudNative.available') }}</th><th>{{ t('cloudNative.usage') }}</th><th>{{ t('cloudNative.mount') }}</th></tr></thead><tbody><tr v-for="fs in filteredFilesystems" :key="`${fs.device}-${fs.mountpoint}`"><td><button class="resource-name" @click="inspectResource('filesystem', fs)">{{ fs.device }}</button></td><td>{{ fs.type }}</td><td>{{ bytesLabel(fs.size) }}</td><td>{{ bytesLabel(fs.used) }}</td><td>{{ bytesLabel(fs.available) }}</td><td><div class="usage-cell"><span class="usage-pill" :class="usageClass(fs.use_percent)">{{ fs.use_percent }}</span><span class="usage-track"><i :class="usageClass(fs.use_percent)" :style="{ width: usagePercent(fs.use_percent) + '%' }"></i></span></div></td><td>{{ fs.mountpoint }}</td></tr></tbody></table></div></div>
      </section>

      <section v-else-if="activeTab === 'network'" class="section-panel network-page">
        <div class="section-heading">
          <div><span class="eyebrow">HOST + LIBVIRT</span><h2>{{ t('cloudNative.network') }}</h2><p class="muted">{{ t('cloudNative.networkEditable') }}</p></div>
          <div class="filter-bar">
            <input v-model="networkFilter" class="search-input" :placeholder="t('cloudNative.searchNetworkItems')" :aria-label="t('cloudNative.searchNetworkItems')" />
            <select v-model="networkStateFilter" class="search-input" :aria-label="t('cloudNative.filterState')"><option value="all">{{ t('cloudNative.allNetworkItems') }}</option><option value="active">{{ t('cloudNative.active') }}</option><option value="inactive">{{ t('cloudNative.inactive') }}</option></select>
          </div>
        </div>
        <div class="network-summary">
          <article class="network-stat"><span>{{ t('cloudNative.interfaces') }}</span><strong>{{ inventory.network.interfaces.length }}</strong><small>{{ t('cloudNative.activeInterfaces', { count: activeInterfaceCount }) }}</small></article>
          <article class="network-stat"><span>{{ t('cloudNative.networkConnections') }}</span><strong>{{ inventory.network_connections.length }}</strong><small>{{ t('cloudNative.activeConnections', { count: activeConnectionCount }) }}</small></article>
          <article class="network-stat"><span>{{ t('cloudNative.virtualNetworks') }}</span><strong>{{ inventory.libvirt_networks.length }}</strong><small>{{ t('cloudNative.activeVirtualNetworks', { count: activeLibvirtNetworkCount }) }}</small></article>
        </div>

        <section class="subsection">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.interfaces') }}</h3><p>{{ t('cloudNative.interfaceDetails') }}</p></div><span class="count-badge">{{ filteredNetworkInterfaces.length }}</span></div>
          <div v-if="!filteredNetworkInterfaces.length" class="empty-state">{{ t(networkFilter ? 'cloudNative.noNetworkMatch' : 'cloudNative.noInterface') }}</div>
          <div v-else class="network-grid">
            <article v-for="nic in filteredNetworkInterfaces" :key="nic.ifname" class="network-card interface-card">
              <div class="network-card-heading"><div class="network-identity"><span class="network-symbol" aria-hidden="true">↔</span><div><strong>{{ nic.ifname }}</strong><small>{{ nic.link_type || t('cloudNative.interface') }}</small></div></div><span class="state" :class="nic.operstate === 'UP' ? 'ready' : 'unknown'"><i></i>{{ nic.operstate || '—' }}</span></div>
              <div class="network-addresses"><span class="detail-label">{{ t('cloudNative.addresses') }}</span><strong v-if="addresses(nic)">{{ addresses(nic) }}</strong><span v-else class="muted">{{ t('cloudNative.noIpAddresses') }}</span></div>
              <div class="network-meta"><span><small>{{ t('cloudNative.mac') }}</small><b>{{ nic.address || '—' }}</b></span><span><small>MTU</small><b>{{ nic.mtu || '—' }}</b></span></div><div class="connection-actions"><button class="btn role-link btn-sm" @click="inspectResource('interface', nic)">{{ t('cloudNative.details') }}</button></div>
            </article>
          </div>
        </section>

        <section class="subsection">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.networkConnections') }}</h3><p>{{ t('cloudNative.networkConnectionDetails') }}</p></div><span class="count-badge">{{ filteredNetworkConnections.length }}</span></div>
          <div v-if="networkForm" class="network-editor-wrap">
            <form class="admin-form network-editor" @submit.prevent="saveNetwork">
              <div class="editor-heading"><div><span class="eyebrow">{{ t('cloudNative.ipv4Configuration') }}</span><h4>{{ networkForm.name }}</h4></div><button type="button" class="text-button" @click="networkForm = null">{{ t('cloudNative.cancel') }}</button></div>
              <label>{{ t('cloudNative.ipMethod') }}<select v-model="networkForm.method" class="search-input"><option value="auto">DHCP</option><option value="manual">{{ t('cloudNative.manual') }}</option><option value="shared">{{ t('cloudNative.shared') }}</option><option value="link-local">{{ t('cloudNative.linkLocal') }}</option><option value="disabled">{{ t('cloudNative.disabled') }}</option></select></label>
              <label>{{ t('cloudNative.addresses') }}<input v-model="networkForm.addresses" class="search-input" :disabled="networkForm.method === 'auto'" :required="networkForm.method === 'manual'" placeholder="192.0.2.10/24" /></label>
              <label>{{ t('cloudNative.gateway') }}<input v-model="networkForm.gateway" class="search-input" :disabled="networkForm.method === 'auto'" placeholder="192.0.2.1" /></label>
              <label>{{ t('cloudNative.dnsServers') }}<input v-model="networkForm.dns" class="search-input" :disabled="networkForm.method === 'auto'" placeholder="1.1.1.1, 8.8.8.8" /></label>
              <div class="field-wide network-family-heading"><span class="eyebrow">{{ t('cloudNative.ipv6Configuration') }}</span></div><label>{{ t('cloudNative.ipv6Method') }}<select v-model="networkForm.ipv6_method" class="search-input"><option value="auto">{{ t('cloudNative.automatic') }}</option><option value="manual">{{ t('cloudNative.manual') }}</option><option value="disabled">{{ t('cloudNative.disabled') }}</option></select></label>
              <label>{{ t('cloudNative.addresses') }} (IPv6)<input v-model="networkForm.ipv6_addresses" class="search-input" :disabled="networkForm.ipv6_method !== 'manual'" :required="networkForm.ipv6_method === 'manual'" placeholder="2001:db8::10/64" /></label><label>{{ t('cloudNative.gateway') }} (IPv6)<input v-model="networkForm.ipv6_gateway" class="search-input" :disabled="networkForm.ipv6_method !== 'manual'" placeholder="2001:db8::1" /></label><label>{{ t('cloudNative.dnsServers') }} (IPv6)<input v-model="networkForm.ipv6_dns" class="search-input" :disabled="networkForm.ipv6_method === 'disabled'" placeholder="2001:4860:4860::8888" /></label>
              <label class="vm-autostart-option field-wide"><input v-model="networkForm.autoconnect" type="checkbox" />{{ t('cloudNative.autoconnect') }}</label>
              <div class="network-editor-footer"><p class="safety-note">{{ t('cloudNative.networkWarning') }}</p><button class="btn role-primary" :disabled="busy === `connection:${networkForm.uuid}`">{{ t('cloudNative.saveChanges') }}</button></div>
            </form>
          </div>
          <div v-if="!filteredNetworkConnections.length" class="empty-state">{{ t(networkFilter ? 'cloudNative.noNetworkMatch' : 'cloudNative.noConnection') }}</div>
          <div v-else class="connection-list">
            <article v-for="connection in filteredNetworkConnections" :key="connection.uuid" class="connection-card">
              <div class="connection-main"><div class="network-identity"><span class="network-symbol" aria-hidden="true">⌁</span><div><strong>{{ connection.name }}</strong><small>{{ connection.type }}<template v-if="connection.device"> · {{ connection.device }}</template></small></div></div><span class="state" :class="connection.active ? 'ready' : 'unknown'"><i></i>{{ connection.active ? t('cloudNative.active') : t('cloudNative.inactive') }}</span></div>
              <div class="connection-details"><span><small>{{ t('cloudNative.ipMethod') }}</small><b>{{ ipv4MethodLabel(connection.ipv4_method) }}</b></span><span><small>{{ t('cloudNative.addresses') }}</small><b>{{ connection.ipv4_addresses.join(', ') || '—' }}</b></span><span><small>{{ t('cloudNative.gateway') }}</small><b>{{ connection.ipv4_gateway || '—' }}</b></span><span><small>{{ t('cloudNative.dnsServers') }}</small><b>{{ connection.ipv4_dns.join(', ') || '—' }}</b></span><span><small>IPv6</small><b>{{ connection.ipv6_method }} · {{ connection.ipv6_addresses.join(', ') || '—' }}</b></span><span><small>{{ t('cloudNative.autoconnect') }}</small><b>{{ connection.autoconnect ? t('cloudNative.enabled') : t('cloudNative.disabled') }}</b></span></div>
              <div class="connection-actions"><button class="btn role-link btn-sm" @click="inspectResource('connection', connection)">{{ t('cloudNative.details') }}</button><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === `connection:${connection.uuid}`" @click="editNetwork(connection)">{{ t('cloudNative.edit') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `connection:${connection.uuid}`" @click="actOnConnection(connection)">{{ connection.active ? t('cloudNative.deactivate') : t('cloudNative.activate') }}</button></div>
            </article>
          </div>
        </section>

        <section class="subsection">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.virtualNetworks') }}</h3><p>{{ t('cloudNative.libvirtNetworkDetails') }}</p></div><div class="row-actions"><span class="count-badge">{{ filteredLibvirtNetworks.length }}</span><button v-if="permissions.canManageHostResources" class="btn role-primary btn-sm" @click="openLibvirtNetworkForm()">{{ t('cloudNative.createVirtualNetwork') }}</button></div></div>
          <form v-if="libvirtNetworkForm" class="admin-form libvirt-network-form" @submit.prevent="saveLibvirtNetwork">
            <div class="editor-heading"><div><span class="eyebrow">LIBVIRT</span><h4>{{ t(libvirtNetworkForm.action === 'create' ? 'cloudNative.createVirtualNetwork' : 'cloudNative.editVirtualNetwork') }}<template v-if="libvirtNetworkForm.action === 'edit'"> · {{ libvirtNetworkForm.name }}</template></h4><p class="muted">{{ t('cloudNative.virtualNetworkFormHelp') }}</p></div><button type="button" class="text-button" @click="libvirtNetworkForm = null">{{ t('cloudNative.cancel') }}</button></div>
            <div class="admin-field-grid"><label>{{ t('cloudNative.networkName') }}<input v-model.trim="libvirtNetworkForm.name" class="search-input" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*" :disabled="libvirtNetworkForm.action === 'edit'" /></label>
              <label>{{ t('cloudNative.forwardMode') }}<select v-model="libvirtNetworkForm.forward_mode" class="search-input"><option value="nat">NAT</option><option value="route">{{ t('cloudNative.routeMode') }}</option><option value="bridge">{{ t('cloudNative.bridgeMode') }}</option><option value="none">{{ t('cloudNative.isolatedMode') }}</option></select></label>
              <label v-if="libvirtNetworkForm.forward_mode === 'bridge'">{{ t('cloudNative.hostBridge') }}<input v-model.trim="libvirtNetworkForm.bridge" class="search-input" maxlength="15" pattern="[A-Za-z0-9_.-]+" required placeholder="br0" /></label>
              <label v-if="libvirtNetworkForm.forward_mode !== 'bridge'" class="field-wide">{{ t('cloudNative.virtualNetworkGateway') }}<input v-model.trim="libvirtNetworkForm.ipv4_address" class="search-input" placeholder="192.168.100.1/24" /></label>
              <label v-if="libvirtNetworkForm.forward_mode !== 'bridge'">{{ t('cloudNative.dhcpStart') }}<input v-model.trim="libvirtNetworkForm.dhcp_start" class="search-input" placeholder="192.168.100.100" /></label><label v-if="libvirtNetworkForm.forward_mode !== 'bridge'">{{ t('cloudNative.dhcpEnd') }}<input v-model.trim="libvirtNetworkForm.dhcp_end" class="search-input" placeholder="192.168.100.200" /></label>
              <label v-if="libvirtNetworkForm.action === 'create'" class="vm-autostart-option"><input v-model="libvirtNetworkForm.start_after_create" type="checkbox" />{{ t('cloudNative.startAfterCreate') }}</label><label class="vm-autostart-option"><input v-model="libvirtNetworkForm.autostart" type="checkbox" />{{ t('cloudNative.enableAutostart') }}</label>
            </div><p class="safety-note">{{ t('cloudNative.libvirtNetworkWarning') }}</p><div class="row-actions"><button type="button" class="btn role-secondary" @click="libvirtNetworkForm = null">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'libvirt-network' || !libvirtNetworkForm.name">{{ t('cloudNative.saveChanges') }}</button></div>
          </form>
          <div v-if="!filteredLibvirtNetworks.length" class="empty-state">{{ t(networkFilter ? 'cloudNative.noNetworkMatch' : 'cloudNative.noNetwork') }}</div>
          <div v-else class="network-grid">
            <article v-for="network in filteredLibvirtNetworks" :key="network.name" class="network-card libvirt-network-card">
              <div class="network-card-heading"><div class="network-identity"><span class="network-symbol" aria-hidden="true">⌘</span><div><strong>{{ network.name }}</strong><small>{{ network.persistent === 'yes' ? t('cloudNative.persistent') : t('cloudNative.temporary') }}</small></div></div><span class="state" :class="network.state === 'active' ? 'ready' : 'unknown'"><i></i>{{ network.state }}</span></div>
              <div class="network-meta"><span><small>{{ t('cloudNative.forwardMode') }}</small><b>{{ network.forward_mode }}</b></span><span v-if="network.bridge"><small>{{ t('cloudNative.hostBridge') }}</small><b>{{ network.bridge }}</b></span><span v-if="network.ipv4_address"><small>{{ t('cloudNative.virtualNetworkGateway') }}</small><b>{{ network.ipv4_address }}/{{ network.ipv4_netmask }}</b></span><span v-if="network.dhcp_start"><small>DHCP</small><b>{{ network.dhcp_start }} – {{ network.dhcp_end }}</b></span><span><small>{{ t('cloudNative.autostart') }}</small><b>{{ network.autostart === 'yes' ? t('cloudNative.enabled') : t('cloudNative.disabled') }}</b></span><span><small>{{ t('cloudNative.persistence') }}</small><b>{{ network.persistent === 'yes' ? t('cloudNative.persistent') : t('cloudNative.temporary') }}</b></span></div>
              <div class="connection-actions"><button class="btn role-link btn-sm" @click="inspectResource('libvirtNetwork', network)">{{ t('cloudNative.details') }}</button><button v-if="permissions.canManageHostResources && network.state !== 'active' && ['nat', 'route', 'bridge', 'none'].includes(network.forward_mode)" class="btn role-secondary btn-sm" :disabled="busy === `network:${network.name}`" @click="openLibvirtNetworkForm(network)">{{ t('cloudNative.edit') }}</button><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === `network:${network.name}`" @click="actOnLibvirt('networks', network.name, network.state === 'active' ? 'stop' : 'start')">{{ network.state === 'active' ? t('cloudNative.stop') : t('cloudNative.start') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `network:${network.name}`" @click="actOnLibvirt('networks', network.name, network.autostart === 'yes' ? 'disable' : 'enable')">{{ network.autostart === 'yes' ? t('cloudNative.disableAutostart') : t('cloudNative.enableAutostart') }}</button><button v-if="permissions.canManageHostResources && network.state !== 'active'" class="btn role-link btn-sm danger-text" :disabled="busy === `network:${network.name}`" @click="deleteLibvirtNetwork(network.name)">{{ t('cloudNative.delete') }}</button></div>
            </article>
          </div>
        </section>

        <section class="subsection routes-section">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.routes') }}</h3><p>{{ t('cloudNative.routeDetails') }}</p></div><span class="count-badge">{{ inventory.network.routes.length }}</span></div>
          <div v-if="primaryRoute" class="gateway-card"><span class="gateway-icon" aria-hidden="true">↗</span><div><small>{{ t('cloudNative.defaultGateway') }}</small><strong>{{ primaryRoute.gateway || '—' }}</strong></div><div><small>{{ t('cloudNative.interface') }}</small><strong>{{ primaryRoute.dev || '—' }}</strong></div><div><small>{{ t('cloudNative.destination') }}</small><strong>{{ primaryRoute.dst || 'default' }}</strong></div></div>
          <p v-else class="empty-state">{{ t('cloudNative.noDefaultGateway') }}</p>
          <div v-if="otherRoutes.length" class="table-wrap routes-table"><table class="table"><thead><tr><th>{{ t('cloudNative.destination') }}</th><th>{{ t('cloudNative.gateway') }}</th><th>{{ t('cloudNative.interface') }}</th><th>{{ t('cloudNative.protocol') }}</th></tr></thead><tbody><tr v-for="(route, index) in otherRoutes" :key="`${route.dst}-${route.dev}-${index}`"><td><strong>{{ route.dst || '—' }}</strong></td><td>{{ route.gateway || '—' }}</td><td>{{ route.dev || '—' }}</td><td>{{ route.protocol || '—' }}</td></tr></tbody></table></div>
        </section>
      </section>
      <section v-else-if="activeTab === 'services'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SYSTEMD</span><h2>{{ t('cloudNative.systemServices') }}</h2><p class="muted">{{ t('cloudNative.failedServices', { count: failedServiceCount }) }}</p></div><div class="filter-bar"><input v-model="serviceFilter" class="search-input" :placeholder="t('cloudNative.searchService')" :aria-label="t('cloudNative.searchService')" /><select v-model="serviceStateFilter" class="search-input" :aria-label="t('cloudNative.filterState')"><option value="all">{{ t('cloudNative.allStates') }}</option><option value="active">{{ t('cloudNative.active') }}</option><option value="failed">{{ t('cloudNative.failed') }}</option><option value="inactive">{{ t('cloudNative.inactive') }}</option></select></div></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.service') }}</th><th>{{ t('cloudNative.state') }}</th><th>{{ t('cloudNative.substate') }}</th><th>{{ t('cloudNative.description') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="service in visibleServices" :key="service.name"><td><button class="resource-name" @click="inspectResource('service', service)">{{ service.name }}</button></td><td><span class="state" :class="service.active === 'active' ? 'ready' : service.active === 'failed' ? 'unreachable' : 'unknown'">{{ t(`cloudNative.${service.active}`) }}</span></td><td>{{ service.sub }}</td><td class="description-cell">{{ service.description }}</td><td class="row-actions"><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === service.name || service.active === 'active'" @click="actOnService(service, 'start')">{{ t('cloudNative.start') }}</button><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === service.name || service.active !== 'active'" @click="actOnService(service, 'restart')">{{ t('cloudNative.restart') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === service.name || service.active !== 'active'" @click="actOnService(service, 'stop')">{{ t('cloudNative.stop') }}</button></td></tr><tr v-if="!filteredServices.length"><td colspan="5" class="empty-row">{{ t('cloudNative.noServiceMatch') }}</td></tr></tbody></table></div><div v-if="filteredServices.length" class="pagination-row"><span>{{ t('cloudNative.showingServices', { shown: visibleServices.length, total: filteredServices.length }) }}</span><button v-if="visibleServices.length < filteredServices.length" class="btn role-secondary btn-sm" @click="showMoreServices">{{ t('cloudNative.showMore') }}</button></div><p class="safety-note">{{ t('cloudNative.serviceWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'accounts'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SYSTEM USERS</span><h2>{{ t('cloudNative.accounts') }}</h2><p class="muted">{{ t('cloudNative.accountsDescription') }}</p></div><div class="section-tools"><input v-model="accountFilter" class="search-input" :placeholder="t('cloudNative.searchAccounts')" :aria-label="t('cloudNative.searchAccounts')" /><button v-if="permissions.canManageHostResources" class="btn role-primary" @click="openAccountForm()">{{ t('cloudNative.addAccount') }}</button></div></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.account') }}</th><th>UID / GID</th><th>{{ t('cloudNative.homeDirectory') }}</th><th>{{ t('cloudNative.shell') }}</th><th>{{ t('cloudNative.groups') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="account in filteredAccounts" :key="account.username"><td><button class="resource-name" @click="inspectResource('account', account)">{{ account.username }}</button><small>{{ account.locked ? t('cloudNative.locked') : t('cloudNative.unlocked') }}</small></td><td>{{ account.uid }} / {{ account.gid }}</td><td>{{ account.home }}</td><td>{{ account.shell }}</td><td>{{ account.groups.join(', ') || '—' }}</td><td class="row-actions"><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === `account:${account.username}` || (!account.locked && (account.username === host.username || account.uid === 0))" @click="actOnAccount(account, account.locked ? 'unlock' : 'lock')">{{ account.locked ? t('cloudNative.unlock') : t('cloudNative.lock') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `account:${account.username}`" @click="openAccountForm(account)">{{ t('cloudNative.edit') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `account:${account.username}` || account.username === host.username || account.uid === 0" @click="actOnAccount(account, 'delete')">{{ t('cloudNative.delete') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === `account:${account.username}`" @click="accountPasswordTarget = account.username; accountPassword = ''">{{ t('cloudNative.setPassword') }}</button></td></tr><tr v-if="!filteredAccounts.length"><td colspan="6" class="empty-row">{{ t(accountFilter ? 'cloudNative.noAccountMatch' : 'cloudNative.noAccounts') }}</td></tr></tbody></table></div><p class="safety-note">{{ t('cloudNative.accountsWarning') }}</p>
        <form v-if="accountForm" class="admin-form guided-admin-form" @submit.prevent="saveAccount">
          <header class="form-intro"><span class="eyebrow">{{ t('cloudNative.accountSettings') }}</span><h3>{{ t(accountForm.action === 'create' ? 'cloudNative.addAccount' : 'cloudNative.editAccount') }}</h3><p>{{ t('cloudNative.accountFormHelp') }}</p></header>
          <div class="admin-field-grid">
            <label class="field-wide">{{ t('cloudNative.account') }}<input v-model.trim="accountForm.username" class="search-input" :readonly="accountForm.action === 'edit'" required maxlength="32" pattern="[a-z_][a-z0-9_-]{0,31}" autocomplete="off" /><small>{{ t('cloudNative.accountNameHelp') }}</small></label>
            <label>{{ t('cloudNative.shell') }}<input v-model.trim="accountForm.shell" class="search-input" placeholder="/bin/bash" autocomplete="off" /><small>{{ t('cloudNative.shellHelp') }}</small></label>
            <label>{{ t('cloudNative.homeDirectory') }}<input v-model.trim="accountForm.home" class="search-input" placeholder="/home/username" autocomplete="off" /><small>{{ t('cloudNative.homeHelp') }}</small></label>
            <label class="field-wide">{{ t('cloudNative.groups') }}<input v-model.trim="accountForm.groups" class="search-input" placeholder="users, libvirt" autocomplete="off" /><small>{{ t('cloudNative.groupsEditHelp') }}</small></label>
            <label v-if="accountForm.action === 'create'" class="field-wide">{{ t('cloudNative.newPassword') }}<input v-model="accountForm.password" class="search-input" type="password" minlength="8" maxlength="1024" autocomplete="new-password" required /><small>{{ t('cloudNative.passwordPolicyHelp') }}</small></label>
          </div>
          <p class="safety-note">{{ t('cloudNative.accountFormWarning') }}</p>
          <div class="row-actions"><button type="button" class="btn role-secondary" @click="accountForm = null">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === `account:${accountForm.username}`">{{ t('cloudNative.saveChanges') }}</button></div>
        </form>
      </section>

      <section v-else-if="activeTab === 'repositories'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">ZYPPER</span><h2>{{ t('cloudNative.repositories') }}</h2><p class="muted">{{ t('cloudNative.repositoriesDescription') }}</p></div><div class="section-tools"><input v-model="repositoryFilter" class="search-input" :placeholder="t('cloudNative.searchRepositories')" :aria-label="t('cloudNative.searchRepositories')" /><div class="row-actions"><button v-if="permissions.canManageHostResources" class="btn role-secondary" :disabled="busy === 'repositories'" @click="actOnRepository('*', 'refresh')">{{ busy === 'repositories' ? t('cloudNative.updating') : t('cloudNative.refreshRepositories') }}</button><button v-if="permissions.canManageHostResources" class="btn role-primary" @click="showRepositoryForm = !showRepositoryForm">{{ t(showRepositoryForm ? 'cloudNative.cancel' : 'cloudNative.addRepository') }}</button></div></div></div>
        <form v-if="showRepositoryForm" class="admin-form" @submit.prevent="saveRepository"><h3>{{ t('cloudNative.addRepository') }}</h3><label>{{ t('cloudNative.alias') }}<input v-model="repositoryForm.alias" class="search-input" required pattern="[A-Za-z0-9_.:-]+" /></label><label>{{ t('cloudNative.repository') }}<input v-model="repositoryForm.name" class="search-input" required maxlength="256" /></label><label>{{ t('cloudNative.uri') }}<input v-model="repositoryForm.uri" class="search-input" required type="url" /></label><button class="btn role-primary" :disabled="busy === 'repositories'">{{ t('cloudNative.saveChanges') }}</button></form>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.repository') }}</th><th>{{ t('cloudNative.alias') }}</th><th>{{ t('cloudNative.status') }}</th><th>{{ t('cloudNative.uri') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="repo in filteredRepositories" :key="repo.alias"><td><button class="resource-name" @click="inspectResource('repository', repo)">{{ repo.name }}</button></td><td>{{ repo.alias }}</td><td><span class="state" :class="repo.enabled ? 'ready' : 'unknown'">{{ repo.enabled ? t('cloudNative.enabled') : t('cloudNative.disabled') }}</span></td><td class="description-cell">{{ repo.uri || '—' }}</td><td class="row-actions"><button v-if="permissions.canManageHostResources" class="btn role-secondary btn-sm" :disabled="busy === repo.alias" @click="actOnRepository(repo.alias, repo.enabled ? 'disable' : 'enable')">{{ repo.enabled ? t('cloudNative.disable') : t('cloudNative.enable') }}</button><button v-if="permissions.canManageHostResources" class="btn role-link btn-sm" :disabled="busy === repo.alias" @click="actOnRepository(repo.alias, 'remove')">{{ t('cloudNative.delete') }}</button></td></tr><tr v-if="!filteredRepositories.length"><td colspan="5" class="empty-row">{{ t(repositoryFilter ? 'cloudNative.noRepositoryMatch' : 'cloudNative.noRepositories') }}</td></tr></tbody></table></div><p class="safety-note">{{ t('cloudNative.repositoryWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'selinux'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SECURITY</span><h2>{{ t('cloudNative.selinux') }}</h2><p class="muted">{{ t('cloudNative.selinuxDescription') }}</p></div></div>
        <article class="info-panel security-panel"><h3>{{ t('cloudNative.selinuxStatus') }}</h3><div class="resource-row"><span>{{ t('cloudNative.selinuxMode') }}</span><strong>{{ inventory.selinux.mode }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.selinuxPolicy') }}</span><strong>{{ inventory.selinux.policy || '—' }}</strong></div><div class="resource-row"><span>AppArmor</span><strong>{{ inventory.selinux.apparmor }}</strong></div><div v-if="inventory.selinux.available && permissions.canManageHostResources" class="row-actions security-actions"><button class="btn role-secondary btn-sm" :disabled="busy === 'selinux' || inventory.selinux.mode === 'enforcing'" @click="setSecurityMode('enforcing')">{{ t('cloudNative.setEnforcing') }}</button><button class="btn role-secondary btn-sm" :disabled="busy === 'selinux' || inventory.selinux.mode === 'permissive'" @click="setSecurityMode('permissive')">{{ t('cloudNative.setPermissive') }}</button></div><p v-else-if="!inventory.selinux.available" class="safety-note">{{ t('cloudNative.selinuxUnavailable') }}</p></article>
      </section>

      <section v-else-if="activeTab === 'subscriptions'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SUSECONNECT</span><h2>{{ t('cloudNative.subscriptions') }}</h2><p class="muted">{{ t('cloudNative.subscriptionsDescription') }}</p></div><button class="btn role-secondary" :disabled="loading || extensionsLoading" @click="refreshSubscriptions">{{ t('cloudNative.refreshStatus') }}</button></div>
        <article class="info-panel subscription-card">
          <div class="resource-row"><span>{{ t('cloudNative.client') }}</span><strong>{{ inventory.subscription.available ? 'SUSEConnect' : t('cloudNative.notInstalled') }}</strong></div>
          <div class="subscription-status-row"><h3>{{ t('cloudNative.registrationStatus') }}</h3><span class="state" :class="subscriptionRegistered ? 'ready' : 'unknown'"><i></i>{{ t(subscriptionRegistered ? 'cloudNative.registered' : 'cloudNative.notRegistered') }}</span></div>
          <pre class="status-view">{{ inventory.subscription.status || t('cloudNative.noSubscriptionData') }}</pre>
          <div v-if="permissions.canManageHostResources && inventory.subscription.available" class="row-actions"><button class="btn role-primary" @click="showSubscriptionForm = !showSubscriptionForm">{{ t(subscriptionRegistered ? 'cloudNative.changeSubscription' : 'cloudNative.registerSubscription') }}</button><button v-if="subscriptionRegistered" class="btn role-link" @click="deregisterSubscription">{{ t('cloudNative.deregisterSubscription') }}</button></div>
          <form v-if="showSubscriptionForm" class="admin-form" @submit.prevent="registerSubscription"><h3>{{ t('cloudNative.subscriptionFormTitle') }}</h3><p class="muted">{{ t(subscriptionRegistered ? 'cloudNative.changeSubscriptionHelp' : 'cloudNative.subscriptionFormHelp') }}</p><label>{{ t('cloudNative.registrationEmail') }}<input v-model="subscriptionForm.email" class="search-input" type="email" autocomplete="email" required /></label><label>{{ t('cloudNative.registrationCode') }}<input v-model="subscriptionForm.regcode" class="search-input" type="password" autocomplete="off" required maxlength="256" /></label><p class="safety-note">{{ t('cloudNative.registrationCodeHelp') }}</p><div class="row-actions"><button type="button" class="btn role-secondary" @click="showSubscriptionForm = false">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'subscription'">{{ t(subscriptionRegistered ? 'cloudNative.changeSubscription' : 'cloudNative.registerSubscription') }}</button></div></form>
        </article><p class="safety-note">{{ t('cloudNative.subscriptionWarning') }}</p>
        <section v-if="inventory.subscription.available" class="subsection extension-manager">
          <div class="subsection-heading"><div><h3>{{ t('cloudNative.extensionsTitle') }}</h3><p>{{ t('cloudNative.extensionsDescription') }}</p></div><button class="btn role-secondary btn-sm" :disabled="extensionsLoading" @click="loadSubscriptionExtensions">{{ extensionsLoading ? t('cloudNative.loadingExtensions') : t('cloudNative.refreshStatus') }}</button></div>
          <div v-if="extensionsError" class="banner error" role="alert">{{ extensionsError }}</div>
          <div v-if="extensionsLoading && !extensions.length" class="loading">{{ t('cloudNative.loadingExtensions') }}</div>
          <div v-else-if="!extensions.length" class="empty-state">{{ t('cloudNative.noExtensions') }}</div>
          <article v-if="haExtension" class="ha-addon-card"><span class="ha-addon-mark">HA</span><div><strong>{{ t('cloudNative.haAddon') }}</strong><p>{{ t(haExtension.active ? 'cloudNative.haAddonActive' : 'cloudNative.haAddonAvailable') }}</p><code>{{ haExtension.product }}</code></div><span class="state" :class="haExtension.active ? 'ready' : 'unknown'"><i></i>{{ t(haExtension.active ? 'cloudNative.extensionActive' : 'cloudNative.extensionAvailable') }}</span><template v-if="permissions.canManageHostResources && !haExtension.active"><div v-if="haExtension.requires_regcode" class="addon-registration"><label :for="`ha-regcode-${haExtension.product}`">{{ t('cloudNative.registrationCode') }}</label><input :id="`ha-regcode-${haExtension.product}`" v-model="extensionRegcodes[haExtension.product]" class="search-input extension-code" type="password" autocomplete="off" :aria-label="`${t('cloudNative.registrationCode')} ${haExtension.name}`" maxlength="256" /><small>{{ t('cloudNative.addonRegistrationCodeHelp') }}</small></div><button class="btn role-primary btn-sm" :disabled="busy === 'subscription' || (haExtension.requires_regcode && !extensionRegcodes[haExtension.product])" @click="changeExtension(haExtension, 'activate_extension')">{{ t('cloudNative.activateExtension') }}</button></template></article>
          <div v-else-if="extensions.length" class="info-panel ha-addon-missing"><strong>{{ t('cloudNative.haAddon') }}</strong><p>{{ t('cloudNative.haAddonNotOffered') }}</p></div>
          <div v-if="extensions.length" class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.extensionName') }}</th><th>{{ t('cloudNative.productId') }}</th><th>{{ t('cloudNative.state') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody>
            <tr v-for="extension in extensions" :key="extension.product"><td><strong>{{ extension.name }}</strong><small v-if="extension.requires_regcode && !extension.active">{{ t('cloudNative.extensionCodeRequired') }}</small></td><td><code>{{ extension.product }}</code></td><td><span class="state" :class="extension.active ? 'ready' : 'unknown'">{{ extension.active ? t('cloudNative.extensionActive') : t('cloudNative.extensionAvailable') }}</span></td><td class="extension-actions"><template v-if="permissions.canManageHostResources && !extension.active"><div v-if="extension.requires_regcode" class="addon-registration"><label :for="`addon-regcode-${extension.product}`">{{ t('cloudNative.registrationCode') }}</label><input :id="`addon-regcode-${extension.product}`" v-model="extensionRegcodes[extension.product]" class="search-input extension-code" type="password" autocomplete="off" maxlength="256" /><small>{{ t('cloudNative.addonRegistrationCodeHelp') }}</small></div><button class="btn role-primary btn-sm" :disabled="busy === 'subscription' || (extension.requires_regcode && !extensionRegcodes[extension.product])" @click="changeExtension(extension, 'activate_extension')">{{ t('cloudNative.activateExtension') }}</button></template><button v-else-if="permissions.canManageHostResources && extension.active && !extension.protected" class="btn role-secondary btn-sm" :disabled="busy === 'subscription'" @click="changeExtension(extension, 'deactivate_extension')">{{ t('cloudNative.deactivateExtension') }}</button><span v-else-if="extension.protected" class="muted">{{ t('cloudNative.coreExtensionProtected') }}</span></td></tr>
          </tbody></table></div>
          <p class="safety-note">{{ t('cloudNative.extensionChangesWarning') }}</p>
        </section>
      </section>

      <section v-else-if="activeTab === 'terminal' && permissions.canAdministerHost" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SSH</span><h2>{{ t('cloudNative.terminal') }}</h2><p class="muted">{{ t('cloudNative.terminalDescription', { user: host.username }) }}</p></div></div>
        <form class="terminal-form" @submit.prevent="runTerminal"><label for="terminal-command">{{ t('cloudNative.command') }}</label><textarea id="terminal-command" v-model="terminalCommand" class="search-input terminal-input" rows="3" :placeholder="t('cloudNative.commandPlaceholder')" required maxlength="4000"></textarea><button class="btn role-primary" :disabled="busy === 'terminal' || !terminalCommand.trim()">{{ busy === 'terminal' ? t('cloudNative.runningCommand') : t('cloudNative.runCommand') }}</button></form><p class="safety-note">{{ t('cloudNative.terminalWarning') }}</p><div v-if="terminalResult" class="terminal-result"><div class="terminal-result-header"><strong>{{ t('cloudNative.commandResult') }}</strong><span :class="terminalResult.return_code === 0 ? 'ready-text' : 'error-text'">{{ t('cloudNative.exitCode') }}: {{ terminalResult.return_code }}</span></div><pre class="log-view">{{ [terminalResult.stdout, terminalResult.stderr].filter(Boolean).join('\n') || t('cloudNative.noOutput') }}</pre></div>
      </section>

      <section v-else class="section-panel"><div class="section-heading"><div><span class="eyebrow">JOURNALD</span><h2>{{ t('cloudNative.systemLogs') }}</h2><p class="muted">{{ t('cloudNative.lastJournal', { count: inventory.logs.length }) }}</p></div><input v-model="logFilter" class="search-input" :placeholder="t('cloudNative.filterLogs')" :aria-label="t('cloudNative.filterLogs')" /></div><pre class="log-view"><span v-for="(line, index) in filteredLogs" :key="index" :class="logLineClass(line)">{{ line }}</span><span v-if="!filteredLogs.length">{{ t('cloudNative.noLogMatch') }}</span></pre></section>
    <div v-if="accountPasswordTarget" class="modal-backdrop" @click.self="accountPasswordTarget = ''"><section class="account-password-modal" role="dialog" aria-modal="true"><h2>{{ t('cloudNative.setPassword') }}: {{ accountPasswordTarget }}</h2><form @submit.prevent="saveAccountPassword"><label>{{ t('cloudNative.newPassword') }}<input v-model="accountPassword" class="search-input" type="password" minlength="8" maxlength="1024" autocomplete="new-password" required /></label><div class="modal-actions"><button type="button" class="btn role-secondary" @click="accountPasswordTarget = ''">{{ t('hosts.cancel') }}</button><button class="btn role-primary" :disabled="busy === `account:${accountPasswordTarget}`">{{ t('cloudNative.setPassword') }}</button></div></form></section></div>
      </main>
      </div>
    </template>
    <div v-if="selectedVmName" class="modal-backdrop" @click.self="closeVmDetails">
      <section class="details-modal" role="dialog" aria-modal="true" :aria-label="t('cloudNative.vmDetails')">
        <header><div><span class="eyebrow">{{ t('cloudNative.vmDetails') }}</span><h2>{{ selectedVmName }}</h2></div><div class="row-actions"><button v-if="permissions.canOperateVms" class="btn role-primary btn-sm" :disabled="!vmDetail || !vmIsRunning(vmDetail) || vmDetail.serial_console === false" :title="!vmDetail || !vmDetail.serial_console ? t('cloudNative.serialConsoleMissing') : !vmIsRunning(vmDetail) ? t('cloudNative.consoleRequiresRunning') : t('cloudNative.vmConsole')" @click="vmDetail && vmIsRunning(vmDetail) && vmDetail.serial_console !== false && openVmConsole(vmDetail)">{{ t('cloudNative.vmConsole') }}</button><button class="btn role-secondary btn-sm" @click="closeVmDetails">{{ t('cloudNative.close') }}</button></div></header>
        <p v-if="vmDetailLoading" class="loading">{{ t('cloudNative.loadingVmDetails') }}</p>
        <div v-else-if="vmDetail" class="details-content">
          <div v-if="vmDetail.serial_console === false" class="banner warning" role="status">{{ t('cloudNative.serialConsoleMissing') }}</div>
          <div class="vm-detail-tabs" role="tablist" :aria-label="t('cloudNative.vmDetailsSections')"><button v-for="section in vmDetailSections" :key="section.id" role="tab" :aria-selected="vmDetailSection === section.id" :class="{ active: vmDetailSection === section.id }" @click="selectVmDetailSection(section.id)">{{ t(`cloudNative.${section.label}`) }}</button></div>
          <section v-if="vmDetailSection === 'overview'" class="vm-config-editor vm-detail-section"><h3>{{ t('cloudNative.vmOverview') }}</h3><p class="vm-description">{{ vmDetail.description || t('cloudNative.noVmDescription') }}</p><div class="detail-stats vm-live-config-stats"><div><span>{{ t('cloudNative.runtimeVcpus') }}</span><strong>{{ vmIsRunning(vmDetail) ? (vmDetail.live_vcpus || vmDetail.current_vcpus) : '—' }}</strong><small>{{ t('cloudNative.savedConfiguration') }}: {{ vmDetail.configured_vcpus }}</small></div><div><span>{{ t('cloudNative.runtimeMemory') }}</span><strong>{{ vmIsRunning(vmDetail) && vmDetail.live_memory_kib ? memoryLabel(vmDetail.live_memory_kib) : '—' }}</strong><small>{{ t('cloudNative.savedConfiguration') }}: {{ memoryLabel(vmDetail.configured_memory_kib) }}</small></div><div><span>{{ t('cloudNative.stateLabel') }}</span><strong>{{ vmDetail.state }}</strong><small>{{ t('cloudNative.autostart') }}: {{ vmDetail.autostart === 'yes' ? t('cloudNative.enabled') : t('cloudNative.disabled') }}</small></div></div><div class="network-meta vm-hardware-meta"><span><small>{{ t('cloudNative.architecture') }}</small><b>{{ vmDetail.architecture || '—' }}</b></span><span><small>{{ t('cloudNative.machineType') }}</small><b>{{ vmDetail.machine || '—' }}</b></span><span><small>{{ t('cloudNative.firmware') }}</small><b>{{ vmDetail.firmware || '—' }}</b></span><span><small>{{ t('cloudNative.cpuMode') }}</small><b>{{ vmDetail.cpu_mode }}<template v-if="vmDetail.cpu_model"> · {{ vmDetail.cpu_model }}</template></b></span><span><small>{{ t('cloudNative.bootOrder') }}</small><b>{{ vmDetail.boot_order.join(' → ') || '—' }}</b></span><span><small>{{ t('cloudNative.vmIdentifier') }}</small><b>{{ vmDetail.uuid || '—' }}</b></span></div></section>
          <section v-if="vmDetailSection === 'configuration'" class="vm-config-editor vm-detail-section"><h3>{{ t('cloudNative.vmConfiguration') }}</h3><p class="muted">{{ t('cloudNative.vmConfigurationHelp') }}</p><form v-if="permissions.canOperateVms" class="admin-form" @submit.prevent="saveVmConfiguration"><label>{{ t('cloudNative.vcpuCount') }}<input v-model.number="vmConfigForm.vcpus" class="search-input" type="number" min="1" max="512" step="1" required /></label><label>{{ t('cloudNative.memoryMiB') }}<input v-model.number="vmConfigForm.memory_mib" class="search-input" type="number" min="128" max="1048576" step="128" required /></label><p class="safety-note">{{ t('cloudNative.vmConfigurationRestartNote') }}</p><div class="row-actions"><button class="btn role-primary" :disabled="busy === 'vm-config' || vmDetailLoading">{{ busy === 'vm-config' ? t('cloudNative.saving') : t('cloudNative.saveChanges') }}</button></div></form><form v-if="permissions.canOperateVms" class="admin-form vm-details-editor" @submit.prevent="saveVmDetailsConfiguration"><label>{{ t('cloudNative.vmDescription') }}<input v-model.trim="vmDetailsForm.description" class="search-input" maxlength="256" /></label><label>{{ t('cloudNative.cpuMode') }}<select v-model="vmDetailsForm.cpu_mode" class="search-input"><option value="host-model">host-model</option><option value="host-passthrough">host-passthrough</option><option value="custom">{{ t('cloudNative.customCpuModel') }}</option></select></label><label v-if="vmDetailsForm.cpu_mode === 'custom'">{{ t('cloudNative.cpuModel') }}<input v-model.trim="vmDetailsForm.cpu_model" class="search-input" maxlength="100" pattern="[A-Za-z0-9_.+-]+" required placeholder="Skylake-Client" /></label><label>{{ t('cloudNative.bootOrder') }}<input v-model.trim="vmDetailsForm.boot_order" class="search-input" required pattern="(hd|cdrom|network)(,(hd|cdrom|network))*" placeholder="hd,cdrom,network" /><small>{{ t('cloudNative.bootOrderHelp') }}</small></label><label class="vm-autostart-option"><input v-model="vmDetailsForm.autostart" type="checkbox" />{{ t('cloudNative.enableAutostart') }}</label><p class="safety-note field-wide">{{ t('cloudNative.vmDetailsRestartNote') }}</p><div class="row-actions field-wide"><button class="btn role-primary" :disabled="busy === 'vm-details-config' || vmDetailLoading">{{ busy === 'vm-details-config' ? t('cloudNative.saving') : t('cloudNative.saveChanges') }}</button></div></form></section>
          <section v-if="vmDetailSection === 'devices'" class="vm-detail-section"><section class="vm-device-panel"><div class="subsection-heading"><div><h3>{{ t('cloudNative.vmDisks') }}</h3><p>{{ t('cloudNative.vmDeviceRestartNote') }}</p></div><button v-if="permissions.canOperateVms" class="btn role-secondary btn-sm" @click="openVmDiskForm">{{ t('cloudNative.attachDisk') }}</button></div>
            <form v-if="showVmDiskForm" class="admin-form" @submit.prevent="changeVmDevice('attach_disk')"><label>{{ t('cloudNative.storagePool') }}<select v-model="vmDeviceForm.pool" class="search-input" required @change="vmDeviceForm.volume = ''"><option disabled value="">{{ t('cloudNative.selectPool') }}</option><option v-for="pool in availableVmPools" :key="pool.name" :value="pool.name">{{ pool.name }}</option></select></label><label>{{ t('cloudNative.volume') }}<select v-model="vmDeviceForm.volume" class="search-input" required><option disabled value="">{{ t('cloudNative.selectVolume') }}</option><option v-for="volume in availableVmDeviceVolumes" :key="`${volume.pool}/${volume.name}`" :value="volume.name">{{ volume.name }} · {{ volume.format }}</option></select></label><div class="row-actions"><button type="button" class="btn role-secondary" @click="showVmDiskForm = false">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'vm-device' || !vmDeviceForm.volume">{{ t('cloudNative.attachDisk') }}</button></div></form>
            <div v-if="volumesLoading" class="loading">{{ t('cloudNative.loadingVolumes') }}</div><div v-if="!vmDetail.disks?.length" class="empty-state">{{ t('cloudNative.noDisk') }}</div><div v-for="disk in vmDetail.disks" :key="disk.target" class="detail-row"><b>{{ disk.target }} · {{ disk.device }}</b><span>{{ disk.source }}</span><small>{{ disk.type }} · {{ disk.format }}</small><button v-if="permissions.canManageHostResources && diskVolume(disk) && !vmIsRunning(vmDetail)" class="btn role-secondary btn-sm" :disabled="volumesLoading || busy === 'vm-disk-resize'" @click="openVmDiskResize(disk)">{{ t('cloudNative.expandDisk') }}</button><button v-if="permissions.canOperateVms" class="btn role-link btn-sm danger-text" :disabled="busy === 'vm-device'" @click="changeVmDevice('detach_disk', { target: disk.target, device: disk.device })">{{ disk.device === 'cdrom' ? t('cloudNative.ejectInstaller') : t('cloudNative.detachDisk') }}</button><form v-if="vmDiskResizeForm?.vm_name === vmDetail.name && vmDiskResizeForm?.name === diskVolume(disk)?.name" class="admin-form vm-disk-resize-form" @submit.prevent="saveVmDiskResize"><label>{{ t('cloudNative.currentDiskSize') }}<input class="search-input" :value="bytesLabel(vmDiskResizeForm.current_capacity_bytes)" disabled /></label><label>{{ t('cloudNative.newDiskSizeGiB') }}<input v-model.number="vmDiskResizeForm.capacity_gib" class="search-input" type="number" :min="(vmDiskResizeForm.current_capacity_bytes / 1073741824) + 0.001" max="10240" step="0.001" required /></label><p class="safety-note field-wide">{{ t('cloudNative.expandDiskHelp') }}</p><div class="row-actions field-wide"><button type="button" class="btn role-secondary" @click="vmDiskResizeForm = null">{{ t('cloudNative.cancel') }}</button><button class="btn role-primary" :disabled="busy === 'vm-disk-resize'">{{ busy === 'vm-disk-resize' ? t('cloudNative.saving') : t('cloudNative.expandDisk') }}</button></div></form></div>
          </section>
          <section class="vm-device-panel"><div class="subsection-heading"><div><h3>{{ t('cloudNative.vmNetworks') }}</h3><p>{{ t('cloudNative.vmDeviceRestartNote') }}</p></div></div>
            <form v-if="permissions.canOperateVms" class="vm-network-attach" @submit.prevent="changeVmDevice('attach_network')"><label>{{ t('cloudNative.virtualNetwork') }}<select v-model="vmDeviceForm.network" class="search-input" required><option disabled value="">{{ t('cloudNative.selectNetwork') }}</option><option v-for="network in activeVmNetworks" :key="network.name" :value="network.name">{{ network.name }}</option></select></label><button class="btn role-secondary btn-sm" :disabled="busy === 'vm-device' || !vmDeviceForm.network">{{ t('cloudNative.attachNetwork') }}</button></form>
            <div v-if="!vmDetail.interfaces?.length" class="empty-state">{{ t('cloudNative.noInterface') }}</div><div v-for="nic in vmDetail.interfaces" :key="nic.mac" class="detail-row"><b>{{ nic.name }} · {{ nic.source }}</b><span>{{ nic.ip_addresses?.join(', ') || t('cloudNative.noIpAddresses') }}</span><small>{{ nic.mac }} · {{ nic.type }} · {{ nic.model }}</small><button v-if="permissions.canOperateVms" class="btn role-link btn-sm danger-text" :disabled="busy === 'vm-device'" @click="changeVmDevice('detach_network', { mac: nic.mac })">{{ t('cloudNative.detachNetwork') }}</button></div>
          </section></section>
          <section v-if="vmDetailSection === 'snapshots'" class="vm-snapshot-panel vm-detail-section"><div class="subsection-heading"><div><h3>{{ t('cloudNative.snapshots') }}</h3><p>{{ t('cloudNative.snapshotHelp') }}</p></div></div>
            <div v-if="!vmDetail.snapshot_supported" class="banner warning" role="status">{{ t('cloudNative.snapshotUnsupported') }}</div>
            <form v-else-if="permissions.canOperateVms && isVmStopped(vmDetail)" class="admin-form snapshot-form" @submit.prevent="controlVmSnapshot('create')"><label>{{ t('cloudNative.snapshotName') }}<input v-model.trim="snapshotForm.name" class="search-input" required maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]*" /></label><label>{{ t('cloudNative.description') }}<input v-model.trim="snapshotForm.description" class="search-input" maxlength="256" /></label><button class="btn role-primary" :disabled="busy === 'vm-snapshot' || !snapshotForm.name">{{ t('cloudNative.createSnapshot') }}</button></form>
            <p v-else class="safety-note">{{ t('cloudNative.snapshotRequiresStopped') }}</p>
            <div v-if="!vmDetail.snapshots.length" class="empty-state">{{ t('cloudNative.noSnapshots') }}</div><div v-for="snapshot in vmDetail.snapshots" :key="snapshot.name" class="snapshot-row"><div><strong>{{ snapshot.name }}</strong><small>{{ snapshot.created_at ? formatSnapshotTime(snapshot.created_at) : '—' }}<span v-if="snapshot.description"> · {{ snapshot.description }}</span></small></div><div v-if="permissions.canOperateVms && isVmStopped(vmDetail)" class="row-actions"><button class="btn role-secondary btn-sm" :disabled="busy === 'vm-snapshot'" @click="controlVmSnapshot('revert', snapshot)">{{ t('cloudNative.revertSnapshot') }}</button><button class="btn role-link btn-sm danger-text" :disabled="busy === 'vm-snapshot'" @click="controlVmSnapshot('delete', snapshot)">{{ t('cloudNative.deleteSnapshot') }}</button></div></div>
          </section>
        </div>
        <div v-if="vmDetailError" class="banner error">{{ vmDetailError }}</div>
      </section>
    </div>
    <div v-if="selectedResource" class="modal-backdrop" @click.self="closeResourceDetails"><aside class="resource-details-panel" role="dialog" aria-modal="true" :aria-label="selectedResource.title"><header><div><span class="eyebrow">{{ selectedResource.subtitle }}</span><h2>{{ selectedResource.title }}</h2></div><button class="btn role-secondary btn-sm" @click="closeResourceDetails">{{ t('cloudNative.close') }}</button></header><dl><template v-for="field in selectedResource.fields" :key="field.label"><dt>{{ field.label }}</dt><dd>{{ field.value }}</dd></template></dl></aside></div>
    <VmConsole v-if="consoleVm" :host-id="hostId" :vm-name="consoleVm.name" @close="consoleVm = null" />
  </div>
</template>

<script lang="ts">
import { defineAsyncComponent, defineComponent } from 'vue';
import VmTable from './VmTable.vue';
const VmConsole = defineAsyncComponent(() => import(/* webpackChunkName: "kvm-vm-console" */ './VmConsole.vue'));

const shellLayoutSnapshots = new WeakMap<HTMLElement, { navWidth: string; navWidthPriority: string; sideNav: HTMLElement | null; sideNavDisplay: string; sideNavDisplayPriority: string }>();

type Host = { id: string; name: string; address: string; port: number; hostname?: string; username: string; status: string };
type Vm = { name: string; uuid: string; state: string; vcpus: number; current_vcpus: number; max_vcpus: number; memory_kib: number; used_memory_kib: number; autostart: string; ip_addresses?: string[] };
type VmSnapshot = { name: string; state: string; created_at: string; description: string };
type VmDetail = Vm & { serial_console?: boolean; live_vcpus: number; live_memory_kib: number; configured_vcpus: number; configured_memory_kib: number; snapshot_supported: boolean; snapshots: VmSnapshot[]; description: string; cpu_mode: string; cpu_model: string; architecture: string; machine: string; firmware: string; boot_order: string[]; disks: { type: string; device: string; target: string; source: string; format: string }[]; interfaces: { name: string; type: string; source: string; model: string; mac: string; ip_addresses?: string[] }[] };
type Service = { name: string; load: string; active: string; sub: string; description: string };
type Account = { username: string; uid: number; gid: number; home: string; shell: string; groups: string[]; locked: boolean };
type Repository = { alias: string; name: string; enabled: boolean; autorefresh: boolean; uri: string };
type TerminalResult = { stdout: string; stderr: string; return_code: number };
type NetworkConnection = { name: string; uuid: string; type: string; device: string; active: boolean; ipv4_method: string; ipv4_addresses: string[]; ipv4_gateway: string; ipv4_dns: string[]; ipv6_method: string; ipv6_addresses: string[]; ipv6_gateway: string; ipv6_dns: string[]; autoconnect: boolean };
type StorageVolume = { pool: string; name: string; path: string; format: string; capacity_bytes: number; allocation_bytes: number };
type SubscriptionExtension = { product: string; name: string; active: boolean; requires_regcode: boolean; protected: boolean };
type Permissions = { accessLevel?: string; canOperateVms: boolean; canManageHostResources: boolean; canAdministerHost: boolean };
type SystemInfo = { hostname: string; os: string; kernel: string; architecture: string; cpu_count: number; memory_total_kib: number; memory_available_kib: number; uptime_seconds: number; load_average: number[] };
type Inventory = {
  system: SystemInfo; vms: Vm[];
  storage: { devices: { name: string; path: string; type: string; size: number; filesystem: string; mountpoints: string[]; model: string }[]; filesystems: { device: string; type: string; size: number; used: number; available: number; use_percent: string; mountpoint: string }[] };
  network: { interfaces: any[]; routes: any[] }; services: Service[]; logs: string[];
  storage_pools: { name: string; type: string; target: string; state: string; autostart: string; capacity: string; allocation: string; available: string }[];
  libvirt_networks: { name: string; state: string; autostart: string; persistent: string; forward_mode: string; bridge: string; ipv4_address: string; ipv4_netmask: string; dhcp_start: string; dhcp_end: string }[];
  accounts: Account[]; repositories: Repository[]; selinux: { available: boolean; mode: string; policy: string; apparmor: string };
  subscription: { available: boolean; status: string; return_code?: number }; network_connections: NetworkConnection[]; errors: string[];
};

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmCloudNativeHost',
  components: { VmTable, VmConsole },
  data() {
    return {
      host: null as Host | null, inventory: null as Inventory | null, permissions: { canOperateVms: false, canManageHostResources: false, canAdministerHost: false } as Permissions, loading: false, error: '', actionError: '', actionSuccess: false, dataUpdatedAt: '', staleClock: Date.now(), staleTimer: 0 as number, metricsRefreshing: false, metricsTimer: 0 as number, loadSequence: 0,
      busy: '' as string, activeTab: 'overview', vmFilter: '', vmStateFilter: 'all', storageFilter: '', accountFilter: '', repositoryFilter: '', networkFilter: '', networkStateFilter: 'all', serviceFilter: '', serviceStateFilter: 'all', serviceLimit: 25, logFilter: '', terminalCommand: '', terminalResult: null as TerminalResult | null, accountPasswordTarget: '', accountPassword: '', selectedResource: null as null | { title: string; subtitle: string; fields: { label: string; value: string }[] },
      showPoolForm: false, poolForm: { action: 'create' as 'create' | 'edit', name: '', target: '' }, networkForm: null as null | { name: string; uuid: string; method: string; addresses: string; gateway: string; dns: string; ipv6_method: string; ipv6_addresses: string; ipv6_gateway: string; ipv6_dns: string; autoconnect: boolean }, libvirtNetworkForm: null as null | { action: 'create' | 'edit'; name: string; forward_mode: 'nat' | 'route' | 'bridge' | 'none'; bridge: string; ipv4_address: string; dhcp_start: string; dhcp_end: string; autostart: boolean; start_after_create: boolean }, accountForm: null as null | { action: 'create' | 'edit'; username: string; shell: string; home: string; groups: string; password: string }, showRepositoryForm: false, repositoryForm: { alias: '', name: '', uri: '' }, showSubscriptionForm: false, subscriptionForm: { email: '', regcode: '' },
      storageVolumes: [] as StorageVolume[], volumesLoading: false, volumesLoaded: false, showVolumeForm: false, volumeForm: { pool: '', name: '', capacity_gib: 10, format: 'qcow2' },
      extensions: [] as SubscriptionExtension[], extensionsLoading: false, extensionsLoaded: false, extensionsError: '', extensionRegcodes: {} as Record<string, string>,
      selectedVmName: '', vmDetail: null as VmDetail | null, vmDetailLoading: false, vmDetailError: '', vmDetailSection: 'overview', vmDetailSections: [{ id: 'overview', label: 'vmOverview' }, { id: 'configuration', label: 'vmConfiguration' }, { id: 'devices', label: 'vmDevices' }, { id: 'snapshots', label: 'snapshots' }], vmConfigForm: { vcpus: 1, memory_mib: 1024 }, vmDetailsForm: { description: '', cpu_mode: 'host-model' as 'host-model' | 'host-passthrough' | 'custom', cpu_model: '', boot_order: 'hd,cdrom,network', autostart: false }, consoleVm: null as Vm | null,
      showVmCreateForm: false, vmCreateForm: { name: '', pool: '', volume: '', network: '', vcpus: 2, memory_mib: 2048, iso_path: '', autostart: false }, vmCreateError: '', snapshotForm: { name: '', description: '' },
      showVmDiskForm: false, vmDeviceForm: { pool: '', volume: '', network: '' }, vmDiskResizeForm: null as null | { pool: string; name: string; current_capacity_bytes: number; capacity_gib: number; vm_name: string },
      navGroups: [{ id: 'system' }, { id: 'tools' }],
      tabs: [
        { id: 'overview', group: 'system', icon: '◉' }, { id: 'logs', group: 'system', icon: '≋' },
        { id: 'storage', group: 'system', icon: '▣', countKey: 'storage' }, { id: 'network', group: 'system', icon: '⌘', countKey: 'network' },
        { id: 'vms', group: 'system', icon: '▤', countKey: 'vms' }, { id: 'accounts', group: 'system', icon: '♙', countKey: 'accounts' },
        { id: 'services', group: 'system', icon: '⚙︎' },
        { id: 'repositories', group: 'tools', icon: '⇩', countKey: 'repositories' }, { id: 'selinux', group: 'tools', icon: '⬡' },
        { id: 'subscriptions', group: 'tools', icon: '▧' }, { id: 'terminal', group: 'tools', icon: '>_' },
      ],
    };
  },
  computed: {
    hostId(): string { return String(this.$route.query.hostId || ''); },
    dataIsStale(): boolean { return Boolean(this.dataUpdatedAt) && this.staleClock - Date.parse(this.dataUpdatedAt) > 90000; },
    subscriptionRegistered(): boolean { const value = this.inventory?.subscription; return !!value?.available && value.return_code === 0 && !/not registered|unregistered/i.test(value.status || ''); },
    haExtension(): SubscriptionExtension | undefined { return this.extensions.find((item) => /(^|\/)sle-ha(\/|$)|high.?availability/i.test(`${item.product} ${item.name}`)); },
    availableTabs(): { id: string; group: string; icon: string; countKey?: string }[] { return this.tabs.filter((tab) => tab.id !== 'terminal' || this.permissions.canAdministerHost); },
    runningVmCount(): number { return this.inventory?.vms.filter((vm) => vm.state.toLowerCase().includes('running')).length || 0; },
    vmRunningPercent(): number { return this.inventory?.vms.length ? Math.round(this.runningVmCount / this.inventory.vms.length * 100) : 0; },
    cpuLoadPercent(): number { return Math.min(100, Math.round((this.inventory?.system.load_average?.[0] || 0) / Math.max(1, this.inventory?.system.cpu_count || 1) * 100)); },
    memoryUsedPercent(): number { const total = this.inventory?.system.memory_total_kib || 0; return total ? Math.round((total - (this.inventory?.system.memory_available_kib || 0)) / total * 100) : 0; },
    criticalFilesystemCount(): number { return this.inventory?.storage.filesystems.filter((filesystem) => Number.parseInt(filesystem.use_percent, 10) >= 90).length || 0; },
    activeInterfaceCount(): number { return this.inventory?.network.interfaces.filter((nic: any) => nic.operstate === 'UP').length || 0; },
    activeConnectionCount(): number { return this.inventory?.network_connections.filter((connection) => connection.active).length || 0; },
    activeLibvirtNetworkCount(): number { return this.inventory?.libvirt_networks.filter((network) => network.state === 'active').length || 0; },
    availableVmPools(): Inventory['storage_pools'] { return (this.inventory?.storage_pools || []).filter((pool) => pool.state.toLowerCase() === 'running'); },
    availableVmCreateVolumes(): StorageVolume[] { return this.storageVolumes.filter((volume) => volume.pool === this.vmCreateForm.pool && ['qcow2', 'raw'].includes(volume.format.toLowerCase()) && volume.capacity_bytes > 0); },
    availableVmDeviceVolumes(): StorageVolume[] { return this.storageVolumes.filter((volume) => volume.pool === this.vmDeviceForm.pool && ['qcow2', 'raw'].includes(volume.format.toLowerCase()) && volume.capacity_bytes > 0); },
    activeVmNetworks(): Inventory['libvirt_networks'] { return (this.inventory?.libvirt_networks || []).filter((network) => network.state.toLowerCase() === 'active'); },
    primaryRoute(): any | null { return this.inventory?.network.routes.find((route: any) => route.dst === 'default' || !route.dst) || null; },
    otherRoutes(): any[] { return (this.inventory?.network.routes || []).filter((route: any) => route !== this.primaryRoute); },
    filteredNetworkInterfaces(): any[] {
      const term = this.networkFilter.toLowerCase().trim();
      return (this.inventory?.network.interfaces || []).filter((nic: any) => {
        const addresses = this.addresses(nic).toLowerCase();
        const matchesTerm = !term || `${nic.ifname} ${nic.address} ${nic.link_type} ${addresses}`.toLowerCase().includes(term);
        const isUp = nic.operstate === 'UP';
        return matchesTerm && (this.networkStateFilter === 'all' || (this.networkStateFilter === 'active' ? isUp : !isUp));
      }).sort((a: any, b: any) => String(a.ifname).localeCompare(String(b.ifname)));
    },
    filteredNetworkConnections(): NetworkConnection[] {
      const term = this.networkFilter.toLowerCase().trim();
      return (this.inventory?.network_connections || []).filter((connection) => {
        const matchesTerm = !term || `${connection.name} ${connection.type} ${connection.device} ${connection.ipv4_addresses.join(' ')} ${connection.ipv4_gateway} ${connection.ipv4_dns.join(' ')}`.toLowerCase().includes(term);
        return matchesTerm && (this.networkStateFilter === 'all' || (this.networkStateFilter === 'active' ? connection.active : !connection.active));
      }).sort((a, b) => a.name.localeCompare(b.name));
    },
    filteredLibvirtNetworks(): Inventory['libvirt_networks'] {
      const term = this.networkFilter.toLowerCase().trim();
      return (this.inventory?.libvirt_networks || []).filter((network) => {
        const matchesTerm = !term || `${network.name} ${network.state} ${network.persistent} ${network.autostart}`.toLowerCase().includes(term);
        return matchesTerm && (this.networkStateFilter === 'all' || (this.networkStateFilter === 'active' ? network.state === 'active' : network.state !== 'active'));
      }).sort((a, b) => a.name.localeCompare(b.name));
    },
    failedServiceCount(): number { return this.inventory?.services.filter((service) => service.active === 'failed').length || 0; },
    filteredVms(): Vm[] { const term = this.vmFilter.toLowerCase().trim(); return (this.inventory?.vms || []).filter((vm) => { const state = vm.state.toLowerCase(); const matchesTerm = !term || `${vm.name} ${vm.uuid}`.toLowerCase().includes(term); const matchesState = this.vmStateFilter === 'all' || (this.vmStateFilter === 'running' && state.includes('running')) || (this.vmStateFilter === 'paused' && state.includes('paused')) || (this.vmStateFilter === 'stopped' && !state.includes('running') && !state.includes('paused')); return matchesTerm && matchesState; }).sort((a, b) => a.name.localeCompare(b.name)); },
    filteredStoragePools(): Inventory['storage_pools'] { const term = this.storageFilter.toLowerCase().trim(); return (this.inventory?.storage_pools || []).filter((pool) => !term || `${pool.name} ${pool.target} ${pool.type} ${pool.state}`.toLowerCase().includes(term)).sort((a, b) => a.name.localeCompare(b.name)); },
    filteredStorageDevices(): Inventory['storage']['devices'] { const term = this.storageFilter.toLowerCase().trim(); return (this.inventory?.storage.devices || []).filter((device) => !term || `${device.name} ${device.path} ${device.type} ${device.filesystem} ${device.model}`.toLowerCase().includes(term)).sort((a, b) => a.name.localeCompare(b.name)); },
    filteredFilesystems(): Inventory['storage']['filesystems'] { const term = this.storageFilter.toLowerCase().trim(); return (this.inventory?.storage.filesystems || []).filter((filesystem) => !term || `${filesystem.device} ${filesystem.mountpoint} ${filesystem.type}`.toLowerCase().includes(term)).sort((a, b) => a.mountpoint.localeCompare(b.mountpoint)); },
    filteredAccounts(): Account[] { const term = this.accountFilter.toLowerCase().trim(); return (this.inventory?.accounts || []).filter((account) => !term || `${account.username} ${account.home} ${account.shell} ${account.groups.join(' ')}`.toLowerCase().includes(term)).sort((a, b) => a.username.localeCompare(b.username)); },
    filteredRepositories(): Repository[] { const term = this.repositoryFilter.toLowerCase().trim(); return (this.inventory?.repositories || []).filter((repo) => !term || `${repo.name} ${repo.alias} ${repo.uri}`.toLowerCase().includes(term)).sort((a, b) => a.name.localeCompare(b.name)); },
    filteredServices(): Service[] { const term = this.serviceFilter.toLowerCase().trim(); return (this.inventory?.services || []).filter((service) => { const matchesTerm = !term || `${service.name} ${service.description}`.toLowerCase().includes(term); const matchesState = this.serviceStateFilter === 'all' || service.active === this.serviceStateFilter; return matchesTerm && matchesState; }).sort((a, b) => a.name.localeCompare(b.name)); },
    visibleServices(): Service[] { return this.filteredServices.slice(0, this.serviceLimit); },
    filteredLogs(): string[] { const term = this.logFilter.toLowerCase().trim(); return (this.inventory?.logs || []).filter((line) => !term || line.toLowerCase().includes(term)); },
  },
  watch: {
    hostId(newHostId: string, oldHostId: string) { if (newHostId && newHostId !== oldHostId) this.load(); },
    '$route.query.tab'(tab: string) { if (this.tabs.some((item) => item.id === tab)) this.selectTab(tab); },
    serviceFilter() { this.serviceLimit = 25; },
    serviceStateFilter() { this.serviceLimit = 25; },
  },
  mounted() {
    const initialTab = String(this.$route.query.tab || '');
    if (this.tabs.some((tab) => tab.id === initialTab)) this.selectTab(initialTab);
    this.load();
    this.metricsTimer = window.setInterval(() => { if (!document.hidden) this.refreshMetrics(); }, 30000);
    this.staleTimer = window.setInterval(() => { this.staleClock = Date.now(); }, 15000);
    document.addEventListener('visibilitychange', this.onVisibilityChange);
    this.$nextTick(() => this.collapseEmptyProductNav());
  },
  beforeUnmount() { window.clearInterval(this.metricsTimer); window.clearInterval(this.staleTimer); document.removeEventListener('visibilitychange', this.onVisibilityChange); this.restoreProductNav(); },
  methods: {
    collapseEmptyProductNav() {
      const layout = document.querySelector('.dashboard-content') as HTMLElement | null;
      const sideNav = layout?.querySelector(':scope > .default-side-nav') as HTMLElement | null;

      if (!layout || shellLayoutSnapshots.has(layout)) return;
      shellLayoutSnapshots.set(layout, {
        navWidth: layout.style.getPropertyValue('--nav-width'),
        navWidthPriority: layout.style.getPropertyPriority('--nav-width'),
        sideNav,
        sideNavDisplay: sideNav?.style.getPropertyValue('display') || '',
        sideNavDisplayPriority: sideNav?.style.getPropertyPriority('display') || '',
      });
      layout.style.setProperty('--nav-width', '0px');
      sideNav?.style.setProperty('display', 'none');
    },
    restoreProductNav() {
      const layout = document.querySelector('.dashboard-content') as HTMLElement | null;
      const snapshot = layout && shellLayoutSnapshots.get(layout);

      if (!layout || !snapshot) return;
      if (snapshot.navWidth) layout.style.setProperty('--nav-width', snapshot.navWidth, snapshot.navWidthPriority);
      else layout.style.removeProperty('--nav-width');
      if (snapshot.sideNav) {
        if (snapshot.sideNavDisplay) snapshot.sideNav.style.setProperty('display', snapshot.sideNavDisplay, snapshot.sideNavDisplayPriority);
        else snapshot.sideNav.style.removeProperty('display');
      }
      shellLayoutSnapshots.delete(layout);
    },
    t(key: string, args?: Record<string, unknown>): string { const translate = (this as any).$store?.getters?.['i18n/t']; return translate ? translate(`kvmManager.${key}`, args) : key; },
    inspectResource(kind: string, item: any) {
      const definitions: Record<string, { title: string; fields: [string, string][] }> = {
        interface: { title: 'interface', fields: [['link_type', 'type'], ['operstate', 'state'], ['address', 'mac'], ['addresses', 'addresses'], ['mtu', 'mtu']] },
        pool: { title: 'storagePool', fields: [['type', 'type'], ['state', 'state'], ['target', 'poolPath'], ['capacity', 'capacity'], ['allocation', 'allocated'], ['available', 'available'], ['autostart', 'autostart']] },
        connection: { title: 'connection', fields: [['type', 'type'], ['device', 'interface'], ['active', 'state'], ['ipv4_method', 'ipMethod'], ['ipv4_addresses', 'addresses'], ['ipv4_gateway', 'gateway'], ['ipv4_dns', 'dnsServers'], ['uuid', 'uuid']] },
        libvirtNetwork: { title: 'virtualNetworks', fields: [['state', 'state'], ['persistent', 'persistence'], ['autostart', 'autostart']] },
        service: { title: 'service', fields: [['load', 'load'], ['active', 'state'], ['sub', 'substate'], ['description', 'description']] },
        account: { title: 'account', fields: [['uid', 'uid'], ['gid', 'gid'], ['home', 'homeDirectory'], ['shell', 'shell'], ['groups', 'groups'], ['locked', 'status']] },
        repository: { title: 'repository', fields: [['alias', 'alias'], ['enabled', 'status'], ['uri', 'uri'], ['autorefresh', 'autorefresh']] },
        disk: { title: 'device', fields: [['path', 'device'], ['type', 'type'], ['size', 'size'], ['filesystem', 'filesystem'], ['mountpoints', 'mount'], ['model', 'model']] },
        filesystem: { title: 'filesystem', fields: [['device', 'device'], ['type', 'type'], ['size', 'size'], ['used', 'used'], ['available', 'available'], ['use_percent', 'usage'], ['mountpoint', 'mount']] },
      };
      const definition = definitions[kind];
      if (!definition) return;
      const valueFor = (key: string) => {
        if (key === 'addresses') return this.addresses(item) || '—';
        const value = item[key];
        if (key === 'size' && kind === 'disk') return this.bytesLabel(value || 0);
        if (['size', 'used', 'available'].includes(key) && kind === 'filesystem') return this.bytesLabel(value || 0);
        if (typeof value === 'boolean') return value ? this.t('cloudNative.enabled') : this.t('cloudNative.disabled');
        if (Array.isArray(value)) return value.join(', ') || '—';
        return value === undefined || value === null || value === '' ? '—' : String(value);
      };
      const resourceName = item.name || item.ifname || item.username || item.alias || item.mountpoint || kind;
      this.selectedResource = {
        title: String(resourceName),
        subtitle: this.t(`cloudNative.${definition.title}`),
        fields: definition.fields.map(([key, label]) => ({ label: this.t(`cloudNative.${label}`), value: valueFor(key) })),
      };
    },
    closeResourceDetails() { this.selectedResource = null; },
    showMoreServices() { this.serviceLimit += 25; },
    async request(path: string, options: RequestInit = {}) {
      const response = await fetch(`${apiBase}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers }, credentials: 'include', cache: 'no-store' });
      if (!response.ok) {
        const operation = this.operationLabel(path);
        const host = this.host?.hostname || this.host?.name || this.t('cloudNative.title');
        const key = response.status === 401 ? 'errorSessionExpired'
          : response.status === 403 ? 'errorPermissionDenied'
            : response.status === 422 ? 'errorInvalidInput'
              : response.status === 502 ? 'errorHostOperation'
                : response.status >= 500 ? 'errorServiceUnavailable' : 'errorRequest';
        throw new Error(this.t(`cloudNative.${key}`, { operation, host }));
      }
      return response.status === 204 ? null : response.json();
    },
    operationLabel(path: string): string {
      const key = path.includes('/vms/') ? 'vms' : path.includes('/network') ? 'network'
        : path.includes('/storage') ? 'storage' : path.includes('/accounts') ? 'accounts'
          : path.includes('/repositories') ? 'repositories' : path.includes('/subscriptions') ? 'subscriptions'
            : path.includes('/services') ? 'services' : path.includes('/terminal') ? 'terminal' : 'title';
      return this.t(`cloudNative.${key}`);
    },
    updateVmFromDetails(details: VmDetail) {
      if (!this.inventory) return;
      const row = { ...details, ip_addresses: [...new Set(details.interfaces.flatMap((nic) => nic.ip_addresses || []))] };
      const index = this.inventory.vms.findIndex((vm) => vm.name === details.name);
      if (index >= 0) this.inventory.vms.splice(index, 1, { ...this.inventory.vms[index], ...row });
      else this.inventory.vms.push(row);
    },
    async refreshVmInventory(vmName: string) {
      const details = await this.request(`/hosts/${this.hostId}/vms/detail?vm_name=${encodeURIComponent(vmName)}`);
      this.updateVmFromDetails(details);
    },
    async refreshServiceInventory() {
      const services = await this.request(`/hosts/${this.hostId}/services`);
      if (this.inventory) this.inventory.services = services;
    },
    async load() {
      if (!this.hostId) { this.error = this.t('cloudNative.hostRequired'); return; }
      const requestedHostId = this.hostId;
      const sequence = ++this.loadSequence;
      this.loading = true; this.error = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        const [hosts, inventory, permissions] = await Promise.all([this.request('/hosts'), this.request(`/hosts/${requestedHostId}/cloud-native`), this.request('/permissions')]);
        if (sequence !== this.loadSequence || requestedHostId !== this.hostId) return;
        this.host = hosts.find((item: Host) => item.id === requestedHostId) || null;
        if (!this.host) throw new Error(this.t('cloudNative.hostRemoved'));
        this.inventory = inventory; this.permissions = permissions;
        this.dataUpdatedAt = new Date().toISOString();
      } catch (error) { if (sequence === this.loadSequence && requestedHostId === this.hostId) this.error = (error as Error).message; }
      finally { if (sequence === this.loadSequence) this.loading = false; }
      // Refresh this shared metrics snapshot after a potentially slow full inventory query.
      // Both the summary cards and Overview read inventory.system, so they show the same sample.
      if (sequence === this.loadSequence && this.inventory && this.host?.id === requestedHostId) await this.refreshMetrics();
    },
    async refreshMetrics() {
      if (!this.inventory || !this.hostId || this.host?.id !== this.hostId || this.metricsRefreshing || document.hidden) return;
      const requestedHostId = this.hostId;
      const targetInventory = this.inventory;
      this.metricsRefreshing = true;
      try {
        const metrics = await this.request(`/hosts/${requestedHostId}/metrics`);
        if (this.hostId !== requestedHostId || this.host?.id !== requestedHostId || this.inventory !== targetInventory) return;
        Object.assign(targetInventory.system, metrics);
        this.dataUpdatedAt = new Date().toISOString(); this.error = '';
      } catch (error) { if (this.hostId === requestedHostId && this.inventory === targetInventory) this.error = (error as Error).message; }
      finally {
        this.metricsRefreshing = false;
        if (this.host?.id === this.hostId && this.inventory && this.inventory !== targetInventory && !document.hidden) this.refreshMetrics();
      }
    },
    onVisibilityChange() { if (!document.hidden) this.refreshMetrics(); },
    async openVmCreateForm() {
      this.vmCreateError = ''; this.showVmCreateForm = true;
      if (!this.volumesLoaded) await this.loadStorageVolumes();
      if (!this.vmCreateForm.pool && this.availableVmPools.length) this.vmCreateForm.pool = this.availableVmPools[0].name;
      if (!this.vmCreateForm.network && this.activeVmNetworks.length) this.vmCreateForm.network = this.activeVmNetworks[0].name;
      if (!this.vmCreateForm.volume && this.availableVmCreateVolumes.length) this.vmCreateForm.volume = this.availableVmCreateVolumes[0].name;
    },
    async createVm() {
      const form = { ...this.vmCreateForm, iso_path: this.vmCreateForm.iso_path.trim() };
      if (!form.name || !form.pool || !form.volume || !form.network || !Number.isInteger(form.vcpus) || !Number.isInteger(form.memory_mib)) {
        this.vmCreateError = this.t('cloudNative.invalidVmCreate'); return;
      }
      const summary = this.t('cloudNative.confirmVmCreate', { name: form.name, vcpus: form.vcpus, memory: this.memoryLabel(form.memory_mib * 1024), disk: form.volume, network: form.network });
      if (!window.confirm(summary)) return;
      this.busy = 'vm-create'; this.vmCreateError = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/vms/create`, { method: 'POST', body: JSON.stringify(form) });
        this.showVmCreateForm = false; this.vmCreateForm = { name: '', pool: '', volume: '', network: form.network, vcpus: 2, memory_mib: 2048, iso_path: '', autostart: false };
        await this.load(); this.actionSuccess = true;
      } catch (error) { this.vmCreateError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async openVmDiskForm() {
      this.showVmDiskForm = true;
      if (!this.volumesLoaded) await this.loadStorageVolumes();
      if (!this.vmDeviceForm.pool && this.availableVmPools.length) this.vmDeviceForm.pool = this.availableVmPools[0].name;
      if (!this.vmDeviceForm.volume && this.availableVmDeviceVolumes.length) this.vmDeviceForm.volume = this.availableVmDeviceVolumes[0].name;
    },
    async changeVmDevice(action: 'attach_disk' | 'detach_disk' | 'attach_network' | 'detach_network', target: { target?: string; device?: string; mac?: string } = {}) {
      if (!this.vmDetail) return;
      const vmName = this.vmDetail.name;
      const payload: Record<string, unknown> = { action };
      if (action === 'attach_disk') { payload.pool = this.vmDeviceForm.pool; payload.volume = this.vmDeviceForm.volume; }
      if (action === 'detach_disk') { payload.target = target.target; }
      if (action === 'attach_network') payload.network = this.vmDeviceForm.network;
      if (action === 'detach_network') payload.mac = target.mac;
      const detail = action === 'attach_disk' ? `${this.vmDeviceForm.volume} on ${vmName}` : action === 'detach_disk' ? `${target.device} ${target.target} from ${vmName}` : action === 'attach_network' ? `${this.vmDeviceForm.network} to ${vmName}` : `network interface ${target.mac} from ${vmName}`;
      const actionLabel = this.t(action === 'attach_disk' ? 'cloudNative.attachDisk' : action === 'detach_disk' ? 'cloudNative.detachDisk' : action === 'attach_network' ? 'cloudNative.attachNetwork' : 'cloudNative.detachNetwork');
      if (!window.confirm(this.t('cloudNative.confirmVmDeviceChange', { action: actionLabel, detail }))) return;
      this.busy = 'vm-device'; this.vmDetailError = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/vms/devices?vm_name=${encodeURIComponent(vmName)}`, { method: 'POST', body: JSON.stringify(payload) });
        this.showVmDiskForm = false; this.vmDeviceForm = { pool: '', volume: '', network: this.vmDeviceForm.network };
        await this.showVmDetails({ ...this.vmDetail, name: vmName }); this.actionSuccess = true;
      } catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async controlVmSnapshot(action: 'create' | 'delete' | 'revert', snapshot?: VmSnapshot) {
      if (!this.vmDetail) return;
      const vmName = this.vmDetail.name;
      const selected = snapshot || { name: this.snapshotForm.name.trim(), description: this.snapshotForm.description.trim(), state: '', created_at: '' };
      if (!selected.name) { this.vmDetailError = this.t('cloudNative.invalidSnapshotName'); return; }
      const key = action === 'create' ? 'confirmSnapshotCreate' : action === 'delete' ? 'confirmSnapshotDelete' : 'confirmSnapshotRevert';
      if (!window.confirm(this.t(`cloudNative.${key}`, { name: selected.name, vm: vmName }))) return;
      this.busy = 'vm-snapshot'; this.vmDetailError = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/vms/snapshots?vm_name=${encodeURIComponent(vmName)}`, { method: 'POST', body: JSON.stringify({ action, name: selected.name, description: selected.description }) });
        this.snapshotForm = { name: '', description: '' };
        await this.showVmDetails({ ...this.vmDetail, name: vmName }); this.actionSuccess = true;
      } catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnVm(vm: Vm, action: 'start' | 'shutdown' | 'reboot' | 'pause' | 'resume') {
      const labelKey = action === 'shutdown' ? 'shutdownVm' : action === 'reboot' ? 'rebootVm' : action === 'pause' ? 'pauseVm' : action === 'resume' ? 'resumeVm' : 'startVm';
      if (!window.confirm(this.t('cloudNative.confirmAction', { action: this.t(`cloudNative.${labelKey}`).toLowerCase(), name: vm.name }))) return;
      this.busy = vm.name; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/vms/actions?vm_name=${encodeURIComponent(vm.name)}`, { method: 'POST', body: JSON.stringify({ action }) }); await this.refreshVmInventory(vm.name); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    openVmConsole(vm: Vm) { this.consoleVm = vm; },
    vmIsRunning(vm: Vm) { return vm.state.toLowerCase().includes('running'); },
    isVmStopped(vm: Vm) { const state = vm.state.toLowerCase(); return state.includes('shut off') || state.includes('shutoff') || state === 'stopped'; },
    formatSnapshotTime(value: string) { const numeric = Number(value); const date = Number.isFinite(numeric) && numeric > 0 ? new Date(numeric * 1000) : new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString(); },
    async actOnService(service: Service, action: 'start' | 'stop' | 'restart') {
      const labelKey = action === 'stop' ? 'stop' : action === 'restart' ? 'restart' : 'start';
      if (!window.confirm(this.t('cloudNative.confirmService', { action: this.t(`cloudNative.${labelKey}`).toLowerCase(), name: service.name }))) return;
      this.busy = service.name; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/services/actions?service_name=${encodeURIComponent(service.name)}`, { method: 'POST', body: JSON.stringify({ action }) }); await this.refreshServiceInventory(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnRepository(alias: string, action: 'enable' | 'disable' | 'refresh' | 'remove') {
      const confirmation = action === 'refresh'
        ? this.t('cloudNative.confirmRepositoryRefresh')
        : action === 'remove'
          ? this.t('cloudNative.confirmRepositoryRemove', { alias })
          : this.t('cloudNative.confirmRepositoryChange', { action: this.t(`cloudNative.${action}`).toLowerCase(), alias });
      if (!window.confirm(confirmation)) return;
      this.busy = action === 'refresh' ? 'repositories' : alias; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/repositories/actions`, { method: 'POST', body: JSON.stringify({ alias, action }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnAccount(account: Account, action: 'lock' | 'unlock' | 'delete') {
      const prompt = action === 'delete'
        ? this.t('cloudNative.confirmAccountDelete', { username: account.username })
        : this.t('cloudNative.confirmAccountAction', { action: this.t(`cloudNative.${action}`).toLowerCase(), username: account.username });
      if (!window.confirm(prompt)) return;
      const key = `account:${account.username}`; this.busy = key; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/accounts/actions`, { method: 'POST', body: JSON.stringify({ username: account.username, action }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async saveAccountPassword() {
      const username = this.accountPasswordTarget;
      if (!username || !this.accountPassword) return;
      const key = `account:${username}`; this.busy = key; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/accounts/actions`, { method: 'POST', body: JSON.stringify({ username, action: 'password', password: this.accountPassword }) });
        this.accountPasswordTarget = ''; this.accountPassword = ''; this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    openAccountForm(account?: Account) {
      this.accountForm = account
        ? { action: 'edit', username: account.username, shell: account.shell, home: account.home, groups: account.groups.join(', '), password: '' }
        : { action: 'create', username: '', shell: '/bin/bash', home: '', groups: '', password: '' };
    },
    async saveAccount() {
      if (!this.accountForm) return;
      const form = this.accountForm;
      if (!window.confirm(this.t(form.action === 'create' ? 'cloudNative.confirmAccountCreate' : 'cloudNative.confirmAccountEdit', { username: form.username }))) return;
      const key = `account:${form.username}`; this.busy = key; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/accounts/actions`, { method: 'POST', body: JSON.stringify({ username: form.username, action: form.action, shell: form.shell, home: form.home, groups: form.groups.split(',').map((group) => group.trim()).filter(Boolean), password: form.password || undefined }) });
        this.accountForm = null; await this.load(); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async savePool() {
      const form = { ...this.poolForm };
      if (!window.confirm(this.t(form.action === 'edit' ? 'cloudNative.confirmPoolEdit' : 'cloudNative.confirmPoolCreate', { name: form.name, path: form.target }))) return;
      this.busy = 'storage-pool'; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/storage-pools/config`, { method: 'POST', body: JSON.stringify({ action: form.action, name: form.name, target: form.target }) });
        this.showPoolForm = false; this.poolForm = { action: 'create', name: '', target: '' }; await this.load(); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    editPool(pool: Inventory['storage_pools'][number]) { this.poolForm = { action: 'edit', name: pool.name, target: pool.target }; this.showPoolForm = true; },
    async deletePool(name: string) {
      if (!window.confirm(this.t('cloudNative.confirmPoolDelete', { name }))) return;
      this.busy = `storage:${name}`; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/storage-pools/config`, { method: 'POST', body: JSON.stringify({ action: 'delete', name }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    editNetwork(connection: NetworkConnection) {
      this.networkForm = { name: connection.name, uuid: connection.uuid, method: ['auto', 'manual', 'shared', 'link-local', 'disabled'].includes(connection.ipv4_method) ? connection.ipv4_method : 'auto', addresses: connection.ipv4_addresses.join(', '), gateway: connection.ipv4_gateway || '', dns: connection.ipv4_dns.join(', '), ipv6_method: ['auto', 'manual', 'disabled'].includes(connection.ipv6_method) ? connection.ipv6_method : 'auto', ipv6_addresses: connection.ipv6_addresses.join(', '), ipv6_gateway: connection.ipv6_gateway || '', ipv6_dns: connection.ipv6_dns.join(', '), autoconnect: connection.autoconnect };
    },
    async saveNetwork() {
      if (!this.networkForm) return;
      const form = this.networkForm;
      const addresses = form.method === 'manual' ? form.addresses.split(',').map((value) => value.trim()).filter(Boolean).join(', ') : '—';
      const gateway = form.method === 'manual' ? form.gateway.trim() || '—' : '—';
      const dns = form.method === 'manual' ? form.dns.split(',').map((value) => value.trim()).filter(Boolean).join(', ') || '—' : '—';
      const ipv6List = form.ipv6_addresses.split(',').map((value) => value.trim()).filter(Boolean);
      const ipv6Addresses = form.ipv6_method === 'manual' ? ipv6List.join(', ') || '—' : form.ipv6_method;
      if (form.ipv6_method === 'manual' && !ipv6List.length) { this.actionError = this.t('cloudNative.invalidIpv6Configuration'); return; }
      if (!window.confirm(this.t('cloudNative.confirmNetworkEditSummary', { name: form.name, method: form.method === 'manual' ? this.t('cloudNative.manual') : 'DHCP', addresses, gateway, dns, ipv6: ipv6Addresses }))) return;
      this.busy = `connection:${form.uuid}`; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/network-connections/config`, { method: 'POST', body: JSON.stringify({ uuid: form.uuid, method: form.method, addresses: form.method === 'manual' ? form.addresses.split(',').map((value) => value.trim()).filter(Boolean) : [], gateway: form.method === 'manual' ? form.gateway.trim() : '', dns: form.method === 'manual' ? form.dns.split(',').map((value) => value.trim()).filter(Boolean) : [], ipv6_method: form.ipv6_method, ipv6_addresses: form.ipv6_method === 'manual' ? form.ipv6_addresses.split(',').map((value) => value.trim()).filter(Boolean) : [], ipv6_gateway: form.ipv6_method === 'manual' ? form.ipv6_gateway.trim() : '', ipv6_dns: form.ipv6_method !== 'disabled' ? form.ipv6_dns.split(',').map((value) => value.trim()).filter(Boolean) : [], autoconnect: form.autoconnect }) });
        this.networkForm = null; await this.load(); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async saveRepository() {
      const form = { ...this.repositoryForm };
      if (!window.confirm(this.t('cloudNative.confirmRepositoryAdd', { alias: form.alias }))) return;
      this.busy = 'repositories'; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/repositories/actions`, { method: 'POST', body: JSON.stringify({ ...form, action: 'add' }) });
        this.showRepositoryForm = false; this.repositoryForm = { alias: '', name: '', uri: '' }; await this.load(); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async registerSubscription() {
      const form = { ...this.subscriptionForm };
      const replacing = this.subscriptionRegistered;
      if (!window.confirm(this.t(replacing ? 'cloudNative.confirmSubscriptionChange' : 'cloudNative.confirmSubscriptionRegister'))) return;
      this.busy = 'subscription'; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/subscriptions/actions`, { method: 'POST', body: JSON.stringify({ action: replacing ? 'replace' : 'register', email: form.email, regcode: form.regcode }) });
        this.showSubscriptionForm = false; this.subscriptionForm = { email: '', regcode: '' }; await Promise.all([this.load(), this.loadSubscriptionExtensions()]); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async deregisterSubscription() {
      if (!window.confirm(this.t('cloudNative.confirmSubscriptionDeregister'))) return;
      this.busy = 'subscription'; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/subscriptions/actions`, { method: 'POST', body: JSON.stringify({ action: 'deregister' }) }); await Promise.all([this.load(), this.loadSubscriptionExtensions()]); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async loadSubscriptionExtensions() {
      if (this.extensionsLoading) return;
      this.extensionsLoading = true; this.extensionsError = '';
      try { this.extensions = await this.request(`/hosts/${this.hostId}/subscriptions/extensions`); this.extensionsLoaded = true; }
      catch (error) { this.extensionsError = (error as Error).message; }
      finally { this.extensionsLoading = false; }
    },
    async refreshSubscriptions() { await this.load(); await this.loadSubscriptionExtensions(); },
    async changeExtension(extension: SubscriptionExtension, action: 'activate_extension' | 'deactivate_extension') {
      const actionLabel = this.t(action === 'activate_extension' ? 'cloudNative.activateExtension' : 'cloudNative.deactivateExtension');
      if (!window.confirm(this.t('cloudNative.confirmExtensionAction', { action: actionLabel, name: extension.name }))) return;
      const regcode = this.extensionRegcodes[extension.product] || '';
      this.busy = 'subscription'; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/subscriptions/actions`, { method: 'POST', body: JSON.stringify({ action, product: extension.product, regcode }) });
        delete this.extensionRegcodes[extension.product];
        await Promise.all([this.load(), this.loadSubscriptionExtensions()]); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async setSecurityMode(mode: 'enforcing' | 'permissive') {
      if (!window.confirm(this.t('cloudNative.confirmSecurityMode', { mode }))) return;
      this.busy = 'selinux'; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/security/selinux`, { method: 'POST', body: JSON.stringify({ mode }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnLibvirt(resource: 'storage-pools' | 'networks', name: string, action: 'start' | 'stop' | 'enable' | 'disable') {
      const key = `${resource}:${name}`;
      if (!window.confirm(this.t('cloudNative.confirmLibvirtAction', { action: this.t(`cloudNative.${action}`).toLowerCase(), name }))) return;
      this.busy = key; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/libvirt/${resource}/actions`, { method: 'POST', body: JSON.stringify({ name, action }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    openLibvirtNetworkForm(network?: Inventory['libvirt_networks'][number]) {
      this.libvirtNetworkForm = network ? { action: 'edit', name: network.name, forward_mode: (['nat', 'route', 'bridge', 'none'].includes(network.forward_mode) ? network.forward_mode : 'none') as 'nat' | 'route' | 'bridge' | 'none', bridge: network.bridge || '', ipv4_address: network.ipv4_address && network.ipv4_netmask ? `${network.ipv4_address}/${this.netmaskPrefix(network.ipv4_netmask)}` : '', dhcp_start: network.dhcp_start || '', dhcp_end: network.dhcp_end || '', autostart: network.autostart === 'yes', start_after_create: false } : { action: 'create', name: '', forward_mode: 'nat', bridge: '', ipv4_address: '192.168.100.1/24', dhcp_start: '192.168.100.100', dhcp_end: '192.168.100.200', autostart: true, start_after_create: true };
    },
    netmaskPrefix(mask: string) { try { return mask.split('.').map((part) => Number(part).toString(2).padStart(8, '0')).join('').replace(/0+$/, '').length; } catch { return 24; } },
    async saveLibvirtNetwork() {
      if (!this.libvirtNetworkForm) return;
      const form = { ...this.libvirtNetworkForm };
      if (form.forward_mode === 'bridge' && !form.bridge.trim()) { this.actionError = this.t('cloudNative.bridgeRequired'); return; }
      if (!!form.dhcp_start !== !!form.dhcp_end || (!!form.dhcp_start && !form.ipv4_address)) { this.actionError = this.t('cloudNative.invalidDhcpRange'); return; }
      const summary = this.t(form.action === 'create' ? 'cloudNative.confirmVirtualNetworkCreate' : 'cloudNative.confirmVirtualNetworkEdit', { name: form.name, mode: form.forward_mode, address: form.ipv4_address || '—' });
      if (!window.confirm(summary)) return;
      this.busy = 'libvirt-network'; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/libvirt/networks/config`, { method: 'POST', body: JSON.stringify({ ...form, bridge: form.forward_mode === 'bridge' ? form.bridge : '', ipv4_address: form.forward_mode === 'bridge' ? '' : form.ipv4_address, dhcp_start: form.forward_mode === 'bridge' ? '' : form.dhcp_start, dhcp_end: form.forward_mode === 'bridge' ? '' : form.dhcp_end }) });
        this.libvirtNetworkForm = null; await this.load(); this.actionSuccess = true;
      } catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async deleteLibvirtNetwork(name: string) {
      if (!window.confirm(this.t('cloudNative.confirmVirtualNetworkDelete', { name }))) return;
      this.busy = `network:${name}`; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/libvirt/networks/config`, { method: 'POST', body: JSON.stringify({ action: 'delete', name }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnConnection(connection: NetworkConnection) {
      const action = connection.active ? 'down' : 'up';
      if (!window.confirm(this.t('cloudNative.confirmNetworkConnection', { action: this.t(`cloudNative.${action}`).toLowerCase(), name: connection.name }))) return;
      this.busy = `connection:${connection.uuid}`; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/network-connections/actions`, { method: 'POST', body: JSON.stringify({ uuid: connection.uuid, action }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async runTerminal() {
      if (!this.terminalCommand.trim()) return;
      this.busy = 'terminal'; this.actionError = ''; this.actionSuccess = false; this.terminalResult = null;
      try { this.terminalResult = await this.request(`/hosts/${this.hostId}/terminal/command`, { method: 'POST', body: JSON.stringify({ command: this.terminalCommand }) }); }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async setAutostart(vm: Vm) {
      const enabled = !(vm.autostart === 'enable' || vm.autostart === 'yes');
      if (!window.confirm(this.t('cloudNative.confirmAutostart', { action: enabled ? this.t('cloudNative.autostartOn').toLowerCase() : this.t('cloudNative.autostartOff').toLowerCase(), name: vm.name }))) return;
      this.busy = vm.name; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/vms/autostart?vm_name=${encodeURIComponent(vm.name)}`, { method: 'POST', body: JSON.stringify({ enabled }) }); await this.refreshVmInventory(vm.name); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async showVmDetails(vm: Vm) {
      this.selectedVmName = vm.name; this.vmDetail = null; this.vmDetailError = ''; this.vmDetailLoading = true;
      this.vmDetailSection = 'overview';
      try { const details: VmDetail = await this.request(`/hosts/${this.hostId}/vms/detail?vm_name=${encodeURIComponent(vm.name)}`); this.vmDetail = details; this.vmConfigForm = { vcpus: details.configured_vcpus || details.current_vcpus || 1, memory_mib: Math.max(128, Math.round((details.configured_memory_kib || details.memory_kib) / 1024)) }; this.vmDetailsForm = { description: details.description || '', cpu_mode: (['host-model', 'host-passthrough', 'custom'].includes(details.cpu_mode) ? details.cpu_mode : 'custom') as 'host-model' | 'host-passthrough' | 'custom', cpu_model: details.cpu_model || '', boot_order: (details.boot_order || []).join(',') || 'hd', autostart: details.autostart === 'yes' }; this.updateVmFromDetails(details); }
      catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.vmDetailLoading = false; }
    },
    diskVolume(disk: { source: string }): StorageVolume | undefined { return this.storageVolumes.find((volume) => volume.path === disk.source); },
    async selectVmDetailSection(section: string) { this.vmDetailSection = section; if (section === 'devices' && !this.volumesLoaded) await this.loadStorageVolumes(); },
    async openVmDiskResize(disk: { source: string }) {
      if (!this.vmDetail || !this.vmDetail.name || this.vmIsRunning(this.vmDetail)) return;
      if (!await this.loadStorageVolumes()) { this.vmDetailError = this.actionError || this.t('cloudNative.diskResizeUnsupported'); return; }
      const volume = this.diskVolume(disk);
      if (!volume || !['qcow2', 'raw'].includes(volume.format.toLowerCase())) { this.vmDetailError = this.t('cloudNative.diskResizeUnsupported'); return; }
      this.vmDetailError = '';
      this.vmDiskResizeForm = { pool: volume.pool, name: volume.name, current_capacity_bytes: volume.capacity_bytes, capacity_gib: Math.ceil(volume.capacity_bytes / 1073741824 * 1000) / 1000, vm_name: this.vmDetail.name };
    },
    async saveVmDiskResize() {
      const form = this.vmDiskResizeForm;
      if (!form || !this.vmDetail || !Number.isFinite(form.capacity_gib) || form.capacity_gib * 1073741824 <= form.current_capacity_bytes || form.capacity_gib > 10240) { this.vmDetailError = this.t('cloudNative.invalidDiskCapacity'); return; }
      if (this.vmIsRunning(this.vmDetail)) { this.vmDetailError = this.t('cloudNative.stopVmBeforeDiskResize'); return; }
      const capacity_bytes = Math.floor(form.capacity_gib * 1073741824);
      if (!window.confirm(this.t('cloudNative.confirmDiskResize', { name: form.name, size: this.bytesLabel(capacity_bytes) }))) return;
      this.busy = 'vm-disk-resize'; this.vmDetailError = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/storage-volumes`, { method: 'POST', body: JSON.stringify({ action: 'resize', pool: form.pool, name: form.name, capacity_bytes, vm_name: form.vm_name }) });
        this.vmDiskResizeForm = null; this.volumesLoaded = false; await this.loadStorageVolumes(); await this.showVmDetails({ ...this.vmDetail, name: form.vm_name }); this.vmDetailSection = 'devices'; this.actionSuccess = true;
      } catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async saveVmDetailsConfiguration() {
      if (!this.vmDetail) return;
      const form = { ...this.vmDetailsForm };
      const boot_order = form.boot_order.split(',').map((item) => item.trim()).filter(Boolean);
      if (!boot_order.length || boot_order.length > 3 || new Set(boot_order).size !== boot_order.length || boot_order.some((item) => !['hd', 'cdrom', 'network'].includes(item))) { this.vmDetailError = this.t('cloudNative.invalidBootOrder'); return; }
      if (form.cpu_mode === 'custom' && !form.cpu_model.trim()) { this.vmDetailError = this.t('cloudNative.customCpuModelRequired'); return; }
      if (!window.confirm(this.t('cloudNative.confirmVmDetailsConfig', { name: this.vmDetail.name, mode: form.cpu_mode, boot: boot_order.join(' → ') }))) return;
      const name = this.vmDetail.name; this.busy = 'vm-details-config'; this.vmDetailError = ''; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/vms/details-config?vm_name=${encodeURIComponent(name)}`, { method: 'POST', body: JSON.stringify({ description: form.description, cpu_mode: form.cpu_mode, cpu_model: form.cpu_mode === 'custom' ? form.cpu_model : null, boot_order, autostart: form.autostart }) }); await this.showVmDetails({ ...this.vmDetail, name }); this.actionSuccess = true; }
      catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async saveVmConfiguration() {
      if (!this.vmDetail || !Number.isInteger(this.vmConfigForm.vcpus) || !Number.isInteger(this.vmConfigForm.memory_mib) || this.vmConfigForm.vcpus < 1 || this.vmConfigForm.vcpus > 512 || this.vmConfigForm.memory_mib < 128 || this.vmConfigForm.memory_mib > 1048576) {
        this.vmDetailError = this.t('cloudNative.invalidVmConfiguration'); return;
      }
      if (!window.confirm(this.t('cloudNative.confirmVmConfiguration', { name: this.vmDetail.name, vcpus: this.vmConfigForm.vcpus, memory: this.memoryLabel(this.vmConfigForm.memory_mib * 1024) }))) return;
      const vmName = this.vmDetail.name;
      this.busy = 'vm-config'; this.vmDetailError = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        await this.request(`/hosts/${this.hostId}/vms/config?vm_name=${encodeURIComponent(vmName)}`, { method: 'POST', body: JSON.stringify(this.vmConfigForm) });
        await this.showVmDetails({ ...this.vmDetail, name: vmName });
        this.actionSuccess = true;
      } catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    closeVmDetails() { this.selectedVmName = ''; this.vmDetail = null; this.vmDetailError = ''; },
    logLineClass(line: string) { return /\b(err|error|failed|critical|panic)\b/i.test(line) ? 'log-error' : /\b(warn|warning)\b/i.test(line) ? 'log-warning' : ''; },
    usageClass(value: string) { const percent = Number.parseInt(value, 10); return percent >= 90 ? 'usage-high' : percent >= 75 ? 'usage-medium' : 'usage-normal'; },
    usagePercent(value: string) { return Math.max(0, Math.min(100, Number.parseInt(value, 10) || 0)); },
    selectTab(tab: string) { this.activeTab = tab; if (tab === 'storage') this.loadStorageVolumes(); if (tab === 'subscriptions') this.loadSubscriptionExtensions(); },
    async loadStorageVolumes(): Promise<boolean> {
      if (this.volumesLoading) return false;
      this.volumesLoading = true;
      try { this.storageVolumes = await this.request(`/hosts/${this.hostId}/storage-volumes`); this.volumesLoaded = true; this.actionError = ''; return true; }
      catch (error) { this.actionError = (error as Error).message; return false; }
      finally { this.volumesLoading = false; }
    },
    async saveVolume() {
      this.busy = 'storage-volume'; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/storage-volumes`, { method: 'POST', body: JSON.stringify({ action: 'create', pool: this.volumeForm.pool, name: this.volumeForm.name, capacity_bytes: Math.floor(this.volumeForm.capacity_gib * 1024 ** 3), format: this.volumeForm.format }) }); this.showVolumeForm = false; await this.loadStorageVolumes(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async deleteVolume(volume: StorageVolume) {
      if (!window.confirm(this.t('cloudNative.confirmDeleteVolume', { name: volume.name }))) return;
      this.busy = 'storage-volume'; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/storage-volumes`, { method: 'POST', body: JSON.stringify({ action: 'delete', pool: volume.pool, name: volume.name }) }); await this.loadStorageVolumes(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    tabCount(key?: string) {
      if (key === 'vms') return this.inventory?.vms.length || 0;
      if (key === 'storage') return this.inventory?.storage_pools.length || 0;
      if (key === 'network') return this.inventory?.network.interfaces.length || 0;
      if (key === 'services') return this.inventory?.services.length || 0;
      if (key === 'accounts') return this.inventory?.accounts.length || 0;
      if (key === 'repositories') return this.inventory?.repositories.length || 0;
      return '';
    },
    backToHosts() { window.location.assign(window.location.pathname.replace(/\/cloud-native\/?$/, '/hosts')); },
    cockpitUrl(host: Host) { return `${apiBase}/hosts/${host.id}/cockpit`; },
    statusLabel(status: string) { return this.t(`hosts.${status}`); },
    dateLabel(value: string) { const locale = (this as any).$store?.state?.i18n?.selected; return new Date(value).toLocaleString(locale || undefined); },
    memoryLabel(kib: number) { return `${(kib / 1048576).toFixed(1)} GiB`; },
    bytesLabel(value: number) {
      if (!value) return '0 B';
      const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
      return `${(value / (1024 ** index)).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
    },
    uptimeLabel(seconds: number) { const days = Math.floor(seconds / 86400); const hours = Math.floor((seconds % 86400) / 3600); return days ? `${days}d ${hours}h` : `${hours}h ${Math.floor((seconds % 3600) / 60)}m`; },
    addresses(nic: any) { return (nic.addr_info || []).map((item: any) => `${item.local}/${item.prefixlen}`).join(', ') || '—'; },
    ipv4MethodLabel(method: string) { if (method === 'auto') return 'DHCP'; if (['manual', 'shared', 'link-local', 'disabled'].includes(method)) return this.t(`cloudNative.${method === 'link-local' ? 'linkLocal' : method}`); return method || '—'; },
  },
});
</script>

<style scoped>
.cloud-native-page { --cn-border: var(--border, #d9dee8); --cn-muted: var(--muted, #6e7888); --cn-panel: var(--input-bg, var(--body-bg, #fff)); padding: 28px clamp(18px, 3vw, 42px) 48px; color: var(--body-text, #243043); }
.breadcrumbs { display:flex; align-items:center; gap:10px; margin-bottom:22px; color:var(--cn-muted); font-size:13px; }
.breadcrumbs button,.text-button { border:0; padding:0; color:var(--link, #2563eb); background:transparent; cursor:pointer; }
.breadcrumbs button:hover,.text-button:hover { text-decoration:underline; }
.page-header,.section-heading { display:flex; align-items:flex-end; justify-content:space-between; gap:22px; margin-bottom:20px; }
.title-block h1 { margin:5px 0 7px; font-size:28px; font-weight:600; letter-spacing:-.025em; }
.eyebrow { color:var(--cn-muted); font-size:10px; font-weight:700; letter-spacing:.11em; }
.muted,small { color:var(--cn-muted); }
small { display:block; margin-top:4px; font-size:12px; }
.toolbar,.filter-bar { display:flex; align-items:center; gap:10px; }
.toolbar form { margin:0; }
.permission-badge { padding:5px 9px; border:1px solid var(--cn-border); border-radius:5px; color:var(--cn-muted); background:var(--cn-panel); font-size:11px; font-weight:600; }
.cluster-summary { display:grid; grid-template-columns:1.35fr repeat(3,1fr); gap:14px; margin:26px 0 28px; }
.summary-card { position:relative; display:flex; flex-direction:column; gap:12px; min-width:0; padding:19px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); box-shadow:0 2px 6px rgba(20,34,58,.035); }
.summary-card.host-card { flex-direction:row; align-items:center; gap:13px; }
.host-card>div:nth-child(2) { min-width:0; flex:1; }
.host-card strong,.host-card small { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.card-top { display:flex; align-items:center; justify-content:space-between; color:var(--cn-muted); font-size:13px; }
.summary-card>div>span,.summary-card>span { color:var(--cn-muted); font-size:12px; }
.summary-card strong { font-size:16px; }
.summary-card .metric { font-size:23px; line-height:1; }
.summary-card .metric small { display:inline; font-size:12px; font-weight:500; }
.metric-track { height:4px; overflow:hidden; border-radius:10px; background:#edf0f5; }
.metric-track i { display:block; height:100%; min-width:2px; border-radius:10px; background:linear-gradient(90deg,#4c83e8,#2563eb); }
.health-summary { display:flex; align-items:center; flex-wrap:wrap; gap:14px 22px; margin:-10px 0 22px; padding:11px 15px; border:1px solid var(--cn-border); border-radius:7px; color:var(--cn-muted); background:var(--cn-panel); font-size:12px; }
.health-summary.health-warning { border-color:rgba(217,156,48,.5); }
.health-indicator { display:inline-flex; align-items:center; gap:7px; font-weight:600; }
.health-indicator i { width:8px; height:8px; border-radius:50%; background:#45a86d; }
.health-indicator.warning i { background:#d99c30; }
.admin-layout { display:grid; grid-template-columns:224px minmax(0,1fr); align-items:start; gap:24px; }
.admin-tabs { position:sticky; top:16px; display:flex; flex-direction:column; gap:18px; min-width:0; max-height:calc(100vh - 32px); overflow-y:auto; padding:12px 10px 16px 0; border-right:1px solid var(--cn-border); }
.nav-group { display:grid; gap:3px; }
.nav-group h2 { margin:0 0 5px; padding:0 12px; color:var(--cn-muted); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.admin-tabs button { display:grid; grid-template-columns:22px minmax(0,1fr) auto; align-items:center; gap:9px; width:100%; border:0; border-radius:5px; padding:9px 11px; color:var(--body-text,#dce1e8); background:transparent; cursor:pointer; text-align:left; font-size:13px; }
.admin-tabs button:hover { background:rgba(140,160,190,.12); }
.admin-tabs button.active { color:var(--body-text,#f1f5f9); background:rgba(95,150,125,.23); box-shadow:inset 3px 0 #65c99a; font-weight:600; }
.admin-tabs .nav-icon { display:inline-flex; width:18px; height:18px; align-items:center; justify-content:center; color:var(--cn-muted); font-family:Arial,sans-serif; font-size:15px; font-variant-emoji:text; line-height:1; text-align:center; }
.admin-tabs .nav-icon svg { width:16px; height:16px; stroke:currentColor; stroke-width:1.6; stroke-linecap:round; stroke-linejoin:round; }
.admin-tabs button.active .nav-icon { color:#65c99a; }
.nav-count,.count-badge { justify-self:end; min-width:18px; border-radius:10px; padding:2px 6px; color:var(--body-text,#dce1e8); background:rgba(140,160,190,.18); font-size:10px; text-align:center; }
.admin-content { min-width:0; }
.section-panel h2 { margin:4px 0 6px; font-size:21px; font-weight:600; letter-spacing:-.015em; }
.section-panel h3 { margin:0 0 14px; font-size:15px; font-weight:600; }
.section-tools { display:flex; align-items:center; justify-content:flex-end; flex-wrap:wrap; gap:9px; }
.updated-at { color:var(--cn-muted); font-size:12px; }.updated-at.stale { color:var(--warning-text,var(--body-text)); font-weight:600; }
.overview-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }
.info-panel,.pool-card,.network-card { border:1px solid var(--cn-border); border-radius:8px; padding:19px; background:var(--cn-panel); }
.panel-heading { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
.panel-heading h3 { margin:0 0 4px; }
.panel-heading p { margin:0; color:var(--cn-muted); font-size:12px; }
.info-panel dl { display:grid; grid-template-columns:minmax(130px,.8fr) 1fr; gap:13px; margin:0; font-size:13px; }
.info-panel dt,.resource-row>span { color:var(--cn-muted); }
.info-panel dd { margin:0; overflow-wrap:anywhere; font-weight:500; }
.resource-row { display:flex; justify-content:space-between; gap:15px; padding:11px 0; border-bottom:1px solid var(--cn-border); font-size:13px; }
.resource-row:last-child { border-bottom:0; }
.vm-heading { margin:28px 0 12px; }
.vm-heading h2 { margin-top:4px; }
.text-button { font-size:13px; }
.subsection { margin:24px 0 30px; }
.subsection h3 { display:flex; align-items:center; gap:9px; }
.pool-grid,.network-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:12px; }
.storage-summary { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:0 0 24px; }
.storage-summary article { display:grid; gap:7px; padding:15px 17px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
.storage-summary article>span,.storage-summary article small { color:var(--cn-muted); font-size:11px; }
.storage-summary article>strong { font-size:22px; }
.storage-summary article small { margin:0; }
.pool-card { min-width:0; }
.pool-card>div:first-child { align-items:flex-start; }
.pool-card>div:first-child strong { font-size:14px; }
.pool-card dd { overflow-wrap:anywhere; text-align:right; }
.network-page .section-heading { align-items:flex-end; }
.network-summary { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:4px 0 28px; }
.network-stat { display:grid; gap:8px; min-width:0; padding:16px 18px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
.network-stat>span,.network-stat small,.network-meta small,.connection-details small,.gateway-card small,.detail-label { color:var(--cn-muted); font-size:11px; }
.network-stat>strong { font-size:23px; line-height:1.15; }
.network-stat small { margin:0; font-size:12px; }
.network-page .subsection { margin:26px 0 30px; }
.subsection-heading { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:12px; }
.subsection-heading h3 { margin:0 0 4px; }
.subsection-heading p { margin:0; color:var(--cn-muted); font-size:12px; }
.network-card { display:flex; flex-direction:column; align-items:stretch; justify-content:flex-start; gap:14px; min-width:0; }
.network-card-heading,.connection-main { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.network-identity { display:flex; align-items:center; gap:10px; min-width:0; }
.network-identity>div { min-width:0; }
.network-identity strong,.network-identity small { display:block; overflow:hidden; text-overflow:ellipsis; }
.network-identity strong { overflow-wrap:anywhere; }
.network-symbol,.gateway-icon { display:inline-flex; flex:0 0 34px; width:34px; height:34px; align-items:center; justify-content:center; border-radius:8px; color:#287e59; background:rgba(87,193,142,.14); font-size:18px; }
.network-addresses { display:grid; gap:6px; padding:11px 0; border-top:1px solid var(--cn-border); border-bottom:1px solid var(--cn-border); }
.network-addresses strong { overflow-wrap:anywhere; font-size:13px; font-weight:500; line-height:1.5; }
.network-meta { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; min-width:0; }
.network-meta>span,.connection-details>span { display:grid; gap:4px; min-width:0; }
.network-meta b,.connection-details b { overflow-wrap:anywhere; font-size:12px; font-weight:500; }
.connection-list { display:grid; gap:10px; }
.connection-card { display:grid; gap:14px; padding:16px 18px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
.connection-details { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; padding-top:12px; border-top:1px solid var(--cn-border); }
.connection-actions { display:flex; justify-content:flex-end; gap:7px; padding-top:10px; border-top:1px solid var(--cn-border); }
.network-editor-wrap { margin:0 0 14px; }
.network-editor { grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin:0; }
.libvirt-network-form { margin:8px 0 18px; padding:18px; border:1px solid var(--cn-border); border-radius:8px; background:var(--body-bg,#252b33); }
.libvirt-network-form .admin-field-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
.libvirt-network-form .editor-heading,.libvirt-network-form .safety-note,.libvirt-network-form>.row-actions { grid-column:1/-1; }
.network-family-heading { padding-top:8px; border-top:1px solid var(--cn-border); }
.vm-details-editor { grid-template-columns:repeat(2,minmax(0,1fr)); }
.vm-disk-resize-form { grid-column:1 / -1; grid-template-columns:repeat(2,minmax(0,1fr)); width:100%; margin-top:10px; padding:14px; border:1px solid var(--border); border-radius:var(--border-radius); background:var(--body-bg); }
.vm-hardware-meta { margin:12px 0; }
.vm-detail-tabs { display:flex; gap:4px; overflow-x:auto; margin:0 -18px 18px; padding:0 18px; border-bottom:1px solid var(--cn-border); }
.vm-detail-tabs button { flex:0 0 auto; padding:11px 14px; color:var(--cn-muted); background:transparent; border:0; border-bottom:2px solid transparent; cursor:pointer; font-weight:600; }
.vm-detail-tabs button.active { color:var(--body-text,#243043); border-bottom-color:var(--success,#4ade80); }
.vm-detail-section { margin-top:0; }
.vm-description { margin:4px 0 14px; color:var(--cn-muted); }
.vm-live-config-stats { grid-template-columns:repeat(3,minmax(0,1fr)); margin:14px 0; }
.vm-live-config-stats small { color:var(--cn-muted); }
.network-editor label { max-width:none; }
.network-editor .search-input { width:100%; max-width:none; }
.editor-heading,.network-editor-footer { grid-column:1/-1; display:flex; align-items:center; justify-content:space-between; gap:14px; }
.editor-heading h4 { margin:4px 0 0; font-size:16px; }
.network-editor-footer { padding-top:8px; border-top:1px solid var(--cn-border); }
.network-editor-footer .safety-note { margin:0; }
.gateway-card { display:grid; grid-template-columns:auto repeat(3,minmax(0,1fr)); align-items:center; gap:15px; margin-bottom:12px; padding:15px 17px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
.gateway-card>div { display:grid; gap:5px; min-width:0; }
.gateway-card strong { overflow-wrap:anywhere; font-size:13px; }
.routes-table { margin-top:12px; }
.pool-card>div,.network-card { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.pool-card>div strong { overflow-wrap:anywhere; }
.pool-card dl { display:grid; grid-template-columns:1fr auto; gap:9px 15px; margin:18px 0 0; font-size:12px; }
.pool-card dt { color:var(--cn-muted); }.pool-card dd { margin:0; font-weight:600; }
.network-card { justify-content:flex-start; }.network-card>div { min-width:0; flex:1; }.network-card strong,.network-card small { overflow-wrap:anywhere; }
.table-wrap { width:100%; overflow-x:auto; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
:deep(.table) { width:100%; border-collapse:collapse; }
:deep(.table) { color:var(--body-text); background:var(--cn-panel); }
:deep(.table th),:deep(.table td) { padding:12px 14px; color:var(--body-text); text-align:left; border-bottom:1px solid var(--cn-border); vertical-align:middle; font-size:13px; }
:deep(.table th) { color:var(--cn-muted); background:rgba(120,135,160,.08); font-size:11px; font-weight:700; letter-spacing:.035em; white-space:nowrap; }
:deep(.table tbody tr:last-child td) { border-bottom:0; }
:deep(.table tbody tr:hover) { background:rgba(65,110,190,.035); }
:deep(.table small) { max-width:240px; overflow-wrap:anywhere; }
:deep(.table .empty-row) { padding:28px; color:var(--cn-muted); text-align:center; }
.state { display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:12px; color:#536174; background:#eef1f5; font-size:11px; font-weight:600; white-space:nowrap; }
.state i { width:6px; height:6px; border-radius:50%; background:currentColor; }
.state.ready { color:#287447; background:#e8f6ed; }.state.unreachable { color:#a52822; background:#fdeceb; }.state.warning-state { color:#8b5a00; background:#fff4db; }.state.unknown { color:#596579; background:#eef1f5; }
.toggle-pill { border:1px solid var(--cn-border); border-radius:14px; padding:4px 9px; color:#667085; background:transparent; cursor:pointer; font-size:11px; }
.toggle-pill.enabled { border-color:#c7e9d0; color:#267644; background:#effaf2; }
.row-actions { display:flex; flex-wrap:wrap; gap:5px; min-width:260px; }.btn-sm { padding:5px 9px; font-size:11px; }
.description-cell { min-width:210px; white-space:normal; }
.resource-name { border:0; padding:0; color:var(--link,#4e8fe8); background:transparent; cursor:pointer; font:inherit; font-weight:600; text-align:left; }
.resource-name:hover { text-decoration:underline; }
.resource-name:focus-visible { outline:2px solid #5288e5; outline-offset:3px; }
.row-actions .btn,.resource-actions .btn,.connection-actions .btn { min-height:29px; white-space:nowrap; }
.search-input { min-width:190px; max-width:270px; border:1px solid var(--cn-border); border-radius:var(--border-radius, 4px); padding:9px 11px; color:var(--body-text,#e5e7eb) !important; background:var(--body-bg,#252b33) !important; font-size:13px; }
.search-input:focus { border-color:#5288e5; outline:2px solid rgba(55,112,215,.13); }
.filter-bar { flex-wrap:wrap; justify-content:flex-end; }
.pagination-row { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:11px 3px; color:var(--cn-muted); font-size:12px; }
.safety-note { margin:12px 2px; color:var(--cn-muted); font-size:12px; }
.security-panel { max-width:720px; }.security-panel h3 { margin:0 0 10px; }.security-actions { margin-top:16px; }
.status-view { max-height:55vh; overflow:auto; padding:16px; border:1px solid var(--cn-border); border-radius:6px; color:var(--body-text,#e5e7eb); background:rgba(12,18,27,.72); white-space:pre-wrap; overflow-wrap:anywhere; font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; }
.subscription-card h3 { margin:14px 0 8px; }.subscription-status-row { display:flex; align-items:center; justify-content:space-between; gap:12px; }.subscription-status-row h3 { margin:12px 0 8px; }
.ha-addon-card { display:flex; flex-wrap:wrap; align-items:center; gap:14px; margin:14px 0; padding:14px; border:1px solid var(--cn-border); border-radius:7px; background:var(--body-bg,#252b33); }.ha-addon-card>div { flex:1; min-width:200px; }.ha-addon-card p { margin:4px 0; color:var(--muted,#9aa4b2); font-size:12px; }.ha-addon-card code { overflow-wrap:anywhere; font-size:11px; }.ha-addon-card .extension-code { min-width:155px; max-width:200px; }.ha-addon-mark { display:grid; width:42px; height:42px; flex:0 0 42px; place-items:center; border-radius:8px; color:#b5f3ce; background:rgba(50,170,112,.18); font-size:13px; font-weight:800; }.ha-addon-missing { margin-top:14px; }.ha-addon-missing p { margin:5px 0 0; color:var(--muted,#9aa4b2); }
.resource-actions { display:flex; flex-wrap:wrap; gap:6px; margin-top:14px; }
.extension-manager { margin-top:24px; }.extension-actions { min-width:280px; white-space:normal !important; }.extension-actions .search-input { margin-right:6px; }.extension-code { min-width:150px; max-width:190px; padding:7px 9px; }.addon-registration { display:grid; gap:5px; max-width:220px; margin:0 0 8px; }.addon-registration label { font-size:11px; font-weight:600; }.addon-registration small { color:var(--cn-muted); font-size:11px; line-height:1.35; }
.terminal-form { display:grid; justify-items:start; gap:10px; }.terminal-form label { font-weight:600; }.terminal-input { width:100%; max-width:900px; font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }.terminal-result { margin-top:22px; }.terminal-result-header { display:flex; justify-content:space-between; gap:12px; margin-bottom:8px; }.ready-text { color:#67d391; }.error-text { color:#ff9690; }
.usage-pill { display:inline-block; border-radius:12px; padding:3px 8px; font-size:11px; font-weight:600; }.usage-normal { color:#287447; background:#e8f6ed; }.usage-medium { color:#8b5a00; background:#fff4db; }.usage-high { color:#a52822; background:#fdeceb; }
.usage-cell { display:grid; gap:5px; min-width:80px; }.usage-track { display:block; height:4px; overflow:hidden; border-radius:5px; background:rgba(120,135,160,.2); }.usage-track i { display:block; height:100%; border-radius:5px; background:#45a86d; }.usage-track i.usage-medium { background:#d99c30; }.usage-track i.usage-high { background:#d45b52; }
.empty-state { padding:20px; border:1px dashed var(--cn-border); border-radius:7px; color:var(--cn-muted); text-align:center; font-size:13px; }
.log-view { max-height:65vh; overflow:auto; margin:0; padding:18px; border:1px solid #263345; border-radius:8px; background:#111a27; color:#d6dfeb; font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }
.log-error { color:#ff9892; }.log-warning { color:#ffd27d; }
.banner { margin:14px 0; padding:13px 15px; border-radius:6px; color:var(--body-text); }.banner.error { background:color-mix(in srgb,#d45b52 16%,var(--body-bg,#252b33)); }.banner.warning { background:color-mix(in srgb,#d99c30 18%,var(--body-bg,#252b33)); }.banner.success { background:color-mix(in srgb,#45a86d 16%,var(--body-bg,#252b33)); }.banner.progress { background:color-mix(in srgb,var(--primary,#3d98ff) 14%,var(--body-bg,#252b33)); }
.loading { padding:48px; color:var(--cn-muted); text-align:center; }
.modal-backdrop { position:fixed; z-index:1000; inset:0; display:flex; justify-content:flex-end; background:rgba(15,24,38,.38); }
.details-modal { width:min(560px,100vw); height:100%; overflow:auto; padding:26px; background:var(--cn-panel); box-shadow:-12px 0 40px rgba(15,24,38,.18); }
.resource-details-panel { width:min(500px,100vw); height:100%; overflow:auto; padding:24px; color:var(--body-text,#e5e7eb); background:var(--body-bg,#252b33); box-shadow:-12px 0 40px rgba(15,24,38,.22); }
.resource-details-panel>header { display:flex; align-items:flex-start; justify-content:space-between; gap:14px; padding-bottom:18px; border-bottom:1px solid var(--cn-border); }
.resource-details-panel h2 { margin:5px 0 0; overflow-wrap:anywhere; font-size:20px; }
.resource-details-panel dl { display:grid; grid-template-columns:minmax(130px,.75fr) minmax(0,1fr); gap:0 14px; margin:8px 0; }
.resource-details-panel dt,.resource-details-panel dd { padding:12px 0; border-bottom:1px solid var(--cn-border); font-size:12px; }
.resource-details-panel dt { color:var(--cn-muted); }.resource-details-panel dd { margin:0; overflow-wrap:anywhere; font-weight:500; }
.admin-form { display:grid; gap:12px; margin:16px 0; padding:18px; border:1px solid var(--cn-border); border-radius:8px; background:var(--cn-panel); }
.guided-admin-form { gap:18px; padding:22px; }
.form-intro { padding-bottom:14px; border-bottom:1px solid var(--cn-border); }
.form-intro .eyebrow { color:var(--cn-muted); font-size:11px; font-weight:700; letter-spacing:.05em; text-transform:uppercase; }
.form-intro h3 { margin:5px 0; font-size:18px; }
.form-intro p { margin:6px 0 0; max-width:800px; color:var(--cn-muted); font-size:13px; line-height:1.5; }
.admin-field-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px 20px; }
.admin-field-grid .field-wide { grid-column:1/-1; }
.guided-admin-form label { display:grid; gap:7px; max-width:none; font-size:13px; font-weight:600; }
.guided-admin-form label small { color:var(--cn-muted); font-size:12px; font-weight:400; line-height:1.45; }
.guided-admin-form .search-input { width:100%; max-width:none; min-height:38px; box-sizing:border-box; }
.guided-admin-form .row-actions { padding-top:12px; border-top:1px solid var(--cn-border); }
.admin-form h3,.admin-form h4 { margin:0 0 2px; }
.admin-form label { display:grid; gap:6px; max-width:680px; font-size:13px; font-weight:600; }
.admin-form .row-actions { justify-content:flex-end; }
.account-password-modal { width:min(460px,100vw); align-self:center; margin:auto; padding:24px; border:1px solid var(--cn-border); border-radius:8px; color:var(--body-text,#e5e7eb); background:var(--body-bg,#252b33); box-shadow:0 16px 48px rgba(0,0,0,.35); }.account-password-modal form,.account-password-modal label { display:grid; gap:12px; }.account-password-modal h2 { margin:0 0 20px; font-size:18px; }.modal-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:8px; }
.details-modal>header { display:flex; justify-content:space-between; align-items:flex-start; padding-bottom:18px; border-bottom:1px solid var(--cn-border); }.details-modal h2 { margin:5px 0; font-size:22px; }
.close-button { border:0; color:var(--cn-muted); background:transparent; cursor:pointer; font-size:28px; }
.details-content h3 { margin:24px 0 10px; font-size:14px; }.detail-stats { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:18px 0; }.detail-stats>div { display:flex; flex-direction:column; gap:6px; padding:12px; border:1px solid var(--cn-border); border-radius:6px; }.detail-stats span,.detail-row small { color:var(--cn-muted); font-size:11px; }.detail-stats strong { font-size:14px; }.detail-row { display:grid; grid-template-columns:70px 1fr; gap:4px 10px; padding:11px 0; border-bottom:1px solid var(--cn-border); font-size:12px; overflow-wrap:anywhere; }.detail-row small { grid-column:2; }
.vm-config-editor { margin:20px 0 26px; padding:16px; border:1px solid var(--cn-border); border-radius:8px; background:var(--body-bg,#252b33); }.vm-config-editor h3 { margin:0 0 6px; }.vm-config-editor>.muted { margin:0; font-size:12px; }.vm-config-editor .admin-form { margin:12px 0 0; }
.vm-list-toolbar { display:flex; align-items:center; gap:10px; }.vm-create-form { margin:0 0 20px; }.vm-autostart-option { display:flex !important; align-items:center; gap:8px !important; }.vm-autostart-option input { width:16px; height:16px; }.vm-device-panel,.vm-snapshot-panel { margin:24px 0; padding:16px; border:1px solid var(--cn-border); border-radius:8px; background:var(--body-bg,#252b33); }.vm-device-panel .subsection-heading,.vm-snapshot-panel .subsection-heading { margin-bottom:10px; }.vm-device-panel .subsection-heading h3,.vm-snapshot-panel .subsection-heading h3 { margin:0 0 4px; }.vm-device-panel .subsection-heading p,.vm-snapshot-panel .subsection-heading p { margin:0; color:var(--cn-muted); font-size:12px; }.vm-device-panel .detail-row { grid-template-columns:minmax(90px,auto) 1fr auto; align-items:center; }.vm-device-panel .detail-row small { grid-column:2; }.vm-network-attach { display:flex; align-items:flex-end; gap:10px; margin:12px 0; }.vm-network-attach label { display:grid; flex:1; gap:6px; max-width:420px; font-size:13px; font-weight:600; }.snapshot-form { grid-template-columns:1fr 1fr auto; align-items:end; }.snapshot-form label { display:grid; gap:6px; font-size:13px; font-weight:600; }.snapshot-row { display:flex; align-items:center; justify-content:space-between; gap:14px; padding:12px 0; border-bottom:1px solid var(--cn-border); }.snapshot-row strong,.snapshot-row small { display:block; }.snapshot-row small { margin-top:4px; color:var(--cn-muted); font-size:11px; }
@media (max-width:1100px) { .cluster-summary { grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (max-width:1050px) { .connection-details { grid-template-columns:repeat(2,minmax(0,1fr)); }.gateway-card { grid-template-columns:auto repeat(2,minmax(0,1fr)); }.gateway-card>div:last-child { grid-column:2/-1; } }
@media (max-width:1000px) { .admin-layout { grid-template-columns:190px minmax(0,1fr); gap:16px; } }
@media (max-width:820px) { .page-header,.section-heading { align-items:flex-start; flex-direction:column; }.toolbar { flex-wrap:wrap; }.filter-bar { justify-content:flex-start; }.overview-grid { grid-template-columns:1fr; }.admin-layout { display:block; }.admin-tabs { position:static; flex-direction:row; max-height:none; overflow:visible; margin:0 0 20px; padding:0 0 12px; border-right:0; border-bottom:1px solid var(--cn-border); }.nav-group { min-width:190px; }.admin-tabs button { padding:8px 10px; } }
@media (max-width:820px) { .network-page .section-heading { align-items:flex-start; }.network-summary,.storage-summary { grid-template-columns:repeat(3,minmax(0,1fr)); width:100%; }.network-editor,.libvirt-network-form .admin-field-grid,.vm-details-editor { grid-template-columns:1fr; }.editor-heading,.network-editor-footer,.libvirt-network-form .editor-heading,.libvirt-network-form .safety-note,.libvirt-network-form>.row-actions { grid-column:auto; }.section-tools { justify-content:flex-start; } }
@media (max-width:560px) { .cloud-native-page { padding:18px 12px 32px; }.cluster-summary { grid-template-columns:1fr; }.host-card { flex-wrap:wrap; }.host-card .state { margin-left:48px; }.admin-tabs { overflow-x:auto; }.search-input { max-width:100%; }.detail-stats,.vm-live-config-stats { grid-template-columns:1fr; }.network-summary,.storage-summary { grid-template-columns:1fr; }.connection-details { grid-template-columns:1fr 1fr; }.network-card-heading,.connection-main { align-items:flex-start; }.gateway-card { grid-template-columns:auto 1fr; }.gateway-card>div:last-child { grid-column:2; }.network-editor-footer { align-items:flex-start; flex-direction:column; }.connection-actions { justify-content:flex-start; }.section-tools,.section-tools>.row-actions { width:100%; }.section-tools>.row-actions { min-width:0; justify-content:flex-start; }.resource-details-panel dl { grid-template-columns:1fr; }.resource-details-panel dt { padding-bottom:3px; border-bottom:0; }.resource-details-panel dd { padding-top:3px; } }
@media (max-width:680px) { .admin-field-grid { grid-template-columns:1fr; }.admin-field-grid .field-wide { grid-column:auto; }.guided-admin-form { padding:16px; } }
@media (max-width:680px) { .vm-list-toolbar,.vm-network-attach,.snapshot-row { align-items:stretch; flex-direction:column; }.snapshot-form { grid-template-columns:1fr; }.vm-device-panel .detail-row { grid-template-columns:1fr; }.vm-device-panel .detail-row small { grid-column:1; } }
</style>
