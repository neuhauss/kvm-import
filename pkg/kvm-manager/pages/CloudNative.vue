<template>
  <div class="cloud-native-page">
    <div class="breadcrumbs"><button @click="backToHosts">KVM</button><span>›</span><button @click="backToHosts">{{ t('hosts.title') }}</button><span>›</span><strong>{{ host?.hostname || host?.name || t('cloudNative.title') }}</strong></div>
    <header class="page-header">
      <div class="title-block"><span class="eyebrow">{{ t('cloudNative.title') }}</span><h1>{{ host ? host.hostname || host.name : t('cloudNative.title') }}</h1><p class="muted">{{ t('cloudNative.subtitle') }}</p><small v-if="dataUpdatedAt" class="updated-at" :class="{ stale: !!error }">{{ t(error ? 'cloudNative.updateFailedAt' : 'cloudNative.lastUpdatedAt', { time: dateLabel(dataUpdatedAt) }) }}</small></div>
      <div v-if="host" class="toolbar">
        <span class="state" :class="host.status"><i></i>{{ statusLabel(host.status) }}</span>
        <form :action="cockpitUrl(host)" method="post" target="_blank"><button class="btn role-secondary" type="submit">{{ t('cloudNative.openCockpit') }}</button></form>
        <button class="btn role-primary" :disabled="loading" @click="load">{{ loading ? t('cloudNative.updating') : t('cloudNative.updateData') }}</button>
      </div>
    </header>

    <div v-if="error" class="banner error" role="alert">{{ error }}</div>
    <div v-if="loading && !inventory" class="loading">{{ t('cloudNative.queryHost') }}</div>
    <template v-else-if="inventory">
      <div class="cluster-summary">
        <article class="summary-card host-card"><div><span>Host</span><strong>{{ inventory.system.hostname }}</strong><small>{{ inventory.system.os }}</small></div><span class="state ready"><i></i>{{ t('cloudNative.connected') }}</span></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.vms') }}</span></div><strong class="metric">{{ inventory.vms.length }}</strong><small>{{ t('cloudNative.runningStopped', { running: runningVmCount, stopped: inventory.vms.length - runningVmCount }) }}</small><div class="metric-track"><i :style="{ width: vmRunningPercent + '%' }"></i></div></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.hostCpu') }}</span></div><strong class="metric">{{ inventory.system.cpu_count }} <small>{{ t('cloudNative.cores') }}</small></strong><small>Load average {{ inventory.system.load_average.map((n) => n.toFixed(2)).join(' · ') }}</small><div class="metric-track"><i :style="{ width: cpuLoadPercent + '%' }"></i></div></article>
        <article class="summary-card"><div class="card-top"><span>{{ t('cloudNative.memory') }}</span></div><strong class="metric">{{ memoryLabel(inventory.system.memory_total_kib) }}</strong><small>{{ memoryLabel(inventory.system.memory_total_kib - inventory.system.memory_available_kib) }} {{ t('cloudNative.inUse') }}</small><div class="metric-track"><i :style="{ width: memoryUsedPercent + '%' }"></i></div></article>
      </div>

      <div class="admin-layout">
      <nav class="admin-tabs" :aria-label="t('cloudNative.adminAreas')">
        <section v-for="group in navGroups" :key="group.id" class="nav-group">
          <h2>{{ t(`cloudNative.group_${group.id}`) }}</h2>
          <button v-for="tab in tabs.filter((item) => item.group === group.id)" :key="tab.id" :class="{ active: activeTab === tab.id }" :aria-current="activeTab === tab.id ? 'page' : undefined" @click="selectTab(tab.id)"><span class="nav-icon" aria-hidden="true">{{ tab.icon }}</span><span>{{ t(`cloudNative.${tab.id}`) }}</span><span v-if="tab.countKey !== undefined" class="nav-count">{{ tabCount(tab.countKey) }}</span></button>
        </section>
      </nav>
      <main class="admin-content">
      <div v-if="inventory.errors.length" class="banner warning">{{ t('cloudNative.loadError') }}: {{ inventory.errors.join('; ') }}</div>
      <section v-if="activeTab === 'overview'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">{{ t('cloudNative.systemSummary') }}</span><h2>{{ t('cloudNative.overview') }}</h2></div><span class="updated-at">{{ t('cloudNative.uptime') }} {{ uptimeLabel(inventory.system.uptime_seconds) }}</span></div>
        <div class="overview-grid">
          <article class="info-panel"><div class="panel-heading"><div><h3>{{ t('cloudNative.system') }}</h3><p>{{ t('cloudNative.hostIdentity') }}</p></div></div><dl><dt>{{ t('cloudNative.os') }}</dt><dd>{{ inventory.system.os }}</dd><dt>{{ t('cloudNative.kernel') }}</dt><dd>{{ inventory.system.kernel }}</dd><dt>{{ t('cloudNative.architecture') }}</dt><dd>{{ inventory.system.architecture }}</dd><dt>{{ t('cloudNative.uptime') }}</dt><dd>{{ uptimeLabel(inventory.system.uptime_seconds) }}</dd></dl></article>
          <article class="info-panel"><div class="panel-heading"><div><h3>{{ t('cloudNative.resources') }}</h3><p>{{ t('cloudNative.currentUsage') }}</p></div></div><div class="resource-row"><span>CPU</span><strong>{{ inventory.system.cpu_count }} {{ t('cloudNative.cores') }}</strong></div><div class="resource-row"><span>Load average</span><strong>{{ inventory.system.load_average.map((n) => n.toFixed(2)).join(' · ') }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.availableMemory') }}</span><strong>{{ memoryLabel(inventory.system.memory_available_kib) }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.devices') }}</span><strong>{{ inventory.storage.devices.length }}</strong></div></article>
        </div>
        <div class="section-heading vm-heading"><div><span class="eyebrow">LIBVIRT</span><h2>{{ t('cloudNative.vms') }}</h2></div><button class="text-button" @click="selectTab('vms')">{{ t('cloudNative.fullInventory') }}</button></div>
        <VmTable :vms="inventory.vms.slice(0, 5)" :busy="busy" @action="actOnVm" @details="showVmDetails" @autostart="setAutostart" @console="openVmConsole" />
      </section>

      <section v-else-if="activeTab === 'vms'" class="section-panel"><div class="section-heading"><div><span class="eyebrow">LIBVIRT</span><h2>{{ t('cloudNative.vms') }}</h2><p class="muted">{{ t('cloudNative.vmLifecycle') }}</p></div><div class="filter-bar"><input v-model="vmFilter" class="search-input" :placeholder="t('cloudNative.filterVms')" :aria-label="t('cloudNative.filterVms')" /><select v-model="vmStateFilter" class="search-input" :aria-label="t('cloudNative.filterVmState')"><option value="all">{{ t('cloudNative.allVmStates') }}</option><option value="running">{{ t('cloudNative.running') }}</option><option value="paused">{{ t('cloudNative.paused') }}</option><option value="stopped">{{ t('cloudNative.stopped') }}</option></select></div></div><div v-if="!filteredVms.length" class="empty-state">{{ t(vmFilter || vmStateFilter !== 'all' ? 'cloudNative.noVmMatch' : 'cloudNative.noVm') }}</div><VmTable v-else :vms="filteredVms" :busy="busy" @action="actOnVm" @details="showVmDetails" @autostart="setAutostart" @console="openVmConsole" /></section>

      <section v-else-if="activeTab === 'storage'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">HOST + LIBVIRT</span><h2>{{ t('cloudNative.storage') }}</h2><p class="muted">{{ t('cloudNative.storageDescription') }}</p></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.storagePools') }} <span class="count-badge">{{ inventory.storage_pools.length }}</span></h3><div v-if="!inventory.storage_pools.length" class="empty-state">{{ t('cloudNative.noPool') }}</div><div v-else class="pool-grid"><article v-for="pool in inventory.storage_pools" :key="pool.name" class="pool-card"><div><strong>{{ pool.name }}</strong><span class="state" :class="pool.state.toLowerCase()">{{ pool.state }}</span></div><dl><dt>{{ t('cloudNative.capacity') }}</dt><dd>{{ pool.capacity }}</dd><dt>{{ t('cloudNative.allocated') }}</dt><dd>{{ pool.allocation }}</dd><dt>{{ t('cloudNative.available') }}</dt><dd>{{ pool.available }}</dd><dt>{{ t('cloudNative.autostart') }}</dt><dd>{{ pool.autostart }}</dd></dl><div class="resource-actions"><button class="btn role-secondary btn-sm" :disabled="busy === `storage:${pool.name}`" @click="actOnLibvirt('storage-pools', pool.name, pool.state.toLowerCase() === 'running' ? 'stop' : 'start')">{{ pool.state.toLowerCase() === 'running' ? t('cloudNative.stop') : t('cloudNative.start') }}</button><button class="btn role-link btn-sm" :disabled="busy === `storage:${pool.name}`" @click="actOnLibvirt('storage-pools', pool.name, pool.autostart === 'yes' ? 'disable' : 'enable')">{{ pool.autostart === 'yes' ? t('cloudNative.disableAutostart') : t('cloudNative.enableAutostart') }}</button></div></article></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.devicesTitle') }}</h3><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.devices') }}</th><th>{{ t('cloudNative.type') }}</th><th>{{ t('cloudNative.size') }}</th><th>{{ t('cloudNative.filesystem') }}</th><th>{{ t('cloudNative.mount') }}</th><th>{{ t('cloudNative.model') }}</th></tr></thead><tbody><tr v-for="disk in inventory.storage.devices" :key="disk.path || disk.name"><td><strong>{{ disk.name }}</strong><small>{{ disk.path }}</small></td><td>{{ disk.type }}</td><td>{{ bytesLabel(disk.size) }}</td><td>{{ disk.filesystem || '—' }}</td><td>{{ disk.mountpoints.join(', ') || '—' }}</td><td>{{ disk.model || '—' }}</td></tr><tr v-if="!inventory.storage.devices.length"><td colspan="6">{{ t('cloudNative.noDevice') }}</td></tr></tbody></table></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.mountedFilesystems') }}</h3><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.device') }}</th><th>{{ t('cloudNative.type') }}</th><th>{{ t('cloudNative.size') }}</th><th>{{ t('cloudNative.used') }}</th><th>{{ t('cloudNative.available') }}</th><th>{{ t('cloudNative.usage') }}</th><th>{{ t('cloudNative.mount') }}</th></tr></thead><tbody><tr v-for="fs in inventory.storage.filesystems" :key="`${fs.device}-${fs.mountpoint}`"><td>{{ fs.device }}</td><td>{{ fs.type }}</td><td>{{ bytesLabel(fs.size) }}</td><td>{{ bytesLabel(fs.used) }}</td><td>{{ bytesLabel(fs.available) }}</td><td><span class="usage-pill" :class="usageClass(fs.use_percent)">{{ fs.use_percent }}</span></td><td>{{ fs.mountpoint }}</td></tr></tbody></table></div></div>
      </section>

      <section v-else-if="activeTab === 'network'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">HOST + LIBVIRT</span><h2>{{ t('cloudNative.network') }}</h2><p class="muted">{{ t('cloudNative.networkReadOnly') }}</p></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.virtualNetworks') }} <span class="count-badge">{{ inventory.libvirt_networks.length }}</span></h3><div v-if="!inventory.libvirt_networks.length" class="empty-state">{{ t('cloudNative.noNetwork') }}</div><div v-else class="network-grid"><article v-for="network in inventory.libvirt_networks" :key="network.name" class="network-card"><div><strong>{{ network.name }}</strong><small>{{ network.persistent === 'yes' ? t('cloudNative.persistent') : t('cloudNative.temporary') }} · {{ network.autostart === 'yes' ? t('cloudNative.autostart') : t('cloudNative.noAutostart') }}</small></div><span class="state" :class="network.state === 'active' ? 'ready' : 'unknown'">{{ network.state }}</span><div class="resource-actions"><button class="btn role-secondary btn-sm" :disabled="busy === `network:${network.name}`" @click="actOnLibvirt('networks', network.name, network.state === 'active' ? 'stop' : 'start')">{{ network.state === 'active' ? t('cloudNative.stop') : t('cloudNative.start') }}</button><button class="btn role-link btn-sm" :disabled="busy === `network:${network.name}`" @click="actOnLibvirt('networks', network.name, network.autostart === 'yes' ? 'disable' : 'enable')">{{ network.autostart === 'yes' ? t('cloudNative.disableAutostart') : t('cloudNative.enableAutostart') }}</button></div></article></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.interfaces') }}</h3><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.interface') }}</th><th>{{ t('cloudNative.state') }}</th><th>{{ t('cloudNative.mac') }}</th><th>{{ t('cloudNative.addresses') }}</th><th>MTU</th></tr></thead><tbody><tr v-for="nic in inventory.network.interfaces" :key="nic.ifname"><td><strong>{{ nic.ifname }}</strong></td><td><span class="state" :class="nic.operstate === 'UP' ? 'ready' : 'unknown'"><i></i>{{ nic.operstate || '—' }}</span></td><td>{{ nic.address || '—' }}</td><td>{{ addresses(nic) }}</td><td>{{ nic.mtu || '—' }}</td></tr><tr v-if="!inventory.network.interfaces.length"><td colspan="5">{{ t('cloudNative.noInterface') }}</td></tr></tbody></table></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.routes') }}</h3><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.destination') }}</th><th>{{ t('cloudNative.gateway') }}</th><th>{{ t('cloudNative.interface') }}</th><th>{{ t('cloudNative.protocol') }}</th></tr></thead><tbody><tr v-for="(route, index) in inventory.network.routes" :key="`${route.dst}-${route.dev}-${index}`"><td>{{ route.dst || 'default' }}</td><td>{{ route.gateway || '—' }}</td><td>{{ route.dev || '—' }}</td><td>{{ route.protocol || '—' }}</td></tr></tbody></table></div></div>
        <div class="subsection"><h3>{{ t('cloudNative.networkConnections') }}</h3><div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.connection') }}</th><th>{{ t('cloudNative.type') }}</th><th>{{ t('cloudNative.interface') }}</th><th>{{ t('cloudNative.state') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="connection in inventory.network_connections" :key="connection.uuid"><td><strong>{{ connection.name }}</strong></td><td>{{ connection.type }}</td><td>{{ connection.device || '—' }}</td><td><span class="state" :class="connection.active ? 'ready' : 'unknown'">{{ connection.active ? t('cloudNative.active') : t('cloudNative.inactive') }}</span></td><td><button class="btn role-secondary btn-sm" :disabled="busy === `connection:${connection.uuid}`" @click="actOnConnection(connection)">{{ connection.active ? t('cloudNative.deactivate') : t('cloudNative.activate') }}</button></td></tr><tr v-if="!inventory.network_connections.length"><td colspan="5" class="empty-row">{{ t('cloudNative.noConnection') }}</td></tr></tbody></table></div><p class="safety-note">{{ t('cloudNative.networkWarning') }}</p></div>
      </section>

      <section v-else-if="activeTab === 'services'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SYSTEMD</span><h2>{{ t('cloudNative.systemServices') }}</h2><p class="muted">{{ t('cloudNative.failedServices', { count: failedServiceCount }) }}</p></div><div class="filter-bar"><input v-model="serviceFilter" class="search-input" :placeholder="t('cloudNative.searchService')" :aria-label="t('cloudNative.searchService')" /><select v-model="serviceStateFilter" class="search-input" :aria-label="t('cloudNative.filterState')"><option value="all">{{ t('cloudNative.allStates') }}</option><option value="active">{{ t('cloudNative.active') }}</option><option value="failed">{{ t('cloudNative.failed') }}</option><option value="inactive">{{ t('cloudNative.inactive') }}</option></select></div></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.service') }}</th><th>{{ t('cloudNative.state') }}</th><th>{{ t('cloudNative.substate') }}</th><th>{{ t('cloudNative.description') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="service in visibleServices" :key="service.name"><td><strong>{{ service.name }}</strong></td><td><span class="state" :class="service.active === 'active' ? 'ready' : service.active === 'failed' ? 'unreachable' : 'unknown'">{{ t(`cloudNative.${service.active}`) }}</span></td><td>{{ service.sub }}</td><td class="description-cell">{{ service.description }}</td><td class="row-actions"><button class="btn role-secondary btn-sm" :disabled="busy === service.name || service.active === 'active'" @click="actOnService(service, 'start')">{{ t('cloudNative.start') }}</button><button class="btn role-secondary btn-sm" :disabled="busy === service.name || service.active !== 'active'" @click="actOnService(service, 'restart')">{{ t('cloudNative.restart') }}</button><button class="btn role-link btn-sm" :disabled="busy === service.name || service.active !== 'active'" @click="actOnService(service, 'stop')">{{ t('cloudNative.stop') }}</button></td></tr><tr v-if="!filteredServices.length"><td colspan="5" class="empty-row">{{ t('cloudNative.noServiceMatch') }}</td></tr></tbody></table></div><div v-if="filteredServices.length" class="pagination-row"><span>{{ t('cloudNative.showingServices', { shown: visibleServices.length, total: filteredServices.length }) }}</span><button v-if="visibleServices.length < filteredServices.length" class="btn role-secondary btn-sm" @click="showMoreServices">{{ t('cloudNative.showMore') }}</button></div><p class="safety-note">{{ t('cloudNative.serviceWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'accounts'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SYSTEM USERS</span><h2>{{ t('cloudNative.accounts') }}</h2><p class="muted">{{ t('cloudNative.accountsDescription') }}</p></div></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.account') }}</th><th>UID / GID</th><th>{{ t('cloudNative.homeDirectory') }}</th><th>{{ t('cloudNative.shell') }}</th><th>{{ t('cloudNative.groups') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="account in inventory.accounts" :key="account.username"><td><strong>{{ account.username }}</strong><small>{{ account.locked ? t('cloudNative.locked') : t('cloudNative.unlocked') }}</small></td><td>{{ account.uid }} / {{ account.gid }}</td><td>{{ account.home }}</td><td>{{ account.shell }}</td><td>{{ account.groups.join(', ') || '—' }}</td><td class="row-actions"><button class="btn role-secondary btn-sm" :disabled="busy === `account:${account.username}` || (!account.locked && (account.username === host.username || account.uid === 0))" @click="actOnAccount(account, account.locked ? 'unlock' : 'lock')">{{ account.locked ? t('cloudNative.unlock') : t('cloudNative.lock') }}</button><button class="btn role-link btn-sm" :disabled="busy === `account:${account.username}`" @click="accountPasswordTarget = account.username; accountPassword = ''">{{ t('cloudNative.setPassword') }}</button></td></tr><tr v-if="!inventory.accounts.length"><td colspan="6" class="empty-row">{{ t('cloudNative.noAccounts') }}</td></tr></tbody></table></div><p class="safety-note">{{ t('cloudNative.accountsWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'repositories'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">ZYPPER</span><h2>{{ t('cloudNative.repositories') }}</h2><p class="muted">{{ t('cloudNative.repositoriesDescription') }}</p></div><button class="btn role-secondary" :disabled="busy === 'repositories'" @click="actOnRepository('*', 'refresh')">{{ busy === 'repositories' ? t('cloudNative.updating') : t('cloudNative.refreshRepositories') }}</button></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>{{ t('cloudNative.repository') }}</th><th>{{ t('cloudNative.alias') }}</th><th>{{ t('cloudNative.status') }}</th><th>{{ t('cloudNative.uri') }}</th><th>{{ t('hosts.action') }}</th></tr></thead><tbody><tr v-for="repo in inventory.repositories" :key="repo.alias"><td><strong>{{ repo.name }}</strong></td><td>{{ repo.alias }}</td><td><span class="state" :class="repo.enabled ? 'ready' : 'unknown'">{{ repo.enabled ? t('cloudNative.enabled') : t('cloudNative.disabled') }}</span></td><td class="description-cell">{{ repo.uri || '—' }}</td><td><button class="btn role-secondary btn-sm" :disabled="busy === repo.alias" @click="actOnRepository(repo.alias, repo.enabled ? 'disable' : 'enable')">{{ repo.enabled ? t('cloudNative.disable') : t('cloudNative.enable') }}</button></td></tr><tr v-if="!inventory.repositories.length"><td colspan="5" class="empty-row">{{ t('cloudNative.noRepositories') }}</td></tr></tbody></table></div><p class="safety-note">{{ t('cloudNative.repositoryWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'selinux'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SECURITY</span><h2>{{ t('cloudNative.selinux') }}</h2><p class="muted">{{ t('cloudNative.selinuxDescription') }}</p></div></div>
        <article class="info-panel security-panel"><h3>{{ t('cloudNative.selinuxStatus') }}</h3><div class="resource-row"><span>{{ t('cloudNative.selinuxMode') }}</span><strong>{{ inventory.selinux.mode }}</strong></div><div class="resource-row"><span>{{ t('cloudNative.selinuxPolicy') }}</span><strong>{{ inventory.selinux.policy || '—' }}</strong></div><div class="resource-row"><span>AppArmor</span><strong>{{ inventory.selinux.apparmor }}</strong></div><div v-if="inventory.selinux.available" class="row-actions security-actions"><button class="btn role-secondary btn-sm" :disabled="busy === 'selinux' || inventory.selinux.mode === 'enforcing'" @click="setSecurityMode('enforcing')">{{ t('cloudNative.setEnforcing') }}</button><button class="btn role-secondary btn-sm" :disabled="busy === 'selinux' || inventory.selinux.mode === 'permissive'" @click="setSecurityMode('permissive')">{{ t('cloudNative.setPermissive') }}</button></div><p v-else class="safety-note">{{ t('cloudNative.selinuxUnavailable') }}</p></article>
      </section>

      <section v-else-if="activeTab === 'subscriptions'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SUSECONNECT</span><h2>{{ t('cloudNative.subscriptions') }}</h2><p class="muted">{{ t('cloudNative.subscriptionsDescription') }}</p></div><button class="btn role-secondary" :disabled="loading" @click="load">{{ t('cloudNative.refreshStatus') }}</button></div>
        <article class="info-panel"><div class="resource-row"><span>{{ t('cloudNative.client') }}</span><strong>{{ inventory.subscription.available ? 'SUSEConnect' : t('cloudNative.notInstalled') }}</strong></div><h3>{{ t('cloudNative.registrationStatus') }}</h3><pre class="status-view">{{ inventory.subscription.status || t('cloudNative.noSubscriptionData') }}</pre></article><p class="safety-note">{{ t('cloudNative.subscriptionWarning') }}</p>
      </section>

      <section v-else-if="activeTab === 'terminal'" class="section-panel">
        <div class="section-heading"><div><span class="eyebrow">SSH</span><h2>{{ t('cloudNative.terminal') }}</h2><p class="muted">{{ t('cloudNative.terminalDescription', { user: host.username }) }}</p></div></div>
        <form class="terminal-form" @submit.prevent="runTerminal"><label for="terminal-command">{{ t('cloudNative.command') }}</label><textarea id="terminal-command" v-model="terminalCommand" class="search-input terminal-input" rows="3" :placeholder="t('cloudNative.commandPlaceholder')" required maxlength="4000"></textarea><button class="btn role-primary" :disabled="busy === 'terminal' || !terminalCommand.trim()">{{ busy === 'terminal' ? t('cloudNative.runningCommand') : t('cloudNative.runCommand') }}</button></form><p class="safety-note">{{ t('cloudNative.terminalWarning') }}</p><div v-if="terminalResult" class="terminal-result"><div class="terminal-result-header"><strong>{{ t('cloudNative.commandResult') }}</strong><span :class="terminalResult.return_code === 0 ? 'ready-text' : 'error-text'">{{ t('cloudNative.exitCode') }}: {{ terminalResult.return_code }}</span></div><pre class="log-view">{{ [terminalResult.stdout, terminalResult.stderr].filter(Boolean).join('\n') || t('cloudNative.noOutput') }}</pre></div>
      </section>

      <section v-else class="section-panel"><div class="section-heading"><div><span class="eyebrow">JOURNALD</span><h2>{{ t('cloudNative.systemLogs') }}</h2><p class="muted">{{ t('cloudNative.lastJournal', { count: inventory.logs.length }) }}</p></div><input v-model="logFilter" class="search-input" :placeholder="t('cloudNative.filterLogs')" :aria-label="t('cloudNative.filterLogs')" /></div><pre class="log-view"><span v-for="(line, index) in filteredLogs" :key="index" :class="logLineClass(line)">{{ line }}</span><span v-if="!filteredLogs.length">{{ t('cloudNative.noLogMatch') }}</span></pre></section>
    <div v-if="actionError" class="banner error" role="alert">{{ actionError }}</div>
    <div v-else-if="actionSuccess" class="banner success" role="status">{{ t('cloudNative.actionSucceeded') }}</div>
    <div v-if="accountPasswordTarget" class="modal-backdrop" @click.self="accountPasswordTarget = ''"><section class="account-password-modal" role="dialog" aria-modal="true"><h2>{{ t('cloudNative.setPassword') }}: {{ accountPasswordTarget }}</h2><form @submit.prevent="saveAccountPassword"><label>{{ t('cloudNative.newPassword') }}<input v-model="accountPassword" class="search-input" type="password" minlength="8" maxlength="1024" autocomplete="new-password" required /></label><div class="modal-actions"><button type="button" class="btn role-secondary" @click="accountPasswordTarget = ''">{{ t('hosts.cancel') }}</button><button class="btn role-primary" :disabled="busy === `account:${accountPasswordTarget}`">{{ t('cloudNative.setPassword') }}</button></div></form></section></div>
      </main>
      </div>
    </template>
    <div v-if="selectedVmName" class="modal-backdrop" @click.self="closeVmDetails">
      <section class="details-modal" role="dialog" aria-modal="true" :aria-label="t('cloudNative.vmDetails')">
        <header><div><span class="eyebrow">{{ t('cloudNative.vmDetails') }}</span><h2>{{ selectedVmName }}</h2></div><button class="btn role-secondary btn-sm" @click="closeVmDetails">{{ t('cloudNative.close') }}</button></header>
        <p v-if="vmDetailLoading" class="loading">{{ t('cloudNative.loadingVmDetails') }}</p>
        <div v-else-if="vmDetail" class="details-content"><div class="detail-stats"><div><span>{{ t('cloudNative.stateLabel') }}</span><strong>{{ vmDetail.state }}</strong></div><div><span>vCPU</span><strong>{{ vmDetail.current_vcpus || vmDetail.vcpus }}</strong></div><div><span>{{ t('cloudNative.maxMemory') }}</span><strong>{{ memoryLabel(vmDetail.memory_kib) }}</strong></div></div><h3>{{ t('cloudNative.disk') }}</h3><div v-if="!vmDetail.disks?.length" class="empty-state">{{ t('cloudNative.noDisk') }}</div><div v-for="disk in vmDetail.disks" :key="disk.target" class="detail-row"><b>{{ disk.target }}</b><span>{{ disk.source }}</span><small>{{ disk.type }} · {{ disk.device }}</small></div><h3>{{ t('cloudNative.interfaces') }}</h3><div v-if="!vmDetail.interfaces?.length" class="empty-state">{{ t('cloudNative.noInterface') }}</div><div v-for="nic in vmDetail.interfaces" :key="nic.mac" class="detail-row"><b>{{ nic.name }}</b><span>{{ nic.ip_addresses?.join(', ') || t('cloudNative.noIpAddresses') }}</span><small>{{ nic.mac }} · {{ nic.type }} · {{ nic.source }} · {{ nic.model }}</small></div></div>
        <div v-if="vmDetailError" class="banner error">{{ vmDetailError }}</div>
      </section>
    </div>
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
type VmDetail = Vm & { disks: { type: string; device: string; target: string; source: string }[]; interfaces: { name: string; type: string; source: string; model: string; mac: string; ip_addresses?: string[] }[] };
type Service = { name: string; load: string; active: string; sub: string; description: string };
type Account = { username: string; uid: number; gid: number; home: string; shell: string; groups: string[]; locked: boolean };
type Repository = { alias: string; name: string; enabled: boolean; autorefresh: boolean; uri: string };
type TerminalResult = { stdout: string; stderr: string; return_code: number };
type NetworkConnection = { name: string; uuid: string; type: string; device: string; active: boolean };
type SystemInfo = { hostname: string; os: string; kernel: string; architecture: string; cpu_count: number; memory_total_kib: number; memory_available_kib: number; uptime_seconds: number; load_average: number[] };
type Inventory = {
  system: SystemInfo; vms: Vm[];
  storage: { devices: { name: string; path: string; type: string; size: number; filesystem: string; mountpoints: string[]; model: string }[]; filesystems: { device: string; type: string; size: number; used: number; available: number; use_percent: string; mountpoint: string }[] };
  network: { interfaces: any[]; routes: any[] }; services: Service[]; logs: string[];
  storage_pools: { name: string; state: string; autostart: string; capacity: string; allocation: string; available: string }[];
  libvirt_networks: { name: string; state: string; autostart: string; persistent: string }[];
  accounts: Account[]; repositories: Repository[]; selinux: { available: boolean; mode: string; policy: string; apparmor: string };
  subscription: { available: boolean; status: string; return_code?: number }; network_connections: NetworkConnection[]; errors: string[];
};

const apiBase = (process.env.VUE_APP_KVM_API || '/kvm-api').replace(/\/$/, '');

export default defineComponent({
  name: 'KvmCloudNativeHost',
  components: { VmTable, VmConsole },
  data() {
    return {
      host: null as Host | null, inventory: null as Inventory | null, loading: false, error: '', actionError: '', actionSuccess: false, dataUpdatedAt: '',
      busy: '' as string, activeTab: 'overview', vmFilter: '', vmStateFilter: 'all', serviceFilter: '', serviceStateFilter: 'all', serviceLimit: 25, logFilter: '', terminalCommand: '', terminalResult: null as TerminalResult | null, accountPasswordTarget: '', accountPassword: '',
      selectedVmName: '', vmDetail: null as VmDetail | null, vmDetailLoading: false, vmDetailError: '', consoleVm: null as Vm | null,
      navGroups: [{ id: 'system' }, { id: 'tools' }],
      tabs: [
        { id: 'overview', group: 'system', icon: '◉' }, { id: 'logs', group: 'system', icon: '≋' },
        { id: 'storage', group: 'system', icon: '▣', countKey: 'storage' }, { id: 'network', group: 'system', icon: '⌘', countKey: 'network' },
        { id: 'vms', group: 'system', icon: '▤', countKey: 'vms' }, { id: 'accounts', group: 'system', icon: '♙', countKey: 'accounts' },
        { id: 'services', group: 'system', icon: '⚙' },
        { id: 'repositories', group: 'tools', icon: '⇩', countKey: 'repositories' }, { id: 'selinux', group: 'tools', icon: '⬡' },
        { id: 'subscriptions', group: 'tools', icon: '▧' }, { id: 'terminal', group: 'tools', icon: '>_' },
      ],
    };
  },
  computed: {
    hostId(): string { return String(this.$route.query.hostId || ''); },
    runningVmCount(): number { return this.inventory?.vms.filter((vm) => vm.state.toLowerCase().includes('running')).length || 0; },
    vmRunningPercent(): number { return this.inventory?.vms.length ? Math.round(this.runningVmCount / this.inventory.vms.length * 100) : 0; },
    cpuLoadPercent(): number { return Math.min(100, Math.round((this.inventory?.system.load_average?.[0] || 0) / Math.max(1, this.inventory?.system.cpu_count || 1) * 100)); },
    memoryUsedPercent(): number { const total = this.inventory?.system.memory_total_kib || 0; return total ? Math.round((total - (this.inventory?.system.memory_available_kib || 0)) / total * 100) : 0; },
    failedServiceCount(): number { return this.inventory?.services.filter((service) => service.active === 'failed').length || 0; },
    filteredVms(): Vm[] { const term = this.vmFilter.toLowerCase().trim(); return (this.inventory?.vms || []).filter((vm) => { const state = vm.state.toLowerCase(); const matchesTerm = !term || `${vm.name} ${vm.uuid}`.toLowerCase().includes(term); const matchesState = this.vmStateFilter === 'all' || (this.vmStateFilter === 'running' && state.includes('running')) || (this.vmStateFilter === 'paused' && state.includes('paused')) || (this.vmStateFilter === 'stopped' && !state.includes('running') && !state.includes('paused')); return matchesTerm && matchesState; }); },
    filteredServices(): Service[] { const term = this.serviceFilter.toLowerCase().trim(); return (this.inventory?.services || []).filter((service) => { const matchesTerm = !term || `${service.name} ${service.description}`.toLowerCase().includes(term); const matchesState = this.serviceStateFilter === 'all' || service.active === this.serviceStateFilter; return matchesTerm && matchesState; }); },
    visibleServices(): Service[] { return this.filteredServices.slice(0, this.serviceLimit); },
    filteredLogs(): string[] { const term = this.logFilter.toLowerCase().trim(); return (this.inventory?.logs || []).filter((line) => !term || line.toLowerCase().includes(term)); },
  },
  watch: {
    serviceFilter() { this.serviceLimit = 25; },
    serviceStateFilter() { this.serviceLimit = 25; },
  },
  mounted() {
    this.load();
    this.$nextTick(() => this.collapseEmptyProductNav());
  },
  beforeUnmount() { this.restoreProductNav(); },
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
    showMoreServices() { this.serviceLimit += 25; },
    async request(path: string, options: RequestInit = {}) {
      const response = await fetch(`${apiBase}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...options.headers }, credentials: 'include', cache: 'no-store' });
      if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail || `API request failed (${response.status})`); }
      return response.status === 204 ? null : response.json();
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
      this.loading = true; this.error = ''; this.actionError = ''; this.actionSuccess = false;
      try {
        const [hosts, inventory] = await Promise.all([this.request('/hosts'), this.request(`/hosts/${this.hostId}/cloud-native`)]);
        this.host = hosts.find((item: Host) => item.id === this.hostId) || null;
        if (!this.host) throw new Error(this.t('cloudNative.hostRemoved'));
        this.inventory = inventory;
        this.dataUpdatedAt = new Date().toISOString();
      } catch (error) { this.error = (error as Error).message; }
      finally { this.loading = false; }
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
    async actOnService(service: Service, action: 'start' | 'stop' | 'restart') {
      const labelKey = action === 'stop' ? 'stop' : action === 'restart' ? 'restart' : 'start';
      if (!window.confirm(this.t('cloudNative.confirmService', { action: this.t(`cloudNative.${labelKey}`).toLowerCase(), name: service.name }))) return;
      this.busy = service.name; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/services/actions?service_name=${encodeURIComponent(service.name)}`, { method: 'POST', body: JSON.stringify({ action }) }); await this.refreshServiceInventory(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnRepository(alias: string, action: 'enable' | 'disable' | 'refresh') {
      const confirmation = action === 'refresh'
        ? this.t('cloudNative.confirmRepositoryRefresh')
        : this.t('cloudNative.confirmRepositoryChange', { action: this.t(`cloudNative.${action}`).toLowerCase(), alias });
      if (!window.confirm(confirmation)) return;
      this.busy = action === 'refresh' ? 'repositories' : alias; this.actionError = ''; this.actionSuccess = false;
      try { await this.request(`/hosts/${this.hostId}/repositories/actions`, { method: 'POST', body: JSON.stringify({ alias, action }) }); await this.load(); this.actionSuccess = true; }
      catch (error) { this.actionError = (error as Error).message; }
      finally { this.busy = ''; }
    },
    async actOnAccount(account: Account, action: 'lock' | 'unlock') {
      if (!window.confirm(this.t('cloudNative.confirmAccountAction', { action: this.t(`cloudNative.${action}`).toLowerCase(), username: account.username }))) return;
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
      try { const details: VmDetail = await this.request(`/hosts/${this.hostId}/vms/detail?vm_name=${encodeURIComponent(vm.name)}`); this.vmDetail = details; this.updateVmFromDetails(details); }
      catch (error) { this.vmDetailError = (error as Error).message; }
      finally { this.vmDetailLoading = false; }
    },
    closeVmDetails() { this.selectedVmName = ''; this.vmDetail = null; this.vmDetailError = ''; },
    logLineClass(line: string) { return /\b(err|error|failed|critical|panic)\b/i.test(line) ? 'log-error' : /\b(warn|warning)\b/i.test(line) ? 'log-warning' : ''; },
    usageClass(value: string) { const percent = Number.parseInt(value, 10); return percent >= 90 ? 'usage-high' : percent >= 75 ? 'usage-medium' : 'usage-normal'; },
    selectTab(tab: string) { this.activeTab = tab; },
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
.admin-layout { display:grid; grid-template-columns:224px minmax(0,1fr); align-items:start; gap:24px; }
.admin-tabs { position:sticky; top:16px; display:flex; flex-direction:column; gap:18px; min-width:0; max-height:calc(100vh - 32px); overflow-y:auto; padding:12px 10px 16px 0; border-right:1px solid var(--cn-border); }
.nav-group { display:grid; gap:3px; }
.nav-group h2 { margin:0 0 5px; padding:0 12px; color:var(--cn-muted); font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; }
.admin-tabs button { display:grid; grid-template-columns:22px minmax(0,1fr) auto; align-items:center; gap:9px; width:100%; border:0; border-radius:5px; padding:9px 11px; color:var(--body-text,#dce1e8); background:transparent; cursor:pointer; text-align:left; font-size:13px; }
.admin-tabs button:hover { background:rgba(140,160,190,.12); }
.admin-tabs button.active { color:var(--body-text,#f1f5f9); background:rgba(95,150,125,.23); box-shadow:inset 3px 0 #65c99a; font-weight:600; }
.admin-tabs .nav-icon { color:var(--cn-muted); font-size:16px; text-align:center; }
.admin-tabs button.active .nav-icon { color:#65c99a; }
.nav-count,.count-badge { justify-self:end; min-width:18px; border-radius:10px; padding:2px 6px; color:var(--body-text,#dce1e8); background:rgba(140,160,190,.18); font-size:10px; text-align:center; }
.admin-content { min-width:0; }
.section-panel h2 { margin:4px 0 6px; font-size:21px; font-weight:600; letter-spacing:-.015em; }
.section-panel h3 { margin:0 0 14px; font-size:15px; font-weight:600; }
.updated-at { color:var(--cn-muted); font-size:12px; }
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
.search-input { min-width:190px; max-width:270px; border:1px solid var(--cn-border); border-radius:var(--border-radius, 4px); padding:9px 11px; color:var(--body-text,#e5e7eb) !important; background:var(--body-bg,#252b33) !important; font-size:13px; }
.search-input:focus { border-color:#5288e5; outline:2px solid rgba(55,112,215,.13); }
.filter-bar { flex-wrap:wrap; justify-content:flex-end; }
.pagination-row { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:11px 3px; color:var(--cn-muted); font-size:12px; }
.safety-note { margin:12px 2px; color:var(--cn-muted); font-size:12px; }
.security-panel { max-width:720px; }.security-panel h3 { margin:0 0 10px; }.security-actions { margin-top:16px; }
.status-view { max-height:55vh; overflow:auto; padding:16px; border:1px solid var(--cn-border); border-radius:6px; color:var(--body-text,#e5e7eb); background:rgba(12,18,27,.72); white-space:pre-wrap; overflow-wrap:anywhere; font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; }
.resource-actions { display:flex; flex-wrap:wrap; gap:6px; margin-top:14px; }
.terminal-form { display:grid; justify-items:start; gap:10px; }.terminal-form label { font-weight:600; }.terminal-input { width:100%; max-width:900px; font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }.terminal-result { margin-top:22px; }.terminal-result-header { display:flex; justify-content:space-between; gap:12px; margin-bottom:8px; }.ready-text { color:#67d391; }.error-text { color:#ff9690; }
.usage-pill { display:inline-block; border-radius:12px; padding:3px 8px; font-size:11px; font-weight:600; }.usage-normal { color:#287447; background:#e8f6ed; }.usage-medium { color:#8b5a00; background:#fff4db; }.usage-high { color:#a52822; background:#fdeceb; }
.empty-state { padding:20px; border:1px dashed var(--cn-border); border-radius:7px; color:var(--cn-muted); text-align:center; font-size:13px; }
.log-view { max-height:65vh; overflow:auto; margin:0; padding:18px; border:1px solid #263345; border-radius:8px; background:#111a27; color:#d6dfeb; font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }
.log-error { color:#ff9892; }.log-warning { color:#ffd27d; }
.banner { margin:14px 0; padding:13px 15px; border-radius:6px; }.banner.error { color:#8f211a; background:#fff0ee; }.banner.warning { color:#6b4d0c; background:#fff7db; }
.loading { padding:48px; color:var(--cn-muted); text-align:center; }
.modal-backdrop { position:fixed; z-index:1000; inset:0; display:flex; justify-content:flex-end; background:rgba(15,24,38,.38); }
.details-modal { width:min(560px,100vw); height:100%; overflow:auto; padding:26px; background:var(--cn-panel); box-shadow:-12px 0 40px rgba(15,24,38,.18); }
.account-password-modal { width:min(460px,100vw); align-self:center; margin:auto; padding:24px; border:1px solid var(--cn-border); border-radius:8px; color:var(--body-text,#e5e7eb); background:var(--body-bg,#252b33); box-shadow:0 16px 48px rgba(0,0,0,.35); }.account-password-modal form,.account-password-modal label { display:grid; gap:12px; }.account-password-modal h2 { margin:0 0 20px; font-size:18px; }.modal-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:8px; }
.details-modal>header { display:flex; justify-content:space-between; align-items:flex-start; padding-bottom:18px; border-bottom:1px solid var(--cn-border); }.details-modal h2 { margin:5px 0; font-size:22px; }
.close-button { border:0; color:var(--cn-muted); background:transparent; cursor:pointer; font-size:28px; }
.details-content h3 { margin:24px 0 10px; font-size:14px; }.detail-stats { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin:18px 0; }.detail-stats>div { display:flex; flex-direction:column; gap:6px; padding:12px; border:1px solid var(--cn-border); border-radius:6px; }.detail-stats span,.detail-row small { color:var(--cn-muted); font-size:11px; }.detail-stats strong { font-size:14px; }.detail-row { display:grid; grid-template-columns:70px 1fr; gap:4px 10px; padding:11px 0; border-bottom:1px solid var(--cn-border); font-size:12px; overflow-wrap:anywhere; }.detail-row small { grid-column:2; }
@media (max-width:1100px) { .cluster-summary { grid-template-columns:repeat(2,minmax(0,1fr)); } }
@media (max-width:1000px) { .admin-layout { grid-template-columns:190px minmax(0,1fr); gap:16px; } }
@media (max-width:820px) { .page-header,.section-heading { align-items:flex-start; flex-direction:column; }.toolbar { flex-wrap:wrap; }.filter-bar { justify-content:flex-start; }.overview-grid { grid-template-columns:1fr; }.admin-layout { display:block; }.admin-tabs { position:static; flex-direction:row; max-height:none; overflow:visible; margin:0 0 20px; padding:0 0 12px; border-right:0; border-bottom:1px solid var(--cn-border); }.nav-group { min-width:190px; }.admin-tabs button { padding:8px 10px; } }
@media (max-width:560px) { .cloud-native-page { padding:18px 12px 32px; }.cluster-summary { grid-template-columns:1fr; }.host-card { flex-wrap:wrap; }.host-card .state { margin-left:48px; }.admin-tabs { overflow-x:auto; }.search-input { max-width:100%; }.detail-stats { grid-template-columns:1fr; } }
</style>
