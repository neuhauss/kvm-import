import test from 'node:test';
import assert from 'node:assert/strict';
import { aggregateWorkloadServiceAvailability, clusterResourceDraftForTemplate, clusterTemplateAgentsPresent, clusterTemplateRequiredAgents, workloadServiceInstalled, workloadServiceRequirementFit } from '../../pkg/kvm-manager/utils/cluster-resource-templates.ts';

test('NFS profile requires the complete SUSE reference agent set, including DRBD replication', () => {
  assert.deepEqual(clusterTemplateRequiredAgents('nfs', 'drbd'), [
    'linbit:drbd', 'heartbeat:Filesystem', 'heartbeat:nfsserver', 'heartbeat:exportfs', 'heartbeat:IPaddr2',
  ]);
  assert.deepEqual(clusterTemplateRequiredAgents('nfs', 'shared'), [
    'heartbeat:Filesystem', 'heartbeat:nfsserver', 'heartbeat:exportfs', 'heartbeat:IPaddr2',
  ]);
  const agents = ['linbit:drbd', 'heartbeat:Filesystem', 'heartbeat:nfsserver', 'heartbeat:exportfs', 'heartbeat:IPaddr2'];
  assert.equal(clusterTemplateAgentsPresent('nfs', [agents, agents], 'drbd'), true);
  assert.equal(clusterTemplateAgentsPresent('nfs', [agents, agents.filter((agent) => agent !== 'linbit:drbd')], 'drbd'), false);
  assert.equal(clusterTemplateAgentsPresent('nfs', [agents.filter((agent) => agent !== 'linbit:drbd')], 'shared'), true);
});

test('templates only suggest SUSE HA agents reported by the selected live cluster', () => {
  const available = ['ocf:heartbeat:VirtualDomain', 'ocf:heartbeat:apache', 'ocf:heartbeat:Filesystem'];

  assert.deepEqual(clusterResourceDraftForTemplate('vm', available), {
    resource_id: 'ha-vm', agent: 'ocf:heartbeat:VirtualDomain',
    suggested_agent: 'ocf:heartbeat:VirtualDomain', suggested_agent_unavailable: false,
  });
  assert.deepEqual(clusterResourceDraftForTemplate('web', available), {
    resource_id: 'ha-web', agent: 'ocf:heartbeat:apache',
    suggested_agent: 'ocf:heartbeat:apache', suggested_agent_unavailable: false,
  });
  assert.deepEqual(clusterResourceDraftForTemplate('nfs', available), {
    resource_id: 'ha-nfs', agent: 'ocf:heartbeat:Filesystem',
    suggested_agent: 'ocf:heartbeat:Filesystem', suggested_agent_unavailable: false,
  });
});

test('SUSE web template requires both agents from the documented Apache/VIP profile on every host', () => {
  assert.deepEqual(clusterTemplateRequiredAgents('web'), ['heartbeat:apache', 'heartbeat:IPaddr']);
  const ready = ['heartbeat:apache', 'heartbeat:IPaddr'];
  assert.equal(clusterTemplateAgentsPresent('web', [ready, ready]), true);
  assert.equal(clusterTemplateAgentsPresent('web', [ready, ['heartbeat:apache']]), false);
});

test('generic service profile asks the operator to choose its actual installed agent', () => {
  assert.deepEqual(clusterResourceDraftForTemplate('service', ['ocf:heartbeat:apache']), {
    resource_id: 'ha-service', agent: '', suggested_agent: '', suggested_agent_unavailable: false,
  });
});

test('VirtualDomain preparation uses a guided reviewed path and keeps generic creation blocked', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');
  const api = readFileSync(new URL('../../service/app.py', import.meta.url), 'utf8');
  assert.match(source, /virtualDomainPrepareReady\(\): boolean/);
  assert.match(source, /vms\/virtualdomain-prepare/);
  assert.match(source, /shared_disks_confirmed/);
  assert.match(source, /fencing_tested/);
  assert.match(source, /clusters\.vmPrepareSucceeded/);
  assert.match(api, /def virtualdomain_prepare_blockers\(/);
  assert.match(api, /def prepare_virtualdomain_vm\(/);
  assert.match(api, /create_operation_job\("cluster_virtualdomain_prepare"/);
  assert.match(api, /VirtualDomain preparation is blocked: /);
  assert.match(source, /trackOperationJob\(job/);
  assert.match(source, /resumeVirtualDomainOperation\(\)/);
  assert.match(source, /kvm-virtualdomain-prepare-job/);
  assert.match(api, /VirtualDomain resources must use the guided VM preflight/);
  assert.match(api, /target-role="Stopped"/);
  assert.match(api, /order '\+order_id\+' Mandatory: '\+lock_clone\+' '\+rid/);
  assert.match(api, /colocation '\+coloc_id\+' inf: '\+rid\+' '\+lock_clone/);
});

test('a missing suggested agent is never submitted as a hidden default', () => {
  const draft = clusterResourceDraftForTemplate('vm', ['ocf:heartbeat:apache']);
  assert.equal(draft.agent, '');
  assert.equal(draft.suggested_agent_unavailable, true);
});

test('HA workload readiness checks installation, not whether the service is currently active', () => {
  const stoppedButInstalled = {
    workload_service_units: { nfsserver: { unit: 'nfs-server.service', installed: true, active: 'inactive' } },
    workload_services: { nfsserver: false },
  };
  assert.equal(workloadServiceInstalled(stoppedButInstalled, 'nfsserver'), true);
  assert.equal(aggregateWorkloadServiceAvailability([true, true]), true);
  assert.equal(aggregateWorkloadServiceAvailability([true, null]), null);
  assert.equal(aggregateWorkloadServiceAvailability([true, false]), false);
});

test('legacy API active-state false is treated as unknown, not a missing-package blocker', () => {
  assert.equal(workloadServiceInstalled({ workload_services: { apache2: false } }, 'apache2'), null);
  assert.equal(workloadServiceInstalled({ workload_services: { apache2: true } }, 'apache2'), true);
});

test('unknown service installation status requires review and never counts as template readiness', () => {
  assert.equal(workloadServiceRequirementFit(true, true), 'ready');
  assert.equal(workloadServiceRequirementFit(false, true), 'missing');
  assert.equal(workloadServiceRequirementFit(null, true), 'review_required');
  assert.equal(workloadServiceRequirementFit(null, false), 'not_checked');
});

test('template UI distinguishes an unknown service result from a missing service', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');
  assert.match(source, /applicationServiceFit === 'review_required'/);
  assert.match(source, /templateNextVerifyService/);
  assert.match(source, /hostCheck\.reviewRequired \? 'warning-state'/);
  assert.match(source, /v-model="nfsStorageMode"/);
  assert.match(source, /clusterTemplateRequiredAgents\(templateId, this\.nfsStorageMode\)/);
});

test('service template uses the reviewed service/VIP workflow instead of a generic first-resource form', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');
  assert.match(source, /templateId === 'service'.*serviceVipDraft/s);
  assert.match(source, /service-vip\/config/);
  assert.match(source, /v-model\.trim="serviceVipDraft\.service_unit"/);
  assert.match(source, /serviceVipDraft\.shared_network_confirmed/);
  assert.match(source, /serviceVipReady\(\): boolean.*status\.quorum\?\.quorate.*status\.fencing\?\.configured/s);
  assert.match(source, /serviceVipCreateStopped/);
});

test('web template opens the guided SUSE Apache profile with config and start-order review', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');
  const api = readFileSync(new URL('../../service/app.py', import.meta.url), 'utf8');
  assert.match(source, /templateId === 'service' \|\| templateId === 'web'/);
  assert.match(source, /profile: apache \? 'apache' : 'service'/);
  assert.match(source, /apache_configfile: apache \? '\/etc\/apache2\/httpd\.conf'/);
  assert.match(source, /serviceVipDraft\.apache_configfile/);
  assert.match(source, /serviceVipDraft\.apache_start_order_confirmed/);
  assert.match(source, /draft\.profile !== 'apache' \|\| \(draft\.apache_configfile\.trim\(\)\.startsWith\('\/'\) && draft\.apache_start_order_confirmed\)/);
  assert.match(source, /clusters\.apacheReviewSummary/);
  assert.match(api, /primitive \{ids\["service"\]\} apache params configfile=/);
  assert.match(api, /primitive \{ids\["vip"\]\} \{vip_agent\} params ip=/);
  assert.match(api, /group \{ids\["group"\]\} \{ordered\} meta target-role="Stopped"/);
});
