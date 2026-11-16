import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const component = readFileSync(new URL('../../pkg/kvm-manager/pages/Clusters.vue', import.meta.url), 'utf8');

test('cluster plans render without waiting for the SSH readiness fan-out', () => {
  const start = component.indexOf('async load() {');
  const end = component.indexOf('async fetchQnetdWitnesses()', start);
  assert.notEqual(start, -1);
  const load = component.slice(start, end);
  assert.match(load, /const readinessTask = this\.fetchReadiness\(\)/);
  assert.match(load, /Promise\.all\(\[this\.fetchPermissions\(\), this\.fetchClusterPlans\(\), this\.fetchManagedSuseHaClusters\(\), this\.fetchQnetdWitnesses\(\)\]\)/);
  assert.match(load, /this\.loading = false; this\.loaded = true;/);
  assert.match(load, /finally\(\(\) => \{ this\.readinessLoading = false; \}\)/);
  assert.doesNotMatch(load, /Promise\.all\(\[this\.fetchReadiness\(\)/);
});

test('cluster page shows separate live-readiness progress and prevents overlapping refreshes', () => {
  assert.match(component, /v-if="readinessLoading"[^>]*role="status"/);
  assert.match(component, /:disabled="loading \|\| readinessLoading \|\| refreshingStale"/);
  assert.match(component, /if \(this\.refreshingStale \|\| this\.readinessLoading \|\| !this\.hosts\.length\) return/);
  assert.match(component, /this\.load\(\)\.then\(\(\) => this\.resumeVirtualDomainOperation\(\)\)/);
});
