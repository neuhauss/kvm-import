import test from 'node:test';
import assert from 'node:assert/strict';
import { isSensitiveFencingParameter, validateFencingDeviceDraft, validateFencingParameterEdits } from '../../pkg/kvm-manager/utils/cluster-fencing.ts';

const base = {
  resource_id: 'fence-node-a',
  agent: 'stonith:fence_ipmilan',
  target_node: 'node-a',
  parameters: [{ key: 'ip', value: '192.0.2.20' }, { key: 'username', value: 'operator' }, { key: 'password', value: 'secret' }],
  monitor_interval: '30min',
  monitor_timeout: '120s',
};

test('validates a fencing agent and node against the current cluster membership', () => {
  const result = validateFencingDeviceDraft(base, ['node-a', 'node-b']);
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.parameters, { ip: '192.0.2.20', username: 'operator', password: 'secret' });
    assert.equal(result.target_node, 'node-a');
  }
  assert.deepEqual(validateFencingDeviceDraft({ ...base, target_node: 'stale-node' }, ['node-a', 'node-b']), { ok: false, reason: 'invalid_target' });
});

test('rejects invalid identifiers, non-STONITH agents, and extension-owned target mapping fields', () => {
  assert.deepEqual(validateFencingDeviceDraft({ ...base, resource_id: '../unsafe' }, ['node-a']), { ok: false, reason: 'invalid_id' });
  assert.deepEqual(validateFencingDeviceDraft({ ...base, agent: 'ocf:heartbeat:IPaddr2' }, ['node-a']), { ok: false, reason: 'invalid_agent' });
  assert.deepEqual(validateFencingDeviceDraft({ ...base, parameters: [...base.parameters, { key: 'pcmk_host_list', value: 'node-b' }] }, ['node-a']), { ok: false, reason: 'reserved_parameter' });
});

test('validates fencing monitor settings using the shared interval and timeout rules', () => {
  assert.deepEqual(validateFencingDeviceDraft({ ...base, monitor_timeout: '0' }, ['node-a']), { ok: false, reason: 'invalid_monitor' });
  assert.equal(validateFencingDeviceDraft({ ...base, monitor_interval: '1min', monitor_timeout: '2min' }, ['node-a']).ok, true);
});

test('masks credential-like agent parameters by default', () => {
  for (const name of ['password', 'passwd', 'api_token', 'client_secret', 'credential_file']) assert.equal(isSensitiveFencingParameter(name), true);
  for (const name of ['ip', 'lanplus', 'username', 'cipher']) assert.equal(isSensitiveFencingParameter(name), false);
});

test('fencing parameter edits retain blank existing values and only submit explicit changes', () => {
  assert.deepEqual(validateFencingParameterEdits([
    { key: 'ip', value: '', existing: true },
    { key: 'password', value: 'new-secret', existing: true },
    { key: 'lanplus', value: '1' },
  ]), { ok: true, parameters: { password: 'new-secret', lanplus: '1' }, parameter_removals: [] });
  assert.deepEqual(validateFencingParameterEdits([
    { key: 'ip', value: '', existing: true, remove: true },
    { key: 'password', value: '', existing: true },
  ]), { ok: true, parameters: {}, parameter_removals: ['ip'] });
});

test('fencing parameter edits reject no-op, malformed, duplicate, and target-mapping changes', () => {
  assert.deepEqual(validateFencingParameterEdits([{ key: 'ip', value: '', existing: true }]), { ok: false, reason: 'no_changes' });
  assert.deepEqual(validateFencingParameterEdits([{ key: 'ip', value: '', existing: true, remove: true }, { key: 'ip', value: '1.2.3.4' }]), { ok: false, reason: 'invalid_parameters' });
  assert.deepEqual(validateFencingParameterEdits([{ key: 'pcmk_host_list', value: 'node-a' }]), { ok: false, reason: 'reserved_parameter' });
});
