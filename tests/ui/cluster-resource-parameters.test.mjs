import test from 'node:test';
import assert from 'node:assert/strict';
import { resourceParametersFromRows } from '../../pkg/kvm-manager/utils/cluster-resource-parameters.ts';

test('builds a parameter map and ignores unused blank rows', () => {
  assert.deepEqual(resourceParametersFromRows([
    { key: '', value: '' },
    { key: 'ip', value: '192.0.2.10' },
    { key: 'cidr_netmask', value: '24' },
  ]), { ok: true, parameters: { ip: '192.0.2.10', cidr_netmask: '24' } });
});

test('rejects malformed names, empty values and multiline values with a row number', () => {
  for (const row of [
    { key: 'bad key', value: 'x' },
    { key: 'ip', value: '' },
    { key: 'ip', value: 'first\nsecond' },
  ]) assert.deepEqual(resourceParametersFromRows([row]), { ok: false, reason: 'invalid_row', row: 1 });
});

test('rejects duplicate parameters and more than forty populated rows', () => {
  assert.deepEqual(resourceParametersFromRows([{ key: 'ip', value: '192.0.2.1' }, { key: 'ip', value: '192.0.2.2' }]), { ok: false, reason: 'duplicate_key', row: 2 });
  const rows = Array.from({ length: 41 }, (_, index) => ({ key: `param_${index}`, value: String(index) }));
  assert.deepEqual(resourceParametersFromRows(rows), { ok: false, reason: 'too_many' });
});
