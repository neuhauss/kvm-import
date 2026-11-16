import test from 'node:test';
import assert from 'node:assert/strict';
import { hostMetricsNeedRefresh } from '../../pkg/kvm-manager/utils/host-metrics.ts';

test('initial inventory metrics are not fetched again while their sample is fresh', () => {
  const now = Date.parse('2026-11-14T12:00:30.000Z');
  assert.equal(hostMetricsNeedRefresh('2026-11-14T12:00:00.001Z', now), false);
  assert.equal(hostMetricsNeedRefresh('2026-11-14T12:00:00.000Z', now), true);
});

test('missing or invalid metric timestamps trigger a refresh', () => {
  assert.equal(hostMetricsNeedRefresh(''), true);
  assert.equal(hostMetricsNeedRefresh('not-a-date', Date.now()), true);
});
