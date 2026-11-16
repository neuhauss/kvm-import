import test from 'node:test';
import assert from 'node:assert/strict';
import { apiErrorDetail } from '../../pkg/kvm-manager/utils/api-errors.ts';

test('reads nested object detail without rendering [object Object]', () => {
  assert.equal(apiErrorDetail({ detail: { message: 'Preflight could not connect to host' } }), 'Preflight could not connect to host');
});

test('formats FastAPI validation errors with field locations', () => {
  assert.equal(apiErrorDetail({ detail: [{ loc: ['body', 'host_ids'], msg: 'Field required' }] }), 'host_ids: Field required');
});

test('keeps opaque objects from becoming the literal [object Object]', () => {
  assert.equal(apiErrorDetail({ error: { unexpected: { value: true } } }), '');
});

test('discards already-coerced opaque object strings so the UI can show its localized fallback', () => {
  assert.equal(apiErrorDetail({ detail: '[object Object]' }), '');
  assert.equal(apiErrorDetail({ error: '[object Array]' }), '');
});

test('redacts secret-like values in structured API details', () => {
  assert.equal(apiErrorDetail({ detail: { error: 'regcode: PRIVATE-123 failed' } }), 'regcode: [redacted] failed');
});
