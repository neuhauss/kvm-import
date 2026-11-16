import assert from 'node:assert/strict';
import test from 'node:test';
import {
  qnetdWitnessFingerprintRequest,
  qnetdWitnessFingerprintSignature,
  qnetdWitnessVerificationPayload,
} from '../../pkg/kvm-manager/utils/qnetd-witness-onboarding.ts';

const draft = {
  name: 'lab witness', address: '  witness.suse.test ', port: 2222,
  username: 'qnetd-admin', password: 'never-send-before-confirmation',
};

test('SSH identity discovery sends only the endpoint, never the account or password', () => {
  const payload = qnetdWitnessFingerprintRequest(draft);
  assert.deepEqual(payload, { name: 'lab witness', address: 'witness.suse.test', port: 2222 });
  assert.equal('username' in payload, false);
  assert.equal('password' in payload, false);
});

test('fingerprint identity stays tied to endpoint while ignoring secret edits', () => {
  assert.equal(qnetdWitnessFingerprintSignature(draft), qnetdWitnessFingerprintSignature({ ...draft, password: 'changed' }));
  assert.notEqual(qnetdWitnessFingerprintSignature(draft), qnetdWitnessFingerprintSignature({ ...draft, address: 'other.suse.test' }));
});

test('readiness credentials cannot be sent before explicit fingerprint confirmation', () => {
  assert.throws(() => qnetdWitnessVerificationPayload(draft, 'SHA256:abcdefghijklmnopqrstuvwx', false), /Confirm the SSH host fingerprint/);
  assert.throws(() => qnetdWitnessVerificationPayload(draft, '', true), /Confirm the SSH host fingerprint/);
  assert.deepEqual(qnetdWitnessVerificationPayload(draft, 'SHA256:abcdefghijklmnopqrstuvwx', true), {
    name: 'lab witness', address: 'witness.suse.test', port: 2222,
    username: 'qnetd-admin', password: 'never-send-before-confirmation',
    expected_fingerprint: 'SHA256:abcdefghijklmnopqrstuvwx',
  });
});
