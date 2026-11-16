import test from 'node:test';
import assert from 'node:assert/strict';
import { terminalPrefillCommand } from '../../pkg/kvm-manager/utils/terminal-prefill.ts';

test('staged bootstrap command remains editable and does not submit itself', () => {
  const command = "sudo crm cluster init --name 'ha-lab'";
  assert.equal(terminalPrefillCommand(command), command);
  assert.equal(terminalPrefillCommand(`${command}\n`), null);
  assert.equal(terminalPrefillCommand(`${command}\r`), null);
});

test('terminal prefill rejects control characters and oversized input', () => {
  assert.equal(terminalPrefillCommand('sudo crm\u0000'), null);
  assert.equal(terminalPrefillCommand('x'.repeat(2001)), null);
  assert.equal(terminalPrefillCommand(''), null);
});
