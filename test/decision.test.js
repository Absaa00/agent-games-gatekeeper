// Unit tests for the decision engine (no server, no network).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { decide } = require('../src/decision');

const VK = '0x7d3a11111111111111111111111111111111111111111111111111111111f291';
const PROOF_TX = '0xa4c1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8ff1';
const RECIPIENT = '0xDe4200000000000000000000000000000000009f01';

function task(overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_unit_1',
    mode: 'competition',
    issued_at: '2026-11-15T17:30:00.000Z',
    deadline_at: '2026-11-15T17:31:00.000Z',
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: PROOF_TX,
      ...(overrides.input || {}),
    },
    ...(overrides.task || {}),
  };
}

test('valid condition approves', () => {
  const r = decide(task(), new Set(), null);
  assert.equal(r.decision, 'APPROVE');
  assert.equal(r.reason_code, 'VALID_CONDITION');
});

test('vk substitution rejects', () => {
  const r = decide(task({ input: { proof_vk: '0x0000000000000000000000000000000000000000000000000000000000000000' } }), new Set(), null);
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.reason_code, 'VK_SUBSTITUTION');
});

test('threshold mismatch rejects', () => {
  const r = decide(task({ input: { public_balance: '999' } }), new Set(), null);
  assert.equal(r.reason_code, 'THRESHOLD_MISMATCH');
});

test('reused proof rejects', () => {
  const seen = new Set([PROOF_TX.toLowerCase()]);
  const r = decide(task(), seen, null);
  assert.equal(r.reason_code, 'PROOF_REUSED');
});

test('expired condition rejects', () => {
  const r = decide(task({ input: { current_block: 19842201 } }), new Set(), null);
  assert.equal(r.reason_code, 'EXPIRED_CONDITION');
});

test('recipient mismatch rejects', () => {
  const r = decide(task({ input: { recipient: '0xDe4300000000000000000000000000000000009f02' } }), new Set(), null);
  assert.equal(r.reason_code, 'RECIPIENT_MISMATCH');
});

test('amount overflow rejects', () => {
  const r = decide(task({ input: { amount: '1001' } }), new Set(), null);
  assert.equal(r.reason_code, 'AMOUNT_OVERFLOW');
});

test('on-chain not_found fails closed', () => {
  const r = decide(task(), new Set(), { status: 'not_found' });
  assert.equal(r.decision, 'REJECT');
});

test('on-chain unavailable still decides from payload', () => {
  const r = decide(task(), new Set(), { status: 'unavailable' });
  assert.equal(r.decision, 'APPROVE');
});

test('malformed task rejects without crashing', () => {
  const r = decide({ type: 'something.else' }, new Set(), null);
  assert.equal(r.decision, 'REJECT');
  assert.equal(r.reason_code, 'INVALID_TASK');
});
