// Local end-to-end test: starts the agent with a TEST HMAC secret, signs a
// task envelope for each of the 7 documented trap varieties (+ a valid one),
// POSTs them, and checks the decisions. No platform access needed.
// Run: npm run simulate   (expects the agent to build/start locally)
'use strict';

const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');

const TEST_SECRET = 'test-secret-do-not-use-in-production';
const PORT = 3100;
const BASE = `http://127.0.0.1:${PORT}`;

const now = new Date();
const issued = now.toISOString();
const deadline = new Date(now.getTime() + 60000).toISOString();

const VK = '0x7d3a11111111111111111111111111111111111111111111111111111111f291';
const PROOF_TX = '0xa4c1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8ff1';
const RECIPIENT = '0xDe4200000000000000000000000000000000009f01';

function baseTask(overrides = {}) {
  const input = {
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
  };
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_1',
    mode: 'practice',
    issued_at: issued,
    deadline_at: deadline,
    input,
    ...(overrides.task || {}),
  };
}

const CASES = [
  {
    name: 'VALID_CONDITION',
    task: baseTask(),
    expect: { decision: 'APPROVE', reason_code: 'VALID_CONDITION' },
  },
  {
    name: 'VK_SUBSTITUTION',
    task: baseTask({ task: { task_id: 'gk_test_2' }, input: { proof_vk: '0xa4c1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb8ff' } }),
    expect: { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' },
  },
  {
    name: 'THRESHOLD_MISMATCH',
    task: baseTask({ task: { task_id: 'gk_test_3' }, input: { public_balance: '900', proof_tx: '0xa4c1cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc8ff1' } }),
    expect: { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' },
  },
  {
    name: 'PROOF_REUSED (same proof_tx as VALID case, already approved)',
    task: baseTask({ task: { task_id: 'gk_test_4' } }),
    expect: { decision: 'REJECT', reason_code: 'PROOF_REUSED' },
  },
  {
    name: 'EXPIRED_CONDITION',
    task: baseTask({ task: { task_id: 'gk_test_5' }, input: { current_block: 19842201, proof_tx: '0xa4c1dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd8ff1' } }),
    expect: { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' },
  },
  {
    name: 'RECIPIENT_MISMATCH',
    task: baseTask({ task: { task_id: 'gk_test_6' }, input: { recipient: '0xDe4300000000000000000000000000000000009f02', proof_tx: '0xa4c1eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee8ff1' } }),
    expect: { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' },
  },
  {
    name: 'AMOUNT_OVERFLOW',
    task: baseTask({ task: { task_id: 'gk_test_7' }, input: { amount: '1500', proof_tx: '0xa4c1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8ff1' } }),
    expect: { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' },
  },
];

function sign(bodyBuffer) {
  return crypto.createHmac('sha256', TEST_SECRET).update(bodyBuffer).digest('hex');
}

async function postTask(task, secret = TEST_SECRET) {
  const body = Buffer.from(JSON.stringify(task));
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-agent-games-signature': crypto.createHmac('sha256', secret).update(body).digest('hex'),
    },
    body,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) {}
  return { status: res.status, json, signature: res.headers.get('x-agent-games-signature') };
}

async function waitHealth(tries = 30) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

async function main() {
  const server = spawn('node', ['src/server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: TEST_SECRET,
      DATA_DIR: 'data-test',
      ONCHAIN_SCAN_BLOCKS: '0',
      GATEKEEPER_PROVE: '0',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d; });
  server.stderr.on('data', (d) => { serverLog += d; });

  let failures = 0;
  try {
    if (!(await waitHealth())) {
      console.error('FAIL: server did not become healthy');
      console.error(serverLog);
      process.exitCode = 1;
      return;
    }
    console.log('server healthy');

    for (const c of CASES) {
      const { status, json, signature } = await postTask(c.task);
      const ok =
        status === 200 &&
        json &&
        json.decision === c.expect.decision &&
        json.reason_code === c.expect.reason_code &&
        Boolean(signature);
      console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name}: HTTP ${status} -> ${json && json.decision}/${json && json.reason_code} (expected ${c.expect.decision}/${c.expect.reason_code})${signature ? ' + signed' : ' UNSIGNED'}`);
      if (!ok) failures++;
    }

    // Bad HMAC must be rejected.
    const bad = await postTask(CASES[0].task, 'wrong-secret');
    const badOk = bad.status === 401;
    console.log(`${badOk ? 'PASS' : 'FAIL'} BAD_HMAC: HTTP ${bad.status} (expected 401)`);
    if (!badOk) failures++;

    // Retry of the first task must return the cached identical response.
    const retry = await postTask(CASES[0].task);
    const retryOk = retry.status === 200 && retry.json && retry.json.decision === 'APPROVE';
    console.log(`${retryOk ? 'PASS' : 'FAIL'} IDEMPOTENT_RETRY: HTTP ${retry.status} -> ${retry.json && retry.json.decision}/${retry.json && retry.json.reason_code}`);
    if (!retryOk) failures++;

    console.log(failures === 0 ? 'ALL SIMULATED CASES PASSED' : `${failures} FAILURES`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    server.kill('SIGTERM');
  }
}

main().catch((err) => {
  console.error('simulate crashed:', err);
  process.exit(1);
});
