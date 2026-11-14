// Proof Gatekeeper agent — HTTP server (Node built-ins only).
// Routes:
//   GET  /health, GET /            -> status (used by the platform health check)
//   GET  /debug/last              -> last task + decision summary (no secrets)
//   POST / , POST /agent          -> signed task envelope (Proof Gatekeeper)
// Everything else -> 404.
//
// Task flow (all within the 60s hard deadline):
//   1. HMAC-verify x-agent-games-signature over the RAW body (fail closed).
//   2. Parse JSON; reject non-gatekeeper types.
//   3. Idempotency: a retried task_id returns the cached response.
//   4. Optional on-chain proof_tx lookup (time-boxed; 'unavailable' is not
//      fatal unless STRICT_ONCHAIN=1).
//   5. Deterministic decision (src/decision.js) — APPROVE only when every
//      check passes; otherwise REJECT with the specific trap reason_code.
//   6. On APPROVE, record proof_tx in the seen-set (PROOF_REUSED guard).
//   7. Optional Groth16 decision proof (off by default; see src/prover.js).
//   8. Respond { decision, reason_code, proof_tx } signed with
//      x-agent-games-signature over the raw response body.
//   9. Cache the response by task_id; append to the decision log.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const hmac = require('./hmac');
const { decide, TASK_TYPE } = require('./decision');
const { loadSeen, saveSeen, appendLog } = require('./store');
const { lookupProofTx } = require('./onchain');
const kurier = require('./kurier');
const prover = require('./prover');

const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB — task envelopes are ~1 KiB
const RESPONSE_CACHE_LIMIT = 1000;

const dataDir = path.resolve(config.dataDir);
const responsesPath = path.join(dataDir, 'responses.json');
const seenPath = path.resolve(config.seenFile);
const logPath = path.resolve(config.logFile);

fs.mkdirSync(dataDir, { recursive: true });
const seenSet = loadSeen(seenPath);
let responseCache = new Map();
try {
  const raw = fs.readFileSync(responsesPath, 'utf8');
  const obj = JSON.parse(raw);
  if (obj && typeof obj === 'object') responseCache = new Map(Object.entries(obj));
} catch (_) {}

let lastTask = null;

function saveResponses() {
  try {
    const entries = [...responseCache.entries()].slice(-RESPONSE_CACHE_LIMIT);
    responseCache = new Map(entries);
    const tmp = `${responsesPath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(entries)));
    fs.renameSync(tmp, responsesPath);
  } catch (err) {
    console.error('[server] failed to save response cache:', err.message);
  }
}

function log(level, msg, extra) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}` +
    (extra ? ' ' + JSON.stringify(extra) : '');
  console.log(line);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, obj, secret) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'Content-Type': 'application/json' };
  if (secret) headers['x-agent-games-signature'] = hmac.signResponseBody(secret, body);
  res.writeHead(statusCode, headers);
  res.end(body);
}

async function handleTask(req, res) {
  const started = Date.now();
  const secret = config.hmacSecret;
  if (!secret) {
    log('WARN', 'task POST rejected: AGENT_GAMES_HMAC_SECRET not configured');
    return sendJson(res, 401, { error: 'agent_hmac_not_configured' });
  }
  let raw;
  try {
    raw = await readRawBody(req);
  } catch (err) {
    return sendJson(res, 400, { error: 'bad_body', detail: err.message }, secret);
  }
  const signature = req.headers['x-agent-games-signature'] || '';
  if (!hmac.verifyRequestSignature(secret, raw, signature)) {
    log('WARN', 'task POST rejected: bad HMAC signature');
    return sendJson(res, 401, { error: 'bad_signature' }, secret);
  }
  let task;
  try {
    task = JSON.parse(raw.toString('utf8'));
  } catch (_) {
    return sendJson(res, 400, { error: 'invalid_json' }, secret);
  }
  if (!task || task.type !== TASK_TYPE) {
    log('WARN', 'unsupported task type', { type: task && task.type });
    return sendJson(res, 400, { error: 'unsupported_task_type' }, secret);
  }
  const taskId = task.task_id || '';
  const proofTx = String((task.input && task.input.proof_tx) || '').toLowerCase();
  if (!taskId) return sendJson(res, 400, { error: 'missing_task_id' }, secret);

  // Idempotency: the platform may retry after a network failure. A retry
  // returns the exact same response without re-deciding or re-recording.
  if (responseCache.has(taskId)) {
    const cached = responseCache.get(taskId);
    log('INFO', 'task retry — returning cached response', { task_id: taskId });
    return sendJson(res, 200, cached, secret);
  }

  // Optional on-chain lookup, strictly time-boxed so the 60s deadline is
  // never threatened by a slow RPC.
  let onchain = { status: 'unavailable', detail: 'lookup skipped' };
  if (config.onchainScanBlocks > 0) {
    try {
      onchain = await Promise.race([
        lookupProofTx(proofTx, String((task.input && task.input.registered_vk) || '')),
        new Promise((resolve) =>
          setTimeout(() => resolve({ status: 'unavailable', detail: 'lookup timeout' }), config.onchainTimeoutMs)
        ),
      ]);
    } catch (err) {
      onchain = { status: 'unavailable', detail: String(err.message || err) };
    }
  }
  if (onchain.status === 'unavailable' && config.strictOnchain) {
    onchain = { status: 'not_found', detail: 'strict mode: unavailable lookup treated as unconfirmed' };
  }

  const result = decide(task, seenSet, onchain);

  // PROOF_REUSED guard: only APPROVED proofs enter the seen-set.
  if (result.decision === 'APPROVE' && proofTx) {
    seenSet.add(proofTx);
    try { saveSeen(seenPath, seenSet); } catch (err) {
      log('ERROR', 'failed to persist seen-set', { error: err.message });
    }
  }

  const response = {
    decision: result.decision,
    reason_code: result.reason_code,
    proof_tx: proofTx,
  };

  // Optional Groth16 decision proof (off by default). A failure here must
  // never break the decision response.
  const prove = prover.provingAvailable();
  if (prove.ok) {
    try {
      const { proof, publicSignals } = await prover.proveDecision(task, result.decision);
      response.proof = proof;
      response.public_signals = publicSignals;
      if (config.kurierApiKey) {
        try {
          const sub = await kurier.submitProof(proof, publicSignals, config.gatekeeperVkHash);
          if (sub && sub.jobId) {
            response.proofReference = sub.jobId;
            // Do not block the 60s response on finalization; poll in the
            // background and log the outcome.
            kurier.waitFinalized(sub.jobId).then(
              (st) => log('INFO', 'kurier proof finalized', { task_id: taskId, status: st && st.status }),
              (e) => log('WARN', 'kurier finalize failed', { task_id: taskId, error: e.message })
            );
          }
        } catch (e) {
          log('WARN', 'kurier submit-proof failed', { task_id: taskId, error: e.message });
        }
      }
    } catch (e) {
      log('WARN', 'decision proving failed — responding without proof', { task_id: taskId, error: e.message });
    }
  }

  responseCache.set(taskId, response);
  saveResponses();
  lastTask = {
    task_id: taskId,
    mode: task.mode || null,
    received_at: new Date(started).toISOString(),
    ms: Date.now() - started,
    onchain: onchain.status,
    decision: result.decision,
    reason_code: result.reason_code,
    checks: result.checks,
  };
  appendLog(logPath, lastTask);
  log('INFO', 'task decided', {
    task_id: taskId, mode: task.mode || null, decision: result.decision,
    reason_code: result.reason_code, onchain: onchain.status, ms: Date.now() - started,
  });
  return sendJson(res, 200, response, secret);
}

function statusPayload() {
  return {
    status: 'ok',
    agent: config.agentName,
    track: 'proof-gatekeeper',
    time: new Date().toISOString(),
    hmac_configured: Boolean(config.hmacSecret),
    kurier_configured: Boolean(config.kurierApiKey),
    proving: prover.provingAvailable(),
    onchain_scan_blocks: config.onchainScanBlocks,
    seen_proofs: seenSet.size,
    decisions_logged: fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).length : 0,
  };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
      return sendJson(res, 200, statusPayload());
    }
    if (req.method === 'GET' && url.pathname === '/debug/last') {
      return sendJson(res, 200, { last: lastTask });
    }
    if (req.method === 'POST' && (url.pathname === '/' || url.pathname === '/agent')) {
      return await handleTask(req, res);
    }
    return sendJson(res, 404, { error: 'not_found' });
  } catch (err) {
    log('ERROR', 'unhandled request error', { error: err.message });
    try { sendJson(res, 500, { error: 'internal' }); } catch (_) {}
  }
});

server.listen(config.port, config.host, () => {
  log('INFO', `agent ${config.agentName} listening on ${config.host}:${config.port}`);
  log('INFO', 'config', {
    hmac_configured: Boolean(config.hmacSecret),
    kurier_configured: Boolean(config.kurierApiKey),
    proving: prover.provingAvailable(),
    strict_onchain: config.strictOnchain,
    onchain_scan_blocks: config.onchainScanBlocks,
    seen_proofs: seenSet.size,
    cached_responses: responseCache.size,
  });
  if (!config.hmacSecret) {
    log('WARN', 'AGENT_GAMES_HMAC_SECRET is not set — task POSTs will be rejected with 401 until it is configured. GET /health still answers.');
  }
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
