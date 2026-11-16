// Groth16 decision proving with snarkjs (gatekeeper circuit).
//
// STATUS: MAPPING CONFIRMED 2026-11-16 (local, read-only verification).
// The 13 input-signal names were read from gatekeeper.wasm itself via
// getInputSignalSize (calibrated: unknown names return 0), and fullProve +
// groth16.verify against the real vk.json was run on the synthetic VALID
// task from scripts/simulate-task.js:
//   - VALID + APPROVE (decision=1) verifies; VALID + REJECT assert-fails.
//   - Each single trap (vk mismatch, balance<minimum, expired, recipient
//     mismatch, amount>max) + APPROVE assert-fails; + REJECT verifies.
//   - decision=2 assert-fails. salt and taskId encodings are unconstrained
//     for validity (any value verifies); vk hashes only need to be
//     consistent with each other (blake2b-256 and keccak-256 both verified).
//   - There is NO proof_tx input signal: PROOF_REUSED cannot be proven in
//     this circuit (docs: REUSED tasks are excluded from the proof bonus),
//     so proveDecision must not be called for them — the server already
//     catches the assert failure and responds without a proof.
// Residual unknown: the platform-side hash convention for vk/taskId (if the
// platform re-derives expected public signals). Blake2b-256 is used here,
// matching this repo's zkVerify hashing (src/onchain.js). Worst case a
// platform-side mismatch scores the same as no proof (-2), never worse.
// Enable with GATEKEEPER_PROVE=1 (and KURIER_API_KEY for on-chain submit).
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let blake = null;
function loadBlake() {
  if (blake) return blake;
  try {
    blake = require('blakejs');
    return blake;
  } catch (err) {
    throw new Error(`blakejs unavailable: ${err.message}`);
  }
}

// Blake2b-256 of raw bytes (0x hex) or a UTF-8 string, as a decimal field
// element (mod the bn128 scalar prime).
function blake2b256Field(value) {
  const b = loadBlake();
  let bytes;
  const s = String(value);
  if (/^0x[0-9a-fA-F]+$/.test(s)) bytes = Buffer.from(s.slice(2), 'hex');
  else bytes = Buffer.from(s, 'utf8');
  const digest = b.blake2b(bytes, null, 32);
  return (BigInt('0x' + Buffer.from(digest).toString('hex')) % FIELD_PRIME).toString(10);
}
'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');

const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const VK_PATH = path.join(CIRCUITS_DIR, 'vk.json');
const MAPPING_PATH = path.join(CIRCUITS_DIR, 'input-mapping.json');

let snarkjs = null;
function loadSnarkjs() {
  if (snarkjs) return snarkjs;
  try {
    snarkjs = require('snarkjs');
    return snarkjs;
  } catch (err) {
    throw new Error(`snarkjs unavailable: ${err.message}`);
  }
}

function provingAvailable() {
  if (!config.proveDecisions) return { ok: false, reason: 'GATEKEEPER_PROVE is off' };
  if (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH) || !fs.existsSync(VK_PATH)) {
    return { ok: false, reason: 'circuit artifacts missing from circuits/' };
  }
  if (!fs.existsSync(MAPPING_PATH)) {
    return { ok: false, reason: 'circuits/input-mapping.json missing (mapping unconfirmed)' };
  }
  try {
    loadSnarkjs();
  } catch (err) {
    return { ok: false, reason: String(err.message) };
  }
  return { ok: true };
}

// Build the snarkjs input object from a task + decision using the mapping.
// Mapping format: { "<circuit signal>": "<task field path | literal>" }
// Field paths are dot paths into the task object, e.g. "input.amount".
// A value starting with "=" is a literal, e.g. "=1".
// "$decision" maps APPROVE -> "1", REJECT -> "0".
// An object {"hash":"blake2b256","from":"<dot path>"} hashes the field
// (blake2b-256, as a decimal field element mod p).
// Keys starting with "_" in the mapping file are documentation, skipped.
function buildInputs(task, decision) {
  const mapping = JSON.parse(fs.readFileSync(MAPPING_PATH, 'utf8'));
  const input = {};
  const getPath = (obj, p) => p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
  for (const [signal, spec] of Object.entries(mapping)) {
    if (signal.startsWith('_')) continue;
    let value;
    if (typeof spec === 'string' && spec.startsWith('=')) {
      value = spec.slice(1);
    } else if (spec === '$decision') {
      value = decision === 'APPROVE' ? '1' : '0';
    } else if (spec && typeof spec === 'object' && spec.hash === 'blake2b256' && typeof spec.from === 'string') {
      const raw = spec.from === 'task_id' ? task.task_id : getPath(task, spec.from);
      if (raw === undefined || raw === null || raw === '') {
        throw new Error(`mapping: no value for signal ${signal} (spec ${JSON.stringify(spec)})`);
      }
      value = blake2b256Field(raw);
    } else if (typeof spec === 'string') {
      value = getPath(task, spec);
    } else {
      value = spec;
    }
    if (value === undefined || value === null || value === '') {
      throw new Error(`mapping: no value for signal ${signal} (spec ${spec})`);
    }
    input[signal] = String(value);
  }
  return input;
}

async function proveDecision(task, decision) {
  const avail = provingAvailable();
  if (!avail.ok) throw new Error(`proving unavailable: ${avail.reason}`);
  const s = loadSnarkjs();
  const input = buildInputs(task, decision);
  const { proof, publicSignals } = await s.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  // Local sanity check against our own exported vk before trusting it.
  const vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  const valid = await s.groth16.verify(vk, publicSignals, proof);
  if (!valid) throw new Error('local proof verification failed');
  return { proof, publicSignals };
}

module.exports = { provingAvailable, proveDecision, CIRCUITS_DIR };
