// Groth16 decision proving with snarkjs (gatekeeper circuit).
//
// STATUS: DISABLED BY DEFAULT — see config.js GATEKEEPER_PROVE.
// The public docs publish the circuit artifacts (wasm/zkey) and the vkHash,
// but they do NOT publish the circuit's input-signal mapping (which task
// fields feed which circuit signals) nor the exact response field names for
// the proof. Generating a proof with a guessed mapping produces an invalid
// proof, which scores the same as no proof (-2, no bonus) and risks nothing
// extra — but a wrong proof is still a wrong proof, so this module refuses
// to run until a mapping is supplied in circuits/input-mapping.json.
//
// To enable proving after the mapping is confirmed (practice-mode feedback,
// platform docs, or the circuit source):
//   1. Copy circuits/input-mapping.json.example to circuits/input-mapping.json
//      and fill in the real signal names.
//   2. Set GATEKEEPER_PROVE=1 and KURIER_API_KEY.
//   3. Restart. The server then attaches { proof, public_signals } to each
//      response and submits the proof to Kurier, adding `proofReference`.
//
// UNCONFIRMED HYPOTHESIS (do NOT use without confirmation): the circuit has
// 13 public inputs and the task carries 11 input fields + task_id + the
// decision = 13 values. That count match is suggestive but NOT evidence of
// the mapping (inputs may be hashes, and the order is unknown).
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
function buildInputs(task, decision) {
  const mapping = JSON.parse(fs.readFileSync(MAPPING_PATH, 'utf8'));
  const input = {};
  const getPath = (obj, p) => p.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
  for (const [signal, spec] of Object.entries(mapping)) {
    let value;
    if (typeof spec === 'string' && spec.startsWith('=')) {
      value = spec.slice(1);
    } else if (spec === '$decision') {
      value = decision;
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
