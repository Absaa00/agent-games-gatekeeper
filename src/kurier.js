// Kurier REST client (https://api.kurier.xyz/api/v1) — the RECOMMENDED path
// in the Agent Games builder guide. Used ONLY for submitting our own
// Groth16 decision proofs to zkVerify (register-vk once, submit-proof,
// poll job-status until Finalized). Requires a mainnet API key from
// https://kurier.xyz (free signup). All calls use the global fetch.
// No key => every function here is a no-op returning null (the agent still
// decides; it just cannot put its proof on-chain).
'use strict';

const config = require('./config');

function apiUrl() {
  return config.kurierApiUrl.replace(/\/$/, '');
}

async function postJson(path, body) {
  const res = await fetch(`${apiUrl()}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (_) {}
  if (!res.ok) {
    throw new Error(`kurier ${path} HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return data;
}

async function getJson(path) {
  const res = await fetch(`${apiUrl()}${path}`, { method: 'GET' });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch (_) {}
  if (!res.ok) {
    throw new Error(`kurier ${path} HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return data;
}

// Register the gatekeeper verification key once. Returns the vkHash.
// `vk` is the verification key object (circuits/vk.json).
async function registerVk(vk) {
  if (!config.kurierApiKey) return null;
  const params = {
    proofType: 'groth16',
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    vk,
  };
  const data = await postJson(`/register-vk/${config.kurierApiKey}`, params);
  return data;
}

// Submit a Groth16 proof. Returns the Kurier job response (incl. jobId).
// `vkHash` must be the hash returned by register-vk (or the platform's
// registered hash from /api/circuit-info).
async function submitProof(proof, publicSignals, vkHash) {
  if (!config.kurierApiKey) return null;
  const params = {
    proofType: 'groth16',
    vkRegistered: true,
    proofData: { proof, publicSignals, vk: vkHash },
  };
  const data = await postJson(`/submit-proof/${config.kurierApiKey}`, params);
  return data;
}

// Poll job-status until Finalized / Failed or the deadline (ms) passes.
// Returns the last status object, or null on timeout.
async function waitFinalized(jobId, deadlineMs = 120000) {
  if (!config.kurierApiKey) return null;
  const started = Date.now();
  while (Date.now() - started < deadlineMs) {
    const data = await getJson(`/job-status/${config.kurierApiKey}/${jobId}`);
    const status = data && (data.status || data.jobStatus || data.state);
    if (status === 'Finalized' || status === 'Failed') return data;
    await new Promise((r) => setTimeout(r, 5000));
  }
  return null;
}

module.exports = { registerVk, submitProof, waitFinalized };
