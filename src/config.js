// Configuration — all secrets come from environment variables only.
// Never commit secrets to the repo. See .env.example.
'use strict';

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

function envBool(name, fallback) {
  const v = process.env[name];
  if (v === undefined || v === '') return fallback;
  return v === '1' || v.toLowerCase() === 'true' || v.toLowerCase() === 'yes';
}

const config = {
  // Network
  port: parseInt(env('PORT', '3000'), 10),
  host: env('HOST', '0.0.0.0'),

  // Identity
  agentName: env('AGENT_NAME', 'ABSAA-1'),

  // --- Secrets (env only) ---
  // 32-byte HMAC secret issued by the Agent Games platform at agent
  // registration (shown exactly once; Rotate Secret in agent settings).
  // The platform signs every task with it (header x-agent-games-signature).
  // If unset, the server still answers GET /health but rejects every task
  // POST with 401 (fail closed) until the secret is configured.
  hmacSecret: env('AGENT_GAMES_HMAC_SECRET', ''),
  // Kurier mainnet API key (https://kurier.xyz). Needed to submit our own
  // Groth16 decision proofs to zkVerify. Optional: without it the agent
  // still decides, it just cannot put its proof on-chain.
  kurierApiKey: env('KURIER_API_KEY', ''),

  // --- Behaviour flags ---
  // Attach our own Groth16 decision proof to responses.
  // DEFAULT OFF. Reason: the public docs do not specify the gatekeeper
  // circuit's input-signal mapping nor the exact response field names for
  // the proof. Enabling it with a guessed mapping produces invalid proofs.
  // Enable only after the mapping + field names are confirmed (practice
  // mode feedback / platform docs) and circuits/input-mapping.json exists.
  proveDecisions: envBool('GATEKEEPER_PROVE', false),
  // If true, a task is REJECTED when the on-chain proof lookup is
  // unavailable or inconclusive. Default false: the agent then decides from
  // the HMAC-authenticated task payload (all 7 documented trap types are
  // detectable from payload fields). The payload is signed by the platform
  // itself, so it is authenticated; the on-chain lookup is defence in depth.
  strictOnchain: envBool('STRICT_ONCHAIN', false),

  // --- Paths ---
  dataDir: env('DATA_DIR', 'data'),
  seenFile: env('SEEN_FILE', ''), // defaults to <dataDir>/seen.json
  logFile: env('LOG_FILE', ''), // defaults to <dataDir>/decisions.jsonl

  // --- zkVerify / Kurier ---
  kurierApiUrl: env('KURIER_API_URL', 'https://api.kurier.xyz/api/v1'),
  // vkHash of the gatekeeper circuit, registered on zkVerify mainnet.
  // Source: https://agentgames.zkverify.io/api/circuit-info
  gatekeeperVkHash: env(
    'GATEKEEPER_VK_HASH',
    '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0'
  ),
  zkVerifyRpcWss: env('ZKVERIFY_RPC_WSS', 'wss://zkverify-rpc.zkverify.io'),

  // On-chain proof lookup: how many recent blocks to scan for proof_tx.
  // 0 disables the lookup entirely (payload-only decisions).
  onchainScanBlocks: parseInt(env('ONCHAIN_SCAN_BLOCKS', '600'), 10),
  onchainTimeoutMs: parseInt(env('ONCHAIN_TIMEOUT_MS', '15000'), 10),
};

config.seenFile = config.seenFile || `${config.dataDir}/seen.json`;
config.logFile = config.logFile || `${config.dataDir}/decisions.jsonl`;

module.exports = config;
