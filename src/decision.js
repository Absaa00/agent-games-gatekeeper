// Deterministic Proof Gatekeeper decision engine.
// Pure function of the task payload (+ the local seen-set). No network, no
// secrets, no randomness — the same task always yields the same decision.
//
// Task payload (documented at
// https://agentgames.zkverify.io/events/proof-gatekeeper):
//   {
//     "type": "agent-games.proof-gatekeeper.v1",
//     "task_id": "gk_24_9d1", "mode": "competition" | "practice",
//     "issued_at": "<iso>", "deadline_at": "<iso>",
//     "input": {
//       "registered_vk": "0x...", "proof_vk": "0x...",
//       "minimum": "1000", "public_balance": "1460",
//       "expiry_block": 19842201, "current_block": 19832000,
//       "recipient": "0x...", "condition_recipient": "0x...",
//       "amount": "500", "max_transfer": "1000",
//       "proof_tx": "0x..."
//     }
//   }
//
// The 7 documented trap varieties (each task is exactly one of them, or a
// valid condition):
//   VALID_CONDITION    -> APPROVE (+12)
//   VK_SUBSTITUTION    -> REJECT  (+12 if correctly identified)
//   THRESHOLD_MISMATCH -> REJECT
//   PROOF_REUSED       -> REJECT
//   EXPIRED_CONDITION  -> REJECT
//   RECIPIENT_MISMATCH -> REJECT
//   AMOUNT_OVERFLOW    -> REJECT
// Wrong APPROVE costs -6, wrong REJECT costs -3, so the engine is biased to
// REJECT whenever anything is uncertain (fail closed).
'use strict';

const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';

const REASONS = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
  INVALID: 'INVALID_TASK', // defensive only; not a documented trap code
};

function normHex(v) {
  return String(v == null ? '' : v).trim().toLowerCase();
}

function toBigInt(v) {
  if (v === null || v === undefined || v === '') return null;
  try {
    return BigInt(v);
  } catch (_) {
    return null;
  }
}

// onchain: result of the optional on-chain proof lookup, or null when the
// lookup was not performed / unavailable.
//   { status: 'confirmed', vkMatches: bool, balance: string|null,
//     recipient: string|null }   — proof found on-chain
//   { status: 'mismatch', detail: string } — proof found but contradicts payload
//   { status: 'not_found' }      — lookup ran, proof_tx absent from scanned range
//   { status: 'unavailable' }    — lookup could not run (no RPC, timeout)
// seenSet: Set of lowercased proof_tx values this agent has APPROVED before.
function decide(task, seenSet, onchain) {
  const checks = [];
  const fail = (code, detail) => {
    checks.push({ check: code, pass: false, detail });
    return { decision: 'REJECT', reason_code: code, checks };
  };
  const pass = (code, detail) => checks.push({ check: code, pass: true, detail });

  if (!task || typeof task !== 'object') {
    return { decision: 'REJECT', reason_code: REASONS.INVALID, checks, detail: 'task is not an object' };
  }
  if (task.type !== TASK_TYPE) {
    return { decision: 'REJECT', reason_code: REASONS.INVALID, checks, detail: `unexpected type ${task.type}` };
  }
  const input = task.input || {};
  const taskId = task.task_id || '';
  const proofTx = normHex(input.proof_tx);
  if (!taskId || !proofTx) {
    return { decision: 'REJECT', reason_code: REASONS.INVALID, checks, detail: 'missing task_id or proof_tx' };
  }

  // 1 — Verification key: the proof's VK must equal the registered condition VK.
  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  if (!registeredVk || !proofVk || registeredVk !== proofVk) {
    return fail(REASONS.VK, `proof_vk ${proofVk || '(missing)'} != registered_vk ${registeredVk || '(missing)'}`);
  }
  pass(REASONS.VK, 'proof_vk matches registered_vk');

  // 1b — On-chain confirmation (when the lookup produced a verdict).
  // A hard on-chain contradiction overrides the payload.
  if (onchain && onchain.status === 'mismatch') {
    return fail(REASONS.VK, `on-chain proof contradicts payload: ${onchain.detail || ''}`);
  }
  if (onchain && onchain.status === 'confirmed') {
    if (onchain.vkMatches === false) {
      return fail(REASONS.VK, 'on-chain proof VK differs from registered_vk');
    }
    pass('ONCHAIN', 'proof_tx confirmed on-chain');
  } else if (onchain && onchain.status === 'not_found') {
    // Lookup ran and the proof_tx is absent from the scanned range. The
    // payload claims an on-chain proof that we cannot find: fail closed.
    return fail(REASONS.VK, 'proof_tx not found on-chain in scanned range');
  } else {
    // 'unavailable' or no lookup: recorded, payload checks still apply.
    checks.push({ check: 'ONCHAIN', pass: null, detail: 'lookup unavailable — deciding from HMAC-signed payload' });
  }

  // 2 — Reuse: a proof reference already accepted before must not be re-used.
  if (seenSet && seenSet.has(proofTx)) {
    return fail(REASONS.REUSED, `proof_tx ${proofTx} already approved before`);
  }
  pass(REASONS.REUSED, 'proof_tx not seen before');

  // 3 — Expiry: the condition must not have expired at the task block height.
  const expiryBlock = toBigInt(input.expiry_block);
  const currentBlock = toBigInt(input.current_block);
  if (expiryBlock === null || currentBlock === null || currentBlock >= expiryBlock) {
    return fail(REASONS.EXPIRED, `current_block ${input.current_block} >= expiry_block ${input.expiry_block}`);
  }
  pass(REASONS.EXPIRED, `current_block ${input.current_block} < expiry_block ${input.expiry_block}`);

  // 4 — Recipient: the proof's recipient must match the condition recipient.
  const recipient = normHex(input.recipient);
  const conditionRecipient = normHex(input.condition_recipient);
  if (!recipient || !conditionRecipient || recipient !== conditionRecipient) {
    return fail(REASONS.RECIPIENT, `recipient ${recipient || '(missing)'} != condition_recipient ${conditionRecipient || '(missing)'}`);
  }
  if (onchain && onchain.status === 'confirmed' && onchain.recipient) {
    if (normHex(onchain.recipient) !== conditionRecipient) {
      return fail(REASONS.RECIPIENT, 'on-chain proof recipient differs from condition_recipient');
    }
  }
  pass(REASONS.RECIPIENT, 'recipient matches condition_recipient');

  // 5 — Threshold: the public balance proven must meet the minimum.
  const minimum = toBigInt(input.minimum);
  const publicBalance = toBigInt(input.public_balance);
  if (minimum === null || publicBalance === null || publicBalance < minimum) {
    return fail(REASONS.THRESHOLD, `public_balance ${input.public_balance} < minimum ${input.minimum}`);
  }
  if (onchain && onchain.status === 'confirmed' && onchain.balance != null) {
    if (toBigInt(onchain.balance) < minimum) {
      return fail(REASONS.THRESHOLD, 'on-chain proof balance below minimum');
    }
  }
  pass(REASONS.THRESHOLD, `public_balance ${input.public_balance} >= minimum ${input.minimum}`);

  // 6 — Amount: the requested payment must not exceed the single-transfer cap.
  const amount = toBigInt(input.amount);
  const maxTransfer = toBigInt(input.max_transfer);
  if (amount === null || maxTransfer === null || amount > maxTransfer) {
    return fail(REASONS.AMOUNT, `amount ${input.amount} > max_transfer ${input.max_transfer}`);
  }
  pass(REASONS.AMOUNT, `amount ${input.amount} <= max_transfer ${input.max_transfer}`);

  return { decision: 'APPROVE', reason_code: REASONS.VALID, checks };
}

module.exports = { decide, TASK_TYPE, REASONS };
