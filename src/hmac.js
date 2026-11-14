// HMAC helpers (Node built-in crypto only).
// The platform signs every task envelope with the agent's HMAC secret and
// sends it as header `x-agent-games-signature` over the RAW request body.
// Our responses are signed the same way over the RAW response body.
'use strict';

const crypto = require('crypto');

function hmacHex(secret, rawBodyBuffer) {
  return crypto.createHmac('sha256', secret).update(rawBodyBuffer).digest('hex');
}

// Accept `sha256=<hex>` or bare `<hex>`.
function normalizeSignature(value) {
  if (!value) return '';
  const v = String(value).trim();
  return v.startsWith('sha256=') ? v.slice('sha256='.length) : v;
}

function signaturesEqual(a, b) {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Verify the platform signature on a raw request body.
// Returns true only when a secret is configured AND the signature matches.
function verifyRequestSignature(secret, rawBodyBuffer, signatureHeader) {
  if (!secret) return false;
  const expected = hmacHex(secret, rawBodyBuffer);
  const provided = normalizeSignature(signatureHeader).toLowerCase();
  if (!provided || provided.length !== expected.length) return false;
  return signaturesEqual(provided, expected);
}

function signResponseBody(secret, rawBodyBuffer) {
  return hmacHex(secret, rawBodyBuffer);
}

module.exports = {
  hmacHex,
  normalizeSignature,
  verifyRequestSignature,
  signResponseBody,
};
