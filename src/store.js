// Persistent state: the seen-set of approved proof references (PROOF_REUSED
// detection) and an append-only decision log. Plain JSON files under DATA_DIR.
// No secrets are ever stored here.
'use strict';

const fs = require('fs');
const path = require('path');

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function loadSeen(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return new Set(parsed.map((s) => String(s).toLowerCase()));
    if (parsed && Array.isArray(parsed.proofs)) {
      return new Set(parsed.proofs.map((s) => String(s).toLowerCase()));
    }
    return new Set();
  } catch (_) {
    return new Set();
  }
}

function saveSeen(filePath, seenSet) {
  ensureDir(filePath);
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify([...seenSet].sort(), null, 2));
  fs.renameSync(tmp, filePath);
}

function appendLog(filePath, entry) {
  try {
    ensureDir(filePath);
    fs.appendFileSync(filePath, JSON.stringify(entry) + '\n');
  } catch (err) {
    // Logging must never break a decision.
    console.error('[store] failed to append log:', err.message);
  }
}

module.exports = { loadSeen, saveSeen, appendLog };
