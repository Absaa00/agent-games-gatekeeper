// Optional on-chain confirmation of a task's proof_tx on zkVerify mainnet.
// STATUS: UNVERIFIED — the zkVerify WebSocket RPC (wss://zkverify-rpc.zkverify.io)
// did not connect from this VM (20s timeout, twice), and the HTTP RPC
// (https://rpc.zkverify.io) accepts the connection but never answers. The
// lookup is therefore implemented, time-boxed, and FAIL-SAFE: any failure
// returns { status: 'unavailable' } and the decision engine proceeds from
// the HMAC-authenticated payload (see STRICT_ONCHAIN in config.js).
//
// Method (when the RPC is reachable): connect via WebSocket JSON-RPC,
// fetch the latest block, walk backwards up to `scanBlocks` blocks, and
// compare each extrinsic's blake2b-256 hash with proof_tx. A match also
// runs a byte heuristic: whether the extrinsic call data contains the
// registered_vk (32 raw bytes) — a real signal that the on-chain proof was
// submitted under the registered key, not a substituted one.
'use strict';

const config = require('./config');

let blake = null;
try {
  // Tiny, dependency-free blake2b. Absence => lookup unavailable, not fatal.
  blake = require('blakejs');
} catch (_) {
  blake = null;
}

function hexToBytes(hex) {
  const h = String(hex).replace(/^0x/, '');
  if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2 !== 0) return null;
  return Buffer.from(h, 'hex');
}

function extrinsicHashHex(extrinsicHex) {
  const bytes = hexToBytes(extrinsicHex);
  if (!bytes || !blake) return null;
  return '0x' + Buffer.from(blake.blake2b(bytes, null, 32)).toString('hex');
}

class RpcClient {
  constructor(url, timeoutMs) {
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  connect() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('ws connect timeout')), 5000);
      let ws;
      try {
        ws = new WebSocket(this.url);
      } catch (err) {
        clearTimeout(timer);
        reject(err);
        return;
      }
      ws.onopen = () => { clearTimeout(timer); this.ws = ws; resolve(); };
      ws.onerror = () => { clearTimeout(timer); reject(new Error('ws error')); };
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch (_) { return; }
        if (msg && msg.id && this.pending.has(msg.id)) {
          const { resolve: res, reject: rej } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          if (msg.error) rej(new Error(msg.error.message || 'rpc error'));
          else res(msg.result);
        }
      };
      ws.onclose = () => {
        for (const { reject: rej } of this.pending.values()) rej(new Error('ws closed'));
        this.pending.clear();
      };
    });
  }

  call(method, params = []) {
    return new Promise((resolve, reject) => {
      if (!this.ws) return reject(new Error('not connected'));
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`rpc timeout: ${method}`));
      }, this.timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }

  close() {
    try { this.ws && this.ws.close(); } catch (_) {}
  }
}

async function lookupProofTx(proofTx, registeredVk) {
  const target = String(proofTx).toLowerCase();
  if (!blake) return { status: 'unavailable', detail: 'blakejs not installed' };
  const scanBlocks = config.onchainScanBlocks;
  if (!scanBlocks || scanBlocks <= 0) {
    return { status: 'unavailable', detail: 'on-chain lookup disabled (ONCHAIN_SCAN_BLOCKS=0)' };
  }
  const rpc = new RpcClient(config.zkVerifyRpcWss, config.onchainTimeoutMs);
  try {
    await rpc.connect();
    const headHash = await rpc.call('chain_getBlockHash', []);
    const header = await rpc.call('chain_getHeader', [headHash]);
    const headNumber = parseInt(header.number, 16);
    if (!Number.isFinite(headNumber)) throw new Error('bad head number');
    const vkBytes = hexToBytes(registeredVk);

    for (let n = headNumber; n > headNumber - scanBlocks && n >= 0; n--) {
      const blockHash = await rpc.call('chain_getBlockHash', [n]);
      const block = await rpc.call('chain_getBlock', [blockHash]);
      const extrinsics = (block && block.block && block.block.extrinsics) || [];
      for (const ex of extrinsics) {
        if (extrinsicHashHex(ex) === target) {
          const exBytes = hexToBytes(ex);
          let vkMatches = null;
          if (vkBytes && exBytes) {
            vkMatches = exBytes.includes(vkBytes);
          }
          return { status: 'confirmed', vkMatches, blockNumber: n };
        }
      }
    }
    return { status: 'not_found', detail: `not in last ${scanBlocks} blocks` };
  } catch (err) {
    return { status: 'unavailable', detail: String(err.message || err) };
  } finally {
    rpc.close();
  }
}

module.exports = { lookupProofTx };
