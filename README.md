# Proof Gatekeeper agent — zkVerify Agent Games

An AI-agent endpoint for the **Proof Gatekeeper** track of
[Agent Games by zkVerify](https://agentgames.zkverify.io) (400,000 VFY prize
pool, 100,000 VFY per track, top 3 split 50k / 30k / 20k). Competition runs
21 Oct – 21 Nov 2026; scored rounds are daily 16:00–02:00 IST (17:30–03:30
WIB), 8 tasks per agent per round, scores cumulative.

The agent receives a signed task envelope, verifies the HMAC signature
against the raw body, decides **APPROVE** or **REJECT** deterministically, and
responds within the 60-second hard deadline. It never approves on doubt
(fail closed).

## How decisions are made

Each task is a structured payment decision (`agent-games.proof-gatekeeper.v1`)
with a proof reference (`proof_tx`) plus the registered condition. The agent
checks, in order:

| Check | Reject reason | What it catches |
|---|---|---|
| proof VK == registered VK | `VK_SUBSTITUTION` | proof verifies but under the wrong key |
| proof_tx not seen before (local seen-set) | `PROOF_REUSED` | a valid proof submitted twice |
| current_block < expiry_block | `EXPIRED_CONDITION` | payment window already closed |
| recipient == condition_recipient | `RECIPIENT_MISMATCH` | payment would go to the wrong party |
| public_balance >= minimum | `THRESHOLD_MISMATCH` | proof genuine but balance too low |
| amount <= max_transfer | `AMOUNT_OVERFLOW` | payment exceeds the single-transfer cap |

All checks pass → `APPROVE` (`VALID_CONDITION`). Any failure → `REJECT`
with that exact reason code. Scoring: correct decision +12; wrong APPROVE
−6; wrong REJECT −3; timeout −2; a correct decision without a valid Groth16
proof costs an extra −2 and no reliability bonus (+0…+5).

Response shape (exactly as documented on the event page):

```json
{ "decision": "APPROVE", "reason_code": "VALID_CONDITION", "proof_tx": "0x..." }
```

Responses are signed with header `x-agent-games-signature` (HMAC-SHA256 over
the raw response body). Task IDs are idempotency keys: a platform retry
returns the cached response without re-deciding.

## Repository layout

```
src/
  server.js      HTTP server (Node built-ins only), routes, idempotency, logging
  decision.js    pure deterministic decision engine (unit-tested)
  hmac.js        HMAC verify/sign (timing-safe compare)
  onchain.js     optional zkVerify proof_tx lookup (time-boxed, fail-safe)
  kurier.js      Kurier REST client (register-vk / submit-proof / job-status)
  prover.js      Groth16 decision proving via snarkjs (OFF by default)
  store.js       seen-set + decision log persistence
  config.js      env-based config (secrets only from env vars)
circuits/        gatekeeper.wasm + gatekeeper_final.zkey + vk.json (public
                 artifacts from https://agentgames.zkverify.io/api/circuit-info)
                 vkHash: 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
                 (13 public inputs, Groth16/BN128, Circom 2.x)
scripts/simulate-task.js   end-to-end test: 7 trap varieties + bad HMAC + retry
test/decision.test.js       unit tests for the decision engine
Dockerfile, fly.toml        fly.io deploy (primary hosting)
systemd/                    unit file for running on a VM (fallback hosting)
```

## Quick start (local)

```bash
npm install
npm test            # 10 unit tests
npm run simulate    # starts the server with a TEST secret, posts all 7 trap
                    # varieties + a bad-HMAC + a retry, checks every decision
```

Run for real (needs the HMAC secret from the platform — see below):

```bash
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET, never commit .env
npm start
curl localhost:3000/health
```

## Configuration

| Variable | Required | What it is / where to get it |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | **yes** | 32-byte secret shown **exactly once** when the agent is registered on the platform (agent settings → Rotate Secret). Without it the server answers `GET /health` but rejects every task POST with 401. |
| `AGENT_NAME` | no | Public agent name. Default `ABSAA-1`. |
| `KURIER_API_KEY` | no | Kurier mainnet API key from https://kurier.xyz (free signup). Only needed to put our own Groth16 decision proofs on-chain. |
| `GATEKEEPER_PROVE` | no | `1` to attach our own Groth16 proof to responses. **Default 0 — see "Known unknowns".** |
| `STRICT_ONCHAIN` | no | `1` to REJECT when the on-chain proof lookup is unavailable. Default 0 (decide from the HMAC-signed payload). |
| `ONCHAIN_SCAN_BLOCKS` | no | Recent blocks scanned for `proof_tx` (default 600; `0` disables the lookup). |
| `PORT` / `HOST` / `DATA_DIR` | no | Server bind + state dir (default `3000`, `0.0.0.0`, `data`). |

**Never paste a secret into chat or commit it to the repo.** Secrets live in
`.env` (local), `fly secrets` (fly.io), or the systemd `EnvironmentFile`.

## Deploy — fly.io (primary)

The agent is a plain Node server; it needs a host that stays awake (the
rules forfeit tasks when the agent is offline) and can run snarkjs proving.
fly.io free tier fits: 1 shared-cpu 256 MB machine + 1 GB volume for the
seen-set / decision log.

```bash
# Needs a fly.io account + API token (flyctl login). See "Hosting blocker".
flyctl launch --no-deploy        # or: flyctl apps create absaa-gatekeeper
flyctl volumes create gatekeeper_data --size 1 --region sin
flyctl secrets set AGENT_GAMES_HMAC_SECRET="<secret from the platform>"
# optional: flyctl secrets set KURIER_API_KEY="<kurier key>"
flyctl deploy
curl https://absaa-gatekeeper.fly.dev/health
```

Endpoint to register on the platform:

```
https://absaa-gatekeeper.fly.dev/agent
```

## Deploy — VM + systemd (fallback)

The unit file mirrors the telegram-bot pattern (file in the repo, symlinked
into `/etc/systemd/system`). It still needs a public HTTPS front-end in front
of the VM (the VM has no inbound ports); a Cloudflare Tunnel is the intended
front-end, but creating one needs a working Cloudflare API token — see
"Hosting blocker". When a tunnel exists:

```bash
sudo ln -s /home/hatch/workspace/agent-games-gatekeeper/systemd/agent-games-gatekeeper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent-games-gatekeeper
curl http://127.0.0.1:3000/health
```

## Registration form values (for the platform dashboard)

| Field | Value |
|---|---|
| Agent Name | `ABSAA-1` |
| Event Tracks | **Proof Gatekeeper only** (see Steal the VFY below) |
| Repository URL | `https://github.com/Absaa00/agent-games-gatekeeper` |
| Agent Endpoint | `https://absaa-gatekeeper.fly.dev/agent` (once deployed; see "Hosting blocker") |

After registering, the platform shows the HMAC secret exactly once — copy it
into the deploy target (`fly secrets set` / `.env`) and restart. Then run a
health check + at least one practice task from the dashboard (practice tasks
are identical in format to scored tasks, capped at 10/hour, and do not affect
the leaderboard).

## Steal the VFY — SKIPPED

The Swiss tournament runs 13–17 Nov 2026 and the docs state entries lock
once the tournament is paired and a strategy commitment is required before
Swiss Round 1 opens. By 15 Nov the tournament is already running, so a new
entry is almost certainly locked out. The code in this repo is Gatekeeper-only
on purpose. Do not tick Steal the VFY in the form unless the dashboard still
offers it — and never let the agent fill in a strategy: the guide is explicit
that the strategy is the owner's decision, not the model's.

## Known unknowns (honest limitations)

1. **Groth16 decision-proof input mapping — CONFIRMED 2026-11-16.**
   The 13 input-signal names were read from `gatekeeper.wasm` itself
   (`getInputSignalSize`, calibrated against bogus names) and a proof was
   generated + verified against the real `vk.json` for a VALID task
   (APPROVE verifies, REJECT assert-fails) and for each single trap
   (APPROVE assert-fails, REJECT verifies). Real signals (camelCase):
   `amount, conditionRecipient, currentBlock, decision, expiryBlock,
   maxTransfer, minimum, proofVkHash, publicBalance, recipient,
   registeredVkHash, salt, taskId` — note: NO `proof_tx` signal, and the
   vk fields are hashes. Encoding used (`circuits/input-mapping.json`):
   vk hashes = blake2b-256 of the raw vk bytes, taskId = blake2b-256 of the
   task_id string, decision APPROVE=1/REJECT=0, salt="0"; any consistent
   hash verifies cryptographically, so the only residual unknown is the
   platform-side hash convention (worst case: proof counts as invalid,
   −2 — the same as no proof). `GATEKEEPER_PROVE=1` + the mapping file
   enables proving; the decision engine is the main scoring surface
   (+12 per correct decision with a valid proof, +10 without, plus up to
   +5/round reliability bonus).
2. **On-chain proof lookup — UNVERIFIED from this VM.** The zkVerify
   WebSocket RPC (`wss://zkverify-rpc.zkverify.io`) did not connect from
   this VM (20 s timeout, twice) and the HTTP RPC never answers; Subscan's
   API now requires an API key. `src/onchain.js` implements a time-boxed
   recent-block scan for `proof_tx`, but it is untested against the live
   chain. Until it is verified on the deploy host, the agent decides from
   the HMAC-authenticated task payload — all 7 documented trap types are
   detectable from payload fields, and the payload is signed by the platform
   itself. Set `STRICT_ONCHAIN=1` to fail closed instead.
3. **Hosting blocker.** No deploy target is reachable from this VM alone:
   the Cloudflare API credential does not authenticate from a subprocess
   (the `hsurr:` surrogate is rejected by Cloudflare with error 6003, so no
   Tunnel and no Workers deploy), Tailscale cannot host (client-only, and
   this VM is not joined), and fly.io / Vercel need a browser login. The
   repo ships a ready `fly.toml` + `Dockerfile`; deploying needs a fly.io
   account + API token (create at fly.io, hand the token over via the secure
   vault — never in chat — then run the fly.io commands above).

## Security

- No private key, seed phrase, API key, or HMAC secret is ever committed.
  Secrets only via env vars / `fly secrets` / systemd `EnvironmentFile`.
- The HMAC secret is verified with a timing-safe compare, on the raw body,
  before any parsing. Bad signature → 401, no processing.
- The agent never signs, sends, or approves any transaction. It only
  answers decisions. It never touches a wallet.
- The seen-set and decision log contain only task IDs, proof references,
  decisions, and reason codes — no secrets.
