# CLAUDE.md

## Commands
- `npm test` — vitest; `npm run typecheck` — tsc for both targets (main config excludes `src/workers`; `tsconfig.workers.json` checks it with workerd types)
- `MEDIATOR_PUBLIC_URL=http://localhost:8080 npm run dev` — Node dev server
- `npm run dev:workers` — wrangler dev (needs `MEDIATOR_IDENTITY='<json>'` in `.dev.vars`, minted via `npm run mint-identity -- <url>`)
- `npm run smoke -- <url>` — full client flow against any *running* mediator (grant → keylist → anonymous forward → pickup → WS live delivery with binary-frame asserts); the deploy verification tool
- `docker compose up -d` — production shape (needs `MEDIATOR_PUBLIC_URL`)

## Architecture
- **Hono + TypeScript ESM**, two deploy targets off one protocol layer. `src/app.ts` is the shared wire surface (POST `/` return-route, `/.well-known/did`, `/health`, CORS); its plain GET `/` steps aside on an Upgrade header so each target mounts its own WebSocket handler after it. didcomm-node (WASM build of didcomm-rust) does all crypto; the full pack/unpack API is what makes every enc-alg work without the hand-rolled envelope bugs the Affinidi fork had to patch
- **Node target** (`src/server.ts` + `src/index.ts`): @hono/node-server + @hono/node-ws, sessions in process memory (`src/transport/sessions.ts`), SQLite via better-sqlite3
- **Workers target** (`src/workers/`): same app; D1Store (lazy CREATE TABLE, no migrations step); live sockets live in one `InboxHub` Durable Object (`idFromName("hub")`) with hibernatable WebSockets — DID + liveDelivery ride each socket's serialized attachment and the constructor rebuilds the registry after hibernation. The stateless Worker reaches it through the `LiveSink` interface (`wantsPush`/`push`); on Node the in-memory `Sessions` implements the same interface. Identity comes from the `MEDIATOR_IDENTITY` secret — Workers never mint (a redeploy that minted would orphan every client)
- **didcomm on workerd** (`src/workers/didcomm-wasm.ts`): wrangler `alias` maps `didcomm-node` → a shim that instantiates the `didcomm` bundler build manually (`new WebAssembly.Instance(mod, { "./index_bg.js": glue })` + `__wbg_set_wasm`); identical API, same wasm. `nodejs_compat` supplies Buffer/node:crypto to shared code
- **Store** (`src/store/types.ts`): all methods async — D1 has no sync API and the protocol layer is shared. Tables: accounts (row = grant) / keylist (recipient_did PK → owner, exclusive first-come) / messages (TTL + per-account quota). Ownership checks live in the protocol layer, not the store
- `src/didcomm/` is copied lineage from `../didcomm-http` (did-peer-2/4, did-doc, did-resolver); keep fixes in sync. `src/identity-core.ts` is the runtime-free half of identity (StoredIdentity → MediatorIdentity); minting/disk stay in `src/identity.ts` (Node only)
- **Dispatch** (`src/protocols/dispatch.ts`): handlers return `{type, body, attachments?}`; dispatch alone fills id/thid/from/to and packs — replies are sealed to `verifiedFrom` (the DID the envelope proved), never `message.from`. Anonymous senders: `forward` only; unknown types get a problem-report only when there is a proven sender
- **Squat resistance**: recipient-update add refuses non-DIDs, >2048 chars, the mediator's DID, and DIDs holding their own account; forward prefers a local account over any binding **unconditionally** — test "delivers to a registered account DID over any squatted binding" pins this
- **Pickup**: one inbox per account; `recipient_did` echoed, never used to scope. Delivery attachments are **base64url**. Live delivery: WS session binds to first proven DID and never re-binds; push leaves messages queued until messages-received

## Gotchas
- **WS frames must be sent binary** (`TextEncoder`/Buffer, never a string): browsers hand text frames to `onmessage` as strings, and the DIF demo reads every frame with `event.data.text()` — only a Blob has that, and only binary frames arrive as Blobs. Headless ws clients can't catch this; the demo-interop test asserts `isBinary`
- didcomm-node needs `message.from` to match the packing key: test helpers must set `from`/`to` in the plaintext
- didcomm-rust re-serializes JSON with sorted keys — compare forwarded payloads structurally, never by string equality
- `pack_encrypted` here always `forward: false` — the mediator replies directly; wrapping its own replies for another mediator would be wrong
- vitest runs HTTP tests via Hono's `app.request()`, but live delivery needs a real listen + `ws` client (`test/live-delivery.test.ts`)
- tsconfig `rootDir: "src"` and `exclude: src/workers` so Docker's `npx tsc` emits `dist/index.js` without workerd types
- The `@hono/node-server` audit advisory (serve-static path traversal on Windows) doesn't apply: nothing is served statically
