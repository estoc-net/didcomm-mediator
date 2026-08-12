# CLAUDE.md

## Commands
- `npm test` — vitest; `npm run typecheck` — tsc --noEmit
- `MEDIATOR_PUBLIC_URL=http://localhost:8080 npm run dev` — dev server
- `docker compose up -d` — production shape (needs `MEDIATOR_PUBLIC_URL`)

## Architecture
- **Fastify 5 + TypeScript ESM**, no OpenAPI/TypeBox — the API surface is DIDComm envelopes, not JSON routes. didcomm-node (CJS WASM build of didcomm-rust) does all crypto; using its full pack/unpack API is what makes every enc-alg (XC20P, A256GCM, …) work without the hand-rolled envelope bugs the Affinidi fork had to patch
- `src/didcomm/` is copied lineage from `../didcomm-http` (did-peer-2/4, did-doc, did-resolver) with TypeBox schemas replaced by plain interfaces in `types.ts` — didcomm-node's own `ServiceKind` is `any`, so precise types live here. Keep fixes in sync with didcomm-http where they overlap
- **Identity** (`src/identity.ts`): did:peer:2 minted on first boot into `MEDIATOR_DATA_DIR/identity.json`, element order `.E` (X25519, #key-1) then `.V` (Ed25519, #key-2) — resolver numbers keys by element order, secrets use the same numbering; change one and the other breaks silently. `MEDIATOR_PUBLIC_URL` is baked into the DID: changed later it logs a warning and keeps the old endpoint
- **Dispatch** (`src/protocols/dispatch.ts`): handlers return `{type, body, attachments?}`; dispatch alone fills id/thid/from/to and packs — replies are sealed to `verifiedFrom` (the DID the envelope proved), never `message.from` (the claim). Anonymous senders: `forward` only; everything else needs authcrypt, unknown types get a problem-report only when there is a proven sender to address it to
- **Store** (`src/store/sqlite.ts`, better-sqlite3, WAL): accounts (row = grant) / keylist (recipient_did PK → owner, exclusive first-come) / messages (TTL + per-account quota). Ownership checks live in the protocol layer, not the store
- **Squat resistance** (from the Affinidi fork, one incident at a time): recipient-update add refuses non-DIDs, >2048 chars, the mediator's DID, and DIDs holding their own account; forward prefers a local account over any binding **unconditionally** (accounts require proving the DID's own keys, so registration reclaims a squatted DID) — test "delivers to a registered account DID over any squatted binding" pins this
- **Pickup**: one inbox per account; `recipient_did` echoed, never used to scope. Delivery attachments are **base64url** (spec; standard-base64 `atob` clients break). Live delivery: WS session binds to first proven DID and never re-binds; push leaves messages queued until messages-received
- **Transport** (`src/server.ts`): POST `/` return-route reply in body (200 sealed / 202 silence / 400 unparseable), WS upgrade on `/`, `/.well-known/did`, `/health`. DIDComm content types parsed as opaque strings — unpack is the parser

## Gotchas
- didcomm-node needs `message.from` to match the packing key: test helpers must set `from`/`to` in the plaintext
- `pack_encrypted` here always `forward: false` — the mediator replies directly, wrapping its own replies for another mediator would be wrong
- vitest runs HTTP tests via `app.inject`, but live delivery needs a real `listen` + `ws` client (`test/live-delivery.test.ts`)
- tsconfig `rootDir: "src"` so Docker's `npx tsc` emits `dist/index.js` (the image CMD)
