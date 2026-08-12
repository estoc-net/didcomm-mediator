# didcomm-mediator

A DIDComm v2 mediator anyone can run with one command. TypeScript, standard
protocols over plain HTTP/WebSocket transport, no accounts to create and no
vendor SDK to adopt — authentication is the envelope itself.

Two deployment targets share one protocol implementation:

- **Node + Docker** — one process, SQLite on a volume.
- **Cloudflare Workers** — D1 for storage, a Durable Object holding the live
  WebSockets; `wrangler deploy` and there is no server at all.

## Quick start (Docker)

```sh
MEDIATOR_PUBLIC_URL=https://mediator.example.com docker compose up -d
curl -s https://mediator.example.com/.well-known/did
```

Set `MEDIATOR_PUBLIC_URL` **before first start**: it is encoded into the
mediator's did:peer:2, which cannot change afterwards. The identity and the
message store live on the `mediator-data` volume — keep the volume, keep the
DID; delete it and the next start mints a fresh identity.

TLS is out of scope: put any reverse proxy (Caddy, nginx) in front and point
`MEDIATOR_PUBLIC_URL` at the public HTTPS address. The proxy must also pass
WebSocket upgrades on the same path.

## Quick start (Cloudflare Workers)

```sh
wrangler d1 create mediator                    # paste database_id into wrangler.jsonc
npm run mint-identity -- https://your-worker.example.workers.dev
wrangler secret put MEDIATOR_IDENTITY          # paste the JSON the mint printed
wrangler deploy
npm run smoke -- https://your-worker.example.workers.dev
```

The identity is minted once, by you, and handed over as a secret — a Workers
deploy must never mint its own, because the public URL (and so the DID) has to
outlive every redeploy. Locally, `wrangler dev` works the same way with
`MEDIATOR_IDENTITY='<json>'` in `.dev.vars`.

`npm run smoke -- <url>` drives a real client through the whole surface —
grant, keylist, anonymous forward, pickup, WebSocket live delivery — against
any running mediator, whichever target it is.

## Protocols

| Protocol | Role |
| --- | --- |
| [coordinate-mediation/3.0](https://didcomm.org/coordinate-mediation/3.0) | mediate-request → grant/deny, recipient-update/query |
| [messagepickup/3.0](https://didcomm.org/messagepickup/3.0) | status, delivery, acknowledgement, live delivery over WebSocket |
| [routing/2.0](https://didcomm.org/routing/2.0) | inbound forward for mediated recipients |
| [discover-features/2.0](https://didcomm.org/discover-features/2.0) | protocol disclosure |
| [trust-ping/2.0](https://didcomm.org/trust-ping/2.0) | liveness |
| [out-of-band/2.0](https://didcomm.org/out-of-band/2.0) | invitation issuing (`GET /invitation`, `?_oob=` URL) |

## Transport

Everything hangs off the service endpoint URI, which is all a standard client
knows:

- `POST /` — a DIDComm envelope in, the reply (if the exchange has one) in the
  HTTP response body: the return-route pattern.
- `GET /` + WebSocket upgrade — same dispatch over a socket; enabling
  live delivery (`live-delivery-change`) turns the socket into a push channel
  for incoming forwards.
- `GET /.well-known/did` — the mediator's DID, its out-of-band invitation
  URL, and the protocol list.
- `GET /invitation` — the out-of-band 2.0 invitation as a plaintext JWM. The
  same invitation, base64url-encoded, rides the `?_oob=` parameter of the
  invitation URL — the string to put in a QR code for any standard wallet.
  A browser opening that URL gets a human-readable page instead of JSON.
- `GET /health`.

Anonymous (anoncrypt) envelopes may only carry `forward` — the outer envelope
of a forward is anonymous by design. Everything that grants or reads state
requires an authcrypt envelope, and the proven sender DID *is* the account.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `MEDIATOR_PUBLIC_URL` | — (required) | Public URL, baked into the DID on first start |
| `MEDIATOR_PORT` / `MEDIATOR_HOST` | `8080` / `0.0.0.0` | Listen address |
| `MEDIATOR_DATA_DIR` | `/data` in Docker, `./data` otherwise | Identity + SQLite |
| `MEDIATOR_OPEN_REGISTRATION` | `true` | Grant mediation to any DID that asks |
| `MEDIATOR_CORS_ORIGIN` | `*` | CORS for browser agents |
| `MEDIATOR_MESSAGE_TTL_SECONDS` | 7 days | Unclaimed messages expire |
| `MEDIATOR_MAX_MESSAGES_PER_ACCOUNT` | `1000` | Inbox quota |

## Development

```sh
npm install
MEDIATOR_PUBLIC_URL=http://localhost:8080 npm run dev
npm test
npm run typecheck
```

## Design notes

- **One inbox per account.** Every recipient DID an account binds routes to
  the same queue; pickup always reads the authenticated sender's own inbox.
- **Bindings are exclusive and squat-resistant.** A recipient DID binds to one
  account, first-come; binding the mediator's DID, a non-DID, or a DID that
  holds its own account here is refused — and on the forward path a local
  account always outranks a binding, so registering a DID reclaims it from any
  squatter.
- **Sender identity is what the envelope proves**, never what the plaintext
  claims: grants and reads key off the authcrypt key's DID.
- **Live delivery pushes but never hands off.** A pushed message stays queued
  until `messages-received`; a dropped socket loses nothing.

- **The runtimes differ only where they must.** The wire surface is one Hono
  app (`src/app.ts`) and the protocol layer is runtime-free; Node keeps live
  sockets in process memory, Workers keep them in a Durable Object, and the
  didcomm WASM is the same Rust either way.

The DIDComm layer (pack/unpack via didcomm-node, did:peer:2/4 and did:web
resolution) is shared lineage with
[didcomm-http](https://github.com/estoc-net/didcomm-http).

## Status

Experimental. This mediator and the didcomm libraries under it have not
received an independent security audit, and the protocol surface may still
change. Run your own instance freely; don't yet rely on one to carry anything
you can't afford to lose.

## License

Apache-2.0
