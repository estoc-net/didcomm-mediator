# didcomm-mediator

A DIDComm v2 mediator anyone can run with one command — or one click:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/estoc-net/didcomm-mediator)

TypeScript, standard protocols over plain HTTP/WebSocket transport, no
accounts to create and no vendor SDK to adopt — authentication is the
envelope itself.

Two deployment targets share one protocol implementation:

- **Cloudflare Workers** — D1 for storage, a Durable Object holding the live
  WebSockets; there is no server, no secret, and no URL to configure at all.
- **Node + Docker** — one process, SQLite on a volume.

Either way the mediator's whole identity is two private keys in its own
database, minted on first contact; every DID it answers to is derived from
those keys, so **keep the database, keep the mediator**.

## Quick start (Cloudflare Workers)

Click the button above — it clones this repo into your GitHub account,
provisions the D1 database and Durable Object, and deploys. Or by hand:

```sh
npx wrangler d1 create mediator    # paste database_id into wrangler.jsonc
npx wrangler deploy
npm run smoke -- https://your-worker.example.workers.dev
```

The Workers deployment is URL-agnostic: it answers every host that routes to
it as that host's own `did:web` — `your-worker.example.workers.dev` on day
one, and if you later attach a custom domain in the dashboard, that domain
becomes a second, equally live DID off the same keys. Locally, `npm run
dev:workers` serves `did:web:localhost%3A8787` the same way.

`npm run smoke -- <url>` drives a real client through the whole surface —
grant, keylist, anonymous forward, pickup, WebSocket live delivery — against
any running mediator, whichever target it is.

## Quick start (Docker)

```sh
MEDIATOR_PUBLIC_URL=https://mediator.example.com docker compose up -d
curl -s https://mediator.example.com/
```

On Node the public URL is configuration (`MEDIATOR_PUBLIC_URL`), and the
default method is the same as on Workers: did:web — the mediator's name *is*
its domain. That assumes an https URL (or localhost, for development); for a
URL the world cannot fetch, such as plain http on a LAN, set
`MEDIATOR_DID_METHODS=peer2` for the self-contained method that works
anywhere. Either way the DID is derived from the keys *and* the URL, so
changing the URL renames the mediator (the keys stay). Keep the
`mediator-data` volume and the URL, keep the DID; delete the volume and the
next start mints fresh keys.

TLS is out of scope: put any reverse proxy (Caddy, nginx) in front and point
`MEDIATOR_PUBLIC_URL` at the public HTTPS address. The proxy must also pass
WebSocket upgrades on the same path.

## The mediator's DIDs

One key set, up to three names — each method's DID is a deterministic function
of the stored keys and a public URL:

- **`peer2`** — self-contained: the whole document, endpoint included, is
  encoded in the DID and resolves offline. Works anywhere, plain-http LANs
  included. Changing the URL or the keys means a new DID.
- **`peer4`** — the same trade-offs in did:peer:4's long-form encoding.
- **`web`** (the default) — the DID *is* the domain:
  `https://mediator.example.com` becomes `did:web:mediator.example.com`, and
  keys and endpoints live in the document served at `/.well-known/did.json`
  (also `/did.json`), so both can rotate without changing the DID. Requires
  an https public URL — resolvers fetch did.json over https, nothing else —
  and clients that resolve did:web.

Which names are active is configuration, not storage: `MEDIATOR_DID_METHODS`
is an ordered list (`peer2,web`). The first is the primary — what GET / and
the invitation advertise — and the rest are aliases the mediator answers to
equally: a client is always answered *as the DID it addressed*, and its
mediation grant hands out that same DID for routing. Flipping the order later
changes what new clients see while everyone bound to the other name keeps
working — the migration path from a peer DID to did:web without stranding
anyone. (The peer aliases are still the keys in encoded form, so rotating a
did:web identity's keys renames them; the alias is a bridge, not a place to
stay.)

On Workers the URL half of every derivation is the origin the request arrived
on, so one deployment answers each of its hosts as that host's own DID —
nothing is configured, and no name is more real than another.

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

- `POST /` — a DIDComm envelope in, the reply (if the exchange has one) in
  the HTTP response body — but only when the message declares
  `return_route: "all"`, as messagepickup 3.0 requires of clients. Without
  it the request still runs and the response is an empty 202. Over a
  WebSocket the header is set once and marks the socket as the return route
  for its lifetime.
- `GET /` + WebSocket upgrade — same dispatch over a socket; enabling
  live delivery (`live-delivery-change`) turns the socket into a push channel
  for incoming forwards.
- `GET /` (plain) — the mediator's DID, its out-of-band invitation URL, and
  the protocol list as JSON; a browser (`Accept: text/html`) gets a
  human-readable page instead.
- `GET /invitation` — the out-of-band 2.0 invitation as a plaintext JWM. The
  same invitation, base64url-encoded, rides the `?_oob=` parameter of the
  invitation URL — the string to put in a QR code for any standard wallet.
- `GET /health`.

Anonymous (anoncrypt) envelopes may only carry `forward` — the outer envelope
of a forward is anonymous by design. Everything that grants or reads state
requires an authcrypt envelope, and the proven sender DID *is* the account.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `MEDIATOR_PUBLIC_URL` | — (required; Node only) | Public URL the DIDs derive from — Workers use each request's own origin instead |
| `MEDIATOR_DID_METHODS` | `web` | Ordered list of active methods (`peer2,peer4,web`); first = primary. Set `peer2` for a non-loopback http URL |
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
