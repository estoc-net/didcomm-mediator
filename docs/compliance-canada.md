# Canada compliance runbook

The operator's procedure for a mediator hosted under Canadian
jurisdiction, sitting on top of the universal policy core (README
"Operator policy"; public-folder spec §7). The core is the mechanism;
this document is the thin regional layer: who to tell, how long to hold,
and in what order. Other jurisdictions want their own version of this
file — the mechanism underneath doesn't change.

Written 2026-08. **This is an operator's process note, not legal
advice**; before running a mediator at any real scale, have a lawyer who
knows Canadian technology law review it.

## What the law actually asks

Hosting other people's public folders makes the operator a content host.
For a Canadian host the duties are **reactive** — they trigger when you
are told or when you have reasonable grounds, and there is **no duty to
monitor or search** your own storage. Nothing here requires a scanner,
and the protocol deliberately has no hook for one.

- **Mandatory reporting of child sexual abuse material** (SC 2011, c 4,
  as amended by Bill C-16, royal assent 2026-06-18; applies to anyone
  providing an Internet service, no size threshold):
  - *Advised* of CSAM on your service → **report** to the designated law
    enforcement body.
  - *Reasonable grounds to believe* the service is being used for a CSAM
    offence → **report, and preserve** the related computer data for
    **365 days** (C-16 raised the old 21 days; that section awaits an
    order in council — this runbook assumes 365 regardless, since holding
    longer than required is harmless and shorter is not).
  - **No tipping off**: the publisher must not learn a report was made.
  - For *manifestly* CSAM the report must include the transmission data
    you have **available** — possession is the premise; this mediator
    keeps none (see below), and the report should say so plainly.
- **Court-ordered removal** (Criminal Code s. 164.1): you must be able
  to comply — the `legal` policy mode exists for exactly this.
- **Copyright**: Canada is **notice-and-notice**, not notice-and-takedown
  — the duty is to pass the notice on, not to remove.

## Principles already built in

- **Preservation freezes what you possess; it never collects.** This
  mediator does not log reader IPs and keeps no per-user behavior logs,
  so there is no such data to preserve or to hand over — and PIPEDA's
  minimization principle points the same direction. Do not start
  collecting because of an incident; forward-looking interception is
  law enforcement's power, exercised under judicial authorization and at
  their initiative, never the host's.
- **Refused bytes never enter possession.** A blocked DID's publish is
  refused before attachments land, and barred CIDs are skipped in the
  attachment loop. Do not "keep accepting uploads for evidence" —
  knowingly storing CSAM to collect evidence is itself the offence.
- **The only log is the operator's own audit trail** (`pf_audit`, written
  by every rule change): what you blocked, when, until when. That is
  self-documentation of compliance, not user surveillance.

## The procedure

**1. Intake.** Reports arrive at the abuse address
(`MEDIATOR_ABUSE_EMAIL`, shown in the invitation page footer), from the
platform (Cloudflare enforces its own ToS on CSAM, often faster than the
law), or from law enforcement directly. Note the date and time you were
advised — the clock starts there.

**2. Assess.** Confirm the material is actually on this mediator:
`GET /card/<did>` for the folder's root card, `GET /objects/<cid>` for a
named object. Look no further than needed to act, and never redistribute.

**3. Quarantine — immediately, before anything else.**

```sh
npm run policy -- --remote quarantine <did> --note "abuse 2026-08-22 <ref>"
# a single object rather than a whole folder:
npm run policy -- --remote block <cid> --hold 365d --note "<ref>"
```

The default hold is already the Canadian 365 days. The DID's folder
vanishes from the public face as a generic absence — `did.unknown` over
DIDComm, plain 404 over HTTP, deliberately indistinguishable from never
having existed (no tipping off) — while every object in its current
closure is pinned past the garbage collector for the hold period.

**4. Report — manually.** To the body designated under C-16 (until one
is designated, the original act's channels: Cybertip.ca and local law
enforcement). Manual reporting is fully compliant — there is no volume
here to justify automation. Include the DID, the CIDs, the root card,
and the dates; state what transmission data you hold, which for this
mediator is normally **none beyond the stored objects themselves**. Do
not use `legal` mode (451) for CSAM — that is a removal signal, and
signalling is exactly what tipping off is; CSAM stays `block`. Do not
answer the publisher's questions about the disappearance.

**5. The 365-day clock.** `hold_until` on the cid rules *is* the timer:

```sh
npm run policy -- --remote list
```

shows every hold and its expiry. When a hold lapses — and law enforcement
has not instructed otherwise — clear the cid rules and let the ordinary
purge reclaim the bytes. Whether the DID block outlives the hold is the
operator's own call; nothing requires lifting it.

**6. Records.** `pf_audit` holds the rule history
(`npm run policy -- --remote audit`); keep the report correspondence and
reference numbers alongside it, off the mediator. That file plus this
audit trail is the whole compliance record.

## Removals that are not CSAM

- **Court order** (s. 164.1 or otherwise): `policy legal <did|cid>` —
  same refusal, but HTTP reads may answer 451, which is honest and
  permitted when no tipping-off duty applies.
- **Copyright notice**: forward it to the publisher — the mediation
  relationship is a ready DIDComm channel — and you're done;
  notice-and-notice imposes no takedown. Acting anyway is ToS
  discretion, not legal duty.
- **Operator's own ToS**: `block` at will; a relay may refuse to serve
  anything, any time, as local policy (spec §4.1).

## Configuration for a Canadian deployment

The code defaults *are* the Canadian numbers — a Canada "pack" is this
document, not a build flag:

| Knob | Canadian value | Where |
| --- | --- | --- |
| Quarantine hold | 365 days | `quarantine` default |
| Storage lease | 1 year | `MEDIATOR_PUBLICATION_RETAIN_SECONDS` default |
| Serve default | `allow` (public relay) / `deny` (personal) | `MEDIATOR_PUBLICATION_SERVE_DEFAULT` |

A personal mediator serving an allowlist of a few DIDs (`deny` default)
is arguably not offering a service to the public at all — which is the
applicability threshold for much platform regulation (UK OSA, Bill
C-34). Closed-by-default is a compliance posture, not just a knob.

## Watch list

- The order in council bringing C-16's reporting amendments (including
  the 365-day period) into force, and which body gets designated.
- Bill C-34 (*Safe Social Media Act*): scoped to "social media services"
  above a user threshold to be set by regulation — a self-hosted
  mediator is almost certainly out of scope, but the threshold
  regulation is worth reading when it lands.
- Bill C-22 (*Lawful Access Act, 2026*), SAAIA: capability duties for
  ESPs around lawfully-authorized access to data **in your possession**
  — the only live thread that could touch the never-collect stance.
