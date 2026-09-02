# odd-dns — DNS zone transfer over an optical data diode

Feasibility research and a working proof of concept for mirroring a BIND
zone one-way across an optical data diode.

## Verdict

**Feasible, but not by pointing standard AXFR/IXFR at the diode and hoping.**
A real data diode is a physical guarantee that no signal — not a byte, not
a photon, not an ACK — can travel from the low side back to the high side.
Standard DNS zone transfer is layered on TCP, and TCP requires a
three-way handshake and continuous acknowledgments in *both* directions.
That is a hard physical incompatibility, not a configuration problem, and
no amount of BIND tuning fixes it.

What does work, and is what real cross-domain-solution deployments for DNS
mirroring actually do, is replacing the transport underneath the zone data
with an application-level, one-way protocol: pull the zone with a real
AXFR on the trusted side (so BIND's own transfer mechanism is still what
produces the canonical data), pack it into self-authenticating frames, and
blast it across the diode over UDP with no return channel at all. The
receiving side reassembles, verifies, independently re-validates with
`named-checkzone`, and only then swaps in the new zone file and asks its
own BIND to reload. From the outside BIND's perspective, it's just an
ordinary primary zone that happens to update itself.

This repo implements and tests that approach end-to-end (loopback-tested;
see [Testing performed](#testing-performed)).

## Why plain AXFR can't cross a diode

A physical data diode is built so there is no return path at the photonic
layer — one fiber strand, or a receiver with no laser on the return side.
Practically:

- **AXFR/IXFR ride on TCP.** The secondary (or transfer client) opens a
  TCP connection to the primary: SYN → SYN/ACK → ACK, then a query, then
  the transfer, with ACKs flowing the whole time. A diode allowing traffic
  only high→low means the SYN/ACK — and every subsequent ACK — can never
  get back to the initiator. The handshake never completes. This is true
  regardless of which side initiates.
- **DNS NOTIFY** (UDP, master→secondary) *does* fit the diode's direction
  if the master is on the high side, but NOTIFY alone doesn't transfer any
  data — it just tells a secondary to go pull a zone via AXFR, and that
  pull is exactly the TCP flow that can't complete.
- **A hidden-primary architecture** — keeping the authoritative master
  fully isolated and only letting *data* flow out to a public-facing
  server — is the right security posture here (no path exists for the
  outside world to reach back into the trusted master at all), but it
  makes the direction problem sharper: the entity that would normally
  *request* the transfer sits on the wrong side of the diode.

None of this is BIND-specific. It's true of any TCP-based protocol pointed
at a diode.

## Two architectures, and why this repo picks one

**Option A — transparent TCP-proxy / protocol break.** This is how most
commercial diode appliances (Owl Cyber Defense, Fox DataDiode,
Owl/Everfox, Waterfall) support arbitrary TCP protocols including generic
AXFR: a proxy on the high side terminates the real TCP connection *locally*
(fully bidirectional, but confined to the trusted network), serializes the
byte stream, sends it one-way across the diode, and a proxy on the low
side replays it as a local TCP server or client so the real endpoints
never know the middle of their connection was a one-way hop. This is
generic and works for any protocol, at the cost of depending on the
vendor's proxy SDK and of the low-side proxy having to parse/re-emit
arbitrary TCP/DNS wire traffic — a larger and less auditable attack
surface for something whose only job should be "receive validated zone
data."

**Option B — application-level one-way zone relay (implemented here).**
Don't try to make AXFR's wire protocol survive the diode at all. Use AXFR
normally *inside* the trusted network to get the canonical zone content,
then hand that content to a purpose-built one-way transport whose only
message shapes are "here is a chunk of zone data" and "here is the hash of
the complete zone." The receiver only ever has to parse that tiny,
fixed format — not general DNS/TCP traffic — before independently
re-validating with `named-checkzone`. This is simpler, works with any
generic UDP-capable diode hardware (no vendor SDK dependency), and shrinks
the low side's attack surface to "a hash-verified zone file." The
trade-off is that it's zone-file replication in spirit, not a literal AXFR
session end-to-end — for the goal of "mirror this zone across the diode,"
that distinction doesn't matter; BIND on the low side truly doesn't know
or care how its zone file got there.

This repo builds Option B.

## Architecture

```
   TRUSTED / HIGH SIDE                    │  DIODE  │        UNTRUSTED / LOW SIDE
   ────────────────────                   │  (TX→RX  │        ─────────────────────
                                           │  only)   │
   ┌─────────────────────┐                │          │        ┌──────────────────────┐
   │ named (hidden primary)│               │          │        │ named (public primary)│
   │  zone: example.com    │◄── AXFR ──┐   │          │        │  zone: example.com    │
   │  allow-transfer:       │           │   │          │        │  file owned exclusively│
   │   key txfr-local only  │           │   │          │        │  by zone_diode_rx.py   │
   │  listen-on: 127.0.0.1  │           │   │          │        └───────────▲────────────┘
   └─────────────────────┘           │   │          │                    │ rndc reload
                                       │   │          │                    │ named-checkzone
   ┌─────────────────────┐           │   │          │        ┌───────────┴────────────┐
   │ zone_diode_tx.py       │◄──── pull ──┘   │          │        │ zone_diode_rx.py       │
   │  AXFR over loopback,   │                │          │        │  HMAC-verify each frame│
   │  HMAC-frame + chunk,   │── UDP, send────►┼─────────►┼───────►│  reassemble, sha256     │
   │  send-only socket      │   only          │  no return │        │  check, serial ratchet │
   └─────────────────────┘                │  path exists│       └──────────────────────┘
```

- The **only** thing that ever crosses the diode is the UDP frame stream
  from `zone_diode_tx.py` to `zone_diode_rx.py`.
- The hidden primary is not even reachable from the diode-facing network —
  `zone_diode_tx.py` pulls from it over loopback, and the diode-facing UDP
  socket it uses to send is never bound to receive and never calls
  `recv()`. That's enforced in code, on top of whatever the diode hardware
  itself enforces.
- `zone_diode_rx.py`'s socket is receive-only in the same sense: it never
  calls `sendto()`.

## Wire protocol

Every UDP datagram is a self-contained, HMAC-authenticated frame (see
[common/diode_protocol.py](common/diode_protocol.py) for the exact byte
layout). Two message types:

- **CHUNK** — one piece of the zone's serialized text, tagged with the
  SOA serial and a per-cycle random nonce (so repeat broadcasts of an
  unchanged zone don't collide with each other), plus its index and the
  cycle's total chunk count.
- **MANIFEST** — sent after all chunks, carries the zone name, the
  SHA-256 of the *complete* reassembled payload, and its length.

There is deliberately no "please resend chunk N" message — there is
nothing on the receive side that could ever send one. Reliability instead
comes from:

1. **Redundancy.** Each frame is sent multiple times per cycle
   (`--repeats`, default 3) in shuffled order, so a burst of loss is less
   likely to take out every copy of the same chunk.
2. **The carousel.** The transmitter re-sends the full zone unconditionally
   every `--interval` (default 300s), regardless of whether it changed,
   *and* immediately when it detects the SOA serial has changed (polled
   every `--poll-interval`, default 10s). A cycle that was lost or
   corrupted is simply superseded by the next one. This is the same
   principle one-way satellite/broadcast file transfer tools (e.g. UFTP)
   use, just implemented minimally here rather than with real forward
   error correction — see [Limitations](#limitations--production-hardening).

On the receive side, a cycle is only accepted once **all** of its chunks
have arrived and the reassembled payload's SHA-256 matches the manifest
exactly. A partial or corrupted cycle is silently discarded — the
previously-installed zone keeps serving — and the next carousel cycle gets
another chance.

## Integrity, authenticity, and anti-replay

- **HMAC-SHA256** on every frame, keyed with a pre-shared key provisioned
  out-of-band on both hosts (see [secrets/README.md](secrets/README.md)).
  This is not DNS TSIG — TSIG requires the kind of interactive exchange a
  diode can't carry — but it serves the same purpose for this transport:
  a frame that doesn't carry a valid MAC is dropped before anything else
  is done with it.
- **Serial ratchet.** The receiver persists the last serial it installed
  (`--state-file`) and refuses anything older, which blocks replay of a
  captured older cycle or an accidental rollback. It also refuses to
  *reinstall* if the same serial ever shows up with a different hash than
  what's already live — that combination should never happen legitimately
  (a real content change always bumps the serial) and is treated as a
  corruption/spoofing signal, logged, and rejected.
- **Independent validation before install.** Even though the HMAC already
  authenticates the sender, `named-checkzone` is run against the
  reassembled zone before it ever touches the live file. This turns "a bug
  in our own tx pipeline (or a compromised tx host) produces malformed
  zone data" into "the low side rejects it and keeps serving the last-good
  zone," instead of a crash or an inconsistent zone load.
- **Atomic install.** The new zone is written to a temp file next to the
  target and `os.replace()`'d into place — `named` never observes a
  partially-written file.

## DNSSEC synergy

If the zone is signed (inline-signing or offline `dnssec-signzone`), do it
on the hidden primary, *before* `zone_diode_tx.py` ever reads it. The
outside primary then only ever serves static, pre-signed RRSIGs — it has
no signing configuration at all. The private KSK/ZSK material has no
reason to ever leave the high side, diode included. That's a nice
alignment between the diode's own trust boundary and DNSSEC's.

## No feedback channel, by design

This is the one thing worth being explicit about rather than papering
over: **the high side can never know whether the low side received
anything.** That's not a gap in this implementation, it's the diode doing
its job. Operational consequences:

- Monitor both sides independently. On the low side, alert if
  `zone_diode_rx.py` hasn't logged a verified cycle in longer than a few
  multiples of `--interval`. On the high side, alert on any AXFR-pull or
  send failure. Neither side can infer the other's health from the wire.
- Don't build anything on this path that assumes eventual acknowledgment.
  The carousel exists specifically so correctness doesn't depend on one.

## Repo layout

```
common/diode_protocol.py     wire format + HMAC framing, identical on both hosts
diode_tx/zone_diode_tx.py    high-side transmitter (send-only)
diode_rx/zone_diode_rx.py    low-side receiver (recv-only)
bind/inside/                 hidden-primary named.conf + sample zone
bind/outside/                public-primary named.conf; zones/ populated by zone_diode_rx.py
systemd/                     example unit files for both daemons
secrets/                     key-provisioning instructions (no real keys committed)
test/run_demo.sh             loopback demo, no diode hardware or BIND install required
test/lossy_relay.py          test-only lossy UDP relay used by the demo's --lossy mode
```

In a real deployment, `common/` is copied alongside each of `diode_tx/`
and `diode_rx/` independently — there's no live filesystem link across an
air gap to keep a shared import in sync. Version and checksum it like any
other cross-domain-solution artifact, and re-provision both sides together
when it changes.

## Running the demo

No real diode, and no BIND install, is required to see the protocol work:

```bash
test/run_demo.sh            # single-chunk zone, clean link
test/run_demo.sh --lossy    # multi-chunk zone through a 30%-loss relay
```

Both spin up `zone_diode_rx.py` and `zone_diode_tx.py` against each other
over `127.0.0.1`, with `--skip-validation --skip-reload` (since there's no
`named-checkzone`/`rndc` on a bare dev box), and diff the reassembled zone
against the source.

### Deploying for real

1. Install BIND on both hosts; use [bind/inside/named.conf.inside](bind/inside/named.conf.inside)
   and [bind/outside/named.conf.outside](bind/outside/named.conf.outside) as
   starting points (replace the placeholder TSIG secret via `tsig-keygen`).
2. Generate the diode transport key and provision it to both hosts
   out-of-band — see [secrets/README.md](secrets/README.md).
3. Copy `diode_tx/` + `common/` to the high-side host, `diode_rx/` +
   `common/` to the low-side host.
4. Install [systemd/diode-tx.service](systemd/diode-tx.service) and
   [systemd/diode-rx.service](systemd/diode-rx.service), adjusting paths,
   addresses, and the `rndc` key/user permissions for your environment.
5. Drop `--skip-validation --skip-reload` — those flags exist only for the
   BIND-less demo.
6. Connect the diode: the tx host's UDP destination is the diode's
   transmit-side interface; the rx host listens on the diode's receive-side
   interface.

## Limitations / production hardening

- **Naive redundancy, not real FEC.** `--repeats` improves odds under
  light loss but isn't Reed-Solomon or similar; heavy or bursty loss can
  still cost a cycle (it'll just retry at the next carousel interval, so
  correctness holds, but propagation latency suffers). For high-value or
  latency-sensitive deployments, swap the transport for a real one-way
  file-transfer protocol with proper FEC (e.g. UFTP, or a vendor diode's
  bundled transport) and keep this repo's framing/validation/ratchet logic
  on top of it.
- **Full-zone transfer only**, no incremental (IXFR-style) diffing — every
  cycle sends the complete zone. Fine for typical zone sizes; for very
  large zones with frequent small changes, incremental transfer would cut
  bandwidth at the cost of real complexity (a diode has no channel to
  confirm the receiver's base version before diffing against it).
- **Single zone per port** in this PoC, but the wire format already
  carries the zone name in the manifest, so multiplexing several zones over
  one port (or just running one tx/rx pair per zone) is a small extension,
  not a redesign.
- **Key rotation isn't implemented**, only noted as a possible extension
  in [secrets/README.md](secrets/README.md).
- **rx host's `rndc` permissions** need to be scoped tightly (reload only,
  not full control) — see the comment in
  [systemd/diode-rx.service](systemd/diode-rx.service).

## Testing performed

No physical diode was available, so testing was done over loopback UDP,
which exercises everything except the hardware's own one-way enforcement
(the software already never listens/sends on the wrong side, per the
[Architecture](#architecture) section above):

- Small, single-chunk zone: transmitted and reassembled byte-identical.
- Larger, 4–9 chunk zone through a synthetic 30%-packet-loss relay with
  `--repeats 4`: transmitted and reassembled byte-identical (verified via
  matching SHA-256 logged independently by both the transmitter and
  receiver).
- Anti-corruption check exercised (initially by accident, then
  confirmed deliberately): a repeat of an already-installed serial with
  *different* content is correctly logged and rejected rather than
  installed.
- `named-checkzone`/`rndc` were not available in this environment, so
  `--skip-validation`/`--skip-reload` were used for the above; that code
  path (subprocess invocation and error handling) has not been exercised
  against a real BIND install. Recommend validating that specifically
  before production use.
