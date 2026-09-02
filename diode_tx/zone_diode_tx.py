#!/usr/bin/env python3
"""
zone_diode_tx.py -- one-way DNS zone transmitter, high side of an optical
data diode.

Runs on the trusted network, alongside (or on) the hidden primary BIND
server. Each cycle it:

  1. Obtains the current, authoritative zone content. By default this is a
     real AXFR pulled from the local BIND instance over 127.0.0.1
     (--source-mode axfr) -- i.e. it uses BIND's own zone-transfer
     mechanism as the source of truth, exactly like a normal secondary
     would, just confined to loopback.
  2. Chunks it, wraps every chunk plus a trailing manifest frame in an
     HMAC-authenticated packet (see common/diode_protocol.py), and sends
     them over a UDP socket that is *only ever used to send*.
  3. Repeats periodically (a "carousel") so a lost or corrupted cycle
     self-heals on the next one. There is no feedback channel to request a
     retransmit -- the diode cannot physically carry anything back to this
     host, so none is implemented here either.

This process never opens a listening socket and never calls recv() on
anything. That property should also be enforced by the physical diode
hardware and host firewalling; this script simply does not implement the
capability, as defense in depth.
"""
import argparse
import hashlib
import logging
import random
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import diode_protocol as proto  # noqa: E402

log = logging.getLogger("zone_diode_tx")

SOA_RE = re.compile(r"SOA\s+\S+\s+\S+\s*\(?\s*(\d+)", re.IGNORECASE)


def fetch_zone_axfr(zone: str, server: str, keyname: str, secret_b64: str, dig_bin: str) -> str:
    """Pull the zone via a real AXFR against the local BIND instance."""
    cmd = [dig_bin, "-y", f"hmac-sha256:{keyname}:{secret_b64}",
           "AXFR", zone, f"@{server}", "+time=5", "+tries=1"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or "Transfer failed" in result.stdout or not result.stdout.strip():
        raise RuntimeError(
            f"AXFR pull failed (rc={result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def fetch_zone_compilezone(zone: str, path: str, compilezone_bin: str) -> str:
    """Canonicalize a zone file to single-line records via named-compilezone."""
    cmd = [compilezone_bin, "-f", "text", "-o", "-", zone, path]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"named-compilezone failed: {result.stderr.strip()}")
    return result.stdout


def fetch_zone_rawfile(path: str) -> str:
    """Read a zone file as-is. Dev/demo fallback for hosts without BIND tooling."""
    return Path(path).read_text()


def extract_serial(zone_text: str) -> int:
    m = SOA_RE.search(zone_text)
    if not m:
        raise RuntimeError("could not locate SOA serial in zone content")
    return int(m.group(1))


def send_cycle(sock, dest, key, zone_name, zone_text, repeats, pacing_ms) -> int:
    payload = zone_text.encode("utf-8")
    serial = extract_serial(zone_text)
    nonce = random.getrandbits(32)
    full_hash = hashlib.sha256(payload).digest()
    chunks = list(proto.chunk_payload(payload))
    total = len(chunks)

    log.info("cycle start: zone=%s serial=%d nonce=%d bytes=%d chunks=%d",
              zone_name, serial, nonce, len(payload), total)

    order = list(range(total))
    for _ in range(repeats):
        random.shuffle(order)  # avoid correlated back-to-back loss of the same chunk
        for idx in order:
            pkt = proto.encode_packet(key, proto.MSG_CHUNK, serial, nonce, idx, total, chunks[idx])
            sock.sendto(pkt, dest)
            if pacing_ms:
                time.sleep(pacing_ms / 1000.0)

    manifest_payload = proto.build_manifest_payload(zone_name, full_hash, len(payload))
    for _ in range(repeats):
        pkt = proto.encode_packet(key, proto.MSG_MANIFEST, serial, nonce, 0, total, manifest_payload)
        sock.sendto(pkt, dest)
        if pacing_ms:
            time.sleep(pacing_ms / 1000.0)

    log.info("cycle complete: zone=%s serial=%d sha256=%s", zone_name, serial, full_hash.hex())
    return serial


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zone", required=True)
    ap.add_argument("--dest-host", required=True,
                     help="diode-facing destination address (the diode transmit interface)")
    ap.add_argument("--dest-port", type=int, default=5390)
    ap.add_argument("--key-file", required=True,
                     help="pre-shared HMAC key for the diode transport, shared out-of-band with the rx host")
    ap.add_argument("--source-mode", choices=["axfr", "compilezone", "rawfile"], default="rawfile")
    ap.add_argument("--axfr-server", default="127.0.0.1")
    ap.add_argument("--axfr-keyname", default="txfr-local")
    ap.add_argument("--axfr-secret-file", help="base64 TSIG secret for the local AXFR pull (mode=axfr)")
    ap.add_argument("--zone-file", help="zone file path (mode=compilezone/rawfile)")
    ap.add_argument("--dig-bin", default="dig")
    ap.add_argument("--compilezone-bin", default="named-compilezone")
    ap.add_argument("--interval", type=float, default=300.0,
                     help="unconditional full carousel re-broadcast interval, seconds")
    ap.add_argument("--poll-interval", type=float, default=10.0,
                     help="how often to check for a changed serial between carousel cycles")
    ap.add_argument("--repeats", type=int, default=3,
                     help="how many times to send each frame per cycle (naive redundancy, not FEC)")
    ap.add_argument("--pacing-ms", type=float, default=5.0, help="delay between individual UDP sends")
    ap.add_argument("--once", action="store_true",
                     help="send a single cycle and exit (used by the loopback demo/tests)")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                         format="%(asctime)s %(levelname)s %(message)s")

    if args.source_mode in ("compilezone", "rawfile") and not args.zone_file:
        log.error("--zone-file is required for --source-mode=%s", args.source_mode)
        return 2
    if args.source_mode == "axfr" and not args.axfr_secret_file:
        log.error("--axfr-secret-file is required for --source-mode=axfr")
        return 2

    key = proto.load_psk(args.key_file)
    dest = (args.dest_host, args.dest_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Deliberately: no sock.bind(), no sock.recv*() anywhere in this process.

    def fetch() -> str:
        if args.source_mode == "axfr":
            secret = Path(args.axfr_secret_file).read_text().strip()
            return fetch_zone_axfr(args.zone, args.axfr_server, args.axfr_keyname, secret, args.dig_bin)
        elif args.source_mode == "compilezone":
            return fetch_zone_compilezone(args.zone, args.zone_file, args.compilezone_bin)
        else:
            return fetch_zone_rawfile(args.zone_file)

    last_serial = None
    last_broadcast = 0.0

    while True:
        try:
            zone_text = fetch()
            serial = extract_serial(zone_text)
            due_for_carousel = (time.time() - last_broadcast) >= args.interval
            if args.once or last_serial is None or serial != last_serial or due_for_carousel:
                last_serial = send_cycle(sock, dest, key, args.zone, zone_text, args.repeats, args.pacing_ms)
                last_broadcast = time.time()
            else:
                log.debug("serial unchanged (%d) and carousel not due; skipping", serial)
        except Exception:
            log.exception("cycle failed; will retry")

        if args.once:
            break
        time.sleep(args.poll_interval)

    return 0


if __name__ == "__main__":
    sys.exit(main())
