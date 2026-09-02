#!/usr/bin/env python3
"""
zone_diode_rx.py -- one-way DNS zone receiver, low side of an optical data
diode.

This process only ever calls recvfrom() on its diode-facing socket -- it
never calls sendto(). It reassembles the chunk/manifest carousel produced
by zone_diode_tx.py, verifies each frame's HMAC and the reassembled zone's
SHA-256 against the manifest, rejects any serial older than the last one it
installed (anti-rollback/anti-replay), independently re-validates the zone
syntax with `named-checkzone` before touching anything on disk, and only
then atomically replaces the live zone file and asks the local BIND
instance to reload it.

There is no channel back to the transmit side. Whether fresh cycles are
still arriving has to be monitored independently on this host -- see
README.md.
"""
import argparse
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import diode_protocol as proto  # noqa: E402

log = logging.getLogger("zone_diode_rx")

MAX_INFLIGHT = 4  # cap concurrent (serial, nonce) reassembly buffers


class StateStore:
    """Tracks the last successfully installed serial/hash across restarts."""

    def __init__(self, path: Path):
        self.path = path
        self.last_serial = -1
        self.last_hash = b""
        if path.exists():
            data = json.loads(path.read_text())
            self.last_serial = data.get("last_serial", -1)
            self.last_hash = bytes.fromhex(data.get("last_hash", ""))

    def save(self, serial: int, digest: bytes) -> None:
        self.last_serial = serial
        self.last_hash = digest
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(self.path) + ".tmp")
        tmp.write_text(json.dumps({
            "last_serial": serial,
            "last_hash": digest.hex(),
            "installed_at": time.time(),
        }))
        os.replace(tmp, self.path)


def install_zone(zone: str, zone_bytes: bytes, target_path: Path, checkzone_bin: str,
                  rndc_bin: str, skip_validation: bool, skip_reload: bool) -> bool:
    tmp_path = Path(str(target_path) + ".incoming")
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    # Write the exact bytes that were hashed and verified -- no text-mode
    # newline translation, which would silently alter the file's bytes on
    # some platforms and invalidate the integrity guarantee we just checked.
    tmp_path.write_bytes(zone_bytes)

    if not skip_validation:
        result = subprocess.run([checkzone_bin, zone, str(tmp_path)],
                                 capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.error("named-checkzone rejected incoming zone %s, discarding: %s",
                       zone, result.stdout.strip() or result.stderr.strip())
            tmp_path.unlink(missing_ok=True)
            return False
        log.info("named-checkzone OK for %s", zone)

    os.replace(tmp_path, target_path)  # atomic same-filesystem rename
    log.info("installed new zone content for %s at %s", zone, target_path)

    if not skip_reload:
        result = subprocess.run([rndc_bin, "reload", zone],
                                 capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.error("rndc reload failed for %s: %s", zone,
                       result.stderr.strip() or result.stdout.strip())
            return False
        log.info("rndc reload OK for %s: %s", zone, result.stdout.strip())

    return True


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zone", required=True)
    ap.add_argument("--listen-host", default="0.0.0.0", help="the diode's receive-side interface")
    ap.add_argument("--listen-port", type=int, default=5390)
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--zone-file", required=True, help="live BIND zone file to overwrite in place")
    ap.add_argument("--state-file", default="/var/lib/odd-dns/rx-state.json")
    ap.add_argument("--checkzone-bin", default="named-checkzone")
    ap.add_argument("--rndc-bin", default="rndc")
    ap.add_argument("--skip-validation", action="store_true", help="dev/demo only -- skip named-checkzone")
    ap.add_argument("--skip-reload", action="store_true", help="dev/demo only -- skip rndc reload")
    ap.add_argument("--once", action="store_true",
                     help="exit after installing the first complete, valid cycle (used by the loopback demo/tests)")
    ap.add_argument("--idle-timeout", type=float, default=None, help="with --once, give up after this many seconds")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                         format="%(asctime)s %(levelname)s %(message)s")

    key = proto.load_psk(args.key_file)
    target_path = Path(args.zone_file)
    state = StateStore(Path(args.state_file))
    log.info("starting; last installed serial=%d", state.last_serial)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_host, args.listen_port))
    sock.settimeout(1.0)
    # Deliberately: this socket is only ever recv'd from, never sendto()'d.

    inflight = {}  # (serial, nonce) -> {"chunks": {idx: bytes}, "total": int|None}
    start = time.time()

    while True:
        if args.once and args.idle_timeout and (time.time() - start) > args.idle_timeout:
            log.error("idle timeout waiting for a complete cycle")
            return 1
        try:
            raw, _addr = sock.recvfrom(65535)
        except socket.timeout:
            continue

        try:
            pkt = proto.decode_packet(key, raw)
        except proto.ProtocolError as e:
            log.warning("dropping invalid frame: %s", e)
            continue

        txid = (pkt["serial"], pkt["nonce"])

        if pkt["serial"] < state.last_serial:
            log.warning("dropping frame for stale serial %d (last installed %d) -- possible replay/rollback",
                        pkt["serial"], state.last_serial)
            continue

        if txid not in inflight:
            if len(inflight) >= MAX_INFLIGHT:
                oldest = min(inflight)
                log.debug("evicting oldest in-flight transmission %s to make room for %s", oldest, txid)
                del inflight[oldest]
            inflight[txid] = {"chunks": {}, "total": None}

        buf = inflight[txid]

        if pkt["msg_type"] == proto.MSG_CHUNK:
            buf["total"] = pkt["total_chunks"]
            buf["chunks"][pkt["chunk_index"]] = pkt["payload"]
            continue

        if pkt["msg_type"] != proto.MSG_MANIFEST:
            log.warning("dropping frame with unknown msg_type=%d", pkt["msg_type"])
            continue

        zone_name, full_sha256, full_length = proto.parse_manifest_payload(pkt["payload"])
        total = pkt["total_chunks"]
        have = buf["chunks"]
        if len(have) < total:
            log.debug("manifest for serial=%d nonce=%d arrived but only have %d/%d chunks; waiting",
                      pkt["serial"], pkt["nonce"], len(have), total)
            continue

        assembled = b"".join(have[i] for i in range(total))
        digest = hashlib.sha256(assembled).digest()
        if len(assembled) != full_length or digest != full_sha256:
            log.warning("reassembled payload for serial=%d nonce=%d failed integrity check "
                        "(len %d vs %d, hash_ok=%s); discarding, waiting for next cycle",
                        pkt["serial"], pkt["nonce"], len(assembled), full_length, digest == full_sha256)
            del inflight[txid]
            continue

        if zone_name != args.zone:
            log.warning("manifest zone name %r does not match expected %r; discarding", zone_name, args.zone)
            del inflight[txid]
            continue

        if pkt["serial"] == state.last_serial:
            if digest != state.last_hash:
                log.error("serial %d repeated with DIFFERENT content than what's installed -- "
                          "possible corruption or spoofing attempt; NOT installing", pkt["serial"])
            else:
                log.debug("serial %d re-confirmed, content unchanged, nothing to do", pkt["serial"])
            del inflight[txid]
            if args.once:
                return 0
            continue

        log.info("cycle complete and verified: serial=%d bytes=%d sha256=%s",
                  pkt["serial"], len(assembled), digest.hex())

        ok = install_zone(args.zone, assembled, target_path, args.checkzone_bin, args.rndc_bin,
                           args.skip_validation, args.skip_reload)
        if ok:
            state.save(pkt["serial"], digest)

        del inflight[txid]

        if args.once and ok:
            return 0


if __name__ == "__main__":
    sys.exit(main())
