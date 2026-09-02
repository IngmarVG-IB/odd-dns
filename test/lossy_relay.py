#!/usr/bin/env python3
"""
lossy_relay.py -- test-only UDP relay that randomly drops a fraction of
datagrams, standing in for a lossy diode/fiber link so the demo can show
the tx/rx carousel and per-frame redundancy actually recovering from loss.
This is test scaffolding, not part of the deployed system.
"""
import random
import socket
import sys
import time

def main():
    listen_port, dest_port = int(sys.argv[1]), int(sys.argv[2])
    loss_pct, duration_s = float(sys.argv[3]), float(sys.argv[4])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", listen_port))
    sock.settimeout(0.5)
    dest = ("127.0.0.1", dest_port)

    dropped = forwarded = 0
    end = time.time() + duration_s
    while time.time() < end:
        try:
            data, _addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except ConnectionResetError:
            # Windows UDP quirk: an ICMP port-unreachable from an earlier
            # send can surface on a later recvfrom() on the same socket.
            # Not a real loss event -- just keep relaying.
            continue
        if random.random() < loss_pct:
            dropped += 1
            continue
        sock.sendto(data, dest)
        forwarded += 1

    print(f"relay done: forwarded={forwarded} dropped={dropped} "
          f"({100 * dropped / max(1, forwarded + dropped):.0f}% loss)", file=sys.stderr)


if __name__ == "__main__":
    main()
