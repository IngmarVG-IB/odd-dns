"""
Wire format and crypto helpers for the one-way zone-diode transport.

Deploy this module IDENTICALLY on both the transmit host (inside the diode)
and the receive host (outside the diode). There is no live channel to keep
it in sync after deployment -- treat it like any other cross-domain-solution
artifact: version it, checksum it, and re-provision both sides together
whenever it changes.

Packet layout (big-endian):

    offset  size  field
    0       4     magic            b"ODNS"
    4       1     version          protocol version (currently 1)
    5       1     msg_type         1 = CHUNK, 2 = MANIFEST
    6       2     reserved         zero, reserved for future use
    8       4     serial           SOA serial of the zone content this frame belongs to
    12      4     nonce            random per transmission cycle; disambiguates
                                    repeat broadcasts of an unchanged serial
    16      4     chunk_index      0 for MANIFEST frames
    20      4     total_chunks     chunk count for this cycle
    24      2     payload_len      length of the payload that follows
    26      N     payload
    26+N    32    hmac-sha256      over every byte before this field, keyed
                                    with the pre-shared diode key

There is no field for "please resend" because there is nothing on the
receive side that can ever signal anything back across the diode. Reliability
comes from the sender re-broadcasting full cycles on a fixed carousel
interval, not from retransmission requests.
"""
import hashlib
import hmac
import struct

MAGIC = b"ODNS"
VERSION = 1

MSG_CHUNK = 1
MSG_MANIFEST = 2

_HEADER = struct.Struct(">4sBBHIIIIH")
HMAC_LEN = 32

# Keep comfortably under typical path MTU (1500) once the 26-byte header,
# 32-byte HMAC, and IP/UDP headers (28 bytes) are added: 26+1200+32+28=1286.
MAX_UDP_PAYLOAD = 1200


class ProtocolError(ValueError):
    pass


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def encode_packet(key: bytes, msg_type: int, serial: int, nonce: int,
                   chunk_index: int, total_chunks: int, payload: bytes) -> bytes:
    if len(payload) > MAX_UDP_PAYLOAD:
        raise ProtocolError(f"payload {len(payload)} exceeds MAX_UDP_PAYLOAD {MAX_UDP_PAYLOAD}")
    header = _HEADER.pack(MAGIC, VERSION, msg_type, 0, serial, nonce,
                           chunk_index, total_chunks, len(payload))
    body = header + payload
    return body + _hmac(key, body)


def decode_packet(key: bytes, raw: bytes) -> dict:
    if len(raw) < _HEADER.size + HMAC_LEN:
        raise ProtocolError("packet too short")
    body, mac = raw[:-HMAC_LEN], raw[-HMAC_LEN:]
    if not hmac.compare_digest(mac, _hmac(key, body)):
        raise ProtocolError("HMAC verification failed")
    (magic, version, msg_type, _reserved, serial, nonce,
     chunk_index, total_chunks, payload_len) = _HEADER.unpack(body[:_HEADER.size])
    if magic != MAGIC:
        raise ProtocolError("bad magic")
    if version != VERSION:
        raise ProtocolError(f"unsupported protocol version {version}")
    payload = body[_HEADER.size:_HEADER.size + payload_len]
    if len(payload) != payload_len:
        raise ProtocolError("truncated payload")
    return {
        "msg_type": msg_type,
        "serial": serial,
        "nonce": nonce,
        "chunk_index": chunk_index,
        "total_chunks": total_chunks,
        "payload": payload,
    }


def chunk_payload(data: bytes, chunk_size: int = MAX_UDP_PAYLOAD - 64):
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]


def build_manifest_payload(zone_name: str, full_sha256: bytes, full_length: int) -> bytes:
    name_bytes = zone_name.encode("ascii")
    if len(name_bytes) > 255:
        raise ProtocolError("zone name too long")
    return struct.pack(">B", len(name_bytes)) + name_bytes + full_sha256 + struct.pack(">I", full_length)


def parse_manifest_payload(payload: bytes):
    name_len = payload[0]
    zone_name = payload[1:1 + name_len].decode("ascii")
    offset = 1 + name_len
    full_sha256 = payload[offset:offset + 32]
    full_length = struct.unpack(">I", payload[offset + 32:offset + 36])[0]
    return zone_name, full_sha256, full_length


def load_psk(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read().strip()
    if len(key) < 32:
        raise ProtocolError(
            "pre-shared key must be at least 32 bytes; generate with e.g. `openssl rand -hex 32`"
        )
    return key
