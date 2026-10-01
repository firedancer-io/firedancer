#!/usr/bin/env python3
"""Captures a Dragon's Mouth subscription and normalizes it.

Speaks HTTP/2 over a raw socket, so it needs nothing installed beyond
the protobuf runtime, and it talks to anything that serves the
geyser.Geyser service: the dragon tile, or yellowstone-grpc loaded by
agave, which is what makes the two captures comparable.

  ./capture.py --port 10801 --filters filters/accounts.json \\
               --commitment processed --seconds 120 --out /tmp/cap/acct_p

The run writes four files under the --out prefix:

  <out>.bin         the response messages exactly as they arrived, with
                    their gRPC length prefix and decompressed
  <out>.jsonl       one normalized record per update, except slot
                    statuses
  <out>.slots.jsonl one normalized record per slot status
  <out>.meta.json   what the run saw: counts, the filter set, the
                    trailers the server closed with, and any gap

A normalized record is

  {"seq": n, "slot": s, "kind": k, "key": "...", "payload": {...},
   "nondet": {...}}

`kind` is one of account, transaction, transaction_status, block,
block_meta, slot, entry.  `key` identifies the subject within its slot:
the pubkey of an account, the signature of a transaction, the blockhash
of a block, the status name of a slot update.  `payload` holds
everything a comparison may look at, with the normalization of the
conformance harness (plan section 8) already applied: keys, signatures
and hashes base58, data hex, field order stable, nothing that depends on
which server produced the stream.  The values that do depend on it --
`created_at`, `bank_id`, `write_version` -- are kept out of `payload`
and go in `nondet`, where a diff never looks but the self-consistency
checker can still use them; `--no-nondet` leaves them out entirely.
`seq` is the arrival order and is not part of any comparison.

Decoding uses python classes built at run time from the vendored
.proto files, so nothing generated is checked in.  It needs protoc and
the protobuf runtime.  Decoding is a second pass over <out>.bin, so a
slow decoder cannot make the capture lag behind the server, and
--decode-only runs that pass alone, on this script's own output or on
any file of gRPC response messages (what `curl --output` writes, for
instance).

The filter spec is a SubscribeRequest in protobuf JSON:

  {"accounts": {"all": {"owner": ["Vote111..."]}},
   "accounts_data_slice": [{"offset": 0, "length": 32}],
   "commitment": "FINALIZED"}
"""

import argparse
import json
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------- base58

# ---------------------------------------------------------------- zstd

try:
    import zstandard
    _ZSTD = zstandard.ZstdDecompressor()

    def zstd_decompress(body):
        # The server's frames declare their content size, but a frame
        # that does not must decode too.
        return _ZSTD.decompressobj().decompress(body)
except ImportError:
    _ZSTD = None

    def zstd_decompress(body):
        r = subprocess.run(["zstd", "-d", "-q", "-c"], input=body,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode:
            raise ValueError("zstd -d failed: %s" % r.stderr.decode(errors="replace"))
        return r.stdout


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58enc(raw):
    if not raw:
        return ""
    n = int.from_bytes(raw, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    for c in raw:
        if c:
            break
        out.append("1")
    return "".join(reversed(out))


# ------------------------------------------------------------------ hpack

# RFC 7541 appendix A.  Index 0 is unused.
HPACK_STATIC = [
    None,
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""),
    ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""),
    ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""),
    ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""),
    ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""),
    ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""),
    ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""),
    ("via", ""), ("www-authenticate", ""),
]

# The code length of each of the 257 HPACK huffman symbols, as a
# character per symbol offset by '0'.  The code itself is canonical --
# symbols of equal length take consecutive codes in symbol order -- so
# the lengths determine the whole table (RFC 7541 appendix B).
HUFF_LENS = (
    "=GLLLLLLLHNLLNLLLLLLLLNLLLLLLLLL6::<=68;::8;8666555666666678?6<:=677777777"
    "77777777777777878=C=>6?56565666577666567655677777?;>=LDFDDFFFGFGGGGGHGHHFG"
    "HGGGGEFGFGGHFEDFFGGEGFFHEFGGEEFEGFGGDFFFGFFGJJDCFGFIJJJKKJHICEJKKJKHEEJJLK"
    "KKDHDEFEEGFFIIHHJGJKJJKKKKKLKKKKKJN"
)


def _huff_table():
    lens = [ord(c) - 48 for c in HUFF_LENS]
    table = {}
    code = 0
    prev = None
    for sym in sorted(range(len(lens)), key=lambda s: (lens[s], s)):
        if prev is None:
            prev = lens[sym]
        else:
            code = (code + 1) << (lens[sym] - prev)
            prev = lens[sym]
        table[(lens[sym], code)] = sym
    return table


HUFF = _huff_table()
HUFF_MAXLEN = max(l for l, _ in HUFF)
HUFF_MINLEN = min(l for l, _ in HUFF)


def huff_decode(data):
    out = bytearray()
    cur = 0
    nbits = 0
    for byte in data:
        cur = (cur << 8) | byte
        nbits += 8
        while nbits >= HUFF_MINLEN:
            sym = None
            for ln in range(HUFF_MINLEN, min(nbits, HUFF_MAXLEN) + 1):
                sym = HUFF.get((ln, (cur >> (nbits - ln)) & ((1 << ln) - 1)))
                if sym is not None:
                    break
            if sym is None:
                break
            if sym == 256:
                raise ValueError("huffman EOS in a header value")
            out.append(sym)
            nbits -= ln
            cur &= (1 << nbits) - 1
    if nbits >= HUFF_MAXLEN or (nbits and cur != (1 << nbits) - 1):
        raise ValueError("huffman padding is not all ones")
    return bytes(out)


class Hpack:
    """The decoder half of one connection's header compression."""

    def __init__(self, table_size=4096):
        self.entries = []          # newest first
        self.size = 0
        self.max = table_size

    def _evict(self):
        while self.size > self.max:
            name, value = self.entries.pop()
            self.size -= len(name) + len(value) + 32

    def _insert(self, name, value):
        self.entries.insert(0, (name, value))
        self.size += len(name) + len(value) + 32
        self._evict()

    def _get(self, idx):
        if idx == 0:
            raise ValueError("header index 0")
        if idx < len(HPACK_STATIC):
            return HPACK_STATIC[idx]
        idx -= len(HPACK_STATIC)
        if idx >= len(self.entries):
            raise ValueError("header index %d past the dynamic table" % idx)
        return self.entries[idx]

    @staticmethod
    def _int(buf, i, prefix):
        mask = (1 << prefix) - 1
        v = buf[i] & mask
        i += 1
        if v < mask:
            return v, i
        shift = 0
        while True:
            b = buf[i]
            i += 1
            v += (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return v, i

    def _str(self, buf, i):
        huff = bool(buf[i] & 0x80)
        n, i = self._int(buf, i, 7)
        raw = bytes(buf[i:i + n])
        i += n
        if len(raw) != n:
            raise ValueError("truncated header string")
        if huff:
            raw = huff_decode(raw)
        return raw.decode("utf-8", "replace"), i

    def decode(self, block):
        out = []
        i = 0
        n = len(block)
        while i < n:
            b = block[i]
            if b & 0x80:
                idx, i = self._int(block, i, 7)
                out.append(self._get(idx))
            elif b & 0x40:
                idx, i = self._int(block, i, 6)
                if idx:
                    name = self._get(idx)[0]
                else:
                    name, i = self._str(block, i)
                value, i = self._str(block, i)
                self._insert(name, value)
                out.append((name, value))
            elif b & 0x20:
                self.max, i = self._int(block, i, 5)
                self._evict()
            else:
                idx, i = self._int(block, i, 4)
                if idx:
                    name = self._get(idx)[0]
                else:
                    name, i = self._str(block, i)
                value, i = self._str(block, i)
                out.append((name, value))
        return out


def hpack_lit(name, value):
    """One literal header field without indexing, never huffman coded."""
    n = name.encode()
    v = value.encode()
    if len(n) > 126 or len(v) > 126:
        raise ValueError("header field too long for the simple encoding")
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v


# ------------------------------------------------------------------ http/2

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x01
FLAG_ACK = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08

SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5

WINDOW = (1 << 30)          # what we advertise for the connection and the stream
WINDOW_STEP = (1 << 22)     # replenish once this much has been consumed
MAX_SEND_FRAME = 16384      # every peer must accept a frame this big


def frame(typ, flags, sid, payload=b""):
    return (bytes([(len(payload) >> 16) & 0xFF, (len(payload) >> 8) & 0xFF,
                   len(payload) & 0xFF, typ, flags])
            + struct.pack(">I", sid) + payload)


class StreamEnd(Exception):
    """The server closed the stream or the connection."""

    def __init__(self, reason, status=None, message=None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.message = message


class Call:
    """One server-streaming call on its own connection."""

    def __init__(self, host, port, path, token=None, zstd=False,
                 authority=None, connect_timeout=10.0):
        self.host = host
        self.port = port
        self.path = path
        self.token = token
        self.zstd = zstd
        self.msgs_compressed = 0
        self.coded_bytes = 0   # message bytes as they came off the wire
        self.plain_bytes = 0   # the same messages after decompression
        self.authority = authority or ("%s:%d" % (host, port))
        self.sock = socket.create_connection((host, port), timeout=connect_timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(None)
        self.sock.setblocking(False)
        self.hpack = Hpack()
        self.rx = bytearray()
        self.rxoff = 0
        self.hdr_block = bytearray()
        self.hdr_end_stream = False
        self.msg = bytearray()          # the response message being assembled
        self.conn_used = 0
        self.stream_used = 0
        self.resp_headers = None
        self.trailers = None
        self.resp_encoding = None
        self.bytes_rx = 0
        self._sendq = bytearray()
        self._send(PREFACE)
        self._send(frame(FRAME_SETTINGS, 0, 0,
                         struct.pack(">HI", SETTINGS_INITIAL_WINDOW_SIZE, WINDOW)))
        self._send(frame(FRAME_WINDOW_UPDATE, 0, 0,
                         struct.pack(">I", WINDOW - 65535)))

    # -- sending

    def _send(self, data):
        self._sendq += data
        self._flush()

    def _flush(self):
        while self._sendq:
            try:
                n = self.sock.send(self._sendq)
            except BlockingIOError:
                return
            except OSError as e:
                raise StreamEnd("send failed: %s" % e)
            if not n:
                raise StreamEnd("send returned zero")
            del self._sendq[:n]

    def open(self, req_msg):
        hdrs = (hpack_lit(":method", "POST")
                + hpack_lit(":scheme", "http")
                + hpack_lit(":path", self.path)
                + hpack_lit(":authority", self.authority)
                + hpack_lit("content-type", "application/grpc")
                + hpack_lit("te", "trailers")
                + hpack_lit("user-agent", "fd-dragon-capture"))
        if self.zstd:
            hdrs += hpack_lit("grpc-accept-encoding", "zstd")
        if self.token is not None:
            hdrs += hpack_lit("x-token", self.token)
        self._send(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, hdrs))
        self.send_msg(req_msg)

    def send_msg(self, body):
        payload = b"\x00" + struct.pack(">I", len(body)) + body
        for off in range(0, len(payload), MAX_SEND_FRAME):
            self._send(frame(FRAME_DATA, 0, 1, payload[off:off + MAX_SEND_FRAME]))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # -- receiving

    def _consume(self, n):
        self.conn_used += n
        self.stream_used += n
        if self.conn_used >= WINDOW_STEP:
            self._send(frame(FRAME_WINDOW_UPDATE, 0, 0,
                             struct.pack(">I", self.conn_used)))
            self.conn_used = 0
        if self.stream_used >= WINDOW_STEP:
            self._send(frame(FRAME_WINDOW_UPDATE, 0, 1,
                             struct.pack(">I", self.stream_used)))
            self.stream_used = 0

    def _fill(self, timeout):
        """Reads whatever the socket has.  Returns False on timeout."""
        self._flush()
        want_w = [self.sock] if self._sendq else []
        r, _, _ = select.select([self.sock], want_w, [], timeout)
        if not r:
            return False
        try:
            b = self.sock.recv(1 << 20)
        except BlockingIOError:
            return False
        except OSError as e:
            raise StreamEnd("connection lost: %s" % e)
        if not b:
            raise StreamEnd("connection closed by peer")
        self.bytes_rx += len(b)
        self.rx += b
        return True

    def _frames(self):
        """Yields whole frames out of the receive buffer."""
        while True:
            avail = len(self.rx) - self.rxoff
            if avail < 9:
                break
            h = self.rx[self.rxoff:self.rxoff + 9]
            ln = (h[0] << 16) | (h[1] << 8) | h[2]
            if avail < 9 + ln:
                break
            typ = h[3]
            flags = h[4]
            sid = struct.unpack(">I", h[5:9])[0] & 0x7FFFFFFF
            beg = self.rxoff + 9
            self.rxoff = beg + ln
            yield typ, flags, sid, self.rx[beg:beg + ln]
        if self.rxoff > (1 << 20):
            del self.rx[:self.rxoff]
            self.rxoff = 0

    def poll(self, timeout, on_message):
        """Runs one receive cycle, calling on_message(body) per message."""
        if not self._fill(timeout):
            return
        for typ, flags, sid, payload in self._frames():
            if typ == FRAME_DATA:
                body = payload
                if flags & FLAG_PADDED:
                    body = body[1:len(body) - payload[0]]
                self._consume(len(payload))
                self.msg += body
                self._drain_messages(on_message)
                if flags & FLAG_END_STREAM:
                    raise StreamEnd("stream ended", self.grpc_status())
            elif typ in (FRAME_HEADERS, FRAME_CONTINUATION):
                body = payload
                if typ == FRAME_HEADERS:
                    self.hdr_end_stream = bool(flags & FLAG_END_STREAM)
                    if flags & FLAG_PADDED:
                        body = body[1:len(body) - payload[0]]
                    if flags & 0x20:   # priority
                        body = body[5:]
                self.hdr_block += body
                if flags & FLAG_END_HEADERS:
                    hdrs = self.hpack.decode(bytes(self.hdr_block))
                    self.hdr_block = bytearray()
                    self._on_headers(hdrs)
                    if self.hdr_end_stream:
                        raise StreamEnd("trailers", self.grpc_status())
            elif typ == FRAME_SETTINGS:
                if not flags & FLAG_ACK:
                    self._send(frame(FRAME_SETTINGS, FLAG_ACK, 0))
            elif typ == FRAME_PING:
                if not flags & FLAG_ACK:
                    self._send(frame(FRAME_PING, FLAG_ACK, 0, bytes(payload)))
            elif typ == FRAME_RST_STREAM:
                code = struct.unpack(">I", bytes(payload[:4]))[0] if len(payload) >= 4 else 0
                raise StreamEnd("stream reset, error %d" % code, self.grpc_status())
            elif typ == FRAME_GOAWAY:
                code = struct.unpack(">I", bytes(payload[4:8]))[0] if len(payload) >= 8 else 0
                raise StreamEnd("goaway, error %d" % code, self.grpc_status())

    def _on_headers(self, hdrs):
        table = {}
        for name, value in hdrs:
            table.setdefault(name, value)
        if self.resp_headers is None and not self.hdr_end_stream:
            self.resp_headers = table
            self.resp_encoding = table.get("grpc-encoding")
        else:
            self.trailers = table

    def grpc_status(self):
        for table in (self.trailers, self.resp_headers):
            if table and "grpc-status" in table:
                return (int(table["grpc-status"]), table.get("grpc-message", ""))
        return None

    def _drain_messages(self, on_message):
        buf = self.msg
        off = 0
        while len(buf) - off >= 5:
            compressed = buf[off]
            ln = struct.unpack(">I", bytes(buf[off + 1:off + 5]))[0]
            if len(buf) - off < 5 + ln:
                break
            body = bytes(buf[off + 5:off + 5 + ln])
            off += 5 + ln
            if compressed:
                body = zstd_decompress(body)
                self.msgs_compressed += 1
            self.coded_bytes += ln
            self.plain_bytes += len(body)
            on_message(body)
        if off:
            del buf[:off]


# ------------------------------------------------------- wire-format peek

def _varint(buf, i):
    v = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, i


def _walk(buf):
    """Yields (field number, wire type, value) over one message."""
    i = 0
    n = len(buf)
    while i < n:
        key, i = _varint(buf, i)
        wire = key & 7
        num = key >> 3
        if wire == 0:
            v, i = _varint(buf, i)
            yield num, wire, v
        elif wire == 2:
            ln, i = _varint(buf, i)
            yield num, wire, buf[i:i + ln]
            i += ln
        elif wire == 5:
            yield num, wire, buf[i:i + 4]
            i += 4
        elif wire == 1:
            yield num, wire, buf[i:i + 8]
            i += 8
        else:
            return


def peek_slot_status(body):
    """(slot, status) if this update is a slot status, else None.

    A hand-rolled walk of the top level, so that watching for a target
    slot costs nothing on the messages that carry account or
    transaction data."""
    try:
        for num, wire, val in _walk(body):
            if num == 3 and wire == 2:
                slot = 0
                status = 0
                for fnum, fwire, fval in _walk(val):
                    if fnum == 1 and fwire == 0:
                        slot = fval
                    elif fnum == 3 and fwire == 0:
                        status = fval
                return slot, status
    except (IndexError, ValueError):
        return None
    return None


def peek_kind(body):
    """The field number of the update oneof, or 0."""
    try:
        for num, wire, _ in _walk(body):
            if wire == 2 and num in (2, 3, 4, 5, 7, 8, 10):
                return num
            if wire == 2 and num in (6, 9):
                return num
    except (IndexError, ValueError):
        pass
    return 0


# -------------------------------------------------------- protobuf runtime

class Protos:
    """The message classes of the vendored protos."""

    def __init__(self, pool):
        from google.protobuf import message_factory
        self.pool = pool
        self.SubscribeRequest = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("geyser.SubscribeRequest"))
        self.SubscribeUpdate = message_factory.GetMessageClass(
            pool.FindMessageTypeByName("geyser.SubscribeUpdate"))


def load_protos(proto_dir, work_dir=None):
    """Compiles the vendored protos and builds the message classes.

    protoc writes a descriptor set into a temporary directory and the
    protobuf runtime builds the classes from it, so nothing generated
    is checked in and the classes do not depend on the version of
    protoc that produced them."""
    from google.protobuf import descriptor_pb2, descriptor_pool
    out = work_dir or tempfile.mkdtemp(prefix="dragon-proto-")
    fds_path = os.path.join(out, "geyser.fds")
    subprocess.run(["protoc", "--experimental_allow_proto3_optional",
                    "--include_imports", "--descriptor_set_out=" + fds_path,
                    "-I", proto_dir,
                    "geyser.proto", "solana_storage.proto", "timestamp.proto"],
                   check=True)
    fds = descriptor_pb2.FileDescriptorSet()
    with open(fds_path, "rb") as f:
        fds.ParseFromString(f.read())
    pool = descriptor_pool.DescriptorPool()
    for file_proto in fds.file:
        pool.Add(file_proto)
    return Protos(pool)


def default_proto_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "src", "discof",
                                         "dragon", "proto"))


# ------------------------------------------------------------ normalizing

COMMITMENTS = {"processed": 0, "confirmed": 1, "finalized": 2}

SLOT_STATUS_NAME = {
    0: "processed", 1: "confirmed", 2: "finalized",
    3: "first_shred_received", 4: "completed", 5: "created_bank", 6: "dead",
}


def _opt(msg, field):
    """The value of an optional field, or None when it is not set."""
    return getattr(msg, field) if msg.HasField(field) else None


def norm_message(m):
    out = {
        "header": {
            "num_required_signatures": m.header.num_required_signatures,
            "num_readonly_signed_accounts": m.header.num_readonly_signed_accounts,
            "num_readonly_unsigned_accounts": m.header.num_readonly_unsigned_accounts,
        },
        "account_keys": [b58enc(k) for k in m.account_keys],
        "recent_blockhash": b58enc(m.recent_blockhash),
        "instructions": [
            {"program_id_index": i.program_id_index,
             "accounts": i.accounts.hex(),
             "data": i.data.hex()} for i in m.instructions],
        "versioned": m.versioned,
        "address_table_lookups": [
            {"account_key": b58enc(a.account_key),
             "writable_indexes": a.writable_indexes.hex(),
             "readonly_indexes": a.readonly_indexes.hex()}
            for a in m.address_table_lookups],
    }
    if m.HasField("config"):
        c = m.config
        out["config"] = {
            "priority_fee": _opt(c, "priority_fee"),
            "compute_unit_limit": _opt(c, "compute_unit_limit"),
            "loaded_accounts_data_size_limit": _opt(c, "loaded_accounts_data_size_limit"),
            "heap_size": _opt(c, "heap_size"),
        }
    return out


def norm_token_balance(b):
    return {
        "account_index": b.account_index,
        "mint": b.mint,
        "owner": b.owner,
        "program_id": b.program_id,
        "ui_token_amount": {
            "ui_amount": b.ui_token_amount.ui_amount,
            "decimals": b.ui_token_amount.decimals,
            "amount": b.ui_token_amount.amount,
            "ui_amount_string": b.ui_token_amount.ui_amount_string,
        },
    }


def norm_reward(r):
    return {"pubkey": r.pubkey, "lamports": r.lamports,
            "post_balance": r.post_balance, "reward_type": int(r.reward_type),
            "commission": r.commission, "commission_bps": r.commission_bps}


def norm_rewards(rw):
    return {"rewards": [norm_reward(r) for r in rw.rewards],
            "num_partitions": (rw.num_partitions.num_partitions
                               if rw.HasField("num_partitions") else None)}


def norm_meta(meta):
    return {
        "err": meta.err.err.hex() if meta.HasField("err") else None,
        "fee": meta.fee,
        "pre_balances": list(meta.pre_balances),
        "post_balances": list(meta.post_balances),
        "inner_instructions": [
            {"index": ii.index,
             "instructions": [
                 {"program_id_index": i.program_id_index,
                  "accounts": i.accounts.hex(),
                  "data": i.data.hex(),
                  "stack_height": _opt(i, "stack_height")}
                 for i in ii.instructions]}
            for ii in meta.inner_instructions],
        "inner_instructions_none": meta.inner_instructions_none,
        "log_messages": list(meta.log_messages),
        "log_messages_none": meta.log_messages_none,
        "pre_token_balances": [norm_token_balance(b) for b in meta.pre_token_balances],
        "post_token_balances": [norm_token_balance(b) for b in meta.post_token_balances],
        "rewards": [norm_reward(r) for r in meta.rewards],
        "loaded_writable_addresses": [b58enc(a) for a in meta.loaded_writable_addresses],
        "loaded_readonly_addresses": [b58enc(a) for a in meta.loaded_readonly_addresses],
        "return_data": ({"program_id": b58enc(meta.return_data.program_id),
                         "data": meta.return_data.data.hex()}
                        if meta.HasField("return_data") else None),
        "return_data_none": meta.return_data_none,
        "compute_units_consumed": _opt(meta, "compute_units_consumed"),
        "cost_units": _opt(meta, "cost_units"),
    }


def norm_txn_info(info):
    return {
        "signature": b58enc(info.signature),
        "is_vote": info.is_vote,
        "index": info.index,
        "transaction": {
            "signatures": [b58enc(s) for s in info.transaction.signatures],
            "message": norm_message(info.transaction.message),
        },
        "meta": norm_meta(info.meta) if info.HasField("meta") else None,
    }


def norm_account_info(info):
    return {
        "pubkey": b58enc(info.pubkey),
        "lamports": info.lamports,
        "owner": b58enc(info.owner),
        "executable": info.executable,
        "rent_epoch": info.rent_epoch,
        "data": info.data.hex(),
        "data_len": len(info.data),
        "txn_signature": (b58enc(info.txn_signature)
                          if info.HasField("txn_signature") else None),
    }


def norm_entry(e):
    return {"index": e.index, "num_hashes": e.num_hashes,
            "hash": b58enc(e.hash),
            "executed_transaction_count": e.executed_transaction_count,
            "starting_transaction_index": e.starting_transaction_index}


def normalize(update, seq, nondet=True):
    """One SubscribeUpdate as a normalized record, or None for a
    ping or a pong."""
    which = update.WhichOneof("update_oneof")
    filters = sorted(update.filters)
    nd = {}
    if update.HasField("created_at"):
        nd["created_at"] = "%d.%09d" % (update.created_at.seconds,
                                        update.created_at.nanos)

    if which == "account":
        a = update.account
        payload = norm_account_info(a.account)
        payload["is_startup"] = a.is_startup
        nd["write_version"] = a.account.write_version
        nd["bank_id"] = _opt(a, "bank_id")
        rec = {"slot": a.slot, "kind": "account", "key": payload["pubkey"]}
    elif which == "transaction":
        t = update.transaction
        payload = norm_txn_info(t.transaction)
        nd["bank_id"] = t.bank_id
        rec = {"slot": t.slot, "kind": "transaction", "key": payload["signature"]}
    elif which == "transaction_status":
        t = update.transaction_status
        payload = {"signature": b58enc(t.signature), "is_vote": t.is_vote,
                   "index": t.index,
                   "err": t.err.err.hex() if t.HasField("err") else None}
        nd["bank_id"] = t.bank_id
        rec = {"slot": t.slot, "kind": "transaction_status",
               "key": payload["signature"]}
    elif which == "block":
        b = update.block
        payload = {
            "blockhash": b.blockhash,
            "parent_slot": b.parent_slot,
            "parent_blockhash": b.parent_blockhash,
            "block_time": b.block_time.timestamp if b.HasField("block_time") else None,
            "block_height": (b.block_height.block_height
                             if b.HasField("block_height") else None),
            "executed_transaction_count": b.executed_transaction_count,
            "updated_account_count": b.updated_account_count,
            "entries_count": b.entries_count,
            "rewards": norm_rewards(b.rewards),
            "transactions": sorted((norm_txn_info(t) for t in b.transactions),
                                   key=lambda t: (t["index"], t["signature"])),
            "accounts": sorted((norm_account_info(a) for a in b.accounts),
                               key=lambda a: a["pubkey"]),
            "entries": sorted((norm_entry(e) for e in b.entries),
                              key=lambda e: e["index"]),
        }
        nd["bank_id"] = b.bank_id
        rec = {"slot": b.slot, "kind": "block", "key": b.blockhash}
    elif which == "block_meta":
        b = update.block_meta
        payload = {
            "blockhash": b.blockhash,
            "parent_slot": b.parent_slot,
            "parent_blockhash": b.parent_blockhash,
            "block_time": b.block_time.timestamp if b.HasField("block_time") else None,
            "block_height": (b.block_height.block_height
                             if b.HasField("block_height") else None),
            "executed_transaction_count": b.executed_transaction_count,
            "entries_count": b.entries_count,
            "rewards": norm_rewards(b.rewards),
        }
        nd["bank_id"] = b.bank_id
        rec = {"slot": b.slot, "kind": "block_meta", "key": b.blockhash}
    elif which == "slot":
        s = update.slot
        payload = {"status": SLOT_STATUS_NAME.get(int(s.status), str(int(s.status))),
                   "parent": _opt(s, "parent"),
                   "dead_error": _opt(s, "dead_error")}
        nd["bank_id"] = _opt(s, "bank_id")
        rec = {"slot": s.slot, "kind": "slot", "key": payload["status"]}
    elif which == "entry":
        e = update.entry
        payload = norm_entry(e)
        nd["bank_id"] = e.bank_id
        rec = {"slot": e.slot, "kind": "entry", "key": str(e.index)}
    else:
        return None

    payload["filters"] = filters
    rec["seq"] = seq
    rec["payload"] = payload
    if nondet:
        rec["nondet"] = nd
    return rec


def messages(path):
    """Yields the bodies of a file of gRPC length-prefixed messages."""
    with open(path, "rb") as f:
        while True:
            head = f.read(5)
            if len(head) < 5:
                return
            ln = struct.unpack(">I", head[1:5])[0]
            body = f.read(ln)
            if len(body) < ln:
                return
            yield body


def decode_file(protos, raw_path, out_prefix, nondet=True, limit=0):
    """The second pass: normalized JSONL out of the captured messages."""
    counts = {}
    seq = 0
    dropped = 0
    with open(out_prefix + ".jsonl", "w") as jf, \
            open(out_prefix + ".slots.jsonl", "w") as sf:
        update = protos.SubscribeUpdate()
        for body in messages(raw_path):
            update.Clear()
            update.ParseFromString(body)
            rec = normalize(update, seq, nondet)
            seq += 1
            if rec is None:
                which = update.WhichOneof("update_oneof") or "empty"
                counts[which] = counts.get(which, 0) + 1
                continue
            counts[rec["kind"]] = counts.get(rec["kind"], 0) + 1
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
            if rec["kind"] == "slot":
                sf.write(line + "\n")
            else:
                jf.write(line + "\n")
            if limit and seq >= limit:
                dropped = 1
                break
    counts["_messages"] = seq
    if dropped:
        counts["_truncated_by_limit"] = 1
    return counts


# ------------------------------------------------------------ the capture

def build_request(protos, spec, commitment=None, from_slot=None):
    from google.protobuf import json_format
    req = protos.SubscribeRequest()
    json_format.ParseDict(spec, req)
    if commitment is not None:
        req.commitment = COMMITMENTS[commitment]
    if from_slot is not None:
        req.from_slot = from_slot
    return req


class Capture:
    """Everything one run accumulates, across a reconnect."""

    def __init__(self, path):
        self.f = open(path, "wb", buffering=1 << 20)
        self.msgs = 0
        self.bytes = 0
        self.pings = 0
        self.pongs = 0
        self.last_slot = {}          # status name -> highest slot seen
        self.target_hit = False

    def write(self, body):
        self.f.write(b"\x00" + struct.pack(">I", len(body)) + body)
        self.msgs += 1
        self.bytes += len(body) + 5

    def close(self):
        self.f.close()


def run_capture(args, protos):
    spec = json.load(open(args.filters)) if args.filters else {}
    req = build_request(protos, spec, args.commitment, args.from_slot)
    req_bytes = req.SerializeToString()
    ping_req = protos.SubscribeRequest()

    cap = Capture(args.out + ".bin")
    meta = {
        "reconnect_refused": False,
        "endpoint": "%s:%d%s" % (args.host, args.port, args.path),
        "filters": args.filters,
        "commitment": args.commitment,
        "request_bytes": len(req_bytes),
        "zstd": bool(args.zstd),
        "gaps": [],
        "attempts": [],
    }
    t0 = time.time()
    deadline = t0 + args.seconds if args.seconds else None
    target_status = COMMITMENTS[args.until_status]
    stop_reason = None
    attempts = 1 + max(0, args.reconnect)

    for attempt in range(attempts):
        if attempt:
            # what the stream missed while it was down: the subscription
            # is a new one, and a deferred one starts at the next new
            # bank, so at least one lag of slots is not in the capture
            gap = {"after_message": cap.msgs, "elapsed_s": round(time.time() - t0, 3),
                   "reason": stop_reason,
                   "last_slot": dict(cap.last_slot)}
            time.sleep(args.reconnect_delay)
        call = None
        try:
            call = Call(args.host, args.port, args.path, token=args.token,
                        zstd=args.zstd, authority=args.authority)
            call.open(req_bytes)
        except (OSError, StreamEnd) as e:
            # nothing is listening any more: on a reconnect that is the
            # server having gone away, which ends the run rather than
            # leaving a gap in the middle of one
            stop_reason = ("server gone: %s" % e) if attempt else ("connect failed: %s" % e)
            meta["reconnect_refused"] = bool(attempt)
            meta["attempts"].append({"attempt": attempt, "reason": stop_reason})
            if call is not None:
                call.close()
            break
        if attempt:
            gap["recovered"] = True
            meta["gaps"].append(gap)

        idle_last = time.time()
        ping_id = 0

        def on_message(body):
            nonlocal idle_last, ping_id
            idle_last = time.time()
            cap.write(body)
            kind = peek_kind(body)
            if kind == 6:                      # SubscribeUpdatePing
                cap.pings += 1
                if args.pong:
                    ping_id += 1
                    ping_req.Clear()
                    ping_req.ping.id = ping_id
                    call.send_msg(ping_req.SerializeToString())
                return
            if kind == 9:                      # SubscribeUpdatePong
                cap.pongs += 1
                return
            if kind == 3 and len(body) < 4096:
                st = peek_slot_status(body)
                if st is not None:
                    slot, status = st
                    name = SLOT_STATUS_NAME.get(status, str(status))
                    if slot > cap.last_slot.get(name, 0):
                        cap.last_slot[name] = slot
                    if (args.until_slot and status == target_status
                            and slot >= args.until_slot):
                        cap.target_hit = True

        try:
            while True:
                now = time.time()
                if deadline and now >= deadline:
                    stop_reason = "duration"
                    break
                if cap.target_hit:
                    stop_reason = "target slot"
                    break
                if args.idle_timeout and now - idle_last > args.idle_timeout:
                    stop_reason = "idle for %.0fs" % args.idle_timeout
                    break
                call.poll(0.2, on_message)
        except StreamEnd as e:
            stop_reason = e.reason
            if e.status:
                meta["grpc_status"] = e.status[0]
                meta["grpc_message"] = e.status[1]
        except KeyboardInterrupt:
            stop_reason = "interrupt"
        finally:
            meta["attempts"].append({
                "attempt": attempt,
                "reason": stop_reason,
                "messages": cap.msgs,
                "socket_bytes": call.bytes_rx,
                "compressed_messages": call.msgs_compressed,
                "coded_bytes": call.coded_bytes,
                "plain_bytes": call.plain_bytes,
                "response_encoding": call.resp_encoding,
                "response_headers": call.resp_headers,
                "trailers": call.trailers,
            })
            call.close()

        if stop_reason in ("duration", "target slot", "interrupt") or cap.target_hit:
            break
        if not args.reconnect:
            break

    cap.close()
    meta["stop_reason"] = stop_reason
    meta["elapsed_s"] = round(time.time() - t0, 3)
    meta["messages"] = cap.msgs
    meta["message_bytes"] = cap.bytes
    meta["compressed_messages"] = sum( a.get("compressed_messages", 0)
                                       for a in meta["attempts"] )
    meta["coded_bytes"] = sum( a.get("coded_bytes", 0) for a in meta["attempts"] )
    meta["server_pings"] = cap.pings
    meta["pongs"] = cap.pongs
    meta["last_slot"] = cap.last_slot
    return meta


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10801)
    ap.add_argument("--authority", default=None,
                    help="the :authority header, host:port by default")
    ap.add_argument("--path", default="/geyser.Geyser/Subscribe")
    ap.add_argument("--filters", help="a SubscribeRequest in protobuf JSON")
    ap.add_argument("--commitment", choices=sorted(COMMITMENTS),
                    help="overrides the commitment of the filter spec")
    ap.add_argument("--from-slot", type=int, default=None)
    ap.add_argument("--token", default=None, help="the x-token metadata value")
    ap.add_argument("--zstd", action="store_true",
                    help="ask the server for zstd and decompress what it sends")
    ap.add_argument("--out", required=True, help="prefix of the output files")
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="stop after this long, 0 for no limit")
    ap.add_argument("--until-slot", type=int, default=0,
                    help="stop once this slot reaches --until-status")
    ap.add_argument("--until-status", choices=sorted(COMMITMENTS),
                    default="finalized")
    ap.add_argument("--idle-timeout", type=float, default=0.0,
                    help="stop after this long with nothing from the server")
    ap.add_argument("--reconnect", type=int, default=1,
                    help="how many times to reconnect after a lost connection")
    ap.add_argument("--reconnect-delay", type=float, default=1.0)
    ap.add_argument("--no-pong", dest="pong", action="store_false",
                    help="do not answer the server's pings")
    ap.add_argument("--no-nondet", dest="nondet", action="store_false",
                    help="leave created_at, bank_id and write_version out")
    ap.add_argument("--no-decode", dest="decode", action="store_false",
                    help="capture only, leaving the second pass to --decode-only")
    ap.add_argument("--decode-only", default=None,
                    help="normalize this file of gRPC messages and exit")
    ap.add_argument("--decode-limit", type=int, default=0,
                    help="stop decoding after this many messages")
    ap.add_argument("--proto-dir", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    protos = load_protos(args.proto_dir or default_proto_dir())

    if args.decode_only:
        counts = decode_file(protos, args.decode_only, args.out,
                             args.nondet, args.decode_limit)
        print("%s: %s" % (args.out, json.dumps(counts, sort_keys=True)))
        return 0

    meta = run_capture(args, protos)
    if args.decode:
        meta["counts"] = decode_file(protos, args.out + ".bin", args.out,
                                     args.nondet, args.decode_limit)
    with open(args.out + ".meta.json", "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
    if not args.quiet:
        print("%s: %d messages, %.1f MiB, stop after %.1fs (%s), pings %d/pongs %d"
              % (os.path.basename(args.out), meta["messages"],
                 meta["message_bytes"] / 1048576.0, meta["elapsed_s"],
                 meta["stop_reason"], meta["server_pings"], meta["pongs"]))
        if meta["gaps"]:
            print("  %d gap(s): %s" % (len(meta["gaps"]),
                                       json.dumps(meta["gaps"], sort_keys=True)))
        if "counts" in meta:
            print("  %s" % json.dumps(meta["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
