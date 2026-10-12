#!/usr/bin/env python3
"""Reconnect churn against a Dragon's Mouth server.

Opens and closes a mix of clients continuously: subscriptions of every
kind at every commitment level, some asking for zstd, and some
misbehaving on purpose (never reading, sending garbage, presenting the
wrong token, vanishing mid-stream).  It speaks HTTP/2 over a raw
socket, so it needs nothing installed.

  ./churn.py --port 10000 --clients 24 --seconds 120

Prints what each profile achieved.  The server's own invariants are
checked by the server (test_dragon_tile asserts them at exit)."""

import argparse, os, random, socket, struct, sys, threading, time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def frame(typ, flags, sid, payload=b""):
    return bytes([(len(payload) >> 16) & 0xFF, (len(payload) >> 8) & 0xFF,
                  len(payload) & 0xFF, typ, flags]) + struct.pack(">I", sid) + payload

def hdr_lit(name, value):
    """A literal header field without indexing, never huffman coded."""
    n = name.encode(); v = value.encode()
    return b"\x00" + bytes([len(n)]) + n + bytes([len(v)]) + v

def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        o.append(b | (0x80 if v else 0))
        if not v:
            return bytes(o)

def pb_bytes(f, b):  return varint((f << 3) | 2) + varint(len(b)) + b
def pb_varint(f, v): return varint((f << 3) | 0) + varint(v)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58enc(raw):
    n = int.from_bytes(raw, "big"); out = ""
    while n:
        n, r = divmod(n, 58); out = B58[r] + out
    for c in raw:
        if c: break
        out = "1" + out
    return out or "1"

def key58(b): return b58enc(bytes([b]) * 32)

def map_entry(field, name, value=b""):
    e = pb_bytes(1, name.encode())
    if value: e += pb_bytes(2, value)
    return pb_bytes(field, e)

def request(kind, commitment):
    """One SubscribeRequest of the given kind."""
    r = b""
    if kind == "slots":
        r += map_entry(2, "s", pb_varint(2, 1))
    elif kind == "transactions":
        r += map_entry(3, "t", pb_varint(1, 0))
    elif kind == "transactions_status":
        r += map_entry(10, "ts", b"")
    elif kind == "accounts":
        r += map_entry(1, "a", pb_bytes(3, key58(0x60).encode()))
    elif kind == "accounts_all":
        r += map_entry(1, "a", b"")
    elif kind == "blocks_meta":
        r += map_entry(5, "bm", b"")
    elif kind == "blocks":
        r += map_entry(4, "b", pb_varint(2, 1) + pb_varint(3, 1))
    elif kind == "mixed":
        r += map_entry(2, "s", b"") + map_entry(10, "ts", b"") + map_entry(5, "bm", b"")
    r += pb_varint(6, commitment)
    return r

def grpc_msg(body):
    return b"\x00" + struct.pack(">I", len(body)) + body

def headers(path, token=None, zstd=False):
    b = hdr_lit(":method", "POST") + hdr_lit(":scheme", "http") + hdr_lit(":path", path)
    b += hdr_lit(":authority", "localhost")
    b += hdr_lit("content-type", "application/grpc") + hdr_lit("te", "trailers")
    if zstd:  b += hdr_lit("grpc-accept-encoding", "zstd")
    if token is not None: b += hdr_lit("x-token", token)
    return b

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.by_profile = {}
        self.bytes = 0
        self.conns = 0
        self.errors = 0

    def add(self, profile, nbytes, err=False):
        with self.lock:
            p = self.by_profile.setdefault(profile, [0, 0, 0])
            p[0] += 1
            p[1] += nbytes
            if err: p[2] += 1
            self.bytes += nbytes
            self.conns += 1
            self.errors += int(err)

PROFILES = [
    # (name, weight)
    ("slots_processed", 3), ("slots_finalized", 2),
    ("txn_processed", 2), ("txn_confirmed", 2), ("txn_status_finalized", 2),
    ("accounts_processed", 2), ("accounts_finalized", 2),
    ("blocks_meta_confirmed", 2), ("blocks_finalized", 1),
    ("mixed_zstd", 2),
    ("never_reads", 2), ("garbage", 1), ("wrong_token", 1),
    ("half_open", 1), ("unary_ping", 1), ("unimplemented", 1),
]

def run_client(host, port, profile, token, stop, stats, rng):
    nbytes = 0
    err = False
    s = None
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.settimeout(5)

        if profile == "garbage":
            s.sendall(bytes(rng.randrange(256) for _ in range(rng.randrange(16, 512))))
            time.sleep(rng.uniform(0.0, 0.2))
            return
        s.sendall(PREFACE + frame(4, 0, 0))

        path, body = "/geyser.Geyser/Subscribe", None
        zstd = profile == "mixed_zstd"
        tok = token
        if profile == "wrong_token": tok = "definitely-not-the-token"
        if profile == "unary_ping":
            path, body = "/geyser.Geyser/Ping", pb_varint(1, 7)
        elif profile == "unimplemented":
            path, body = "/geyser.Geyser/SubscribeDeshred", b""
        else:
            kind, level = {
                "slots_processed":       ("slots", 0),
                "slots_finalized":       ("slots", 2),
                "txn_processed":         ("transactions", 0),
                "txn_confirmed":         ("transactions", 1),
                "txn_status_finalized":  ("transactions_status", 2),
                "accounts_processed":    ("accounts_all", 0),
                "accounts_finalized":    ("accounts", 2),
                "blocks_meta_confirmed": ("blocks_meta", 1),
                "blocks_finalized":      ("blocks", 2),
                "mixed_zstd":            ("mixed", 0),
                "never_reads":           ("accounts_all", 0),
                "half_open":             ("slots", 0),
                "wrong_token":           ("slots", 0),
            }[profile]
            body = request(kind, level)

        end_stream = profile in ("unary_ping", "unimplemented")
        s.sendall(frame(1, 0x04 | (0x01 if body is None else 0), 1,
                        headers(path, tok, zstd)))
        s.sendall(frame(0, 0x01 if end_stream else 0, 1, grpc_msg(body)))
        # a window big enough that the server is not the one stalling
        s.sendall(frame(8, 0, 0, struct.pack(">I", 1 << 24)))
        s.sendall(frame(8, 0, 1, struct.pack(">I", 1 << 24)))

        if profile == "never_reads":
            # hold the stream open and read nothing, so the server's
            # queue fills and the subscription is closed as lagged
            time.sleep(rng.uniform(0.5, 2.0))
            return
        if profile == "half_open":
            time.sleep(rng.uniform(0.05, 0.4))
            s.close(); s = None
            return

        deadline = time.time() + rng.uniform(0.2, 2.0)
        while time.time() < deadline and not stop.is_set():
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b: break
            nbytes += len(b)
    except (OSError, socket.timeout):
        err = True
    finally:
        if s is not None:
            try:
                if rng.random() < 0.3:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
            except OSError:
                pass
        stats.add(profile, nbytes, err)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10000)
    ap.add_argument("--clients", type=int, default=24)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--token", default="")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    names = [n for n, w in PROFILES for _ in range(w)]
    stats = Stats()
    stop = threading.Event()

    def worker(idx):
        rng = random.Random(args.seed * 1000 + idx)
        while not stop.is_set():
            run_client(args.host, args.port, rng.choice(names), args.token, stop, stats, rng)
            time.sleep(rng.uniform(0.0, 0.05))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(args.clients)]
    t0 = time.time()
    for t in threads: t.start()
    try:
        while time.time() - t0 < args.seconds:
            time.sleep(0.5)
    finally:
        stop.set()
        for t in threads: t.join(timeout=10)

    print("churn: %d connections in %.1f s, %.1f MiB received, %d socket errors"
          % (stats.conns, time.time() - t0, stats.bytes / 1048576.0, stats.errors))
    print("%-24s %8s %12s %8s" % ("profile", "conns", "bytes", "errors"))
    for name in sorted(stats.by_profile):
        c, b, e = stats.by_profile[name]
        print("%-24s %8d %12d %8d" % (name, c, b, e))

if __name__ == "__main__":
    main()
