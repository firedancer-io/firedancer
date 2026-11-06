#!/usr/bin/env python3
"""Seed corpora for the dragon fuzz targets, built from the shapes the
unit tests use: SubscribeRequests with every filter kind, a legacy
transaction payload, and whole commit records."""
import os, struct, sys

OUT = sys.argv[ 1 ] if len(sys.argv)>1 else "corpus"

def w(target, name, data):
    d = os.path.join(OUT, target)
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(data)

# --- protobuf helpers -------------------------------------------------
def varint(v):
    o = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        o.append(b | (0x80 if v else 0))
        if not v:
            return bytes(o)

def tag(f, wt):   return varint((f << 3) | wt)
def fbytes(f, b): return tag(f, 2) + varint(len(b)) + b
def fvarint(f, v): return tag(f, 0) + varint(v)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58enc(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    for c in raw:
        if c:
            break
        out = "1" + out
    return out or "1"

def key(b):     return bytes([b]) * 32
def key58(b):   return b58enc(key(b)).encode()

def map_entry(field, name, value=b""):
    e = fbytes(1, name)
    if value:
        e += fbytes(2, value)
    return fbytes(field, e)

# --- fuzz_dragon_filter ----------------------------------------------
# SubscribeRequest fields: 1 accounts, 2 slots, 3 transactions,
# 4 blocks, 5 blocks_meta, 6 commitment, 7 accounts_data_slice,
# 8 entry, 9 ping, 10 transactions_status, 11 from_slot.

def filter_seeds():
    # every map, one name each
    every = (map_entry(1, b"a") + map_entry(2, b"s") + map_entry(3, b"t") +
             map_entry(10, b"ts") + map_entry(4, b"b") + map_entry(5, b"bm") +
             map_entry(8, b"e"))
    w("fuzz_dragon_filter", "every_map", b"\x00\x40" + every)

    # an accounts filter with account, owner, memcmp (bytes, base58,
    # base64), datasize, lamports and a data slice
    memcmp_b = fbytes(1, fvarint(1, 8) + fbytes(2, b"\xde\xad\xbe\xef"))
    memcmp58 = fbytes(1, fvarint(1, 0) + fbytes(3, b58enc(b"hello").encode()))
    memcmp64 = fbytes(1, fvarint(1, 4) + fbytes(4, b"aGVsbG8="))
    datasize = fbytes(2, b"") if False else tag(2, 0) + varint(165)
    lamports = fbytes(4, fvarint(3, 1000))
    acct_val = (fbytes(2, key58(0x40)) + fbytes(3, key58(0x60)) +
                fbytes(4, memcmp_b) + fbytes(4, memcmp58) + fbytes(4, memcmp64) +
                fbytes(4, datasize) + fbytes(4, lamports) + fvarint(5, 1))
    req = fbytes(1, fbytes(1, b"acct") + fbytes(2, acct_val))
    req += fbytes(7, fvarint(1, 0) + fvarint(2, 8))
    req += fvarint(6, 1)
    w("fuzz_dragon_filter", "accounts_all", b"\x00\x41" + req)

    # a transactions filter with every list and a signature
    txn_val = (fvarint(1, 0) + fvarint(2, 1) +
               fbytes(5, b58enc(bytes(range(64))).encode()) +
               fbytes(3, key58(0x40)) + fbytes(4, key58(0x41)) +
               fbytes(6, key58(0x42)) + fvarint(30, 1))
    w("fuzz_dragon_filter", "transactions",
      b"\x00\x42" + fbytes(3, fbytes(1, b"t") + fbytes(2, txn_val)))

    # a blocks filter that asks for everything
    blk_val = fbytes(1, key58(0x40)) + fvarint(2, 1) + fvarint(3, 1) + fvarint(4, 1)
    w("fuzz_dragon_filter", "blocks",
      b"\x00\x43" + fbytes(4, fbytes(1, b"b") + fbytes(2, blk_val)))

    # a cuckoo account filter: 8 buckets of zeros plus a seed
    cuckoo = fbytes(1, bytes(64)) + fvarint(5, 0x796c6c7773746e21)
    w("fuzz_dragon_filter", "cuckoo_accounts",
      b"\x00\x44" + fbytes(1, fbytes(1, b"c") + fbytes(2, fbytes(6, cuckoo))))
    w("fuzz_dragon_filter", "cuckoo_txn",
      b"\x00\x45" + fbytes(3, fbytes(1, b"c") + fbytes(2, fbytes(7, cuckoo))))

    # ping and from_slot
    w("fuzz_dragon_filter", "ping", b"\x00\x46" + fbytes(9, fvarint(1, 7)))
    w("fuzz_dragon_filter", "from_slot", b"\x00\x47" + fvarint(11, 12345))

# --- a legacy transaction payload ------------------------------------
def legacy_payload(nkeys=3, ninstr=1):
    p = bytearray()
    p += varint(1)             # one signature
    p += bytes(range(64))      # the signature
    p += bytes([1, 0, 1])      # header
    p += varint(nkeys)
    for i in range(nkeys):
        p += key(0x20 + i)
    p += key(0x77)             # recent blockhash
    p += varint(ninstr)
    for _ in range(ninstr):
        p += bytes([nkeys - 1]) # program id index
        p += varint(2) + bytes([0, 1])
        p += varint(3) + bytes([0xAA, 0xBB, 0xCC])
    return bytes(p)

# --- fuzz_txn_meta ----------------------------------------------------
# The input is read as: 8 scalars, 64 byte signature, 32 byte program
# id, then a length pair and the payload, then the rest.

def txn_meta_seeds():
    head = bytearray()
    head += struct.pack("<Q", 7)    # bank_seq
    head += struct.pack("<Q", 100)  # slot
    head += struct.pack("<Q", 2)    # index_in_slot
    head += bytes([1, 0, 0])        # is_leader, is_simple_vote, is_fees_only
    head += bytes([0, 0, 0, 0])     # txn_err, exec_err, exec_err_kind, exec_err_idx
    head += struct.pack("<Q", 0xFFFFFFFF)  # custom_err
    head += bytes([0xFF])                  # rent_err_account_idx
    for v in (5000, 1000, 200000, 4321, 1234):
        head += struct.pack("<Q", v)
    head += bytes([0])              # logs_truncated
    head += bytes(range(64))        # signature
    head += bytes([0x22]) * 32      # return data program id
    pl = legacy_payload()
    head += bytes([len(pl) // 8, len(pl) % 8])
    head += pl
    tail = bytes([3])               # key_cnt
    for i in range(3):
        tail += bytes([0x20 + i]) + struct.pack("<Q", 10 + i) + struct.pack("<Q", 9 + i) + bytes([1])
    tail += bytes([8])              # logs_sz/4
    tail += b"\x01\x12hello world log entry  "[:32]
    tail += bytes([1])              # trace_cnt
    tail += bytes([2, 3, 2, 0, 1, 0xAA, 0xBB, 0xCC])
    tail += bytes([2, 0x01, 0x02])  # return data
    w("fuzz_txn_meta", "legacy_success", bytes(head) + tail)
    w("fuzz_txn_meta", "legacy_bare", bytes(head))
    w("fuzz_txn_meta", "empty_payload", bytes(head[:-len(pl) - 2]) + b"\x00\x00" + tail)

# --- fuzz_dragon_ingest ----------------------------------------------
# A whole commit record, which the fuzzer frames into fragments.

COMMIT_PREFIX_SZ = 336

def commit_record(payload, keys, touched_data_sz):
    nkeys = len(keys)
    pre = b"".join(struct.pack("<Q", 100 + i) for i in range(nkeys))
    post = b"".join(struct.pack("<Q", 200 + i) for i in range(nkeys))
    writable = bytes([1] * nkeys)
    trace = struct.pack("<IIIIII", nkeys - 1, 1, 2, 0, 0, 3)
    trace_accts = bytes([0, 1])
    trace_data = bytes([0xAA, 0xBB, 0xCC]) + bytes(5)
    touched = struct.pack("<IIQQQ", 0, 0, 500, 0, touched_data_sz) + bytes([0x60]) * 32
    acct_data = bytes([0x5A]) * touched_data_sz

    def pad(b):
        return b + bytes((-len(b)) % 8)

    pfx = bytearray(COMMIT_PREFIX_SZ)
    struct.pack_into("<Q", pfx, 0, 1)        # bank_seq
    struct.pack_into("<Q", pfx, 8, 10)       # slot
    struct.pack_into("<Q", pfx, 16, 0)       # index_in_slot
    struct.pack_into("<Q", pfx, 24, 0)       # commit_index_in_slot
    struct.pack_into("<i", pfx, 48, 1)       # accounts_included
    pfx[56:120] = bytes(range(64))           # signature
    struct.pack_into("<I", pfx, 144, 0xFFFFFFFF)  # exec_err_idx
    struct.pack_into("<I", pfx, 148, 0xFFFFFFFF)  # custom_err
    struct.pack_into("<I", pfx, 152, 0xFFFFFFFF)  # rent_err_account_idx
    struct.pack_into("<Q", pfx, 160, 5000)   # execution_fee
    struct.pack_into("<I", pfx, 200, nkeys)  # acct_addr_cnt
    pfx[208:240] = bytes(32)                 # return data program id
    for off, v in ((240, len(payload)), (248, nkeys), (256, nkeys), (264, nkeys),
                   (272, nkeys), (280, 0), (288, 1), (296, len(trace_accts)),
                   (304, len(trace_data)), (312, 0), (320, 1), (328, touched_data_sz)):
        struct.pack_into("<Q", pfx, off, v)

    return (bytes(pfx) + pad(payload) + pad(b"".join(keys)) + pad(pre) + pad(post) +
            pad(writable) + b"" + pad(trace) + pad(trace_accts) + pad(trace_data) +
            b"" + pad(touched) + pad(acct_data))


def ingest_seeds():
    keys = [key(0x20), key(0x21), key(0x22)]
    for n, dsz in (("commit_small", 8), ("commit_page", 4096)):
        rec = commit_record(legacy_payload(), keys, dsz)
        w("fuzz_dragon_ingest", n, b"\x01\x00\x00\x00\x03" + rec)
    # two records back to back, which the fuzzer frames separately
    rec = commit_record(legacy_payload(), keys, 8)
    w("fuzz_dragon_ingest", "commit_pair", b"\x02\x00\x00\x00\x03" + rec + rec)


# --- fuzz_geyser_core -------------------------------------------------
# Each byte is an action; the low three bits pick it.

def geyser_seeds():
    def act(kind, bank):
        return bytes([((bank & 0x1F) << 3) | kind])
    # a slot that completes, gets records, is confirmed and rooted
    seq = act(0, 1) + act(5, 1) + act(6, 1) + act(6, 1) + act(1, 1) + act(2, 1)
    w("fuzz_geyser_core", "slot_lifecycle", b"\x01\x00\x00\x00\x1a" + seq)
    # a fork: two banks at the same slot, one of which is rooted
    fork = act(0, 1) + act(0, 2) + act(5, 2) + act(2, 2) + act(4, 1)
    w("fuzz_geyser_core", "fork", b"\x02\x00\x00\x00\x08" + fork)
    # records for a bank nobody announced, then a gap
    orphan = act(5, 9) + act(6, 9) + bytes([0x47]) + act(0, 9)
    w("fuzz_geyser_core", "orphan_records", b"\x03\x00\x00\x00\x02" + orphan)
    w("fuzz_geyser_core", "dead", b"\x04\x00\x00\x00\x00" + act(0, 3) + act(3, 3) + act(2, 3))


# --- fuzz_grpc_server -------------------------------------------------
# An input is a four byte RNG seed followed by raw HTTP/2 frames.  With
# the seed's low bit set the target pre-opens a unary call that declares
# grpc-encoding: zstd, so a DATA frame carrying a compressed message
# reaches the decompressor.

def zstd_compress(data, level=1, content_size=True):
    """A zstd frame, with or without a declared content size."""
    try:
        import zstandard
        c = zstandard.ZstdCompressor(level=level,
                                     write_content_size=content_size)
        if content_size:
            return c.compress(data)
        co = c.compressobj()
        return co.compress(data) + co.flush()
    except ImportError:
        pass
    # The CLI declares the content size when it knows it, which it does
    # for a file and does not for a pipe.
    import subprocess, tempfile
    if content_size:
        with tempfile.NamedTemporaryFile() as f:
            f.write(data); f.flush()
            return subprocess.run(["zstd", "-q", "-c", f"-{level}", f.name],
                                  check=True, stdout=subprocess.PIPE).stdout
    return subprocess.run(["zstd", "-q", "-c", f"-{level}"], input=data,
                          check=True, stdout=subprocess.PIPE).stdout


def h2_frame(typ, flags, sid, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([typ, flags]) +
            sid.to_bytes(4, "big") + payload)


def grpc_server_seeds():
    def data_msg(body, compressed):
        msg = bytes([1 if compressed else 0]) + len(body).to_bytes(4, "big") + body
        return h2_frame(0, 0x01, 1, msg)

    plain = b"a compressed request message, repeated: " * 3
    w("fuzz_grpc_server", "zstd_msg",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(plain), True))
    # no content size in the frame header, which is what a streaming
    # encoder such as tonic's produces
    w("fuzz_grpc_server", "zstd_msg_streamed",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(plain, content_size=False), True))
    # a plaintext past max_request_msg_sz (2048 in the target)
    w("fuzz_grpc_server", "zstd_oversize",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(b"A" * (1 << 16)), True))
    # a frame cut short
    w("fuzz_grpc_server", "zstd_truncated",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(plain)[:-4], True))
    # two frames in one message, and a frame with junk behind it
    w("fuzz_grpc_server", "zstd_two_frames",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(plain) * 2, True))
    w("fuzz_grpc_server", "zstd_trailing",
      b"\x01\x00\x00\x00" + data_msg(zstd_compress(plain) + b"\x00", True))
    # a response the server compresses: 'B' asks for a large payload
    w("fuzz_grpc_server", "zstd_response",
      b"\x01\x00\x00\x00" + data_msg(b"B", False))


filter_seeds()
txn_meta_seeds()
ingest_seeds()
geyser_seeds()
grpc_server_seeds()
print("seeds written to", OUT)
