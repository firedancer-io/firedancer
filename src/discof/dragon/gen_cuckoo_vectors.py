#!/usr/bin/env python3
"""Reference vectors for fd_dragon_cuckoo.

This is a transcription of the Apache-2.0 cuckoo filter that ships with
yellowstone-grpc-proto (yellowstone-grpc-proto/src/cuckoo/{constants,
hasher,filter}.rs), not a binding to the Rust crate: no Rust toolchain
runs here, so the algorithm is restated in Python from that source and
anchored on the golden wire fixture the Rust test suite carries
(filter.rs, hash_reuse_preserves_golden_wire_fixture).  Anything the
transcription got wrong would have to be wrong in the same way in the
128 golden bytes, which it reproduces exactly.

The hashing contract that both this file and the C port depend on:

  - SipHash-2-4 with k0 = seed, k1 = rotate_left(seed,32)
  - a [u8; N] key hashes as Rust's `Hash for [T]` writes it: the length
    as a native endian u64 (little endian on x86-64), then the bytes
  - a u16 fingerprint hashes as two little endian bytes
  - fingerprint = bits 32..48 of the hash, or 1 when those are zero
  - bucket index = hash & (bucket_cnt-1), alternate = i1 ^ index(hash(fp))

Emits src/discof/dragon/test_cuckoo_vectors.h.
"""

import struct
import sys

MASK64 = (1 << 64) - 1

ENTRIES_PER_BUCKET = 4
LOAD_FACTOR = 0.95
MAX_KICKS = 500
DEFAULT_HASH_SEED = 0x796C6C7773746E21


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK64


def sip_round(v):
    v[0] = (v[0] + v[1]) & MASK64
    v[1] = rotl(v[1], 13) ^ v[0]
    v[0] = rotl(v[0], 32)
    v[2] = (v[2] + v[3]) & MASK64
    v[3] = rotl(v[3], 16) ^ v[2]
    v[0] = (v[0] + v[3]) & MASK64
    v[3] = rotl(v[3], 21) ^ v[0]
    v[2] = (v[2] + v[1]) & MASK64
    v[1] = rotl(v[1], 17) ^ v[2]
    v[2] = rotl(v[2], 32)


def siphash24(data, k0, k1):
    v = [
        k0 ^ 0x736F6D6570736575,
        k1 ^ 0x646F72616E646F6D,
        k0 ^ 0x6C7967656E657261,
        k1 ^ 0x7465646279746573,
    ]
    n = len(data)
    off = 0
    while off + 8 <= n:
        m = struct.unpack_from("<Q", data, off)[0]
        v[3] ^= m
        sip_round(v)
        sip_round(v)
        v[0] ^= m
        off += 8
    b = (n & 0xFF) << 56
    tail = data[off:]
    for i, c in enumerate(tail):
        b |= c << (8 * i)
    v[3] ^= b
    sip_round(v)
    sip_round(v)
    v[0] ^= b
    v[2] ^= 0xFF
    for _ in range(4):
        sip_round(v)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def keys_from_seed(seed):
    return seed, rotl(seed, 32)


def hash_bytes(seed, key):
    """Rust `Hash for [u8; N]`: length as a native endian usize, then bytes."""
    k0, k1 = keys_from_seed(seed)
    return siphash24(struct.pack("<Q", len(key)) + bytes(key), k0, k1)


def hash_u16(seed, fp):
    k0, k1 = keys_from_seed(seed)
    return siphash24(struct.pack("<H", fp), k0, k1)


def fingerprint(h):
    fp = (h >> 32) & 0xFFFF
    return 1 if fp == 0 else fp


def bucket_cnt_for_capacity(capacity):
    import math

    needed = math.ceil(capacity / (LOAD_FACTOR * ENTRIES_PER_BUCKET))
    n = 1
    while n < needed:
        n <<= 1
    return max(n, 1)


class Cuckoo:
    def __init__(self, seed, bucket_cnt):
        self.seed = seed
        self.bucket = [[0] * ENTRIES_PER_BUCKET for _ in range(bucket_cnt)]

    @classmethod
    def with_capacity(cls, capacity, seed=DEFAULT_HASH_SEED):
        return cls(seed, bucket_cnt_for_capacity(capacity))

    def index(self, h):
        return h & (len(self.bucket) - 1)

    def _try_insert(self, i, fp):
        for s in range(ENTRIES_PER_BUCKET):
            if self.bucket[i][s] == 0:
                self.bucket[i][s] = fp
                return True
        return False

    def insert(self, key):
        h = hash_bytes(self.seed, key)
        fp = fingerprint(h)
        i1 = self.index(h)
        i2 = i1 ^ self.index(hash_u16(self.seed, fp))
        if self._try_insert(i1, fp):
            return True
        if self._try_insert(i2, fp):
            return True
        i = i1
        for n in range(MAX_KICKS):
            slot = (n + fp) % ENTRIES_PER_BUCKET
            fp, self.bucket[i][slot] = self.bucket[i][slot], fp
            i ^= self.index(hash_u16(self.seed, fp))
            if self._try_insert(i, fp):
                return True
        return False

    def contains(self, key):
        h = hash_bytes(self.seed, key)
        fp = fingerprint(h)
        i1 = self.index(h)
        i2 = i1 ^ self.index(hash_u16(self.seed, fp))
        return fp in self.bucket[i1] or fp in self.bucket[i2]

    def remove(self, key):
        h = hash_bytes(self.seed, key)
        fp = fingerprint(h)
        i1 = self.index(h)
        i2 = i1 ^ self.index(hash_u16(self.seed, fp))
        for i in (i1, i2):
            for s in range(ENTRIES_PER_BUCKET):
                if self.bucket[i][s] == fp:
                    self.bucket[i][s] = 0
                    return True
        return False

    def encode(self):
        out = bytearray()
        for b in self.bucket:
            for fp in b:
                out += struct.pack("<H", fp)
        return bytes(out)


# The golden wire fixture of the Rust test suite
# (yellowstone-grpc-proto/src/cuckoo/filter.rs,
# hash_reuse_preserves_golden_wire_fixture).

GOLDEN_SEED = 0x0123456789ABCDEF
GOLDEN_CAPACITY = 32
GOLDEN_KEY_CNT = 47
GOLDEN_DATA = bytes([
    98, 225, 76, 119, 190, 148, 14, 101, 11, 41, 217, 3, 119, 174, 0, 0, 66, 89, 195, 68,
    95, 234, 230, 233, 20, 49, 10, 177, 0, 0, 0, 0, 219, 56, 38, 161, 53, 30, 11, 123, 215,
    189, 20, 44, 123, 34, 176, 131, 12, 189, 134, 227, 205, 228, 142, 117, 68, 108, 97,
    147, 203, 29, 222, 218, 104, 255, 204, 10, 145, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41,
    254, 16, 199, 37, 77, 0, 0, 170, 17, 23, 225, 34, 7, 180, 119, 125, 61, 0, 0, 0, 0, 0,
    0, 199, 228, 152, 62, 183, 114, 0, 0, 209, 244, 248, 9, 104, 65, 230, 66, 0, 0, 0, 0,
    0, 0, 0, 0,
])


def check_golden():
    f = Cuckoo(GOLDEN_SEED, bucket_cnt_for_capacity(GOLDEN_CAPACITY))
    assert len(f.bucket) == 16, len(f.bucket)
    for b in range(GOLDEN_KEY_CNT):
        assert f.insert(bytes([b] * 32)), b
    data = f.encode()
    if data != GOLDEN_DATA:
        print("golden mismatch", file=sys.stderr)
        print("  got  ", list(data), file=sys.stderr)
        print("  want ", list(GOLDEN_DATA), file=sys.stderr)
        return False
    for b in range(GOLDEN_KEY_CNT):
        assert f.contains(bytes([b] * 32)), b
    assert not f.contains(bytes([255] * 32))
    return True


def c_bytes(data, indent):
    out = []
    for i in range(0, len(data), 12):
        out.append(indent + ", ".join("0x%02x" % b for b in data[i:i + 12]) + ",")
    return "\n".join(out)


def key(i):
    """A deterministic 32 byte key.  Not a pubkey, just bytes."""
    h = hash_bytes(0xA5A5A5A5A5A5A5A5, struct.pack("<Q", i))
    out = bytearray()
    for j in range(4):
        out += struct.pack("<Q", hash_bytes(h ^ j, struct.pack("<Q", i)))
    return bytes(out)


def emit_case(out, name, seed, capacity, member_cnt, probe_cnt, fp_want=0):
    f = Cuckoo(seed, bucket_cnt_for_capacity(capacity))
    members = [key(i) for i in range(member_cnt)]
    for m in members:
        assert f.insert(m), "insert failed, filter under-sized"
    data = f.encode()
    probes = [key(1 << 20 | i) for i in range(probe_cnt)]

    # A 16 bit fingerprint makes a false positive rare, so a probe list
    # drawn at random would almost surely have none and would not check
    # that both implementations agree on which non-members hit.  Search
    # for keys that the filter does answer yes to and mix them in.
    found = 0
    i = 0
    while found < fp_want:
        k = key(2 << 20 | i)
        i += 1
        if i > 4_000_000:
            raise SystemExit("no false positive found for %s" % name)
        if f.contains(k):
            probes.append(k)
            found += 1
    probe_cnt = len(probes)
    fp_mask = bytearray((probe_cnt + 7) // 8)
    fp_cnt = 0
    for i, p in enumerate(probes):
        if f.contains(p):
            fp_mask[i >> 3] |= 1 << (i & 7)
            fp_cnt += 1

    out.append("/* %s: %lu keys in %lu buckets, %lu of %lu probes are false"
               " positives */" % (name, member_cnt, len(f.bucket), fp_cnt, probe_cnt))
    out.append("")
    out.append("#define %s_SEED (0x%016xUL)" % (name.upper(), seed))
    out.append("#define %s_BUCKET_CNT (%luUL)" % (name.upper(), len(f.bucket)))
    out.append("#define %s_MEMBER_CNT (%luUL)" % (name.upper(), member_cnt))
    out.append("#define %s_PROBE_CNT (%luUL)" % (name.upper(), probe_cnt))
    out.append("")
    out.append("static uchar const %s_data[ %lu ] = {" % (name, len(data)))
    out.append(c_bytes(data, "  "))
    out.append("};")
    out.append("")
    out.append("static uchar const %s_member[ %lu ][ 32 ] = {" % (name, member_cnt))
    for m in members:
        out.append("  { " + ", ".join("0x%02x" % b for b in m) + " },")
    out.append("};")
    out.append("")
    out.append("static uchar const %s_probe[ %lu ][ 32 ] = {" % (name, probe_cnt))
    for p in probes:
        out.append("  { " + ", ".join("0x%02x" % b for b in p) + " },")
    out.append("};")
    out.append("")
    out.append("/* Bit i is set when probe i is a false positive of the filter. */")
    out.append("static uchar const %s_probe_hit[ %lu ] = {" % (name, len(fp_mask)))
    out.append(c_bytes(bytes(fp_mask), "  "))
    out.append("};")
    out.append("")


def main():
    if not check_golden():
        return 1

    out = []
    out.append("/* Generated by gen_cuckoo_vectors.py.  Do not edit.")
    out.append("")
    out.append("   Reference vectors for the cuckoo filter of")
    out.append("   yellowstone-grpc-proto (Apache-2.0).  The generator is a")
    out.append("   transcription of the Rust source, anchored on the golden wire")
    out.append("   fixture that source's own test suite carries, which appears")
    out.append("   below as cuckoo_golden. */")
    out.append("")
    out.append("#ifndef HEADER_fd_src_discof_dragon_test_cuckoo_vectors_h")
    out.append("#define HEADER_fd_src_discof_dragon_test_cuckoo_vectors_h")
    out.append("")
    out.append("/* The golden fixture of yellowstone-grpc-proto/src/cuckoo/filter.rs:")
    out.append("   %lu keys of 32 equal bytes inserted into a filter built for" % GOLDEN_KEY_CNT)
    out.append("   capacity %lu with seed 0x%016x. */" % (GOLDEN_CAPACITY, GOLDEN_SEED))
    out.append("")
    out.append("#define CUCKOO_GOLDEN_SEED (0x%016xUL)" % GOLDEN_SEED)
    out.append("#define CUCKOO_GOLDEN_CAPACITY (%luUL)" % GOLDEN_CAPACITY)
    out.append("#define CUCKOO_GOLDEN_KEY_CNT (%luUL)" % GOLDEN_KEY_CNT)
    out.append("")
    out.append("static uchar const cuckoo_golden_data[ %lu ] = {" % len(GOLDEN_DATA))
    out.append(c_bytes(GOLDEN_DATA, "  "))
    out.append("};")
    out.append("")

    emit_case(out, "cuckoo_small", DEFAULT_HASH_SEED, 8, 6, 64, fp_want=2)
    emit_case(out, "cuckoo_mid", DEFAULT_HASH_SEED, 1000, 900, 512, fp_want=6)
    emit_case(out, "cuckoo_seeded", 0xDEADBEEFCAFEF00D, 300, 280, 256, fp_want=4)

    out.append("#endif /* HEADER_fd_src_discof_dragon_test_cuckoo_vectors_h */")

    with open("src/discof/dragon/test_cuckoo_vectors.h", "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("golden fixture reproduced; wrote src/discof/dragon/test_cuckoo_vectors.h")
    return 0


if __name__ == "__main__":
    sys.exit(main())
