#ifndef HEADER_fd_src_discof_dragon_fd_dragon_cuckoo_h
#define HEADER_fd_src_discof_dragon_fd_dragon_cuckoo_h

/* fd_dragon_cuckoo is a C port of the cuckoo filter that a Dragon's
   Mouth client uses to compress a large account set into a few bytes
   per account (geyser.proto CuckooFilter,
   SubscribeRequestFilterAccounts.cuckoo_accounts_filter,
   SubscribeRequestFilterTransactions.cuckoo_account_include,
   SubscribeRequestFilterBlocks.cuckoo_account_include).

   Ported from yellowstone-grpc-proto/src/cuckoo (constants.rs,
   hasher.rs, filter.rs), which is licensed Apache-2.0:

     Copyright 2025 Triton One Limited

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing,
     software distributed under the License is distributed on an "AS
     IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
     express or implied.  See the License for the specific language
     governing permissions and limitations under the License.

   The filter's bytes are a wire format, so every arithmetic detail is
   a compatibility constraint rather than a choice:

   - the hash is SipHash-2-4 with k0 = seed and k1 = the seed rotated
     left by 32, where seed comes off the wire in CuckooFilter.hash_seed
   - a 32 byte key is hashed the way Rust's Hash for [u8; N] writes it,
     which is the length as a little endian u64 followed by the bytes
   - a fingerprint is hashed as its two little endian bytes
   - the fingerprint of a key is bits 32..48 of its hash, or 1 when
     those bits are zero, because zero marks an empty slot
   - a key's first bucket is hash & (bucket_cnt-1) and its second is
     the first xor the fingerprint's hash masked the same way

   Wire decoding is deliberately as forgiving as the Rust
   implementation: the buckets are whatever whole buckets the data
   field holds (8 bytes each), an empty or too short field gives one
   empty bucket, and bucket_count, entries_per_bucket, fingerprint_bits
   and hash_algorithm are not read at all.  A filter built by a peer
   that disagrees with those four fields therefore matches nothing in
   particular rather than being refused, which is what a yellowstone
   server does with the same bytes.

   A decoded filter is read-only.  Insertion exists so that tests and
   fuzzers can build the same filters a client builds, and so that the
   port can be checked against the reference vectors byte for byte. */

#include "../../util/fd_util_base.h"

/* Slots per bucket, and the bytes one bucket occupies on the wire. */

#define FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET (4UL)
#define FD_DRAGON_CUCKOO_BUCKET_SZ          (8UL) /* 4 little endian u16 */

/* Relocations an insert attempts before declaring the table full. */

#define FD_DRAGON_CUCKOO_MAX_KICKS (500UL)

/* The seed a client's filter carries unless it chose another one
   (constants.rs DEFAULT_HASH_SEED, ASCII "yllwstn!"). */

#define FD_DRAGON_CUCKOO_DEFAULT_SEED (0x796c6c7773746e21UL)

/* The load factor a filter is built for (constants.rs LOAD_FACTOR),
   as a ratio so that the bucket count is computed in integers. */

#define FD_DRAGON_CUCKOO_LOAD_NUM (95UL)
#define FD_DRAGON_CUCKOO_LOAD_DEN (100UL)

struct fd_dragon_cuckoo {
  ulong    seed;
  ulong    bucket_cnt;  /* >=1 */
  ushort * bucket;      /* bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET entries */
};

typedef struct fd_dragon_cuckoo fd_dragon_cuckoo_t;

FD_PROTOTYPES_BEGIN

/* fd_dragon_cuckoo_siphash24 is SipHash-2-4 over sz bytes of data with
   keys k0 and k1. */

FD_FN_PURE ulong
fd_dragon_cuckoo_siphash24( void const * data,
                            ulong        sz,
                            ulong        k0,
                            ulong        k1 );

/* fd_dragon_cuckoo_hash_key hashes a key of key_sz bytes the way the
   filter does, which is the length as a little endian u64 followed by
   the bytes.  key_sz is at most 64. */

FD_FN_PURE ulong
fd_dragon_cuckoo_hash_key( ulong         seed,
                           uchar const * key,
                           ulong         key_sz );

/* fd_dragon_cuckoo_bucket_cnt returns the number of buckets a filter
   built for capacity keys has: the buckets the load factor asks for,
   rounded up to a power of two, at least one.  Returns 0 for a capacity
   whose filter could not be described, which is one whose data field
   would be longer than a ulong counts (2^61 buckets). */

FD_FN_CONST ulong
fd_dragon_cuckoo_bucket_cnt( ulong capacity );

/* fd_dragon_cuckoo_data_sz returns the bytes a filter of bucket_cnt
   buckets occupies in CuckooFilter.data. */

FD_FN_CONST static inline ulong
fd_dragon_cuckoo_data_sz( ulong bucket_cnt ) {
  return bucket_cnt*FD_DRAGON_CUCKOO_BUCKET_SZ;
}

/* fd_dragon_cuckoo_wire_bucket_cnt returns the number of buckets that
   data_sz bytes of CuckooFilter.data decode to, which is the whole
   buckets they hold, or one empty bucket if they hold none. */

FD_FN_CONST static inline ulong
fd_dragon_cuckoo_wire_bucket_cnt( ulong data_sz ) {
  ulong cnt = data_sz/FD_DRAGON_CUCKOO_BUCKET_SZ;
  return cnt ? cnt : 1UL;
}

/* fd_dragon_cuckoo_init formats bucket as an empty filter of
   bucket_cnt buckets.  bucket points to
   bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET ushorts.  bucket_cnt
   must be at least 1. */

fd_dragon_cuckoo_t *
fd_dragon_cuckoo_init( fd_dragon_cuckoo_t * f,
                       ulong                seed,
                       ushort *             bucket,
                       ulong                bucket_cnt );

/* fd_dragon_cuckoo_decode formats bucket as the filter that data_sz
   bytes of a CuckooFilter.data field describe, with the seed of its
   hash_seed field.  bucket must have room for
   fd_dragon_cuckoo_wire_bucket_cnt( data_sz ) buckets.  Trailing bytes
   that do not complete a bucket are ignored, and data_sz of zero gives
   one empty bucket. */

fd_dragon_cuckoo_t *
fd_dragon_cuckoo_decode( fd_dragon_cuckoo_t * f,
                         ulong                seed,
                         uchar const *        data,
                         ulong                data_sz,
                         ushort *             bucket );

/* fd_dragon_cuckoo_encode writes the filter as a CuckooFilter.data
   field, which is fd_dragon_cuckoo_data_sz( f->bucket_cnt ) bytes. */

void
fd_dragon_cuckoo_encode( fd_dragon_cuckoo_t const * f,
                         uchar *                    out );

/* fd_dragon_cuckoo_insert adds a key of key_sz bytes to the filter.
   Returns 1 on success, or 0 if no relocation path was found within
   FD_DRAGON_CUCKOO_MAX_KICKS, which means the filter is saturated.  A
   failed insert leaves the filter usable but may have moved
   fingerprints, exactly as the Rust implementation does. */

int
fd_dragon_cuckoo_insert( fd_dragon_cuckoo_t * f,
                         uchar const *        key,
                         ulong                key_sz );

/* fd_dragon_cuckoo_remove clears one fingerprint matching the key.
   Returns 1 if one was found.  Removing a key that was never inserted
   can clear a different key that shares its fingerprint. */

int
fd_dragon_cuckoo_remove( fd_dragon_cuckoo_t * f,
                         uchar const *        key,
                         ulong                key_sz );

/* fd_dragon_cuckoo_contains returns 1 if the key is probably in the
   filter and 0 if it is definitely not.  key_sz is at most 64. */

FD_FN_PURE int
fd_dragon_cuckoo_contains( fd_dragon_cuckoo_t const * f,
                           uchar const *              key,
                           ulong                      key_sz );

/* fd_dragon_cuckoo_contains32 is fd_dragon_cuckoo_contains for the 32
   byte keys that every account filter uses. */

FD_FN_PURE static inline int
fd_dragon_cuckoo_contains32( fd_dragon_cuckoo_t const * f,
                             uchar const *              key ) {
  return fd_dragon_cuckoo_contains( f, key, 32UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_cuckoo_h */
