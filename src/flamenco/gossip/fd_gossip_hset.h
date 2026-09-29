#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_hset_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_hset_h

#include "../../util/fd_util_base.h"
#include "../../util/bits/fd_bits.h"

/* fd_gossip_hset is a secondary index over the 32 byte value hashes of
   a pool (the CRDS table or the purged table) that makes building pull
   request bloom filters a mostly sequential scan.

   Hashes are bucketed by the top lg_bucket_cnt bits of their 64-bit
   prefix (fd_ulong_load_8 of the hash, the same prefix the pull request
   mask is applied to).  Each bucket is a list of chunks of 8 hashes
   stored contiguously (256 bytes), so a mask range maps to a run of
   buckets and each chunk feeds one fd_bloom_insert8.  All chunks of a
   bucket are full except its head.  Insert appends to the head chunk
   and remove moves the head chunk's last hash into the hole, so both
   are O(1) regardless of how hashes are distributed.

   Elements are identified by their index in the owning pool, in
   [0,ele_max).  The hset keeps its own copy of the hash. */

#define FD_GOSSIP_HSET_ALIGN (64UL)
#define FD_GOSSIP_HSET_MAGIC (0xf17eda2c3a5e7000UL) /* firedancer hset v0 */

struct fd_gossip_hset_chunk {
  uint next; /* next (full) chunk in the bucket, or UINT_MAX */
  uint cnt;  /* number of hashes in the chunk, in [1,8] while in use */
};

typedef struct fd_gossip_hset_chunk fd_gossip_hset_chunk_t;

struct __attribute__((aligned(FD_GOSSIP_HSET_ALIGN))) fd_gossip_hset_private {
  ulong                    ele_max;
  ulong                    chunk_max;
  ulong                    lg_bucket_cnt;
  uint                     chunk_free;  /* free chunk stack head, UINT_MAX if empty */
  uint *                   bucket_head; /* [2^lg_bucket_cnt] head chunk, UINT_MAX if empty */
  fd_gossip_hset_chunk_t * chunk;       /* [chunk_max] */
  uchar                 (* hash)[ 32 ]; /* [chunk_max*8] */
  uint *                   owner;       /* [chunk_max*8] element index for a hash slot */
  uint *                   slot;        /* [ele_max]     hash slot of an element */
  ulong                    magic;       /* ==FD_GOSSIP_HSET_MAGIC */
};

typedef struct fd_gossip_hset_private fd_gossip_hset_t;

/* fd_gossip_hset_iter_t iterates the chunks holding the hashes whose
   prefix is in [start,end]. */

struct fd_gossip_hset_iter {
  ulong bucket;
  ulong bucket_end;
  ulong chunk;
  ulong start;
  ulong end;
  int   filter; /* the range does not cover whole buckets */
};

typedef struct fd_gossip_hset_iter fd_gossip_hset_iter_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gossip_hset_align( void );

FD_FN_CONST ulong
fd_gossip_hset_footprint( ulong ele_max );

/* fd_gossip_hset_new formats shmem for up to ele_max elements.
   ele_max must be a power of 2 in [1,2^31]. */

void *
fd_gossip_hset_new( void * shmem,
                    ulong  ele_max );

fd_gossip_hset_t *
fd_gossip_hset_join( void * shhset );

/* fd_gossip_hset_insert adds element ele_idx with the given hash.
   ele_idx must not already be in the hset. */

void
fd_gossip_hset_insert( fd_gossip_hset_t * hset,
                       ulong              ele_idx,
                       uchar const *      hash );

/* fd_gossip_hset_remove removes element ele_idx, which must be in the
   hset. */

void
fd_gossip_hset_remove( fd_gossip_hset_t * hset,
                       ulong              ele_idx );

/* fd_gossip_hset_iter_init starts iterating the hashes whose prefix
   falls in the pull request mask range for (mask, mask_bits), see
   fd_gossip_purged_generate_masks.  Iteration yields chunks: a block
   of 8 hashes (fd_gossip_hset_iter_hashes) and a bit mask of the
   lanes that hold an in range hash (fd_gossip_hset_iter_lanes, can be
   0 when filtering).  The hset must not be modified while
   iterating. */

void
fd_gossip_hset_iter_init( fd_gossip_hset_iter_t *  it,
                          fd_gossip_hset_t const * hset,
                          ulong                    start_hash,
                          ulong                    end_hash );

static inline int
fd_gossip_hset_iter_done( fd_gossip_hset_iter_t const * it ) {
  return it->chunk==(ulong)UINT_MAX;
}

void
fd_gossip_hset_iter_next( fd_gossip_hset_iter_t *  it,
                          fd_gossip_hset_t const * hset );

static inline uchar const *
fd_gossip_hset_iter_hashes( fd_gossip_hset_iter_t const * it,
                            fd_gossip_hset_t const *      hset ) {
  return hset->hash[ 8UL*it->chunk ];
}

/* fd_gossip_hset_iter_owner returns the element index that owns the
   hash in the given lane of the current chunk.  The lane must be set in
   fd_gossip_hset_iter_lanes. */

static inline ulong
fd_gossip_hset_iter_owner( fd_gossip_hset_iter_t const * it,
                           fd_gossip_hset_t const *      hset,
                           ulong                         lane ) {
  return hset->owner[ 8UL*it->chunk+lane ];
}

static inline uint
fd_gossip_hset_iter_lanes( fd_gossip_hset_iter_t const * it,
                           fd_gossip_hset_t const *      hset ) {
  uint lanes = (1U<<hset->chunk[ it->chunk ].cnt)-1U;
  if( FD_UNLIKELY( it->filter ) ) {
    uchar const * h = hset->hash[ 8UL*it->chunk ];
    for( ulong i=0UL; i<8UL; i++ ) {
      ulong p = fd_ulong_load_8( h+32UL*i );
      lanes &= ~((uint)((p<it->start) | (p>it->end))<<i);
    }
  }
  return lanes;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_hset_h */
