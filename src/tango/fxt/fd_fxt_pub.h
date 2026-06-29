#ifndef HEADER_fd_src_util_fxt_fd_fxt_pub_h
#define HEADER_fd_src_util_fxt_fd_fxt_pub_h

#include "../mcache/fd_mcache.h"
#include "../dcache/fd_dcache.h"

struct fd_fxt_pub {
  fd_frag_meta_t * mcache;
  uchar *          dcache;

  ulong            seq;
  ulong            chunk;

  ulong            depth;
  ulong            chunk0;
  ulong            wmark;

  ulong            thread_id;
};

typedef struct fd_fxt_pub fd_fxt_pub_t;

FD_PROTOTYPES_BEGIN

/* fd_fxt_pub_init joins an FTF publisher to an mcache/dcache ring. */

FD_FN_UNUSED static fd_fxt_pub_t *
fd_fxt_pub_init( fd_fxt_pub_t *   pub,
                 fd_frag_meta_t * mcache,
                 uchar *          dcache,
                 ulong            mtu,
                 ulong            thread_id ) {
  ulong chunk0 = fd_dcache_compact_chunk0( dcache, dcache );
  ulong wmark  = fd_dcache_compact_wmark ( dcache, dcache, mtu );
  ulong depth  = fd_mcache_depth( mcache );
  *pub = (fd_fxt_pub_t) {
    .mcache = mcache,
    .dcache = dcache,

    .seq   = 0UL,
    .chunk = chunk0,

    .depth  = depth,
    .chunk0 = chunk0,
    .wmark  = wmark,

    .thread_id = thread_id
  };
  return pub;
}

/* fd_fxt_pub_rec1 publishes an 8-byte FTF record. */

static inline void
fd_fxt_pub_rec1( fd_fxt_pub_t * pub,
                 ulong          word0 ) {
  ulong seq = pub->seq;
  fd_mcache_publish( pub->mcache, pub->depth, seq, word0, 0UL, 8UL, 0UL, 0UL, 0UL );
  pub->seq = fd_seq_inc( seq, 1UL );
}

/* fd_fxt_pub_rec2 publishes a 16-byte FTF record. */

static inline void
fd_fxt_pub_rec2( fd_fxt_pub_t * pub,
                 ulong          word0,
                 ulong          word1 ) {
  ulong seq = pub->seq;
  fd_mcache_publish( pub->mcache, pub->depth, seq, word0, 0UL, 16UL, 0UL, word1, word1>>32 );
  pub->seq = fd_seq_inc( seq, 1UL );
}

static inline void *
fd_fxt_pub_rec_prepare( fd_fxt_pub_t * pub ) {
  return fd_chunk_to_laddr( pub->dcache, pub->chunk );
}

static inline void
fd_fxt_pub_rec_publish( fd_fxt_pub_t * pub,
                        ulong          sz ) {
  ulong seq   = pub->seq;
  ulong chunk = pub->chunk;
  fd_mcache_publish( pub->mcache, pub->depth, seq, 0UL, chunk, sz, 1UL, 0UL, 0UL );
  pub->seq   = fd_seq_inc( seq, 1UL );
  pub->chunk = fd_dcache_compact_next( pub->chunk, sz, pub->chunk0, pub->wmark );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fxt_fd_fxt_pub_h */
