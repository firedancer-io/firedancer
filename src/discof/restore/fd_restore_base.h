#ifndef HEADER_fd_src_discof_restore_fd_restore_base_h
#define HEADER_fd_src_discof_restore_fd_restore_base_h

#include "../../tango/mcache/fd_mcache.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../ballet/lthash/fd_lthash.h"

#define DCACHE_SZ 16<<20UL

/* fd_stream_frag_meta_t is a variation of fd_frag_meta_t optimized for
   stream I/O. */

union fd_stream_frag_meta {

  struct {

    ulong  seq;     /* frag sequence number */
    uint   sz;
    ushort unused;
    ushort ctl;

    ulong  goff;    /* stream offset */
    ulong  loff;    /* dcache offset */

  };

  fd_frag_meta_t f[1];

};

typedef union fd_stream_frag_meta fd_stream_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_stream_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_stream_frag_meta_t)==32, abi );

/* fd_account_frag_meta_t is a variation of fd_frag_meta_t optimized for
   accounts. */

union fd_account_frag_meta {

  struct {

    ulong seq;
    ulong rec_hash;

    ulong gaddr;
    ulong frag_seq;

  };

  fd_frag_meta_t f[1];

  fd_stream_frag_meta_t acc[1];

};

typedef union fd_account_frag_meta fd_account_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_account_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_account_frag_meta_t)==32, abi );

/* fd_stream_frag_meta_ctx_t tracks receiving state from a stream */
struct fd_stream_frag_meta_ctx {
  uchar const * in_buf;
  ulong         goff_translate;
  ulong         loff_translate;
  ulong         in_skip;
};
typedef struct fd_stream_frag_meta_ctx fd_stream_frag_meta_ctx_t;

FD_PROTOTYPES_BEGIN

static inline void
fd_mcache_publish_stream( fd_stream_frag_meta_t * mcache,
                          ulong                   depth,
                          ulong                   seq,
                          ulong                   goff,
                          ulong                   loff,
                          ulong                   sz,
                          ulong                   ctl ) {
  fd_stream_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq   = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->goff  = goff;
  meta->sz    = (uint)sz;
  meta->ctl   = (ushort)ctl;
  meta->loff  = loff;
  FD_COMPILER_MFENCE();
  meta->seq   = seq;
  FD_COMPILER_MFENCE();
}

static inline void
fd_mcache_publish_account( fd_account_frag_meta_t * mcache,
                           ulong                    depth,
                           ulong                    seq,
                           ulong                    rec_hash,
                           ulong                    gaddr,
                           ulong                    frag_seq ) {
  fd_account_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );
  FD_COMPILER_MFENCE();
  meta->seq      = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  meta->rec_hash = rec_hash;
  meta->gaddr    = gaddr;
  meta->frag_seq = frag_seq;
  FD_COMPILER_MFENCE();
  meta->seq      = seq;
  FD_COMPILER_MFENCE();
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_fd_restore_base_h */
