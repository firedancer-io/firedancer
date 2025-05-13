#ifndef HEADER_fd_src_discof_restore_fd_restore_base_h
#define HEADER_fd_src_discof_restore_fd_restore_base_h

#include "../../tango/mcache/fd_mcache.h"
#include "../../disco/topo/fd_topo.h"
#include "stream/fd_stream_reader.h"

struct fd_stream_frag_meta_ctx {
  uchar const * in_buf;
  ulong         goff_translate;
  ulong         loff_translate;
  ulong         in_skip;
};
typedef struct fd_stream_frag_meta_ctx fd_stream_frag_meta_ctx_t;

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

};

typedef union fd_account_frag_meta fd_account_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_account_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_account_frag_meta_t)==32, abi );

FD_PROTOTYPES_BEGIN

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
