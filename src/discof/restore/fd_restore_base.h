#ifndef HEADER_fd_src_discof_restore_fd_restore_base_h
#define HEADER_fd_src_discof_restore_fd_restore_base_h

#include "../../tango/mcache/fd_mcache.h"

/* fd_stream_frag_meta_t is a variation of fd_frag_meta_t optimized for
   stream I/O. */

union fd_stream_frag_meta {

  struct {

    ulong  seq;     /* frag sequence number */
    ulong  goff;    /* stream offset */

    uint   sz;
    ushort unused;
    ushort ctl;
    ulong  loff;    /* dcache offset */

  };

  fd_frag_meta_t f[1];

};

typedef union fd_stream_frag_meta fd_stream_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_stream_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_stream_frag_meta_t)==32, abi );

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

FD_PROTOTYPES_END

/* fd_account_frag_meta_t is a variation of fd_frag_meta_t optimized for
   accounts. */

union fd_account_frag_meta {

  struct {

    ulong seq;
    ulong rec_hash;

    ulong frag_seq;
    ulong rec_goff;

  };

  fd_frag_meta_t f[1];

};

typedef union fd_account_frag_meta fd_account_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_account_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_account_frag_meta_t)==32, abi );

#endif /* HEADER_fd_src_discof_restore_fd_restore_base_h */
