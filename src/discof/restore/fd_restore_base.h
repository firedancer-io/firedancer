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

    ulong frag_seq;
    ulong rec_goff;

  };

  fd_frag_meta_t f[1];

};

typedef union fd_account_frag_meta fd_account_frag_meta_t;

FD_STATIC_ASSERT( alignof(fd_account_frag_meta_t)==32, abi );
FD_STATIC_ASSERT( sizeof (fd_account_frag_meta_t)==32, abi );

#endif /* HEADER_fd_src_discof_restore_fd_restore_base_h */
