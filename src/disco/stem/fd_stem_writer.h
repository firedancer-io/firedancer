#ifndef HEADER_fd_src_disco_stem_fd_stem_writer_h
#define HEADER_fd_src_disco_stem_fd_stem_writer_h

#include "../fd_disco_base.h"

struct fd_stem_writer {
  fd_frag_meta_t * mcache;
  ulong            depth;
  ulong            seq;
  ulong            cr_avail;

  ulong volatile ** cons_fseq;

  ulong   magic;
  ulong   cons_cnt;                /* number of consumers */
  ulong   cons_max;                /* max number of consumers */
};

typedef struct fd_stem_writer fd_stem_writer_t;

FD_FN_CONST ulong
fd_stem_writer_align( void );

FD_FN_CONST ulong
fd_stem_writer_footpring( ulong cons_max );

void *
fd_stem_writer_new( void *           shmem,
                    ulong            cons_max,
                    fd_frag_meta_t * mcache );

#endif /* HEADER_fd_src_disco_stem_fd_stem_h */
