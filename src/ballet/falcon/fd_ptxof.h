#ifndef HEADER_fd_src_ballet_falcon_fd_ptfox_h
#define HEADER_fd_src_ballet_falcon_fd_ptfox_h

#include "../fd_ballet_base.h"

#define FD_PTXOF_PARALLEL (8UL)

typedef struct {
  ulong offset;
  ulong idx;
  union {
    ulong state[ FD_PTXOF_PARALLEL ][25];
    uchar bytes[ FD_PTXOF_PARALLEL ][200];
  };
} fd_ptxof_t;

FD_PROTOTYPES_BEGIN

void
fd_ptxof_init( fd_ptxof_t * pt );

void
fd_ptxof_absorb( fd_ptxof_t  * pt,
                 uchar const * data,
                 ulong         len );

void
fd_ptxof_fini( fd_ptxof_t * pt );

void
fd_ptxof_squeeze( fd_ptxof_t * pt,
                  uchar      * out,
                  ulong        len );

#endif /* HEADER_fd_src_ballet_falcon_fd_ptfox_h */
