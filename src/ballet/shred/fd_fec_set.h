#ifndef HEADER_fd_src_ballet_shred_fd_fec_set_h
#define HEADER_fd_src_ballet_shred_fd_fec_set_h

#include "../reedsol/fd_reedsol.h"

/* When using Merkle shreds, an FEC set is essentially the transmission
   granularity.  Each FEC set has likely dozens of packets, but you have
   to construct the entire FEC set before you can send the first byte.
   Similarly, on the receive side, in order to validate an FEC set, you
   have to receive or reconstruct the whole thing.  */

struct fd_fec_set {
  ulong data_shred_cnt;
  ulong parity_shred_cnt;

  uchar * data_shreds[ FD_REEDSOL_DATA_SHREDS_MAX     ];
  uchar * parity_shreds[ FD_REEDSOL_PARITY_SHREDS_MAX ];
};
typedef struct fd_fec_set fd_fec_set_t;


/* Forward declare opaque handle.  It has a lot of types we don't
   necessarily want to bring into the includer */
struct fd_fec_resolver;
typedef struct fd_fec_resolver fd_fec_resolver_t;

/* fd_fec_resolver_{footprint, align} return the footprint and
   alignment (in bytes as always) required to create an FEC set resolver
   that can keep track of depth simultaneous FEC sets. */
ulong fd_fec_resolver_footprint( ulong depth );
ulong fd_fec_resolver_align    ( void        );

ulong fd_fec_resolver_new( void * shmem, ulong depth, fd_fec_set_t * sets );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

fd_fec_set_t * fd_fec_resolver_add_shred( fd_fec_resolver_t * resolver, fd_shred_t * shred, ulong shred_sz );

void * fd_fec_resolver_leave( fd_fec_resolver * resolver );
void * fd_fec_resolver_delete( void * shmem );

#endif /* HEADER_fd_src_ballet_shred_fd_fec_set_h */
