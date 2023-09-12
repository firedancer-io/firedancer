#ifndef HEADER_fd_src_ballet_shred_fd_fec_set_h
#define HEADER_fd_src_ballet_shred_fd_fec_set_h

#include "../reedsol/fd_reedsol.h"

#define SET_NAME d_present
#define SET_MAX  (FD_REEDSOL_DATA_SHREDS_MAX)
#include "../../util/tmpl/fd_set.c"
#define SET_NAME p_present
#define SET_MAX  (FD_REEDSOL_PARITY_SHREDS_MAX)
#include "../../util/tmpl/fd_set.c"

struct fd_shred;
typedef struct fd_shred fd_shred_t;

/* When using Merkle shreds, an FEC set is essentially the transmission
   granularity.  Each FEC set has likely dozens of packets, but you have
   to construct the entire FEC set before you can send the first byte.
   Similarly, on the receive side, in order to validate an FEC set, you
   have to receive or reconstruct the whole thing.  */

struct fd_fec_set {
  ulong data_shred_cnt;
  ulong parity_shred_cnt;

  d_present_t data_shred_present[   d_present_word_cnt ];
  p_present_t parity_shred_present[ p_present_word_cnt ];

  uchar * data_shreds[ FD_REEDSOL_DATA_SHREDS_MAX     ];
  uchar * parity_shreds[ FD_REEDSOL_PARITY_SHREDS_MAX ];
};
typedef struct fd_fec_set fd_fec_set_t;


/* Forward declare opaque handle.  It has a lot of types we don't
   necessarily want to bring into the includer */
#define FD_FEC_RESOLVER_ALIGN (128UL)
struct fd_fec_resolver;
typedef struct fd_fec_resolver fd_fec_resolver_t;

/* fd_fec_resolver_{footprint, align} return the footprint and
   alignment (in bytes as always) required to create an FEC set resolver
   that can keep track of depth simultaneous FEC sets. */
ulong fd_fec_resolver_footprint( ulong depth, ulong done_depth );
ulong fd_fec_resolver_align    ( void        );

void * fd_fec_resolver_new( void * shmem, ulong depth, ulong done_depth, fd_fec_set_t * sets, uchar const * public_key );

fd_fec_resolver_t * fd_fec_resolver_join( void * shmem );

fd_fec_set_t const * fd_fec_resolver_add_shred( fd_fec_resolver_t * resolver, fd_shred_t const * shred, ulong shred_sz );

void * fd_fec_resolver_leave( fd_fec_resolver_t * resolver );
void * fd_fec_resolver_delete( void * shmem );

#endif /* HEADER_fd_src_ballet_shred_fd_fec_set_h */
