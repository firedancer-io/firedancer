#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_h

/* fd_reedsol provides APIs for producing Reed-Solomon encoded parity
   data and for reconstructing missing data from parity data.  The
   encoding process is optimized, and highly optimized for Turbine's
   typical case.

   Reed-Solomon works in GF(2^8), i.e. the codeword size is 1 byte, but
   is typically used on each byte of larger pieces of data called
   shreds (a Solana-specific term, often called shards elswhere in the
   literature).  Mathematically, the encoding process forms a vector
   from the input data, taking one byte from each shred, and
   left-multiplies the vector by a constant matrix in GF(2^8).  The
   resulting vector contains one byte for each of the parity shreds.
   Solana also calls parity shreds "code" shreds, but due to the naming
   collision with executable code, we have opted for "parity."  This
   mathematical structure thus forces each shred to be of identical size
   but doesn't otherwise impose any size restrictions. */

#include "../../util/fd_util.h"

// TODO: Define decode API
//#define SET_NAME reedsol_shred_set
//#include "../../util/tmpl/fd_smallset.c"

/* FD_REEDSOL_{DATA, PARITY}_SHREDS_MAX describe the inclusive maximum
   number of data and parity shreds that this implementation supports.
   These limits are not mathematical limits, but limits based on current
   Solana needs and performance.  It is common for both shred counts to
   be at their maximum values. */
#define FD_REEDSOL_DATA_SHREDS_MAX   (32UL)
#define FD_REEDSOL_PARITY_SHREDS_MAX (32UL)


#define FD_REEDSOL_ALIGN     (128UL)
#define FD_REEDSOL_FOOTPRINT (1664UL)

struct __attribute__((aligned(FD_REEDSOL_ALIGN))) fd_reedsol_private {
  uchar scratch[ 1024 ]; /* Used for the ultra high performance implementation */

  /* shred_sz: the size of each shred in bytes (all shreds must be the
     same size) */
  ulong shred_sz;

  /* {data, parity}_shred_cnt: the number of data or parity shreds
     (respectively) have been added to the in-process operation */
  ulong data_shred_cnt;
  ulong parity_shred_cnt;

  /* {data, parity}_shred: pointers to the first byte of each shred */
  uchar * data_shred[   FD_REEDSOL_DATA_SHREDS_MAX   ];
  uchar * parity_shred[ FD_REEDSOL_PARITY_SHREDS_MAX ];

  /* {data, parity}_shred_valid: whether the shred at the corresponding
     index contains valid data.  Used only for decoding operations. */
  //fd_reedsol_shred_set_t data_shred_valid;
  //fd_reedsol_shred_set_t parity_shred_valid;
};

typedef struct fd_reedsol_private fd_reedsol_t;

FD_PROTOTYPES_BEGIN

/* fd_reedsol_{align, footprint} return the alignment and footprint
   required in bytes for a fd_reedsol_t. */
static inline FD_FN_CONST ulong fd_reedsol_align(     void ) { return FD_REEDSOL_ALIGN;     }
static inline FD_FN_CONST ulong fd_reedsol_footprint( void ) { return FD_REEDSOL_FOOTPRINT; }


/* fd_reedsol_encode_init: starts a Reed-Solomon encoding operation that
   will encode shreds of size shred_sz.  mem is assumed to be a piece
   of memory that meets the alignment and size constraints specified
   above.  Takes a write interest in mem that persists until the
   operation is canceled or finalized.  shred_sz must be >= 32. Returns
   mem. */

static inline fd_reedsol_t *
fd_reedsol_encode_init( void * mem, ulong shred_sz ) {
  fd_reedsol_t * rs = (fd_reedsol_t *)mem;

  rs->shred_sz = shred_sz;
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;

  return rs;
}

/* fd_reedsol_encode_add_data_shred: adds a shred consisting of the
   memory [ptr, ptr+shred_sz) to the in-process Reed-Solomon encoding
   operation.  Takes a read interest in the shred that persists for
   the lifetime of the operation (i.e. until finalized or cancelled).
   Data shreds have no alignment restrictions and can overlap with each
   other but should not overlap with any parity shreds in the same
   encoding operation.

   Note: The order in which data shreds are added relative to other data
   shreds matters.  It impacts the parity data produced by the encoding
   operation. */

static inline fd_reedsol_t *
fd_reedsol_encode_add_data_shred( fd_reedsol_t * rs, void const * ptr ) {
  /* The argument is const to make it clear that an encoding operation
     won't write to the shred, but we store them in the struct as
     non-const so that the same struct can be used for encoding and
     decoding operations, in which the data shreds actually are
     writeable. */
  rs->data_shred[ rs->data_shred_cnt++ ] = (uchar *)ptr;
  return rs;
}

/* fd_reedsol_encode_add_parity_shred: adds the block of memory
   [ptr, ptr+shred_sz) to the in-process Reed-Solomon encoding operation
   as the destination of a parity shred.  Takes a write interest in the
   memory that persists for the lifetime of the operation (i.e. until
   finalized or cancelled).  Parity shreds have no alignment
   restrictions but must not overlap with each other or with data shreds
   in the same operation (U.B. if they overlap).

   Note: The order in which parity shreds are added matters only insofar
   as which data will be written to which location. */

static inline fd_reedsol_t *
fd_reedsol_encode_add_parity_shred( fd_reedsol_t * rs, void * ptr ) {
  rs->parity_shred[ rs->parity_shred_cnt++ ] = (uchar *)ptr;
  return rs;
}


/* fd_reedsol_encode_cancel cancels an in-progress encoding operation.
   Releases any read or write interests in any shreds that were added to
   the operation.  Upon return, the contents of the parity shreds are
   undefined. */

static inline void
fd_reedsol_encode_cancel( fd_reedsol_t * rs ) {
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
}

/* fd_reedsol_encode_fini finishes the in-progress encoding operation.
   Upon return, the parity shreds will be filled with the correct
   Reed-Solomon encoded parity data.  Upon return, this will no longer
   have any read or write interest in any of the provided shreds. */
void fd_reedsol_encode_fini( fd_reedsol_t * rs );


/* FIXME: Add decode API */

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_h */

