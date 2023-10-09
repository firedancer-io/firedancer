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
   but doesn't otherwise impose any size restrictions.*/

#include "../fd_ballet_base.h"

/* FD_REEDSOL_{DATA,PARITY}_SHREDS_MAX describe the inclusive maximum
   number of data and parity shreds that this implementation supports.
   These limits are not mathematical limits, but limits based on current
   Solana needs and performance.  The common case for both shred counts
   to be set to 32. */

#define FD_REEDSOL_DATA_SHREDS_MAX   (67UL)
#define FD_REEDSOL_PARITY_SHREDS_MAX (67UL)

#define FD_REEDSOL_ALIGN     (128UL)
#define FD_REEDSOL_FOOTPRINT (2304UL) /* 18*ALIGN */

/* FD_REEDSOL_SUCCESS, FD_REEDSOL_ERR_* are error code return values used
   by the recover operation, which is the only part that can fail for
   non-bug reasons.  Their meaning is documented with
   fd_reedsol_recover_fini.  SUCCESS must be zero, ERR_* are negative
   and distinct. */

#define FD_REEDSOL_SUCCESS     (0)
#define FD_REEDSOL_ERR_CORRUPT (-1)
#define FD_REEDSOL_ERR_PARTIAL (-2)

struct __attribute__((aligned(FD_REEDSOL_ALIGN))) fd_reedsol_private {
  uchar scratch[ 1024 ];  // Used for the ultra high performance implementation

  ulong shred_sz;         // shred_sz: the size of each shred in bytes (all shreds must be the same size)
  ulong data_shred_cnt;   // {data,parity}_shred_cnt: the number of data or parity shreds
  ulong parity_shred_cnt; // (respectively) have been added to the in-process operation

  union {

    struct {
      uchar const * data_shred  [ FD_REEDSOL_DATA_SHREDS_MAX   ]; // {data,parity}_shred: pointers to the 1st byte of each shred
      uchar *       parity_shred[ FD_REEDSOL_PARITY_SHREDS_MAX ];
    } encode;

    struct {
      uchar * shred[ FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ];
      /* erased: whether the shred at the corresponding index is an
         erasure (i.e. wasn't received or was corrupted).  Used only for
         decoding operations.  TODO: Is this the right data type? Should
         it use a fd_smallset instead? */
      uchar erased[ FD_REEDSOL_DATA_SHREDS_MAX + FD_REEDSOL_PARITY_SHREDS_MAX ];
    } recover;

  };
};

typedef struct fd_reedsol_private fd_reedsol_t;

FD_PROTOTYPES_BEGIN

/* fd_reedsol_{align,footprint} return the alignment and footprint
   required in bytes for a fd_reedsol_t. */

static inline FD_FN_CONST ulong fd_reedsol_align(     void ) { return FD_REEDSOL_ALIGN;     }
static inline FD_FN_CONST ulong fd_reedsol_footprint( void ) { return FD_REEDSOL_FOOTPRINT; }

/* fd_reedsol_encode_init: starts a Reed-Solomon encoding operation that
   will encode shreds of size shred_sz.  mem is assumed to be a piece of
   memory that meets the alignment and size constraints specified above.
   Takes a write interest in mem that persists until the operation is
   aborted or finalized.  shred_sz must be >= 32.  Returns mem as a a
   newly initialized encoder.  Every call to fd_reedsol_encode_init
   should be paired with a call to fd_reedsol_encode_fini (normal
   execution) or fd_reedsol_encode_abort (abnormal execution). */

static inline fd_reedsol_t *
fd_reedsol_encode_init( void * mem,
                        ulong  shred_sz ) {
  fd_reedsol_t * rs = (fd_reedsol_t *)mem;
  rs->shred_sz         = shred_sz;
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
  return rs;
}

/* fd_reedsol_encode_add_data_shred: adds a shred consisting of the
   memory [ptr,ptr+shred_sz) to the in-process Reed-Solomon encoding
   operation.  Takes a read interest in the shred that persists for the
   lifetime of the operation (i.e. until finalized or aborted).  Data
   shreds have no alignment restrictions and can overlap with each other
   but should not overlap with any parity shreds in the same encoding
   operation.

   Note: The order in which data shreds are added relative to other data
   shreds matters.  It impacts the parity data produced by the encoding
   operation.

   Assumes rs is initialized as an encoder and returns rs (still
   initialized as an encoder). */

static inline fd_reedsol_t *
fd_reedsol_encode_add_data_shred( fd_reedsol_t * rs,
                                  void const *   ptr ) {
  rs->encode.data_shred[ rs->data_shred_cnt++ ] = (uchar const*) ptr;
  return rs;
}

/* fd_reedsol_encode_add_parity_shred: adds the block of memory
   [ptr,ptr+shred_sz) to the in-process Reed-Solomon encoding operation
   as the destination of a parity shred.  Takes a write interest in the
   memory that persists for the lifetime of the operation (i.e. until
   finalized or aborted).  Parity shreds have no alignment
   restrictions but must not overlap with each other or with data shreds
   in the same operation (U.B. if they overlap).

   Note: The order in which parity shreds are added matters only insofar
   as which data will be written to which location.

   Assumes rs is initialized as an encoder and returns rs (still
   initialized as an encoder). */

static inline fd_reedsol_t *
fd_reedsol_encode_add_parity_shred( fd_reedsol_t * rs,
                                    void *         ptr ) {
  rs->encode.parity_shred[ rs->parity_shred_cnt++ ] = (uchar *)ptr;
  return rs;
}

/* fd_reedsol_encode_abort aborts an in-progress encoding operation.
   Releases any read or write interests in any shreds that were added to
   the operation.  Upon return, the contents of the parity shreds are
   undefined.  Assumes rs is initialized as an encoder, rs will not be
   initialized on return. */

static inline void
fd_reedsol_encode_abort( fd_reedsol_t * rs ) {
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
}

/* fd_reedsol_encode_fini finishes the in-progress encoding operation.
   Upon return, the parity shreds will be filled with the correct
   Reed-Solomon encoded parity data.  Upon return, this will no longer
   have any read or write interest in any of the provided shreds.
   Assumes rs is initialized as an encoder, rs will not be initialized
   on return. */

void
fd_reedsol_encode_fini( fd_reedsol_t * rs );

/* fd_reedsol_recover_init: starts a Reed-Solomon recover/decode
   operation that will recover shreds of size shred_sz.  mem is assumed
   to be an unused piece of memory that meets the alignment and size
   constraints specified above.  Takes a write interest in mem that
   persists until the operation is aborted or finalized.  shred_sz must
   be >= 32.  Returns mem as a newly initialized recoverer.  Every call
   to fd_reedsol_recover_init should be paired with a call to
   fd_reedsol_recover_fini (normal execution) or
   fd_reedsol_recover_abort (abnormal execution). */

static inline fd_reedsol_t *
fd_reedsol_recover_init( void * mem, ulong shred_sz ) {
  fd_reedsol_t * rs = (fd_reedsol_t *)mem;
  rs->shred_sz         = shred_sz;
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
  return rs;
}

/* fd_reedsol_recover_add_rcvd_shred adds the shred consisting of the of
   memory [ptr, ptr+shred_sz) to the in-process Reed-Solomon recover
   operation as a source of data.  Takes a read interest in the shred
   that persists for the lifetime of the operation (i.e. until finalized
   or aborted).  Received shreds have no alignment restrictions and can
   overlap with each other (if necessary, but there's no known use case
   for doing so), but should not overlap with any erased shreds in the
   same recovery operation.

   The shred is treated as a data shred if is_data_shred is non-zero and
   as a parity shred if not.  Data shreds and parity shreds are mostly
   treated identically in the recover operation, but having the right
   number of data shreds is important for validating the shreds are
   correct.

   Note: The order in which shreds are added (using this function and
   fd_reedsol_recover_add_erased_shred) is very important for recovery.
   Shreds must be added in the natural index order or the recover
   operation will almost certainly fail.  In particular, all data shreds
   must be added before any parity shreds are added.

   Assumes rs is initialized as a recoverer, returns rs (still
   initialized as a recoverer). */

static inline fd_reedsol_t *
fd_reedsol_recover_add_rcvd_shred( fd_reedsol_t * rs,
                                   int            is_data_shred,
                                   void const *   ptr ) {

  /* Assumes is_data_shred==1 implies rs->parity_shred_cnt==0 and
     data_shred_cnt, parity_shred_cnt won't go over the max */

  /* For performance reasons, we need to store all the shred pointers in
     one flat array, which means the array needs to be non-const.  The
     const in the function signature signals that this operation won't
     modify the shred. */

  rs->recover.shred [ rs->data_shred_cnt + rs->parity_shred_cnt ] = (void *)ptr;
  rs->recover.erased[ rs->data_shred_cnt + rs->parity_shred_cnt ] = (uchar)0;
  rs->data_shred_cnt   += !!is_data_shred;
  rs->parity_shred_cnt +=  !is_data_shred;

  return rs;
}

/* fd_reedsol_recover_add_erased_shred adds the block of memory
   [ptr,ptr+shred_sz) to the in-process Reed-Solomon recover operation
   as the destination for a shred that will be recovered.  Takes a write
   interest in the shred that persists for the lifetime of the operation
   (i.e. until finalized or aborted).  Erased shreds have no alignment
   restrictions but should not overlap with any other shreds in the same
   recover operation.  The contents of the the block of memory are
   ignored and will be overwritten by the time the operation is
   finished.

   The shred is treated as a data shred if is_data_shred is non-zero and
   as a parity shred if not.  Data shreds and parity shreds are mostly
   treated identically in the recover operation, but having the right
   number of data shreds is important for validating the shreds are
   correct.

   Note: The order in which shreds are added (using this function and
   fd_reedsol_recover_add_rcvd_shred) is very important for recovery.
   Shreds must be added in the natural index order or the recover
   operation will almost certainly fail.  In particular, all data shreds
   must be added before any parity shreds are added.

   Assumes rs is initialized as a recoverer, returns rs (still
   initialized as a recoverer). */

static inline fd_reedsol_t *
fd_reedsol_recover_add_erased_shred( fd_reedsol_t * rs,
                                     int            is_data_shred,
                                     void *         ptr ) {

  /* Assumes assert is_data_shred==1 implies rs->parity_shred_cnt==0 and
     data_shred_cnt, parity_shred_cnt won't go over the max */

  rs->recover.shred [ rs->data_shred_cnt + rs->parity_shred_cnt ] = ptr;
  rs->recover.erased[ rs->data_shred_cnt + rs->parity_shred_cnt ] = (uchar)1;
  rs->data_shred_cnt   += !!is_data_shred;
  rs->parity_shred_cnt +=  !is_data_shred;

  return rs;
}

/* fd_reedsol_recover_abort aborts an in-progress encoding operation.
   Releases any read or write interests in any shreds that were added to
   the operation.  Upon return, the contents of the erased shreds are
   undefined.  Assumes rs is initialized and rs will not be initialized
   on return. */

static inline void
fd_reedsol_recover_abort( fd_reedsol_t * rs ) {
  rs->data_shred_cnt   = 0UL;
  rs->parity_shred_cnt = 0UL;
}

/* fd_reedsol_recover_fini finishes the in-progress recover operation.
   If successful, upon return, any erased shreds will be filled with the
   correct data as recovered by the Reed-Solomon recovery algorithm.  If
   the recover operation fails with FD_REEDSOL_ERR_{CORRUPT,PARTIAL},
   the contents of any erased shreds are undefined.

   Upon return, this will no longer have any read or write interest in
   any of the provided shreds.

   Returns one of:

   FD_REEDSOL_SUCCESS if the recover operation was successful

   FD_REEDSOL_ERR_CORRUPT if the shreds are not consistent with having
   come from a Reed-Solomon encoding with the provided number of data
   shreds

   FD_REEDSOL_ERR_PARTIAL if there's not enough un-erased data to
   recover data_shred_cnt data shreds.  There must be at least one
   un-erased shred (data or parity) for each data shred in the
   operation.

   It's worth pointing out that the recovery process differs from
   typical network coding theory by making no effort to correct data
   corruption.  The shred signature verification process should detect
   any data corruption, and any shred that fails signature verification
   can be treated as an erasure.  This prevents the network from forking
   if the leader (maliciously) creates data shreds from one version of
   the block and parity shreds from another version of the block.

   Assumes rs is initialized as a recoverer, rs will not be initialized
   on return. */

int
fd_reedsol_recover_fini( fd_reedsol_t * rs );

/* Misc APIs */

/* fd_reedsol_strerror converts a FD_REEDSOL_SUCCESS / FD_REEDSOL_ERR_*
   code into a human readable cstr.  The lifetime of the returned
   pointer is infinite.  The returned pointer is always to a non-NULL
   cstr. */

FD_FN_CONST char const *
fd_reedsol_strerror( int err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_h */
