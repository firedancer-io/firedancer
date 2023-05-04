#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h
#include "../../util/fd_util_base.h"

/* Contains function declarations for the interal encoding and recovery
   functions. */

/* FALLTHRU: Tells the compiler that falling through to the next case
   of the switch statement is intentional and not a bug.  When brutality
   is turned on, this must be used.  Clang an GCC differ on what
   annotations they accept, but this works for both. */
#define FALLTHRU __attribute__((fallthrough));

/* fd_reedsol_encode_{n} requires that data_shred_cnt <= n */
void fd_reedsol_encode_16(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_32(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_64(  ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
void fd_reedsol_encode_128( ulong                 shred_sz,
                            uchar const * const * data_shred,
                            ulong                 data_shred_cnt,
                            uchar       * const * parity_shred,
                            ulong                 parity_shred_cnt );
#if FD_HAS_GFNI
void fd_reedsol_encode_32_32( ulong                 shred_sz,
                              uchar const * const * data_shred,
                              uchar       * const * parity_shred,
                              uchar       *         _scratch );
#endif

/* fd_reedsol_recover_{first, var}_{n}: Verifies the consistency
   of the Reed-Solomon encoded data, and recovers any missing data.
   At least data_shred_cnt of the first n shreds must be un-erased,
   which implies data_shred_cnt <= n.

   The _first variant imposes the additional constraint that the first
   data_shred_cnt shreds must be un-erased, is the case when no packets
   have been lost.  This version is faster.

   Unlike the encode operations, the math doesn't care much whether a
   shred is a data shred or parity shred for recover operations, hence
   the function only has one shred array.  The parity shreds come
   immediately after the data shreds.

   For each value of i in [0, data_shred_cnt+parity_shred_cnt), erased[
   i ] must be 0 (if shred[ i ] contains valid data) or 1 if shred[ i ]
   is an erasure (i.e. wasn't received, was corrupted, etc.).  If
   erased[ i ]==1, the contents of shred[ i ] are ignored on entry, and
   upon return, shred[ i ][ j ] will be overwritten with the correct
   data for j in [0, shred_sz).

   Note that since data_shred_cnt+parity_shred_cnt<=134, shred[ i ] and
   erased[ i ] for i>=134 are completely ignored.

   Returns one of:
   FD_REEDSOL_OK if okay
   FD_REEDSOL_ERR_INCONSISTENT if the shreds are not consistent with
     having come from a Reed-Solomon encoding of data_shred_cnt data
     shreds
   FD_REEDSOL_ERR_INSUFFICIENT if there's not enough un-erased data to
     recover data_shred_cnt data shreds
   */

int fd_reedsol_recover_var_16(  ulong           shred_sz,
                                uchar * const * shred,
                                ulong           data_shred_cnt,
                                ulong           parity_shred_cnt,
                                uchar const *   erased );
int fd_reedsol_recover_var_32(  ulong           shred_sz,
                                uchar * const * shred,
                                ulong           data_shred_cnt,
                                ulong           parity_shred_cnt,
                                uchar const *   erased );
int fd_reedsol_recover_var_64(  ulong           shred_sz,
                                uchar * const * shred,
                                ulong           data_shred_cnt,
                                ulong           parity_shred_cnt,
                                uchar const *   erased );
int fd_reedsol_recover_var_128( ulong           shred_sz,
                                uchar * const * shred,
                                ulong           data_shred_cnt,
                                ulong           parity_shred_cnt,
                                uchar const *   erased );
int fd_reedsol_recover_var_256( ulong           shred_sz,
                                uchar * const * shred,
                                ulong           data_shred_cnt,
                                ulong           parity_shred_cnt,
                                uchar const *   erased );

#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_internal_h */
