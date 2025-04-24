#ifndef HEADER_fd_src_groove_fd_groove_h
#define HEADER_fd_src_groove_fd_groove_h

/* Note: will still function without FD_HAS_ATOMIC but will not be safe
   to use concurrently. */

#include "../flamenco/types/fd_types.h"
#include "../funk/fd_funk.h"
#include "fd_groove_base.h"   /* includes ../util/fd_util.h */
#include "fd_groove_meta.h"   /* includes fd_groove_base.h */
//#include "fd_groove_volume.h" /* includes fd_groove_base.h */
#include "fd_groove_data.h"     /* includes fd_groove_meta.h, fd_groove_volume.h */
#include "../flamenco/fd_flamenco_base.h"

/* FD_GROOVE_MAGIC defines a magic number for verifying the memory of Groove is not corrupted. */
#define FD_GROOVE_MAGIC (0x17eda2ceUL) /* firedancer groove version 0 */

struct fd_groove {
  ulong magic;

  /* Local join handles for the metadata store and data store */
  fd_groove_meta_map_t meta_map[1];
  fd_groove_data_t     data[1];
};
typedef struct fd_groove fd_groove_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_groove_align( void ) {
  return fd_ulong_max(
    alignof( fd_groove_t ),
    fd_ulong_max( alignof( fd_groove_meta_t ),
    fd_ulong_max( fd_groove_meta_map_align(), fd_groove_data_align() ) ) );
}

FD_FN_CONST static inline ulong
fd_groove_footprint( ulong meta_map_ele_max ) {
    return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_groove_t),       sizeof(fd_groove_t) ),
      alignof(fd_groove_meta_t),  fd_ulong_sat_mul( meta_map_ele_max, sizeof(fd_groove_meta_t) ) ),
      fd_groove_meta_map_align(), fd_groove_meta_map_footprint(
        meta_map_ele_max,
        fd_groove_meta_map_lock_cnt_est( meta_map_ele_max ),
        fd_groove_meta_map_probe_max_est( meta_map_ele_max ) ) ),
      fd_groove_data_align(), fd_groove_data_footprint() ),
    fd_groove_align() );
}

void *
fd_groove_new( void * shmem,
               ulong meta_map_ele_max,
               ulong meta_map_seed );

fd_groove_t *
fd_groove_join( void * shmem,
                ulong  meta_map_ele_max,
                void * volume0,
                ulong  volume_max,
                ulong  cgroup_hint );

void *
fd_groove_leave( fd_groove_t * groove );

void
groove_key_init( fd_pubkey_t const * pubkey,
                 fd_groove_key_t *   key );

void
fd_groove_upsert_account( fd_groove_t *       groove,
                          fd_pubkey_t const * pubkey,
                          uchar *             data,
                          ulong               data_len );

uchar *
fd_groove_upsert_account_from_snapshot( fd_groove_t *                   groove,
                                        fd_pubkey_t const *             pubkey,
                                        ulong                           slot,
                                        fd_solana_account_hdr_t const * hdr,
                                        int *                           out_err );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_groove_fd_groove_h */
