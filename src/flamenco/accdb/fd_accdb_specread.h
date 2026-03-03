#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_specread_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_specread_h

/* fd_accdb_specread.h provides pin-based speculative reads of rooted
   account data from the vinyl cache.

   A specread client is a tile (replay, exec, ...) that has read-only
   access to the vinyl meta map, element pool, and line array, plus the
   data workspace.  It reads cached account data directly from shared
   memory, bypassing the rq/cq round-trip.  On cache miss or contention,
   the client falls back to the normal vinyl ACQUIRE path.

   Pin protocol:

     1.  fd_vinyl_meta_query_try → ele_idx, line_idx
     2.  Validate meta seqlock via fd_vinyl_meta_query_test
     3.  FETCH_AND_ADD(&line[line_idx].ctl, 1) to pin
     4.  Bail if EVICTING, ref < 0, or cross-validation fails
     5.  Resolve obj_gaddr, check rd_active == 0
     6.  Point caller at val data (zero-copy)
     7.  On close: FETCH_AND_SUB(&line[line_idx].ctl, 1) to unpin */

#include "../../vinyl/line/fd_vinyl_line.h" /* includes meta + data */
#include "../../discof/accdb/fd_accdb_line_ctl.h"
#include "../fd_flamenco_base.h" /* fd_account_meta_t */

FD_PROTOTYPES_BEGIN

/* fd_accdb_specread_pin attempts to pin a cached account and return a
   direct pointer to its metadata.

   On success (FD_VINYL_SUCCESS): *out_meta points to the
   fd_account_meta_t in the data cache, *out_line_idx gives the pinned
   line.  The caller MUST call fd_accdb_specread_unpin when done.

   On failure: FD_VINYL_ERR_KEY (key not in meta) or FD_VINYL_ERR_AGAIN
   (transient: eviction in progress, I/O pending, seqlock contention).
   No pin is held; caller should fall back to rq/cq ACQUIRE. */

static inline int
fd_accdb_specread_pin( fd_vinyl_meta_t *              meta,
                       fd_vinyl_line_t *              line,
                       ulong                          line_cnt,
                       fd_wksp_t *                    data_wksp,
                       fd_vinyl_key_t const *         key,
                       fd_account_meta_t const **     out_meta,
                       ulong *                        out_line_idx ) {

  /* 1. Lockfree query of the meta map for key */

  fd_vinyl_meta_query_t query[1];
  int err = fd_vinyl_meta_query_try( meta, key, NULL, query, 0 /* non-blocking */ );
  if( FD_UNLIKELY( err ) ) return err; /* ERR_KEY or ERR_AGAIN */

  fd_vinyl_meta_ele_t const * ele = fd_vinyl_meta_query_ele_const( query );

  /* Read fields of interest while the seqlock is held */

  ulong ctl      = ele->phdr.ctl;
  ulong line_idx = ele->line_idx;
  ulong ele_idx  = (ulong)( ele - (fd_vinyl_meta_ele_t const *)fd_vinyl_meta_shele_const( meta ) );

  /* 2. Validate meta seqlock — detect torn reads */

  if( FD_UNLIKELY( fd_vinyl_meta_query_test( query ) ) ) return FD_VINYL_ERR_AGAIN;

  /* Key not in bstream or being created? */

  if( FD_UNLIKELY( !ctl || ctl==ULONG_MAX ) ) return FD_VINYL_ERR_AGAIN;

  /* 3. Validate line_idx in range (key might not be cached) */

  if( FD_UNLIKELY( line_idx>=line_cnt ) ) return FD_VINYL_ERR_AGAIN;

  /* 4. Pin: atomically increment ref count */

  ulong old_ctl = FD_ATOMIC_FETCH_AND_ADD( &line[ line_idx ].ctl, 1UL );

  /* 5. If EVICTING set or ref was negative (acquired for modify),
     undo the pin immediately */

  if( FD_UNLIKELY( (old_ctl & FD_ACCDB_LINE_CTL_EVICTING) ||
                   fd_accdb_line_ctl_ref( old_ctl ) < 0L ) ) {
    FD_ATOMIC_FETCH_AND_SUB( &line[ line_idx ].ctl, 1UL );
    return FD_VINYL_ERR_AGAIN;
  }

  /* 6. Resolve obj_gaddr */

  ulong obj_gaddr = line[ line_idx ].obj_gaddr;
  if( FD_UNLIKELY( !obj_gaddr ) ) {
    FD_ATOMIC_FETCH_AND_SUB( &line[ line_idx ].ctl, 1UL );
    return FD_VINYL_ERR_AGAIN;
  }

  /* 7. Cross-validate: line still maps to same meta element */

  if( FD_UNLIKELY( line[ line_idx ].ele_idx != ele_idx ) ) {
    FD_ATOMIC_FETCH_AND_SUB( &line[ line_idx ].ctl, 1UL );
    return FD_VINYL_ERR_AGAIN;
  }

  /* 8. Resolve to local address */

  fd_vinyl_data_obj_t * obj = (fd_vinyl_data_obj_t *)
      fd_wksp_laddr_fast( data_wksp, obj_gaddr );

  /* 9. Check I/O not in progress */

  if( FD_UNLIKELY( obj->rd_active ) ) {
    FD_ATOMIC_FETCH_AND_SUB( &line[ line_idx ].ctl, 1UL );
    return FD_VINYL_ERR_AGAIN;
  }

  /* 10. Success — return pointer directly into cache (zero-copy).
     fd_vinyl_data_obj_val returns the start of the val payload,
     which for accdb is fd_account_meta_t. */

  *out_meta     = (fd_account_meta_t const *)fd_vinyl_data_obj_val( obj );
  *out_line_idx = line_idx;
  return FD_VINYL_SUCCESS;
}

/* fd_accdb_specread_unpin releases a pin acquired by
   fd_accdb_specread_pin.  Must be called exactly once per successful
   pin. */

static inline void
fd_accdb_specread_unpin( fd_vinyl_line_t * line,
                         ulong             line_idx ) {
  FD_ATOMIC_FETCH_AND_SUB( &line[ line_idx ].ctl, 1UL );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_specread_h */
