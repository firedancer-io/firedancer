#ifndef HEADER_fd_src_choreo_epoch_fd_epoch_h
#define HEADER_fd_src_choreo_epoch_fd_epoch_h

#include "../fd_choreo_base.h"
#include "../voter/fd_voter.h"

/* FD_EPOCH_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_EPOCH_USE_HANDHOLDING
#define FD_EPOCH_USE_HANDHOLDING 1
#endif

#define FD_EPOCH_MAGIC (0xf17eda2ce7e90c40UL) /* firedancer epoch version 0 */

struct __attribute__((aligned(128UL))) fd_epoch {
  ulong magic;       /* ==FD_EPOCH_MAGIC */
  ulong epoch_gaddr; /* wksp gaddr of this in the backing wksp, non-zero gaddr */
  ulong total_stake; /* total amount of stake in the epoch. */
  ulong first_slot;  /* first slot in the epoch */
  ulong last_slot;   /* last slot in the epoch */

  /* voters_gaddr is the global address of a fd_map_dynamic that
     contains all voters in the current epoch keyed by pubkey (vote
     account address). */

  ulong voters_gaddr;
};
typedef struct fd_epoch fd_epoch_t;

#define MAP_NAME               fd_epoch_voters
#define MAP_T                  fd_voter_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(key)      ((key).ui[3])
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_epoch_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as epoch.  align is
   double cache line to mitigate false sharing. */

FD_FN_CONST static inline ulong
fd_epoch_align( void ) {
  return alignof(fd_epoch_t);
}

FD_FN_CONST static inline ulong
fd_epoch_footprint( ulong voter_max ) {
  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( voter_max ) ) + 2; /* fill ratio <= 0.25 */
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_epoch_t),     sizeof(fd_epoch_t) ),
      fd_epoch_voters_align(), fd_epoch_voters_footprint( lg_slot_cnt ) ),
    fd_epoch_align() );
}

/* fd_epoch_new formats an unused memory region for use as an epoch.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_epoch_new( void * mem, ulong voter_max );

/* fd_epoch_join joins the caller to the epoch.  epoch points to the
   first byte of the memory region backing the epoch in the caller's
   address space.

   Returns a pointer in the local address space to epoch on success. */

fd_epoch_t *
fd_epoch_join( void * epoch );

/* fd_epoch_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include epoch is NULL. */

void *
fd_epoch_leave( fd_epoch_t const * epoch );

/* fd_epoch_delete unformats a memory region used as an epoch.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. epoch is obviously not an epoch ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_epoch_delete( void * epoch );

/* fd_epoch_init initializes a fd_choreo epoch using `epoch_bank`.
   Assumes epoch is a valid local join and epoch has not already been
   initialized.  This should only be called once at the beginning of an
   epoch. */

void
fd_epoch_init( fd_epoch_t *                      epoch,
               ulong                             eah_start_slot,
               ulong                             eah_stop_slot,
               fd_vote_accounts_global_t const * vote_accounts );

/* fd_epoch_fini finishes an epoch.  Assumes epoch is a valid local join
   and epoch has already been initialized.  This should only be called
   once at the end of an epoch. */

void
fd_epoch_fini( fd_epoch_t * epoch );

/* fd_epoch_wksp returns the local join to the wksp backing the epoch.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes epoch is a current local
   join. */

FD_FN_PURE static inline fd_wksp_t *
fd_epoch_wksp( fd_epoch_t const * epoch ) {
  return (fd_wksp_t *)( ( (ulong)epoch ) - epoch->epoch_gaddr );
}

FD_FN_PURE static inline fd_voter_t *
fd_epoch_voters( fd_epoch_t * epoch ) {
  return fd_wksp_laddr_fast( fd_epoch_wksp( epoch ), epoch->voters_gaddr );
}

FD_FN_PURE static inline fd_voter_t const *
fd_epoch_voters_const( fd_epoch_t const * epoch ) {
  return fd_wksp_laddr_fast( fd_epoch_wksp( epoch ), epoch->voters_gaddr );
}

#endif /* HEADER_fd_src_choreo_epoch_fd_epoch_h */
