#ifndef HEADER_fd_src_app_fdctl_run_tiles_fd_stake_ci_h
#define HEADER_fd_src_app_fdctl_run_tiles_fd_stake_ci_h

/* fd_stake_ci handles the thorny problem of keeping track of leader
   schedules and shred destinations, which are epoch specific.  Around
   epoch boundaries, we may need to query information from the epoch on
   either side of the boundary.

   When you make a stake delegation change during epoch N, it becomes
   active at the start of the first slot of epoch N+1, but it doesn't
   affect the leader schedule or the shred destinations until epoch N+2.
   These methods take care all that complexity, so the caller does not
   need to do any adjustment. */

#include "fd_shred_dest.h"
#include "../../flamenco/leaders/fd_leaders.h"

#define MAX_SHRED_DESTS              40200UL
#define MAX_SLOTS_PER_EPOCH         432000UL
/* MAX_SHRED_DEST_FOOTPRINT==fd_shred_dest_footprint( MAX_SHRED_DESTS ),
   runtime asserted in the tests.  The size of fd_shred_dest_t, varies
   based on FD_SHA256_BATCH_FOOTPRINT, which depends on the compiler
   settings. */
#define MAX_SHRED_DEST_FOOTPRINT (10067072UL + sizeof(fd_shred_dest_t))

#define FD_STAKE_CI_STAKE_MSG_SZ (32UL + MAX_SHRED_DESTS * 40UL)

struct fd_per_epoch_info_private {
  /* Epoch, and [start_slot, start_slot+slot_cnt) refer to the time
     period for which lsched and sdest are valid. I.e. if you're
     interested in the leader or computing a shred destination for a
     slot s, this struct has the right data when s is in [start_slot,
     start_slot+slot_cnt). */
  ulong epoch;
  ulong start_slot;
  ulong slot_cnt;

  /* Invariant: These are always joined and use the memory below for
     their footprint. */
  fd_epoch_leaders_t * lsched;
  fd_shred_dest_t    * sdest;

  uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_SHRED_DESTS, MAX_SLOTS_PER_EPOCH) ];
  uchar __attribute__((aligned(FD_SHRED_DEST_ALIGN   ))) _sdest [ MAX_SHRED_DEST_FOOTPRINT ];
};
typedef struct fd_per_epoch_info_private fd_per_epoch_info_t;

struct fd_stake_ci {
  fd_pubkey_t identity_key[ 1 ];

  /* scratch and stake_weight are only relevant between stake_msg_init
     and stake_msg_fini.  shred_dest is only relevant between
     dest_add_init and dest_add_fini. */
  struct {
    ulong epoch;
    ulong start_slot;
    ulong slot_cnt;
    ulong staked_cnt;
  } scratch[1];

  fd_stake_weight_t        stake_weight   [ MAX_SHRED_DESTS ];
  fd_shred_dest_weighted_t shred_dest     [ MAX_SHRED_DESTS ];

  fd_shred_dest_weighted_t shred_dest_temp[ MAX_SHRED_DESTS ];

  /* The information to be used for epoch i can be found at
     epoch_info[ i%2 ] if it is known. */
  fd_per_epoch_info_t epoch_info[ 2 ];
};
typedef struct fd_stake_ci fd_stake_ci_t;

/* fd_stake_ci_{footprint, align} return the footprint and alignment
   required of a region of memory to be used as an fd_stake_ci_t.
   fd_stake_ci_t is statically sized, so it can just be declared
   outright if needed, but it's pretty large (~30 MB!), so you probably
   don't want it on the stack. */

static inline ulong fd_stake_ci_footprint( void ) { return sizeof (fd_stake_ci_t); }
static inline ulong fd_stake_ci_align    ( void ) { return alignof(fd_stake_ci_t); }

/* fd_stake_ci_new formats a piece of memory as a valid stake contact
   information store.  `identity_key` is a pointer to the public key of
   the identity keypair of the local validator.  This is used by
   fd_shred_dest to know where in the Turbine tree it belongs.
   Does NOT retain a read interest in identity_key after the function
   returns. */
void          * fd_stake_ci_new ( void * mem, fd_pubkey_t const * identity_key );
fd_stake_ci_t * fd_stake_ci_join( void * mem );

void * fd_stake_ci_leave ( fd_stake_ci_t * info );
void * fd_stake_ci_delete( void          * mem  );

/* fd_stake_ci_stake_msg_{init, fini} are used to handle messages
   containing stake weight updates from the Rust side of the splice, and
   fd_stake_ci_dest_add_{init, fini} are used to handle messages
   containing contact info (potential shred destinations) updates from
   the Rust side of the splice.

   These are very specific to the current splices, but rather than parse
   the message in the pack and shred tiles, we parse it here.  Since
   these messages arrive on a dcache and can get overrun, both expose a
   init/fini model.

   Upon returning from a call to fd_stake_ci_{stake_msg, dest_add}_init,
   the stake contact info object will be in a stake-msg-pending or
   dest-add-pending mode, respectively, regardless of what mode it was
   in before.  In either of these modes, calls to the query functions
   (get_*_for slot) are okay and will return the same values they
   returned prior to the _init call.

   In order to call fd_stake_ci_{stake_msg, dest_add}_fini, the stake
   contact info must be in stake-msg-pending / dest-add-pending mode,
   respectively.  This means, for example, you cannot call
   fd_stake_ci_stake_msg_init followed by fd_stake_ci_dest_add_fini
   without an intervening call to fd_stake_ci_dest_add_init.  There's no
   need to cancel an operation that begun but didn't finish.  Calling
   init multiple times without calling fini will not leak any resources.

   new_message should be a pointer to the first byte of the dcache entry
   containing the stakes update.  new_message will be accessed
   new_message[i] for i in [0, FD_STAKE_CI_STAKE_MSG_SZ).  new_message
   must contain at least one staked pubkey, and the pubkeys must be
   sorted in the usual way (by stake descending, ties broken by pubkey
   ascending).

   fd_stake_ci_dest_add_init behaves slightly differently and returns a
   pointer to the first element of an array of size MAX_SHRED_DESTS-1 to
   be populated.  This allows the caller to add augment the information
   in the message from Rust with additional information (i.e. mac
   addresses).  The `cnt` argument to _dest_add_fini specifies the
   number of elements of the array returned by _init that were
   populated. 0<=cnt<MAX_SHRED_DESTS.  _fini will only read the first
   `cnt` elements of the array.  The stake_lamports field of the input
   is ignored.  The identity pubkey provided at initialization must not
   be one of the cnt values in the array.  The caller should not retain
   a read or write interest in the pointer returned by _init after fini
   has been called, or after the caller has determined that fini will
   not be called for that update, e.g. because the update was overrun.
   Calls to _fini may clobber the array.

   The list used for leader schedules is always just the staked nodes.
   The list used for shred destinations is the staked nodes along with
   any unstaked nodes for which we have contact info.  If a stake
   message doesn't have contact info for a staked node, the previous
   contact info will be preserved.  If a stake message doesn't have
   contact info for an unstaked node, on the other hand, that node will
   be deleted from the list. */
void                       fd_stake_ci_stake_msg_init( fd_stake_ci_t * info, uchar const * new_message );
void                       fd_stake_ci_stake_msg_fini( fd_stake_ci_t * info                            );
fd_shred_dest_weighted_t * fd_stake_ci_dest_add_init ( fd_stake_ci_t * info                            );
void                       fd_stake_ci_dest_add_fini ( fd_stake_ci_t * info, ulong cnt                 );


/* fd_stake_ci_get_{sdest, lsched}_for_slot respectively return a
   pointer to the fd_shred_dest_t and fd_epoch_leaders_t containing
   information about the specified slot, if it is available.  These
   functions are the primary query functions for fd_stake_ci.  They
   return NULL if we don't have information for that slot.

   The fact these take a slot perhaps makes it more clear, but, it's
   worth mentioning again there's nothing like the adjustment performed
   by Solana's get_leader_schedule_epoch going on here.  If you want to
   know the leader in slot X, just pass slot X.  The returned leader
   schedule will not be based on the stake weights active during slot X,
   but rather the stake weights offset in time by an appropriate amount
   so they apply to slot X. */
fd_shred_dest_t *    fd_stake_ci_get_sdest_for_slot ( fd_stake_ci_t const * info, ulong slot );
fd_epoch_leaders_t * fd_stake_ci_get_lsched_for_slot( fd_stake_ci_t const * info, ulong slot );

#endif /* HEADER_fd_src_app_fdctl_run_tiles_fd_stake_ci_h */
