#ifndef HEADER_fd_src_ballet_ledger_fd_leaders_h
#define HEADER_fd_src_ballet_ledger_fd_leaders_h

#include "../fd_ballet.h"
#include "../ed25519/fd_ed25519.h"

//#define FD_EPOCH_SLOT_CNT           (432000UL)
//#define FD_EPOCH_SLOTS_PER_ROTATION (4UL)
//#define FD_EPOCH_ROTATION_CNT       (FD_EPOCH_SLOT_CNT/FD_EPOCH_SLOTS_PER_ROTATION)

/* FD_EPOCH_LEADERS_{ALIGN,FOOTPRINT} are const-friendly versions of the
   fd_epoch_leaders_{align,footprint} functions. */

#define FD_EPOCH_LEADERS_ALIGN (64UL)
#define FD_EPOCH_LEADERS_FOOTPRINT( pub_cnt, sched_cnt )                \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( \
  FD_LAYOUT_INIT,                                                       \
    alignof(fd_epoch_leaders_t), sizeof(fd_epoch_leaders_t)    ),       \
    FD_ED25519_PUB_SZ,           (pub_cnt  )*FD_ED25519_PUB_SZ ),       \
    alignof(uint),               (sched_cnt)*sizeof(uint)      ),       \
    FD_EPOCH_LEADERS_ALIGN                                     )

/* FIXME make position-independent? */

/* fd_stake_weight_t assigns an Ed25519 public key (node identity) a
   stake weight number measured in lamports. */

struct fd_stake_weight {
  fd_ed25519_pub_t pub;
  ulong            stake;
};
typedef struct fd_stake_weight fd_stake_weight_t;

/* fd_epoch_leaders_t contains the block producer (i.e. leader) schedule
   of a Solana epoch. */

struct fd_epoch_leaders {
  /* pub is a lookup table for node public keys with length pub_cnt */
  fd_ed25519_pub_t * pub;
  ulong              pub_cnt;

  /* sched contains the leader schedule in the form of indexes into
     the pub array.  sched_cnt is the number of rotations in the leader
     schedule.  This is not to be confused with the number of slots, as
     each rotation typically spans multiple slots. */
  uint *             sched;
  ulong              sched_cnt;
};
typedef struct fd_epoch_leaders fd_epoch_leaders_t;

FD_PROTOTYPES_BEGIN

/* fd_stake_weight_sort sorts the given array of stake weights with
   length stakes_cnt by tuple (stake, pubkey) in descending order. */

void
fd_stake_weight_sort( fd_stake_weight_t * stakes,
                      ulong               stakes_cnt );

/* fd_epoch_leaders_{align,footprint} describe the required footprint
   and alignment of the leader schedule object. */

FD_FN_CONST ulong
fd_epoch_leaders_align( void );

FD_FN_CONST ulong
fd_epoch_leaders_footprint( ulong pub_cnt,
                            ulong sched_cnt );

/* fd_epoch_leaders_new formats a memory region for use as a leader
   schedule object.  shmem points to the first byte of a memory region
   with matching alignment and footprint requirements.  pub_cnt is the
   number of unique public keys in this schedule.  sched_cnt is the
   number of slots in the schedule (usually the length of an epoch).
   The caller is not joined to the object on return. */

void *
fd_epoch_leaders_new( void * shmem,
                      ulong  pub_cnt,
                      ulong  sched_cnt );

/* fd_epoch_leaders_join joins the caller to the leader schedule object.
   fd_epoch_leaders_leave undoes an existing join. */

fd_epoch_leaders_t *
fd_epoch_leaders_join( void * shleaders );

void *
fd_epoch_leaders_leave( fd_epoch_leaders_t * leaders );

/* fd_epoch_leaders_delete unformats a memory region and returns owner-
   ship back to the caller. */

void *
fd_epoch_leaders_delete( void * shleaders );

/* fd_epoch_leaders_derive derives the leader schedule for a given epoch
   and stake weights.  leaders is a join to an epoch schedule object.
   stakes is an array of stake weights sorted by tuple (stake, pubkey)
   in descending order (as with fd_stake_weight_sort).  The length of
   stakes equals leaders->pub_cnt.  scratch is uninitialized scratch
   space sufficient to fit (leaders->pub_cnt + 1) ulongs.  epoch is used
   to seed the PRNG. */

void
fd_epoch_leaders_derive( fd_epoch_leaders_t *      leaders,
                         fd_stake_weight_t const * stakes,
                         ulong *                   scratch,
                         ulong                     epoch );

/* fd_epoch_leaders_get returns a pointer to the selected public key
   given an index in the schedule.  sched_idx < leaders->sched_cnt */

FD_FN_PURE static inline fd_ed25519_pub_t const *
fd_epoch_leaders_get( fd_epoch_leaders_t const * leaders,
                      ulong                      sched_idx ) {
  return (fd_ed25519_pub_t const *)( leaders->pub + leaders->sched[ sched_idx ] );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ledger_fd_leaders_h */
