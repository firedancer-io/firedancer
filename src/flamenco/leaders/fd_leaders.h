#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_h

/* fd_leaders provides APIs for the Solana leader schedule.
   Logic is compatible with Solana mainnet as of 2023-Jul.

   Every slot is assigned a leader (identified by a "node identity"
   public key).  The sequence of leaders for all slots in an epoch is
   called the "leader schedule".  The main responsibility of the leader
   is to produce a block for the slot.

   The leader schedule is divided into sched_cnt rotations.  Each
   rotation spans one or more slots, such that

     slots_per_epoch = sched_cnt * slots_per_rotation

   The leader can only change between rotations.  An example leader
   schedule looks as follows (where A, B, C are node identities and each
   column is a slot, with 4 slots per rotation)

     A  A  A  A  B  B  B  B  B  B  B  B  C  C  C  C  A  A  A  A
     ^           ^           ^           ^           ^
     rotation    rotation    rotation    rotation    rotation

   The mainnet epoch duration is quite long (currently 432000 slots, for
   more information see fd_sysvar_epoch_schedule.h).  To save space, we
   dedup pubkeys into a lookup table and only store an index for each
   rotation. */

#include "fd_leaders_base.h"
#include "../../ballet/wsample/fd_wsample.h"

#define FD_ULONG_MAX(  a, b ) (__builtin_choose_expr( __builtin_constant_p( a ) & __builtin_constant_p( b ),        \
                                                      ((ulong )(a))>=((ulong )(b)) ? ((ulong )(a)) : ((ulong )(b)), \
                                                      fd_ulong_max( (a), (b) ) ))

/* FD_EPOCH_LEADERS_{ALIGN,FOOTPRINT} are compile-time-friendly versions
   of the fd_epoch_leaders_{align,footprint} functions. */

#define FD_EPOCH_LEADERS_ALIGN (64UL)
#define FD_EPOCH_LEADERS_FOOTPRINT( pub_cnt, slot_cnt )                                              \
  ( FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(                                              \
    FD_LAYOUT_INIT,                                                                                  \
      alignof(fd_epoch_leaders_t), sizeof(fd_epoch_leaders_t)                            ),          \
      alignof(uint),               (                                                                 \
        (slot_cnt+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION*sizeof(uint)          \
        )                                                                                ),          \
      FD_EPOCH_LEADERS_ALIGN                                                             )  +        \
      FD_ULONG_ALIGN_UP( FD_ULONG_MAX( 32UL*((pub_cnt)+1UL),                                         \
                                       FD_WSAMPLE_FOOTPRINT( pub_cnt, 0 ) ), 64UL ) )

#define FD_EPOCH_SLOTS_PER_ROTATION (4UL)

/* fd_epoch_leaders_t contains the leader schedule of a Solana epoch. */

struct fd_epoch_leaders {
  /* This struct contains the schedule for epoch `epoch` which spans
     slots [slot0, slot0+slot_cnt). */
  ulong epoch;
  ulong slot0;
  ulong slot_cnt;

  /* pub is a lookup table for node public keys with length pub_cnt */
  fd_pubkey_t * pub;
  ulong         pub_cnt;

  /* sched contains the leader schedule in the form of indexes into
     the pub array.  For sched_cnt, refer to below. */
  uint *        sched;
  ulong         sched_cnt;
};
typedef struct fd_epoch_leaders fd_epoch_leaders_t;

FD_PROTOTYPES_BEGIN

/* fd_epoch_leaders_{align,footprint} describe the required footprint
   and alignment of the leader schedule object.  pub_cnt is the number
   of unique public keys.  slot_cnt is the number of slots in the
   epoch. */

FD_FN_CONST ulong
fd_epoch_leaders_align( void );

FD_FN_CONST ulong
fd_epoch_leaders_footprint( ulong pub_cnt,
                            ulong slot_cnt );

/* fd_epoch_leaders_new formats a memory region for use as a leader
   schedule object.  shmem points to the first byte of a memory region
   with matching alignment and footprint requirements.  The leader
   schedule object will contain the leader schedule for epoch `epoch`
   which spans slots [slot0, slot0+slot_cnt).  `slot0` must be the first
   slot in the epoch, but slot_cnt can be less than the length of the
   epoch to derive only the first portion of the leader schedule.
   pub_cnt is the number of unique public keys in this schedule.
   `stakes` points to the first entry of pub_cnt entries of stake
   weights sorted by tuple (stake, pubkey) in descending order.
   `vote_keyed_lsched` is either 0 or 1, when 1 the leader schedule
   is computed by vote accounts (see SIMD-0180).

   If `stakes` does not include all staked nodes, e.g. in the case of an
   attack that swamps the network with fake validators, `stakes` should
   contain the first `pub_cnt` of them in the normal sort order, and the
   sum of the remaining stake must be provided in excluded_stake,
   measured in lamports.

   Does NOT retain a read interest in stakes upon return.
   The caller is not joined to the object on return. */
void *
fd_epoch_leaders_new( void  *                  shmem,
                      ulong                    epoch,
                      ulong                    slot0,
                      ulong                    slot_cnt,
                      ulong                    pub_cnt,
                      fd_vote_stake_weight_t * stakes, /* indexed [0, pub_cnt) */
                      ulong                    excluded_stake,
                      ulong                    vote_keyed_lsched );

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

/* FD_INDETERMINATE_LEADER has base58 encoding
   1111111111indeterminateLeader9QSxFYNqsXA.  In hex, this pubkey ends
   with 0x0badf00d0badf00d. */
#define FD_INDETERMINATE_LEADER 0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x99U,0xf6U,0x0fU,0x96U,0x2cU,0xddU,\
                                0x38U,0x21U,0xf3U,0x0cU,0x16U,0x1dU,0xe3U,0x0aU,0x0bU,0xadU,0xf0U,0x0dU,0x0bU,0xadU,0xf0U,0x0dU

/* fd_epoch_leaders_get returns a pointer to the selected public key
   given a slot.  Returns NULL if slot is not in [slot0, slot0+slot_cnt)
   given the values supplied in fd_epoch_leaders_new.

   If a non-zero value was provided for excluded_stake in
   fd_epoch_leaders_new and a validator included in the excluded_stake
   is the leader for the requested slot, instead of returning the
   correct value (which is not known), fd_epoch_leaders_get will return
   a pointer to a pubkey with value FD_INDETERMINATE_LEADER. */

FD_FN_PURE static inline fd_pubkey_t const *
fd_epoch_leaders_get( fd_epoch_leaders_t const * leaders,
                      ulong                      slot ) {
  ulong slot_delta = slot - leaders->slot0;
  if( FD_UNLIKELY( slot      < leaders->slot0    ) ) return NULL;
  if( FD_UNLIKELY( slot_delta>=leaders->slot_cnt ) ) return NULL;
  return (fd_pubkey_t const *)( leaders->pub + leaders->sched[ slot_delta/FD_EPOCH_SLOTS_PER_ROTATION ] );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_h */
