#ifndef HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h
#define HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h

#include "fd_leaders.h"

/* fd_multi_epoch_leaders is a wrapper around multiple fd_epoch_leaders
   objects.  It simplifies tracking leader schedules for multiple epochs,
   and querying to find the leader for a given slot.  While maintaining
   the leader schedule for the current epoch i, you can also prepare the
   schedule for epoch i+1 and send to the next epoch's leader as you
   approach the boundary. */

typedef uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)))
    _lsched_t[FD_EPOCH_LEADERS_FOOTPRINT(MAX_STAKED_LEADERS, MAX_SLOTS_PER_EPOCH)];

#define MULTI_EPOCH_LEADERS_EPOCH_CNT (2UL)
FD_STATIC_ASSERT(MULTI_EPOCH_LEADERS_EPOCH_CNT == 2UL, "This implementation depends on epoch_cnt==2");

struct fd_multi_epoch_leaders_priv {
  fd_epoch_leaders_t * lsched       [ MULTI_EPOCH_LEADERS_EPOCH_CNT ];
  fd_vote_stake_weight_t vote_stake_weight [ MAX_STAKED_LEADERS ];

  /* has that epoch's mem experienced a stake_msg_fini? */
  int                  init_done    [ MULTI_EPOCH_LEADERS_EPOCH_CNT ];
  struct {
    ulong epoch;
    ulong start_slot;
    ulong slot_cnt;
    ulong staked_cnt;
    ulong excluded_stake;
  } scratch[1];

  _lsched_t _lsched[MULTI_EPOCH_LEADERS_EPOCH_CNT];
};
typedef struct fd_multi_epoch_leaders_priv fd_multi_epoch_leaders_priv_t;

typedef fd_multi_epoch_leaders_priv_t fd_multi_epoch_leaders_t;


FD_PROTOTYPES_BEGIN

/* ********    OBJECT LIFECYCLE FUNCTIONS    ******** */

/* fd_epoch_leaders_{align,footprint} describe the required footprint
   and alignment of the leader schedule object. They have compile friendly
   versions for static allocation of underlying mem */

#define FD_MULTI_EPOCH_LEADERS_ALIGN \
  FD_ULONG_MAX( FD_EPOCH_LEADERS_ALIGN, alignof(fd_multi_epoch_leaders_t) )

#define FD_MULTI_EPOCH_LEADERS_FOOTPRINT \
  sizeof(fd_multi_epoch_leaders_t)

FD_FN_CONST static inline ulong
fd_multi_epoch_leaders_align( void ) {
  return FD_MULTI_EPOCH_LEADERS_ALIGN;
}

FD_FN_CONST static inline ulong
fd_multi_epoch_leaders_footprint( void ) {
  return FD_MULTI_EPOCH_LEADERS_FOOTPRINT;
}

/* fd_multi_epoch_leaders_new formats a memory region for use as a multi-epoch
   leader schedule object.  shmem points to the first byte of a memory
   region with matching alignment and footprint requirements. Returns NULL
   if shmem is NULL or misaligned. Else returns pointer to formatted memory.
   Does not join. */

void *
fd_multi_epoch_leaders_new( void  * shmem );

/* fd_multi_epoch_leaders_join joins the caller to the leader schedule object.
   fd_multi_epoch_leaders_leave undoes an existing join. */

fd_multi_epoch_leaders_t *
fd_multi_epoch_leaders_join( void * shleaders );

void *
fd_multi_epoch_leaders_leave( fd_multi_epoch_leaders_t * mleaders );

/* fd_multi_epoch_leaders_delete unformats a memory region and returns owner-
   ship back to the caller. */

void *
fd_multi_epoch_leaders_delete( void * shleaders );

/* ********    LEADER INFO GETTER FUNCTIONS    ******** */

/* fd_multi_epoch_leaders_get_stake_{weights,cnt} returns a pointer to
   the stake weights and count for the latest epoch. Returns null if never
   initialized. The pointer lifetime is until the next leave on mleaders.
   However, cnt is the valid length for stake_weights only until the next
   call to stake_msg_init. */
FD_FN_PURE static inline fd_vote_stake_weight_t const *
fd_multi_epoch_leaders_get_stake_weights( fd_multi_epoch_leaders_t const * mleaders ) {
   return fd_ptr_if( mleaders->init_done[0] | mleaders->init_done[1], (fd_vote_stake_weight_t const *)mleaders->vote_stake_weight, NULL );
}
FD_FN_PURE static inline ulong
fd_multi_epoch_leaders_get_stake_cnt( fd_multi_epoch_leaders_t const * mleaders ) {
   return mleaders->scratch->staked_cnt;
}

/* fd_multi_epoch_leaders_get_leader_for_slot returns a pointer to the selected
   public key given a slot.  Returns NULL if slot is not in epochs tracked
   by multi-epoch leader object. If the leader for slot is part of the
   excluded_stake for that epoch, instead of returning the correct value
   (which is not known), returns a pointer to a pubkey with value
   FD_INDETERMINATE_LEADER. */

FD_FN_PURE fd_pubkey_t const *
fd_multi_epoch_leaders_get_leader_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                            ulong                            slot );

/* fd_multi_epoch_leaders_get_lsched_for_{epoch,slot} return the leader
   schedule for epoch or epoch containing slot, respectively.  Returns
   NULL if not tracked by mleaders. */

FD_FN_PURE fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_epoch( fd_multi_epoch_leaders_t const * mleaders,
                                             ulong                            epoch );
FD_FN_PURE fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                             ulong                           slot   );

/* fd_multi_epoch_leaders_get_sorted_lscheds returns up to two lscheds,
   sorted in increasing epoch order. If we only have data for one epoch,
   the first element will be the corresponding lsched. If no lsched data,
   both will be null. Lifetime of returned pointers is until next call to
   fd_multi_epoch_leaders_stake_msg_fini. */
typedef struct {
  fd_epoch_leaders_t const * lscheds[2];
} fd_multi_epoch_leaders_lsched_sorted_t;

FD_FN_PURE fd_multi_epoch_leaders_lsched_sorted_t
fd_multi_epoch_leaders_get_sorted_lscheds( fd_multi_epoch_leaders_t const * mleaders );


/* fd_multi_epoch_leaders_get_next_slot returns the first slot on or after
   start_slot that 'leader' will be leader. If it can't find one, returns ULONG_MAX.

   Failures cases include:
      - mleaders does not track the epoch containing start_slot
        - It was either never initialized with that epoch information, or
        - It was overwritten by another epoch with the same parity
      - leader_q does not have a leader slot in the epochs tracked
      - leader_q was part of the excluded_stake for that epoch, and the lsched
        returns FD_INDETERMINATE_LEADER as the leader for leader_q's slots.
*/

FD_FN_PURE ulong
fd_multi_epoch_leaders_get_next_slot( fd_multi_epoch_leaders_t const * mleaders,
                                      ulong                            start_slot,
                                      fd_pubkey_t const *              leader_q );

/* ********    STAKE INFO UPDATE METHODS    ******** */

/* fd_stake_ci_stake_msg_{init, fini} are used to handle messages
   containing stake weight updates from the Rust side of the splice,.
   Since these messages arrive on a dcache and can get overrun, both
   expose a init/fini model. Calling init multiple times without calling
   fini will not leak any resources.

   msg should be a pointer to the first byte of the dcache entry
   containing the stakes update.  msg will be accessed
   msg->weights[i] for i in [0, msg->staked_cnt).  msg->weights
   must contain at least one staked pubkey, and the pubkeys must be
   sorted in the usual way (by stake descending, ties broken by pubkey
   ascending). multi_epoch_leaders will only use the staked node.

   init does not maintain a read interest in msg after returning. */

void
fd_multi_epoch_leaders_stake_msg_init( fd_multi_epoch_leaders_t    * mleaders,
                                       fd_stake_weight_msg_t const * msg );

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * mleaders );


/* fd_multi_epoch_leaders_epoch_msg_{init, fini} are the Firedancer
   equivalents to the Frankendancer fd_multi_epoch_leaders_stake_msg_{init, fini}.
   They take a different input message structure (fd_epoch_info_msg_t
   vs fd_stake_weight_msg_t). */

void
fd_multi_epoch_leaders_epoch_msg_init( fd_multi_epoch_leaders_t   * mleaders,
                                       fd_epoch_info_msg_t const  * msg );

void
fd_multi_epoch_leaders_epoch_msg_fini( fd_multi_epoch_leaders_t * mleaders );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h */
