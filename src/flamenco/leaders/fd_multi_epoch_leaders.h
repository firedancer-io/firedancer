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
struct fd_multi_epoch_leaders {
  fd_epoch_leaders_t * lsched       [ MULTI_EPOCH_LEADERS_EPOCH_CNT ];
  fd_stake_weight_t    stake_weight [ MAX_STAKED_LEADERS ];

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
typedef struct fd_multi_epoch_leaders fd_multi_epoch_leaders_t;


FD_PROTOTYPES_BEGIN

/* ///////////////////////////////////////////////////*/
/* ///////     OBJECT LIFECYCLE FUNCTIONS     /////// */
/* ///////////////////////////////////////////////////*/

/* fd_epoch_leaders_{align,footprint} describe the required footprint
   and alignment of the leader schedule object. They have compile friendly
   versions for static allocation of underlying mem */

#define FD_MULTI_EPOCH_LEADERS_ALIGN \
  FD_ULONG_MAX( FD_EPOCH_LEADERS_ALIGN, alignof(fd_multi_epoch_leaders_t) )

#define FD_MULTI_EPOCH_LEADERS_FOOTPRINT \
  sizeof(fd_multi_epoch_leaders_t)

FD_FN_CONST ulong
fd_multi_epoch_leaders_align( void ) {
  return FD_MULTI_EPOCH_LEADERS_ALIGN;
}

FD_FN_CONST ulong
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
fd_multi_epoch_leaders_leave( fd_multi_epoch_leaders_t * leaders );

/* fd_multi_epoch_leaders_delete unformats a memory region and returns owner-
   ship back to the caller. */

void *
fd_multi_epoch_leaders_delete( void * shleaders );

/* ///////////////////////////////////////////////////*/
/* ///////   LEADER INFO GETTER FUNCTIONS     /////// */
/* ///////////////////////////////////////////////////*/

/* fd_multi_epoch_leaders_get_leader_for_slot returns a pointer to the selected
   public key given a slot.  Returns NULL if slot is not in epochs tracked
   by multi-epoch leader object. If the leader for slot is part of the
   excluded_stake for that epoch, instead of returning the correct value
   (which is not known), returns a pointer to a pubkey with value
   FD_INDETERMINATE_LEADER. */

FD_FN_PURE static inline fd_pubkey_t const *
fd_multi_epoch_leaders_get_leader_for_slot( fd_multi_epoch_leaders_t const * leaders,
                                            ulong                            slot ) {
  fd_pubkey_t const * even_leader_option = fd_ptr_if( leaders->init_done[0], fd_epoch_leaders_get( leaders->lsched[ 0 ], slot ), NULL );
  fd_pubkey_t const * odd_leader_option  = fd_ptr_if( leaders->init_done[1], fd_epoch_leaders_get( leaders->lsched[ 1 ], slot ), NULL );
  return fd_ptr_if( !even_leader_option, odd_leader_option, even_leader_option );
}

/* fd_multi_epoch_leaders_get_lsched_for_{epoch,slot} return the leader
   schedule for epoch or epoch containing slot, respectively.  Returns
   NULL if not tracked by mleaders. */

FD_FN_PURE fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_epoch( fd_multi_epoch_leaders_t const * mleaders, ulong epoch );
FD_FN_PURE fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_slot(  fd_multi_epoch_leaders_t const * mleaders, ulong slot  );

/* fd_multi_epoch_leaders_get_next_slot returns the first slot (on or after
   start_slot) that 'leader' will be leader. It only checks the epoch containing
   start_slot. If it can't find one, returns ULONG_MAX. */

FD_FN_PURE ulong
fd_multi_epoch_leaders_get_next_slot( fd_multi_epoch_leaders_t const * leaders,
                                      ulong                            start_slot,
                                      fd_pubkey_t const *              leader_q );

/* ///////////////////////////////////////////////////*/
/* ///////   STAKE INFO UPDATE METHODS        /////// */
/* ///////////////////////////////////////////////////*/

/* fd_stake_ci_stake_msg_{init, fini} are used to handle messages
   containing stake weight updates from the Rust side of the splice,.
   Since these messages arrive on a dcache and can get overrun, both
   expose a init/fini model. Calling init multiple times without calling
   fini will not leak any resources.

   new_message should be a pointer to the first byte of the dcache entry
   containing the stakes update.  new_message will be accessed
   new_message[i] for i in [0, FD_STAKE_CI_STAKE_MSG_SZ).  new_message
   must contain at least one staked pubkey, and the pubkeys must be
   sorted in the usual way (by stake descending, ties broken by pubkey
   ascending). multi_epoch_leaders will only use the staked node.

   init does not maintain a read interest in new_message after returning. */

void
fd_multi_epoch_leaders_stake_msg_init( fd_multi_epoch_leaders_t * leaders,
                                       uchar const *              new_message );

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * leaders );


/* ///////////////////////////////////////////////////*/
/* ///////     MLEADER METADATA GETTERS       /////// */
/* ///////////////////////////////////////////////////*/

/* fd_multi_epoch_leaders_get_start_{epoch,slot} returns the earliest
   epoch/slot that the leader schedule covers. Returns ULONG_MAX
   if stake_msg_fini has never been called */

FD_FN_PURE static inline ulong
fd_multi_epoch_leaders_get_start_epoch( fd_multi_epoch_leaders_t const * mleaders ) {
  ulong even_start_epoch = fd_ulong_if( mleaders->init_done[0], mleaders->lsched[0]->epoch, ULONG_MAX );
  ulong odd_start_epoch  = fd_ulong_if( mleaders->init_done[1], mleaders->lsched[1]->epoch, ULONG_MAX );
  return fd_ulong_min( even_start_epoch, odd_start_epoch );
}

FD_FN_PURE static inline ulong
fd_multi_epoch_leaders_get_start_slot( fd_multi_epoch_leaders_t const * mleaders ) {
  ulong even_start_slot = fd_ulong_if( mleaders->init_done[0], mleaders->lsched[0]->slot0, ULONG_MAX );
  ulong odd_start_slot  = fd_ulong_if( mleaders->init_done[1], mleaders->lsched[1]->slot0, ULONG_MAX );
  return fd_ulong_min( even_start_slot, odd_start_slot );
}


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h */
