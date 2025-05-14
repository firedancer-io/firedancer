#ifndef HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h
#define HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h

#include "fd_leaders.h"

/* fd_multi_epoch_leaders is a wrapper around multiple fd_epoch_leaders
   objects.  It simplifies tracking leader schedules for multiple epochs,
   and querying to find the leader for a given slot.  While maintaining
   the leader schedule for the current epoch i, you can also prepare the
   schedule for epoch i+1 and send to the next epoch's leader as you
   approach the boundary. */

#define MAX_STAKED_LEADERS          40200UL
#define MAX_SLOTS_PER_EPOCH         432000UL

#define MULTI_EPOCH_LEADERS_EPOCH_CNT (2UL)
struct fd_multi_epoch_leaders {
  fd_epoch_leaders_t * lsched       [ MULTI_EPOCH_LEADERS_EPOCH_CNT ];
  fd_stake_weight_t    stake_weight [ MAX_STAKED_LEADERS ];

  struct {
    ulong epoch;
    ulong start_slot;
    ulong slot_cnt;
    ulong staked_cnt;
    ulong excluded_stake;
  } scratch[1];

  uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN)))
    _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_STAKED_LEADERS, MAX_SLOTS_PER_EPOCH) ]
    [MULTI_EPOCH_LEADERS_EPOCH_CNT];

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
/* ///////   LEADER INFO SET/GET FUNCTIONS    /////// */
/* ///////////////////////////////////////////////////*/

/* fd_multi_epoch_leaders_get_slot_leader returns a pointer to the selected
   public key given a slot.  Returns NULL if slot is not in epochs tracked
   by multi-epoch leader object. If the leader for slot is part of the
   excluded_stake for that epoch, instead of returning the correct value
   (which is not known), returns a pointer to a pubkey with value
   FD_INDETERMINATE_LEADER. */

FD_FN_PURE static inline fd_pubkey_t const *
fd_multi_epoch_leaders_get_slot_leader( fd_multi_epoch_leaders_t const * leaders,
                                        ulong                            slot ) {
  fd_pubkey_t const * even_leader_option = fd_epoch_leaders_get( leaders->lsched[ 0 ], slot );
  fd_pubkey_t const * odd_leader_option  = fd_epoch_leaders_get( leaders->lsched[ 1 ], slot );
  return fd_ptr_if( !even_leader_option, odd_leader_option, even_leader_option );
}

/* fd_multi_epoch_leaders_get_next_slot returns the first slot (on or after
   start_slot) that 'leader' will be leader. It only checks the epoch containing
   start_slot. If it can't find one, returns ULONG_MAX. */
   /* AMANTODO - should we check future epochs as well? */

ulong
fd_multi_epoch_leaders_get_next_slot( fd_multi_epoch_leaders_t const * leaders,
                                      ulong                          start_slot,
                                      fd_pubkey_t const *            leader_q );

void
fd_multi_epoch_leaders_stake_msg_init( fd_multi_epoch_leaders_t * leaders,
                                       uchar const *              new_message );

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * leaders );

/* fd_multi_epoch_leaders_set_epoch_leaders populates multi-epoch leader
   object with the leader schedule for epoch `epoch` which spans slots
   [slot0, slot0+slot_cnt). `slot0` must be the first slot in the epoch,
   but slot_cnt can be less than the length of the epoch to derive only the
   first portion of the leader schedule.  pub_cnt is the number of unique
   public keys in this schedule.  `stakes` points to the first entry of
   pub_cnt entries of stake weights sorted by tuple (stake, pubkey) in
   descending order.

   If `stakes` does not include all staked nodes, e.g. in the case of an
   attack that swamps the network with fake validators, `stakes` should
   contain the first `pub_cnt` of them in the normal sort order, and the
   sum of the remaining stake must be provided in excluded_stake,
   measured in lamports.

   Does NOT retain a read interest in stakes upon return.

   CAUTION: Calling with epoch=i+FD_MULTI_EPOCH_LEADERS_N_EPOCHS will
   overwrite leader schedule for epoch i. This is typically intended,
   but can cause unintended consequences of receiving epoch stake info
   wildly out of order. */
void
fd_multi_epoch_leaders_set_epoch_leaders( fd_multi_epoch_leaders_t * leaders,
                                          ulong                      epoch,
                                          ulong                      slot0,
                                          ulong                      slot_cnt,
                                          ulong                      pub_cnt,
                                          fd_stake_weight_t const *  stakes, /* indexed [0, pub_cnt) */
                                          ulong                      excluded_stake );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_leaders_fd_multi_epoch_leaders_h */
