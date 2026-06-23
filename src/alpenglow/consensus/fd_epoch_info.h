#ifndef HEADER_fd_src_alpenglow_consensus_fd_epoch_info_h
#define HEADER_fd_src_alpenglow_consensus_fd_epoch_info_h

/* fd_epoch_info mirrors alpenglow/src/consensus/epoch_info.rs (EpochInfo,
   ValidatorEpochInfo) plus ValidatorInfo (alpenglow/src/lib.rs).  It is the
   shared, read-mostly validator-set snapshot for one epoch: the canonical
   validator list (indexed by ValidatorIndex), total stake, the round-robin
   leader schedule, and the quorum predicates.

   Networking fields of the Rust ValidatorInfo (the SocketAddrs) are omitted —
   they are a concern of the tile's link fabric, not the consensus core.

   fd_epoch_info_t is a flat, self-contained block: the validator array follows
   the header contiguously, so it is trivially relocatable / copyable.  It is
   read-only after fd_epoch_info_new. */

#include "../fd_alpenglow_base.h"
#include "../crypto/fd_aggsig.h"

/* fd_validator_info_t mirrors the consensus-relevant fields of ValidatorInfo. */

struct fd_validator_info {
  ulong          id;            /* ValidatorIndex; must equal array position */
  ulong          stake;         /* Stake                                     */
  fd_pubkey_t    pubkey;        /* ed25519 identity key (block/shred sigs)   */
  fd_aggsig_pk_t voting_pubkey; /* BLS voting key (vote aggregation)         */
};
typedef struct fd_validator_info fd_validator_info_t;

struct fd_epoch_info {
  ulong validator_cnt;
  ulong total_stake;
  /* fd_validator_info_t validators    [ validator_cnt ] follows immediately */
  /* fd_aggsig_pk_t      voting_pubkeys[ validator_cnt ] follows immediately */
};
typedef struct fd_epoch_info fd_epoch_info_t;

/* fd_validator_epoch_info_t mirrors ValidatorEpochInfo: a per-validator view
   adding our own index on top of the shared epoch. */

struct fd_validator_epoch_info {
  ulong                   own_id;
  fd_epoch_info_t const * epoch;
};
typedef struct fd_validator_epoch_info fd_validator_epoch_info_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong fd_epoch_info_align( void );

/* fd_epoch_info_footprint returns the byte footprint of an epoch info holding
   validator_cnt validators. */

FD_FN_CONST ulong fd_epoch_info_footprint( ulong validator_cnt );

/* fd_epoch_info_new formats mem (>= footprint, aligned) as an epoch info over
   the validators[0,validator_cnt) array.  FD_TEST's that validators[i].id==i
   (mirrors EpochInfo::new) and sums total stake.  Returns mem. */

void * fd_epoch_info_new( void *                      mem,
                          fd_validator_info_t const * validators,
                          ulong                       validator_cnt );

/* fd_epoch_info_join returns a typed handle to a formatted epoch info. */

fd_epoch_info_t * fd_epoch_info_join( void * mem );

/* fd_epoch_info_validators returns the contiguous validator array. */

FD_FN_PURE static inline fd_validator_info_t const *
fd_epoch_info_validators( fd_epoch_info_t const * ei ) {
  return (fd_validator_info_t const *)(ei+1);
}

/* fd_epoch_info_validator returns validator info for index id (EpochInfo::validator). */

FD_FN_PURE static inline fd_validator_info_t const *
fd_epoch_info_validator( fd_epoch_info_t const * ei, ulong id ) {
  FD_TEST( id<ei->validator_cnt );
  return fd_epoch_info_validators( ei ) + id;
}

/* fd_epoch_info_voting_pubkeys returns the contiguous array of BLS
   voting pubkeys (one per validator, indexed by validator index), laid
   out immediately after the validator array. */

FD_FN_PURE static inline fd_aggsig_pk_t const *
fd_epoch_info_voting_pubkeys( fd_epoch_info_t const * ei ) {
  return (fd_aggsig_pk_t const *)( fd_epoch_info_validators( ei ) + ei->validator_cnt );
}

/* fd_epoch_info_leader returns the leader for slot (EpochInfo::leader),
   round-robin over windows by validator index. */

FD_FN_PURE static inline fd_validator_info_t const *
fd_epoch_info_leader( fd_epoch_info_t const * ei, ulong slot ) {
  ulong window    = slot / FD_ALPENGLOW_SLOTS_PER_WINDOW;
  ulong leader_id = window % ei->validator_cnt;
  return fd_epoch_info_validator( ei, leader_id );
}

FD_FN_PURE static inline ulong
fd_epoch_info_total_stake( fd_epoch_info_t const * ei ) { return ei->total_stake; }

FD_FN_PURE static inline int fd_epoch_info_is_weakest_quorum( fd_epoch_info_t const * ei, ulong stake ) { return fd_alpenglow_is_weakest_quorum( stake, ei->total_stake ); }
FD_FN_PURE static inline int fd_epoch_info_is_weak_quorum   ( fd_epoch_info_t const * ei, ulong stake ) { return fd_alpenglow_is_weak_quorum   ( stake, ei->total_stake ); }
FD_FN_PURE static inline int fd_epoch_info_is_quorum        ( fd_epoch_info_t const * ei, ulong stake ) { return fd_alpenglow_is_quorum        ( stake, ei->total_stake ); }
FD_FN_PURE static inline int fd_epoch_info_is_strong_quorum ( fd_epoch_info_t const * ei, ulong stake ) { return fd_alpenglow_is_strong_quorum ( stake, ei->total_stake ); }

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_alpenglow_consensus_fd_epoch_info_h */
